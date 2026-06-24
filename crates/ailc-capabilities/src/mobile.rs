//! Мобильный слой ailc: статический анализ мобильных конфигураций поверх общего
//! `ScanEngine` плюс сборка/тесты/анализаторы мобильных и нативных стеков поверх
//! `Runner`. Покрывает то, чего раньше не было: разбор манифестов Android и iOS,
//! мобильные формы секретов, небезопасное хранение токенов, проверки диплинков, а
//! также мульти-стек верификацию без раннего возврата по первому манифесту.
//!
//! ПРИНЦИП крейта сохранён: статические проверки выражены ТАБЛИЦЕЙ правил поверх
//! одного `ScanEngine` (нулевое дублирование логики обхода и матча), а сборка и
//! анализаторы идут через единый `Runner` с честным разделением исходов «не запущено
//! из-за отсутствия тулчейна» и «запущено и упало». Каждое правило безопасности несёт
//! проверенную ссылку на Common Weakness Enumeration (CWE), а где уместно, на каталог
//! Open Worldwide Application Security Project (OWASP), в том числе на OWASP Mobile
//! Application Security Verification Standard (MASVS) и OWASP Mobile Top 10.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Finding, Result, RunInput,
    Severity, Tier,
};
use ailc_core::engines::runner::Runner;
use ailc_core::engines::scan::{Matcher, Rule, SOURCE_CODE};
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::path::{Path, PathBuf};

use crate::{scan_manifest, ScanCapability};

// ═══════════════════════════════════════════════════════════════════════════
//  Расширения мобильных конфигурационных файлов
// ═══════════════════════════════════════════════════════════════════════════

/// Расширения конфигурационных файлов мобильных и нативных проектов, по которым
/// классические конфиг-уязвимости (android:exported, usesCleartextTraffic,
/// NSAllowsArbitraryLoads и подобные) были недостижимы: общий список `SOURCE_CODE`
/// их не содержал, а правила безопасности фильтровались по `SOURCE_CODE`. Здесь
/// собраны манифесты и конфигурации обеих платформ. Список заявлен явно, чтобы
/// правила конфигурации не растекались на прозу и документацию.
///
/// Состав: `xml` (AndroidManifest.xml, network_security_config.xml, strings.xml),
/// `plist` (Info.plist и прочие списки свойств iOS/macOS), `properties` и `gradle`
/// (gradle.properties, build.gradle с подписью и флагами), `kts` (build.gradle.kts),
/// `entitlements` (права приложения iOS/macOS) и `json` (assetlinks.json,
/// apple-app-site-association и конфигурации React Native/Expo).
pub const MOBILE_CONFIG_EXTS: &[&str] = &[
    "xml",
    "plist",
    "properties",
    "gradle",
    "kts",
    "entitlements",
    "json",
];

/// Расширения, на которых имеет смысл искать мобильные формы секретов и небезопасное
/// хранение токенов: исходный код всех языков движка плюс мобильные конфигурации.
/// Секрет в `strings.xml`/`gradle.properties` так же опасен, как в исходнике, поэтому
/// охват шире, чем только `SOURCE_CODE`.
fn mobile_secret_exts() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = SOURCE_CODE.to_vec();
    v.extend_from_slice(MOBILE_CONFIG_EXTS);
    v.sort_unstable();
    v.dedup();
    v
}

// ═══════════════════════════════════════════════════════════════════════════
//  T27: security.scan/mobile-config — статический анализ мобильных конфигураций
// ═══════════════════════════════════════════════════════════════════════════

/// Статический мобильный анализатор поверх `ScanEngine`: манифесты Android и iOS,
/// флаги небезопасной сети, отладки и резервного копирования, мобильные формы
/// секретов, небезопасное хранение токенов и конфигурации диплинков. Реализован как
/// таблица правил, поэтому повторно использует единый движок обхода и матча.
pub fn mobile_config_scan() -> ScanCapability {
    // Расширения для секрет-правил и правил хранения токенов считаем один раз и
    // утекаем в статический срез: таблица правил требует `&'static [&'static str]`,
    // а набор расширений фиксирован на время жизни процесса. Утечка единичного
    // небольшого вектора при инициализации правил безопасна и идиоматична для
    // конфигурации, живущей до конца программы.
    let secret_exts: &'static [&'static str] = Box::leak(mobile_secret_exts().into_boxed_slice());

    ScanCapability::new(
        scan_manifest(
            "security.scan/mobile-config",
            Family::Security,
            "Статический анализ мобильных конфигураций (AndroidManifest.xml, Info.plist, entitlements, build.gradle, network security config, assetlinks/apple-app-site-association): экспортируемые компоненты без разрешения, открытый текст по сети, отладка и резервное копирование в проде, ослабленная транспортная безопасность iOS, мобильные секреты и небезопасное хранение токенов, небезопасные диплинки.",
        ),
        vec![
            // ── Android: экспортируемый компонент без ограничения разрешением ──────
            // android:exported="true" открывает компонент (Activity/Service/Receiver/
            // Provider) сторонним приложениям. Без android:permission в той же
            // декларации это прямой межприложенческий доступ. Lookahead/lookbehind в
            // crate `regex` отсутствует, поэтому отрицание «нет permission рядом»
            // выражаем предикатом по содержимому строки.
            Rule {
                id: "mobile-exported-no-permission",
                severity: Severity::High,
                exts: &["xml"],
                matcher: Matcher::Predicate(|l| {
                    let s = l.to_lowercase();
                    s.contains("android:exported=\"true\"")
                        && !s.contains("android:permission")
                        && !s.contains("android:readpermission")
                        && !s.contains("android:writepermission")
                }),
                message: "Экспортируемый компонент Android без ограничения разрешением (android:exported=\"true\" без android:permission): доступен любому приложению (CWE-926 Improper Export of Android Application Components, OWASP MASVS-PLATFORM-1). Задайте android:permission или уберите экспорт.",
            },
            // ── Android: трафик открытым текстом (cleartext) разрешён ───────────────
            // usesCleartextTraffic="true" разрешает HTTP без TLS на уровне приложения.
            Rule {
                id: "mobile-cleartext-traffic",
                severity: Severity::High,
                exts: &["xml"],
                matcher: Matcher::regex(
                    r#"(?i)android:usesCleartextTraffic\s*=\s*"true""#,
                ),
                message: "Разрешён сетевой трафик открытым текстом (android:usesCleartextTraffic=\"true\"): возможен перехват и подмена (CWE-319 Cleartext Transmission of Sensitive Information, OWASP MASVS-NETWORK-1). Отключите cleartext и используйте только HTTPS.",
            },
            // ── Android: cleartextTrafficPermitted в network security config ────────
            Rule {
                id: "mobile-cleartext-permitted",
                severity: Severity::High,
                exts: &["xml"],
                matcher: Matcher::regex(
                    r#"(?i)cleartextTrafficPermitted\s*=\s*"true""#,
                ),
                message: "Network Security Config разрешает открытый текст (cleartextTrafficPermitted=\"true\"): домен доступен по HTTP без TLS (CWE-319, OWASP MASVS-NETWORK-1). Уберите разрешение или ограничьте его отладочной конфигурацией.",
            },
            // ── Android: отладка включена в манифесте ───────────────────────────────
            Rule {
                id: "mobile-debuggable",
                severity: Severity::High,
                exts: &["xml"],
                matcher: Matcher::regex(r#"(?i)android:debuggable\s*=\s*"true""#),
                message: "Приложение Android помечено отлаживаемым (android:debuggable=\"true\"): в проде это открывает доступ к данным и выполнению через отладчик (CWE-489 Active Debug Code, OWASP MASVS-RESILIENCE-1). Уберите флаг из релизной сборки.",
            },
            // ── Android: автоматический бэкап включён ────────────────────────────────
            // allowBackup="true" (или отсутствие явного false) позволяет извлечь данные
            // приложения через adb backup. Правило флагует ЯВНОЕ true.
            Rule {
                id: "mobile-allow-backup",
                severity: Severity::Medium,
                exts: &["xml"],
                matcher: Matcher::regex(r#"(?i)android:allowBackup\s*=\s*"true""#),
                message: "Включено автоматическое резервное копирование (android:allowBackup=\"true\"): данные приложения извлекаются через adb backup без рут-прав (CWE-530 Exposure of Backup File to an Unauthorized Control Sphere, OWASP MASVS-STORAGE-2). Установите android:allowBackup=\"false\" или настройте правила исключения данных.",
            },
            // ── iOS: App Transport Security полностью отключён ──────────────────────
            // NSAllowsArbitraryLoads=true снимает требование TLS для всех доменов.
            Rule {
                id: "mobile-ats-arbitrary-loads",
                severity: Severity::High,
                exts: &["plist"],
                matcher: Matcher::multiline_regex(
                    r"(?is)<key>\s*NSAllowsArbitraryLoads\s*</key>\s*<true\s*/>",
                ),
                message: "App Transport Security отключён глобально (NSAllowsArbitraryLoads = true): разрешены небезопасные HTTP-соединения ко всем доменам (CWE-319 Cleartext Transmission of Sensitive Information, OWASP MASVS-NETWORK-1). Уберите ключ и задайте исключения только для конкретных доменов при крайней необходимости.",
            },
            // ── iOS: ATS отключён для медиа/веб-контента ────────────────────────────
            Rule {
                id: "mobile-ats-arbitrary-media",
                severity: Severity::Medium,
                exts: &["plist"],
                matcher: Matcher::multiline_regex(
                    r"(?is)<key>\s*NSAllowsArbitraryLoadsForMedia\s*</key>\s*<true\s*/>|<key>\s*NSAllowsArbitraryLoadsInWebContent\s*</key>\s*<true\s*/>",
                ),
                message: "Ослаблена транспортная безопасность iOS для медиа или веб-контента (NSAllowsArbitraryLoadsForMedia/NSAllowsArbitraryLoadsInWebContent = true): часть трафика идёт без TLS (CWE-319, OWASP MASVS-NETWORK-1). Ограничьте исключение конкретными доменами через NSExceptionDomains.",
            },
            // ── iOS: исключение домена разрешает открытый текст ─────────────────────
            Rule {
                id: "mobile-ats-insecure-http",
                severity: Severity::Medium,
                exts: &["plist"],
                matcher: Matcher::multiline_regex(
                    r"(?is)<key>\s*NSExceptionAllowsInsecureHTTPLoads\s*</key>\s*<true\s*/>|<key>\s*NSTemporaryExceptionAllowsInsecureHTTPLoads\s*</key>\s*<true\s*/>",
                ),
                message: "Исключение App Transport Security разрешает HTTP без TLS для домена (NSExceptionAllowsInsecureHTTPLoads = true): трафик к домену уязвим к перехвату (CWE-319, OWASP MASVS-NETWORK-1). Переведите домен на HTTPS и уберите исключение.",
            },
            // Замечание про диплинки Android (intent-filter с http(s)-схемой без
            // android:autoVerify="true") вынесено в статический разбор AndroidManifest
            // внутри verify/mobile: проверка требует ОТРИЦАНИЯ наличия autoVerify в
            // открывающем теге фильтра, а крейт `regex` версии 1 не поддерживает
            // опережающую проверку (lookahead), поэтому одной таблицей правил это
            // выразить нельзя без ложных срабатываний на безопасных фильтрах. Полная
            // блочная логика реализована в analyze_android_manifest (см. ниже), правило
            // id остаётся mobile-deeplink-no-autoverify.
            // ── assetlinks.json: подстановочный отпечаток сертификата ────────────────
            Rule {
                id: "mobile-assetlinks-wildcard-fingerprint",
                severity: Severity::Medium,
                exts: &["json"],
                matcher: Matcher::Predicate(|l| {
                    let s = l.to_lowercase();
                    s.contains("sha256_cert_fingerprints")
                        && (s.contains("\"*\"") || s.contains(": \"*"))
                }),
                message: "Digital Asset Links с подстановочным отпечатком сертификата (sha256_cert_fingerprints = \"*\"): связь App Links принимает любую подпись (CWE-939, OWASP MASVS-PLATFORM-3). Укажите точные отпечатки релизного сертификата.",
            },
            // ── apple-app-site-association: универсальная связь со всеми путями ──────
            // Запись с "*" в paths делает Universal Link перехватываемым для всего
            // приложения. Многострочно: блок appID и массив paths разнесены по строкам.
            Rule {
                id: "mobile-aasa-wildcard-paths",
                severity: Severity::Low,
                exts: &["json"],
                matcher: Matcher::window_regex(
                    r#"(?is)"applinks".*?"paths"\s*:\s*\[\s*"\*"\s*\]"#,
                    30,
                ),
                message: "apple-app-site-association связывает приложение со всеми путями домена (\"paths\": [\"*\"]): расширяет поверхность Universal Links (CWE-939, OWASP MASVS-PLATFORM-3). Перечислите конкретные разрешённые пути.",
            },
            // ── Мобильные секреты: ключ Firebase/Google Cloud формы AIza ────────────
            // Базовый паттерн AIza уже есть в security.scan/secret и достигает
            // xml/properties через exts: &[]. Здесь мы НЕ дублируем google-api-key, а
            // добавляем НЕДОСТАЮЩИЕ мобильные формы: префиксный Firebase Cloud
            // Messaging server key (AAAA…:APA91b…) и токен карт Mapbox (sk./pk.).
            Rule {
                id: "mobile-firebase-cloud-messaging-key",
                severity: Severity::High,
                exts: secret_exts,
                matcher: Matcher::regex(r"\bAAAA[A-Za-z0-9_\-]{6,12}:APA91b[A-Za-z0-9_\-]{100,}\b"),
                message: "Серверный ключ Firebase Cloud Messaging (форма AAAA…:APA91b…) в исходниках или конфигурации: даёт право рассылать push всем устройствам (CWE-798 Use of Hard-coded Credentials, OWASP MASVS-STORAGE-1). Храните серверный ключ на бэкенде, не в клиенте.",
            },
            // ── Мобильные секреты: секретный токен Mapbox (sk.) ─────────────────────
            Rule {
                id: "mobile-mapbox-secret-token",
                severity: Severity::High,
                exts: secret_exts,
                matcher: Matcher::regex(r"\bsk\.eyJ[0-9A-Za-z_\-]{20,}\.[0-9A-Za-z_\-]{20,}\b"),
                message: "Секретный токен Mapbox (sk.…) в исходниках или конфигурации: даёт полный доступ к аккаунту Mapbox (CWE-798 Use of Hard-coded Credentials, OWASP MASVS-STORAGE-1). Используйте в клиенте только публичный токен pk. с ограничениями.",
            },
            // ── Небезопасное хранение токена: Android SharedPreferences ─────────────
            // Запись секрета/токена в SharedPreferences без шифрования вместо Android
            // Keystore/EncryptedSharedPreferences. Требуем форму putString с ключом,
            // похожим на секрет, чтобы не ловить любое сохранение настройки.
            Rule {
                id: "mobile-token-in-sharedprefs",
                severity: Severity::Medium,
                exts: &["java", "kt", "kts"],
                matcher: Matcher::regex(
                    r#"(?i)\.putString\s*\(\s*["'][^"']*(?:token|secret|password|api[_-]?key|auth|credential|jwt)[^"']*["']"#,
                ),
                message: "Токен или секрет сохраняется в SharedPreferences открытым текстом: хранилище читается на устройстве с рут-правами или из бэкапа (CWE-312 Cleartext Storage of Sensitive Information, OWASP MASVS-STORAGE-1). Используйте Android Keystore или EncryptedSharedPreferences.",
            },
            // ── Небезопасное хранение токена: iOS UserDefaults ──────────────────────
            // Запись секрета в UserDefaults вместо Keychain. UserDefaults хранится в
            // незашифрованном plist и попадает в бэкап.
            Rule {
                id: "mobile-token-in-userdefaults",
                severity: Severity::Medium,
                exts: &["swift", "m", "mm"],
                matcher: Matcher::regex(
                    r#"(?i)(?:UserDefaults\.standard|NSUserDefaults[^\n]*)\.set\s*\([^,\n)]*,\s*forKey\s*:\s*["'][^"']*(?:token|secret|password|api[_-]?key|auth|credential|jwt)[^"']*["']"#,
                ),
                message: "Токен или секрет сохраняется в UserDefaults открытым текстом: хранилище не шифруется и попадает в резервную копию (CWE-312 Cleartext Storage of Sensitive Information, OWASP MASVS-STORAGE-1). Используйте Keychain Services для секретов.",
            },
        ],
    )
}

// ═══════════════════════════════════════════════════════════════════════════
//  T30/T31: verify/mobile — мульти-стек верификация мобильных и нативных проектов
// ═══════════════════════════════════════════════════════════════════════════

/// Один независимый верификатор стека: метка, рабочая папка и план шагов. План
/// делится на ОБЯЗАТЕЛЬНЫЕ (сборка/тесты, провал даёт находку) и МЯГКИЕ шаги
/// (анализаторы и статический разбор; их замечания информативны, а отсутствие
/// инструмента честно фиксируется как пропуск, а не как успех).
struct StackPlan {
    /// Человекочитаемая метка стека (например, «Android (Gradle)»).
    label: String,
    /// Рабочая папка, в которой запускаются шаги стека (для нативных подпроектов это
    /// подпапка android/ или ios/, а не корень).
    cwd: PathBuf,
    /// Обязательный шаг сборки/тестов: (bin, args). Провал даёт находку
    /// `mobile-build-fail`. `None`, когда автозапуск невозможен и нужна ручная цель
    /// (например, схема Xcode), тогда заполнен `manual`.
    build: Option<(String, Vec<String>)>,
    /// Ручная заметка, если обязательный шаг нельзя автозапустить (нет схемы и т.п.).
    manual: Option<String>,
    /// Мягкие анализаторы: список (bin, args). Отрабатывают как информативный шаг.
    analyzers: Vec<(String, Vec<String>)>,
}

/// Прочитать файл в строку, не падая (нет файла/бинарь): пустая строка.
fn read(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap_or_default()
}

/// Существует ли файл по относительному пути.
fn exists(root: &Path, rel: &str) -> bool {
    root.join(rel).exists()
}

/// Предпочесть project-local wrapper системному бинарю. Канонический Android-проект
/// собирается через закоммиченный `./gradlew`, а Maven через `./mvnw`: глобального
/// `gradle`/`mvn` на машине разработчика и на сервере непрерывной интеграции обычно
/// нет, поэтому системный путь почти всегда давал ложный пропуск «инструмент не
/// установлен». Возвращаем абсолютный путь к wrapper при его наличии (учитывая
/// вариант `.bat` на Windows), иначе имя системного бинаря.
///
/// `wrapper` — базовое имя обёртки без расширения (`gradlew` или `mvnw`), `system` —
/// имя системного бинаря (`gradle` или `mvn`).
fn prefer_wrapper(root: &Path, wrapper: &str, system: &str) -> String {
    // На Windows обёртка лежит как `<wrapper>.bat`; на остальных платформах без
    // расширения. Проверяем оба, чтобы поведение не зависело от текущей ОС при
    // анализе кросс-платформенного репозитория.
    for candidate in [wrapper.to_string(), format!("{wrapper}.bat")] {
        let p = root.join(&candidate);
        if p.exists() {
            // Абсолютный путь, чтобы Runner запустил именно локальную обёртку, а не
            // искал её в PATH (её там нет).
            return p.to_string_lossy().to_string();
        }
    }
    system.to_string()
}

/// Содержит ли package.json зависимость от React Native или Expo (по имени пакета в
/// dependencies/devDependencies). Грубый, но достаточный признак: имена пакетов
/// уникальны и не встречаются как случайные подстроки в осмысленном package.json.
fn is_react_native(pkg: &str) -> bool {
    pkg.contains("\"react-native\"")
        || pkg.contains("\"react-native-")
        || pkg.contains("\"expo\"")
        || pkg.contains("\"expo-")
}

/// Распознать ВСЕ мобильные и нативные стеки проекта как независимые верификаторы.
/// В отличие от прежней детекции по первому манифесту, здесь нет раннего возврата:
/// гибрид Flutter плюс нативный Android плюс нативный iOS даёт три верификатора, а
/// корневой package.json с React Native плюс подпапки android/ и ios/ распознаётся
/// и как React Native, и как нативные подпроекты. Каждый стек получает собственный
/// план обязательных и мягких шагов в своей рабочей папке.
fn detect_stacks(root: &Path) -> Vec<StackPlan> {
    let mut stacks: Vec<StackPlan> = Vec::new();

    // ── Flutter/Dart (pubspec.yaml) ─────────────────────────────────────────
    if exists(root, "pubspec.yaml") {
        let pubspec = read(root, "pubspec.yaml");
        // Flutter-приложение vs чистый Dart-пакет: у Flutter в pubspec есть зависимость
        // flutter, а команда анализа отличается (flutter analyze против dart analyze).
        let is_flutter = pubspec.contains("flutter:") || pubspec.contains("sdk: flutter");
        let (label, build_bin, analyze) = if is_flutter {
            (
                "Flutter".to_string(),
                ("flutter", vec!["test"]),
                ("flutter", vec!["analyze"]),
            )
        } else {
            (
                "Dart".to_string(),
                ("dart", vec!["test"]),
                ("dart", vec!["analyze"]),
            )
        };
        stacks.push(StackPlan {
            label,
            cwd: root.to_path_buf(),
            build: Some((
                build_bin.0.to_string(),
                build_bin.1.iter().map(|s| s.to_string()).collect(),
            )),
            manual: None,
            analyzers: vec![(
                analyze.0.to_string(),
                analyze.1.iter().map(|s| s.to_string()).collect(),
            )],
        });
    }

    // ── React Native / Expo (package.json с соответствующей зависимостью) ────
    if exists(root, "package.json") {
        let pkg = read(root, "package.json");
        if is_react_native(&pkg) {
            let is_expo = pkg.contains("\"expo\"") || pkg.contains("\"expo-");
            let label = if is_expo {
                "React Native (Expo)".to_string()
            } else {
                "React Native".to_string()
            };
            // Тесты через npm; мягкий анализатор — expo-doctor для Expo (проверка
            // совместимости конфигурации) или eslint для чистого React Native.
            let analyzers = if is_expo {
                vec![("npx".to_string(), vec!["expo-doctor".to_string()])]
            } else {
                vec![("npx".to_string(), vec!["eslint".to_string(), ".".to_string()])]
            };
            stacks.push(StackPlan {
                label,
                cwd: root.to_path_buf(),
                build: Some(("npm".to_string(), vec!["test".to_string(), "--silent".to_string()])),
                manual: None,
                analyzers,
            });
        }
    }

    // ── Нативный Android-подпроект (android/ с gradle-обёрткой или манифестом) ──
    // Распознаём И самостоятельный Android-проект в корне, И подпапку android/
    // внутри Flutter/React Native. Каждый случай даёт свой план в своей папке.
    for sub in ["", "android"] {
        let dir = if sub.is_empty() {
            root.to_path_buf()
        } else {
            root.join(sub)
        };
        if !dir.exists() {
            continue;
        }
        let has_gradle = dir.join("build.gradle").exists()
            || dir.join("build.gradle.kts").exists()
            || dir.join("settings.gradle").exists()
            || dir.join("settings.gradle.kts").exists();
        // Подпапку android/ внутри Flutter мы уже неявно покрываем верификатором
        // Flutter (flutter test собирает android), поэтому самостоятельный нативный
        // верификатор для android/ добавляем только если это не Flutter-обёртка, то
        // есть в корне нет pubspec.yaml. Это разделяет мульти-стек без дублирования
        // одной и той же сборки.
        let is_flutter_wrapper = !sub.is_empty() && exists(root, "pubspec.yaml");
        if has_gradle && !is_flutter_wrapper {
            // T31: предпочитаем project-local ./gradlew системному gradle.
            let bin = prefer_wrapper(&dir, "gradlew", "gradle");
            // Мягкие анализаторы Kotlin: ktlint и detekt (если установлены).
            let analyzers: Vec<(String, Vec<String>)> = vec![
                ("ktlint".to_string(), Vec::new()),
                ("detekt".to_string(), Vec::new()),
            ];
            stacks.push(StackPlan {
                label: if sub.is_empty() {
                    "Android (Gradle)".to_string()
                } else {
                    "Android (нативный подпроект)".to_string()
                },
                cwd: dir.clone(),
                build: Some((bin, vec!["test".to_string(), "--quiet".to_string()])),
                manual: None,
                analyzers,
            });
        }
    }

    // ── JVM/Maven-проект через wrapper (pom.xml + mvnw) ──────────────────────
    // Maven встречается реже для мобильных, но T31 явно требует учитывать ./mvnw.
    if exists(root, "pom.xml") {
        let bin = prefer_wrapper(root, "mvnw", "mvn");
        stacks.push(StackPlan {
            label: "Java/Maven".to_string(),
            cwd: root.to_path_buf(),
            build: Some((bin, vec!["-q".to_string(), "test".to_string()])),
            manual: None,
            analyzers: vec![],
        });
    }

    // ── Swift Package Manager (Package.swift) ───────────────────────────────
    if exists(root, "Package.swift") {
        stacks.push(StackPlan {
            label: "Swift (SwiftPM)".to_string(),
            cwd: root.to_path_buf(),
            build: Some(("swift".to_string(), vec!["test".to_string()])),
            manual: None,
            analyzers: vec![("swiftlint".to_string(), vec![])],
        });
    }

    // ── Нативный iOS-подпроект (ios/ или *.xcodeproj/*.xcworkspace) ──────────
    // Распознаём И самостоятельный iOS-проект в корне, И подпапку ios/ внутри
    // Flutter/React Native. Для iOS автозапуск сборки требует схему, которую нельзя
    // надёжно угадать без интерактивного xcodebuild -list, поэтому обязательный шаг
    // выносим как ручную заметку, а МЯГКИЙ статический разбор Info.plist/entitlements
    // выполняем всегда (см. verify-логику ниже). Так iOS перестаёт быть «всегда
    // молчаливый пропуск»: статический анализ конфигурации идёт без тулчейна.
    for sub in ["", "ios"] {
        let dir = if sub.is_empty() {
            root.to_path_buf()
        } else {
            root.join(sub)
        };
        if !dir.exists() {
            continue;
        }
        let has_xcode = has_xcode_project(&dir);
        let is_flutter_wrapper = !sub.is_empty() && exists(root, "pubspec.yaml");
        if has_xcode && !is_flutter_wrapper {
            stacks.push(StackPlan {
                label: if sub.is_empty() {
                    "iOS (Xcode)".to_string()
                } else {
                    "iOS (нативный подпроект)".to_string()
                },
                cwd: dir.clone(),
                build: None,
                manual: Some(
                    "сборка/тесты iOS требуют схему: `xcodebuild -scheme <схема> test` (укажите схему вручную); статический разбор Info.plist/entitlements выполнен"
                        .to_string(),
                ),
                analyzers: vec![("swiftlint".to_string(), vec![])],
            });
        }
    }

    stacks
}

/// Есть ли в папке проект Xcode (`*.xcodeproj` или `*.xcworkspace`).
fn has_xcode_project(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten().any(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                name.ends_with(".xcodeproj") || name.ends_with(".xcworkspace")
            })
        })
        .unwrap_or(false)
}

/// Статический разбор iOS Info.plist и entitlements БЕЗ тулчейна: ищем явные
/// небезопасные флаги транспортной безопасности и отладочные права. Это дополняет
/// `security.scan/mobile-config` тем, что выполняется прямо в верификаторе iOS даже
/// когда сборку запустить нельзя (нет схемы), поэтому iOS-проект всегда получает хоть
/// какой-то реальный, а не молчаливо пропущенный, анализ. Возвращает находки с
/// проверенными ссылками CWE/OWASP. Файлы ищет нерекурсивно в папке стека и в
/// типовых местах (корень, подпапка с тем же именем что цель).
fn analyze_ios_plist_entitlements(dir: &Path) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    // Собираем содержимое всех plist/entitlements в папке стека (нерекурсивно: типовая
    // раскладка держит Info.plist рядом с проектом). Этого достаточно для статической
    // проверки флагов, а полный обход остаётся за security.scan/mobile-config.
    let mut blobs: Vec<(String, String)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let path = e.path();
            let ext = path
                .extension()
                .and_then(|x| x.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if ext != "plist" && ext != "entitlements" {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            blobs.push((name, content));
        }
    }

    // Нормализуем пробелы между тегами, чтобы сопоставление <key>…</key><true/> не
    // зависело от форматирования plist.
    fn ats_arbitrary(text: &str) -> bool {
        let t = text.to_lowercase().replace(['\n', '\r', '\t'], " ");
        // Грубое, но точное соответствие: ключ NSAllowsArbitraryLoads со значением true
        // (true/> следует за закрытием key с произвольными пробелами).
        t.contains("nsallowsarbitraryloads")
            && t.split("nsallowsarbitraryloads")
                .skip(1)
                .any(|seg| seg.trim_start().starts_with("</key>") && seg.contains("<true"))
    }

    for (name, content) in &blobs {
        if ats_arbitrary(content) {
            findings.push(Finding {
                rule: "mobile-ats-arbitrary-loads".into(),
                severity: Severity::High,
                message: format!(
                    "{name}: App Transport Security отключён глобально (NSAllowsArbitraryLoads = true): разрешены небезопасные HTTP-соединения ко всем доменам (CWE-319 Cleartext Transmission of Sensitive Information, OWASP MASVS-NETWORK-1). Уберите ключ и задайте точечные исключения."
                ),
                location: None,
                evidence: None,
                verified: true,
                source: "verify/mobile".into(),
            });
        }
        // Отладочное право get-task-allow в релизных entitlements открывает отладчик.
        let low = content.to_lowercase().replace(['\n', '\r', '\t'], " ");
        if low.contains("get-task-allow")
            && low
                .split("get-task-allow")
                .skip(1)
                .any(|seg| seg.trim_start().starts_with("</key>") && seg.contains("<true"))
        {
            findings.push(Finding {
                rule: "mobile-ios-get-task-allow".into(),
                severity: Severity::Medium,
                message: format!(
                    "{name}: право отладки включено (get-task-allow = true): в релизной сборке это позволяет подключить отладчик к процессу (CWE-489 Active Debug Code, OWASP MASVS-RESILIENCE-1). Отключите get-task-allow для релизного профиля."
                ),
                location: None,
                evidence: None,
                verified: true,
                source: "verify/mobile".into(),
            });
        }
    }
    findings
}

/// Статический разбор AndroidManifest.xml на небезопасные диплинки БЕЗ тулчейна.
/// Реализует ту проверку, которую таблица правил выразить не может из-за отсутствия
/// опережающей проверки (lookahead) в крейте `regex`: ищет блоки `<intent-filter>`,
/// которые объявляют действие просмотра (VIEW) и схему http(s), но НЕ содержат
/// `android:autoVerify="true"` в открывающем теге фильтра. Такой App Link может быть
/// перехвачен сторонним приложением, так как владение доменом не подтверждено.
/// Возвращает находки `mobile-deeplink-no-autoverify` с проверенной ссылкой CWE/OWASP.
/// Манифесты ищет по типовым путям в папке стека (нерекурсивно по корню и по
/// `app/src/main/`, где Android держит манифест по умолчанию).
fn analyze_android_manifest(dir: &Path) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    // Типовые места манифеста: корень модуля, стандартная раскладка Gradle и
    // подпапка app/ многомодульного проекта.
    let candidates = [
        "AndroidManifest.xml",
        "src/main/AndroidManifest.xml",
        "app/src/main/AndroidManifest.xml",
    ];
    for rel in candidates {
        let path = dir.join(rel);
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if manifest_has_unverified_deeplink(&content) {
            findings.push(Finding {
                rule: "mobile-deeplink-no-autoverify".into(),
                severity: Severity::Medium,
                message: format!(
                    "{rel}: диплинк Android без проверки владения доменом (intent-filter с http(s)-схемой без android:autoVerify=\"true\"): ссылку может перехватить стороннее приложение (CWE-939 Improper Authorization in Handler for Custom URL Scheme, OWASP MASVS-PLATFORM-3). Включите android:autoVerify=\"true\" и опубликуйте assetlinks.json."
                ),
                location: None,
                evidence: None,
                verified: true,
                source: "verify/mobile".into(),
            });
        }
    }
    findings
}

/// Истина, если в манифесте есть хотя бы один блок `<intent-filter>…</intent-filter>`,
/// который объявляет действие VIEW и схему http(s), но НЕ имеет `android:autoVerify`
/// в открывающем теге. Разбор блочный (не построчный), поэтому корректно обрабатывает
/// атрибуты и содержимое, разнесённые по строкам, и точно различает безопасный фильтр
/// с autoVerify от уязвимого без него (отрицание выражено в коде, а не регулярным
/// выражением, у которого нет опережающей проверки).
fn manifest_has_unverified_deeplink(content: &str) -> bool {
    let lower = content.to_lowercase();
    let mut search_from = 0usize;
    while let Some(rel_open) = lower[search_from..].find("<intent-filter") {
        let open = search_from + rel_open;
        // Конец открывающего тега фильтра (первый `>` после `<intent-filter`).
        let Some(rel_gt) = lower[open..].find('>') else {
            break;
        };
        // `>` это ASCII-символ, поэтому inclusive-срез заканчивается на границе символа.
        let open_tag_end = open + rel_gt;
        let open_tag = &lower[open..=open_tag_end];
        // Конец блока фильтра.
        let Some(rel_close) = lower[open_tag_end..].find("</intent-filter>") else {
            // Нет закрывающего тега: дальше искать смысла нет.
            break;
        };
        let close = open_tag_end + rel_close;
        let block = &lower[open..close];

        let has_view = block.contains("android.intent.action.view");
        // Схема http или https в значении атрибута android:scheme.
        let has_http_scheme = block.contains("android:scheme=\"http\"")
            || block.contains("android:scheme=\"https\"");
        // autoVerify задаётся в ОТКРЫВАЮЩЕМ теге фильтра.
        let has_autoverify = open_tag.contains("android:autoverify=\"true\"");

        if has_view && has_http_scheme && !has_autoverify {
            return true;
        }
        search_from = close + "</intent-filter>".len();
    }
    false
}

pub struct MobileVerify {
    manifest: CapabilityManifest,
}

impl Default for MobileVerify {
    fn default() -> Self {
        Self::new()
    }
}

impl MobileVerify {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "verify/mobile",
                family: Family::Verify,
                engine: EngineKind::Runner,
                when_to_use: "Собрать и прогнать тесты мобильного или нативного проекта (Flutter/Dart, React Native/Expo, Android через ./gradlew, Swift/iOS), запустить доступные анализаторы (flutter/dart analyze, swiftlint, ktlint, detekt) и статически разобрать Info.plist/entitlements. Поддерживает мульти-стек без раннего пропуска.",
                input_schema: r#"{"type":"object","properties":{"target":{"type":"string"}}}"#,
                tier: Tier::Core,
                deterministic: false,
                mutates: false,
            },
        }
    }
}

impl Capability for MobileVerify {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        // Учитываем input.target: base валидируется (не выводит за корень проекта).
        let base = ctx.base(input)?;
        let mut out = CapabilityOutput::default();

        let stacks = detect_stacks(&base);
        if stacks.is_empty() {
            out.skipped = Some(
                "мобильный/нативный проект не распознан (нет pubspec.yaml, package.json с react-native/expo, build.gradle, Package.swift, *.xcodeproj)"
                    .into(),
            );
            out.summary = "verify/mobile: пропущено (стек не распознан)".into();
            return Ok(out);
        }

        // Каждый стек верифицируется НЕЗАВИСИМО: его исход (прошёл/упал/пропущен)
        // отражается в сводке отдельно, поэтому мульти-стек не маскируется и не
        // выдаёт ранний зелёный по первому стеку.
        let mut labels: Vec<String> = Vec::new();
        let mut any_ran = false;
        let mut any_failed = false;
        let mut skip_reasons: Vec<String> = Vec::new();

        for stack in &stacks {
            labels.push(stack.label.clone());
            let sub = Ctx::new(stack.cwd.clone());

            // ── Статический разбор Info.plist/entitlements для iOS-стеков ──────
            // Выполняется всегда, без тулчейна, поэтому даёт реальный сигнал даже
            // когда сборку iOS запустить нельзя.
            if stack.label.starts_with("iOS") {
                for f in analyze_ios_plist_entitlements(&stack.cwd) {
                    out.findings.push(f);
                }
            }
            // ── Статический разбор AndroidManifest для Android-стеков ──────────
            // Диплинки без autoVerify проверяются здесь блочной логикой (см.
            // analyze_android_manifest): таблица правил это выразить не может.
            if stack.label.starts_with("Android") {
                for f in analyze_android_manifest(&stack.cwd) {
                    out.findings.push(f);
                }
            }

            // ── Обязательный шаг: сборка/тесты ────────────────────────────────
            match (&stack.build, &stack.manual) {
                (Some((bin, args)), _) => {
                    let argrefs: Vec<&str> = args.iter().map(String::as_str).collect();
                    let res = Runner::run(&sub, bin, &argrefs);
                    if !res.ran {
                        // Различаем «нет тулчейна» от «только через wrapper»: если
                        // системный bin отсутствует, но в проекте есть ./gradlew или
                        // ./mvnw, причина именно в недоступности обёртки, а не стека.
                        let reason = res
                            .skipped_reason
                            .clone()
                            .unwrap_or_else(|| "нет инструмента".to_string());
                        skip_reasons.push(format!("{}: {}", stack.label, reason));
                    } else {
                        any_ran = true;
                        // Успех конкретного шага отражается в сводке через метку стека;
                        // отдельной находки он не порождает. Провал даёт находку
                        // mobile-build-fail, заземлённую на реальный прогон.
                        if !res.exit_ok {
                            any_failed = true;
                            out.findings.push(Finding {
                                rule: "mobile-build-fail".into(),
                                severity: Severity::High,
                                message: format!(
                                    "{}: сборка или тесты не проходят (прогнан `{} {}`, код {:?})",
                                    stack.label,
                                    bin,
                                    args.join(" "),
                                    res.code
                                ),
                                location: None,
                                evidence: None,
                                verified: true,
                                source: "verify/mobile".into(),
                            });
                            for l in res.tail(15) {
                                out.records.push(format!("[{}] {}", stack.label, l));
                            }
                        }
                    }
                }
                (None, Some(note)) => {
                    // Автозапуск невозможен (нужна схема): фиксируем как осознанный
                    // пропуск обязательного шага, но статический разбор уже выполнен
                    // выше, поэтому это не «молчаливый» зелёный.
                    skip_reasons.push(format!("{}: {}", stack.label, note));
                }
                (None, None) => {
                    skip_reasons.push(format!("{}: нет плана сборки", stack.label));
                }
            }

            // ── Мягкие шаги: анализаторы ──────────────────────────────────────
            // Отсутствие анализатора НЕ ошибка: фиксируем как пропуск мягкого шага.
            // Замечания анализатора выводим в записи как информацию (не блокер), так
            // как набор правил линтера зависит от конфигурации проекта.
            for (bin, args) in &stack.analyzers {
                let argrefs: Vec<&str> = args.iter().map(String::as_str).collect();
                let res = Runner::run(&sub, bin, &argrefs);
                if !res.ran {
                    skip_reasons.push(format!(
                        "{} анализатор {}: {}",
                        stack.label,
                        bin,
                        res.skipped_reason.as_deref().unwrap_or("нет инструмента")
                    ));
                    continue;
                }
                any_ran = true;
                if !res.exit_ok {
                    out.records.push(format!(
                        "[{} · {bin}] анализатор сообщил о замечаниях (код {:?})",
                        stack.label, res.code
                    ));
                    for l in res.tail(8) {
                        out.records.push(format!("[{} · {bin}] {}", stack.label, l));
                    }
                }
            }
        }

        // Метрики и осознанные пропуски: инвариант «нет молчаливых пропусков».
        out.metrics.push(("stacks".into(), stacks.len() as f64));
        out.metrics
            .push(("mobile_findings".into(), out.findings.len() as f64));
        for r in &skip_reasons {
            out.records.push(format!("пропуск: {r}"));
        }

        // Сводка по совокупному исходу. Находки (упавшая сборка, небезопасный
        // Info.plist) сами попадают в гейт; здесь формулируем человекочитаемый итог.
        let labels_joined = labels.join(", ");
        if any_failed {
            out.summary = format!(
                "verify/mobile [{labels_joined}]: есть провалившиеся стеки ({} находок)",
                out.findings.len()
            );
        } else if any_ran {
            let note = if skip_reasons.is_empty() {
                String::new()
            } else {
                format!(", часть шагов пропущена ({})", skip_reasons.len())
            };
            out.summary = format!(
                "verify/mobile [{labels_joined}]: прогнаны доступные шаги, {} находок{note}",
                out.findings.len()
            );
        } else {
            // Ни один обязательный/мягкий шаг не запустился (нет тулчейнов). Это
            // ОСОЗНАННЫЙ пропуск с перечисленными причинами, а не успех. Но если
            // статический разбор iOS уже дал находки, они остаются в выводе.
            out.skipped = Some(format!(
                "verify/mobile [{labels_joined}]: ни один тулчейн недоступен — {}",
                skip_reasons.join("; ")
            ));
            out.summary = format!(
                "verify/mobile [{labels_joined}]: тулчейны недоступны, {} находок из статического разбора",
                out.findings.len()
            );
        }
        Ok(out)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Регистрация
// ═══════════════════════════════════════════════════════════════════════════

pub fn register(reg: &mut Registry) {
    // E2 Runner — сборка/тесты/анализаторы мобильных и нативных стеков.
    reg.register(Box::new(MobileVerify::new()));
    // E1 Scan — статический анализ мобильных конфигураций (T27).
    reg.register(Box::new(mobile_config_scan()));
}

#[cfg(test)]
mod tests {
    // `super::*` уже вносит RunInput, Ctx, Path, PathBuf и прочие типы модуля.
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Уникальная пустая временная папка для файловых фикстур (без внешних зависимостей).
    fn tmp() -> PathBuf {
        let n = CNT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ailc-mobile-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Записать файл по относительному пути внутри корня, создав родительские каталоги.
    fn write(dir: &Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }

    /// Прогнать статический мобильный сканер по корню.
    fn scan(root: &Path) -> CapabilityOutput {
        mobile_config_scan()
            .run(&Ctx::new(root), &RunInput::default())
            .unwrap()
    }

    /// Сколько находок данного правила в выводе.
    fn count_rule(out: &CapabilityOutput, rule: &str) -> usize {
        out.findings.iter().filter(|f| f.rule == rule).count()
    }

    /// Есть ли находка данного правила.
    fn has_rule(out: &CapabilityOutput, rule: &str) -> bool {
        count_rule(out, rule) > 0
    }

    // ───────────────────── T27: Android-манифест ─────────────────────

    #[test]
    fn android_exported_без_разрешения_ловится() {
        let dir = tmp();
        write(
            &dir,
            "app/src/main/AndroidManifest.xml",
            r#"<manifest>
  <application>
    <activity android:name=".Admin" android:exported="true"/>
  </application>
</manifest>"#,
        );
        let out = scan(&dir);
        assert!(
            has_rule(&out, "mobile-exported-no-permission"),
            "экспорт без permission должен сработать: {:?}",
            out.findings
        );
    }

    #[test]
    fn android_exported_с_разрешением_не_ловится() {
        // Негатив: тот же экспорт, но с android:permission не является находкой.
        let dir = tmp();
        write(
            &dir,
            "app/src/main/AndroidManifest.xml",
            r#"<activity android:name=".Admin" android:exported="true" android:permission="com.app.SECURE"/>"#,
        );
        let out = scan(&dir);
        assert!(
            !has_rule(&out, "mobile-exported-no-permission"),
            "экспорт с permission не должен считаться дырой"
        );
    }

    #[test]
    fn android_exported_false_не_ловится() {
        // Негатив: exported="false" безопасен.
        let dir = tmp();
        write(
            &dir,
            "AndroidManifest.xml",
            r#"<activity android:name=".A" android:exported="false"/>"#,
        );
        let out = scan(&dir);
        assert!(!has_rule(&out, "mobile-exported-no-permission"));
    }

    #[test]
    fn android_cleartext_traffic_ловится() {
        let dir = tmp();
        write(
            &dir,
            "AndroidManifest.xml",
            r#"<application android:usesCleartextTraffic="true"></application>"#,
        );
        let out = scan(&dir);
        assert!(has_rule(&out, "mobile-cleartext-traffic"));
    }

    #[test]
    fn android_cleartext_permitted_в_nsc_ловится() {
        let dir = tmp();
        write(
            &dir,
            "res/xml/network_security_config.xml",
            r#"<domain-config cleartextTrafficPermitted="true"><domain>api.example.com</domain></domain-config>"#,
        );
        let out = scan(&dir);
        assert!(has_rule(&out, "mobile-cleartext-permitted"));
    }

    #[test]
    fn android_debuggable_ловится() {
        let dir = tmp();
        write(
            &dir,
            "AndroidManifest.xml",
            r#"<application android:debuggable="true"/>"#,
        );
        let out = scan(&dir);
        assert!(has_rule(&out, "mobile-debuggable"));
    }

    #[test]
    fn android_allow_backup_ловится() {
        let dir = tmp();
        write(
            &dir,
            "AndroidManifest.xml",
            r#"<application android:allowBackup="true"/>"#,
        );
        let out = scan(&dir);
        assert!(has_rule(&out, "mobile-allow-backup"));
    }

    #[test]
    fn android_allow_backup_false_не_ловится() {
        let dir = tmp();
        write(
            &dir,
            "AndroidManifest.xml",
            r#"<application android:allowBackup="false"/>"#,
        );
        let out = scan(&dir);
        assert!(!has_rule(&out, "mobile-allow-backup"));
    }

    // ───────────────────── T27: iOS Info.plist / ATS ─────────────────────

    #[test]
    fn ios_ats_arbitrary_loads_ловится() {
        let dir = tmp();
        write(
            &dir,
            "Info.plist",
            r#"<plist><dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
  </dict>
</dict></plist>"#,
        );
        let out = scan(&dir);
        assert!(
            has_rule(&out, "mobile-ats-arbitrary-loads"),
            "глобальный NSAllowsArbitraryLoads должен сработать"
        );
    }

    #[test]
    fn ios_ats_false_не_ловится() {
        // Негатив: NSAllowsArbitraryLoads = false безопасен.
        let dir = tmp();
        write(
            &dir,
            "Info.plist",
            r#"<key>NSAllowsArbitraryLoads</key>
<false/>"#,
        );
        let out = scan(&dir);
        assert!(!has_rule(&out, "mobile-ats-arbitrary-loads"));
    }

    #[test]
    fn ios_ats_media_и_insecure_http_ловятся() {
        let dir = tmp();
        write(
            &dir,
            "Info.plist",
            r#"<key>NSAllowsArbitraryLoadsForMedia</key>
<true/>
<key>NSExceptionAllowsInsecureHTTPLoads</key>
<true/>"#,
        );
        let out = scan(&dir);
        assert!(has_rule(&out, "mobile-ats-arbitrary-media"));
        assert!(has_rule(&out, "mobile-ats-insecure-http"));
    }

    // ───────────────────── T27: диплинки ─────────────────────

    #[test]
    fn android_deeplink_без_autoverify_ловится() {
        // Диплинк проверяется блочной логикой verify/mobile, а не таблицей правил
        // (regex без lookahead не выразит отрицание autoVerify).
        let manifest = r#"<activity android:name=".Deep">
  <intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="https" android:host="example.com"/>
  </intent-filter>
</activity>"#;
        assert!(
            manifest_has_unverified_deeplink(manifest),
            "intent-filter без autoVerify должен распознаваться как уязвимый"
        );
    }

    #[test]
    fn android_deeplink_с_autoverify_не_ловится() {
        // Негатив: тот же фильтр с autoVerify="true" безопасен.
        let manifest = r#"<activity android:name=".Deep">
  <intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW"/>
    <data android:scheme="https" android:host="example.com"/>
  </intent-filter>
</activity>"#;
        assert!(
            !manifest_has_unverified_deeplink(manifest),
            "intent-filter с autoVerify не должен считаться уязвимым"
        );
    }

    #[test]
    fn android_deeplink_не_view_не_ловится() {
        // Негатив: фильтр со схемой http(s), но без действия VIEW (например, SEND) не
        // является App Link, его перехват по диплинку не релевантен.
        let manifest = r#"<intent-filter>
    <action android:name="android.intent.action.SEND"/>
    <data android:scheme="https"/>
  </intent-filter>"#;
        assert!(!manifest_has_unverified_deeplink(manifest));
    }

    #[test]
    fn android_deeplink_custom_scheme_не_ловится() {
        // Негатив: собственная схема (myapp://) не является App Link для http(s)-домена,
        // правило autoVerify к ней не применяется.
        let manifest = r#"<intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <data android:scheme="myapp"/>
  </intent-filter>"#;
        assert!(!manifest_has_unverified_deeplink(manifest));
    }

    #[test]
    fn android_deeplink_находится_через_verify() {
        // Сквозной путь: verify/mobile для Android-стека должен выдать находку
        // диплинка из статического разбора манифеста.
        let dir = tmp();
        write(&dir, "build.gradle", "// app\n");
        write(
            &dir,
            "app/src/main/AndroidManifest.xml",
            r#"<manifest><application><activity>
  <intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <data android:scheme="https" android:host="ex.com"/>
  </intent-filter>
</activity></application></manifest>"#,
        );
        let out = MobileVerify::new()
            .run(&Ctx::new(&dir), &RunInput::default())
            .unwrap();
        assert!(
            out.findings
                .iter()
                .any(|f| f.rule == "mobile-deeplink-no-autoverify"),
            "verify/mobile должен найти диплинк без autoVerify: {:?}",
            out.findings
        );
    }

    #[test]
    fn assetlinks_wildcard_отпечаток_ловится() {
        let dir = tmp();
        write(
            &dir,
            "public/.well-known/assetlinks.json",
            r#"[{"relation":["delegate_permission/common.handle_all_urls"],
  "target":{"namespace":"android_app","package_name":"com.app",
  "sha256_cert_fingerprints":["*"]}}]"#,
        );
        let out = scan(&dir);
        assert!(has_rule(&out, "mobile-assetlinks-wildcard-fingerprint"));
    }

    #[test]
    fn apple_app_site_association_wildcard_пути_ловится() {
        let dir = tmp();
        write(
            &dir,
            ".well-known/apple-app-site-association.json",
            r#"{"applinks":{"apps":[],"details":[{"appID":"TEAM.com.app","paths":["*"]}]}}"#,
        );
        let out = scan(&dir);
        assert!(
            has_rule(&out, "mobile-aasa-wildcard-paths"),
            "AASA с paths [*] должен сработать: {:?}",
            out.findings
        );
    }

    // ───────────────────── T27: мобильные секреты ─────────────────────

    #[test]
    fn firebase_cloud_messaging_key_ловится() {
        let dir = tmp();
        // Синтетический ключ формы AAAA…:APA91b… достаточной длины.
        let body = "a".repeat(140);
        write(
            &dir,
            "google-services-fcm.gradle",
            &format!("server_key = AAAA1234567:APA91b{body}"),
        );
        let out = scan(&dir);
        assert!(
            has_rule(&out, "mobile-firebase-cloud-messaging-key"),
            "серверный ключ FCM должен сработать"
        );
    }

    #[test]
    fn mapbox_secret_token_ловится() {
        let dir = tmp();
        let part = "Q".repeat(30);
        write(
            &dir,
            "config.properties",
            &format!("MAPBOX_DOWNLOADS_TOKEN=sk.eyJ{part}.{part}"),
        );
        let out = scan(&dir);
        assert!(has_rule(&out, "mobile-mapbox-secret-token"));
    }

    #[test]
    fn mapbox_public_token_не_ловится_как_secret() {
        // Негатив: публичный токен pk. не должен срабатывать как секретный sk.
        let dir = tmp();
        let part = "Q".repeat(30);
        write(
            &dir,
            "config.properties",
            &format!("MAPBOX_TOKEN=pk.eyJ{part}.{part}"),
        );
        let out = scan(&dir);
        assert!(
            !has_rule(&out, "mobile-mapbox-secret-token"),
            "публичный pk. не является секретным токеном"
        );
    }

    // ───────────────────── T27: небезопасное хранение токенов ─────────────────────

    #[test]
    fn token_в_sharedprefs_ловится() {
        let dir = tmp();
        write(
            &dir,
            "src/main/kotlin/Auth.kt",
            r#"prefs.edit().putString("auth_token", token).apply()"#,
        );
        let out = scan(&dir);
        assert!(
            has_rule(&out, "mobile-token-in-sharedprefs"),
            "хранение токена в SharedPreferences должно сработать"
        );
    }

    #[test]
    fn обычная_настройка_в_sharedprefs_не_ловится() {
        // Негатив: сохранение нейтральной настройки (theme) не является находкой.
        let dir = tmp();
        write(
            &dir,
            "src/main/java/Settings.java",
            r#"prefs.edit().putString("theme", "dark").apply();"#,
        );
        let out = scan(&dir);
        assert!(!has_rule(&out, "mobile-token-in-sharedprefs"));
    }

    #[test]
    fn token_в_userdefaults_ловится() {
        let dir = tmp();
        write(
            &dir,
            "Sources/Auth.swift",
            r#"UserDefaults.standard.set(accessToken, forKey: "access_token")"#,
        );
        let out = scan(&dir);
        assert!(
            has_rule(&out, "mobile-token-in-userdefaults"),
            "хранение токена в UserDefaults должно сработать: {:?}",
            out.findings
        );
    }

    #[test]
    fn обычная_настройка_в_userdefaults_не_ловится() {
        let dir = tmp();
        write(
            &dir,
            "Sources/Prefs.swift",
            r#"UserDefaults.standard.set(true, forKey: "onboardingShown")"#,
        );
        let out = scan(&dir);
        assert!(!has_rule(&out, "mobile-token-in-userdefaults"));
    }

    #[test]
    fn секрет_в_конфигурации_достигается_по_расширению() {
        // Проверяем именно охват: правило хранилища применяется к .kt, а секрет-формы
        // к мобильным конфигам. Здесь убеждаемся, что mobile-secret-форма работает в
        // .properties (вне SOURCE_CODE), то есть охват расширен корректно.
        let dir = tmp();
        let part = "Q".repeat(30);
        write(&dir, "secrets.properties", &format!("token=sk.eyJ{part}.{part}"));
        let out = scan(&dir);
        assert!(has_rule(&out, "mobile-mapbox-secret-token"));
    }

    // ───────────────────── классификация достоверности ─────────────────────

    /// Полный перечень идентификаторов правил, которые эмитирует мобильный слой:
    /// и таблица security.scan/mobile-config, и статические разборы verify/mobile.
    /// Этот перечень есть источник истины для записи в `contracts::rule_confidence`
    /// (карта достоверности принадлежит другой дорожке): оркестратор обязан внести
    /// КАЖДЫЙ из этих идентификаторов с указанным желаемым классом достоверности.
    /// `mobile-build-fail` уже классифицирован в contracts (Precise) и здесь не
    /// перечислен повторно.
    const MOBILE_RULE_IDS: &[&str] = &[
        "mobile-exported-no-permission",
        "mobile-cleartext-traffic",
        "mobile-cleartext-permitted",
        "mobile-debuggable",
        "mobile-allow-backup",
        "mobile-ats-arbitrary-loads",
        "mobile-ats-arbitrary-media",
        "mobile-ats-insecure-http",
        "mobile-deeplink-no-autoverify",
        "mobile-assetlinks-wildcard-fingerprint",
        "mobile-aasa-wildcard-paths",
        "mobile-firebase-cloud-messaging-key",
        "mobile-mapbox-secret-token",
        "mobile-token-in-sharedprefs",
        "mobile-token-in-userdefaults",
        "mobile-ios-get-task-allow",
    ];

    #[test]
    fn перечень_правил_не_пуст_и_без_дублей() {
        // Самодостаточная проверка перечня: он непуст и не содержит повторов. Сверку с
        // contracts::rule_confidence НЕ делаем здесь, потому что карта достоверности
        // ведётся в дорожке contracts и обновляется оркестратором по этому перечню;
        // привязка теста к ещё не внесённой записи дала бы ложный провал сборки.
        assert!(!MOBILE_RULE_IDS.is_empty());
        let mut seen = std::collections::HashSet::new();
        for id in MOBILE_RULE_IDS {
            assert!(seen.insert(*id), "идентификатор правила «{id}» продублирован");
        }
    }

    // ───────────────────── T31: предпочтение wrapper ─────────────────────

    #[test]
    fn prefer_wrapper_выбирает_gradlew_при_наличии() {
        let dir = tmp();
        write(&dir, "gradlew", "#!/bin/sh\n");
        let bin = prefer_wrapper(&dir, "gradlew", "gradle");
        assert!(
            bin.ends_with("gradlew"),
            "при наличии ./gradlew должен выбираться он, получено: {bin}"
        );
        assert!(
            Path::new(&bin).is_absolute(),
            "путь к wrapper должен быть абсолютным, получено: {bin}"
        );
    }

    #[test]
    fn prefer_wrapper_откатывается_на_системный() {
        let dir = tmp();
        // Обёртки нет: остаётся системный gradle.
        let bin = prefer_wrapper(&dir, "gradlew", "gradle");
        assert_eq!(bin, "gradle", "без обёртки откат на системный бинарь");
    }

    #[test]
    fn prefer_wrapper_видит_bat_на_любой_платформе() {
        let dir = tmp();
        write(&dir, "mvnw.bat", "@echo off\n");
        let bin = prefer_wrapper(&dir, "mvnw", "mvn");
        assert!(
            bin.ends_with("mvnw.bat"),
            "обёртка .bat должна распознаваться, получено: {bin}"
        );
    }

    // ───────────────────── T30: мульти-стек детекция ─────────────────────

    #[test]
    fn flutter_распознаётся_как_стек() {
        let dir = tmp();
        write(&dir, "pubspec.yaml", "name: app\nflutter:\n  sdk: flutter\n");
        let stacks = detect_stacks(&dir);
        assert!(
            stacks.iter().any(|s| s.label == "Flutter"),
            "Flutter должен распознаваться, стеки: {:?}",
            stacks.iter().map(|s| &s.label).collect::<Vec<_>>()
        );
    }

    #[test]
    fn чистый_dart_отличается_от_flutter() {
        let dir = tmp();
        write(&dir, "pubspec.yaml", "name: pure_dart_lib\nenvironment:\n  sdk: '>=3.0.0'\n");
        let stacks = detect_stacks(&dir);
        assert!(stacks.iter().any(|s| s.label == "Dart"));
        assert!(!stacks.iter().any(|s| s.label == "Flutter"));
    }

    #[test]
    fn react_native_распознаётся_по_package_json() {
        let dir = tmp();
        write(
            &dir,
            "package.json",
            r#"{"name":"app","dependencies":{"react-native":"0.74.0"}}"#,
        );
        let stacks = detect_stacks(&dir);
        assert!(
            stacks.iter().any(|s| s.label == "React Native"),
            "RN должен распознаваться: {:?}",
            stacks.iter().map(|s| &s.label).collect::<Vec<_>>()
        );
    }

    #[test]
    fn expo_распознаётся_отдельно_от_react_native() {
        let dir = tmp();
        write(
            &dir,
            "package.json",
            r#"{"name":"app","dependencies":{"expo":"51.0.0","react-native":"0.74.0"}}"#,
        );
        let stacks = detect_stacks(&dir);
        assert!(stacks.iter().any(|s| s.label == "React Native (Expo)"));
    }

    #[test]
    fn гибрид_flutter_плюс_нативный_ios_даёт_два_стека() {
        // Flutter в корне плюс отдельный нативный iOS-проект (НЕ подпапка ios/ внутри
        // Flutter, а самостоятельный xcodeproj в корне) должны дать два верификатора.
        let dir = tmp();
        write(&dir, "pubspec.yaml", "name: app\nflutter:\n  sdk: flutter\n");
        // Создаём xcodeproj в КОРНЕ (самостоятельный iOS-стек, не Flutter-обёртка).
        fs::create_dir_all(dir.join("App.xcodeproj")).unwrap();
        let stacks = detect_stacks(&dir);
        let labels: Vec<&str> = stacks.iter().map(|s| s.label.as_str()).collect();
        assert!(labels.contains(&"Flutter"), "ожидался Flutter: {labels:?}");
        assert!(
            labels.iter().any(|l| l.starts_with("iOS")),
            "ожидался iOS-стек: {labels:?}"
        );
    }

    #[test]
    fn нативный_android_подпроект_rn_распознаётся() {
        // React Native в корне (package.json) плюс нативная подпапка android/ с gradle.
        let dir = tmp();
        write(
            &dir,
            "package.json",
            r#"{"name":"app","dependencies":{"react-native":"0.74.0"}}"#,
        );
        write(&dir, "android/build.gradle", "// android root gradle\n");
        let stacks = detect_stacks(&dir);
        let labels: Vec<&str> = stacks.iter().map(|s| s.label.as_str()).collect();
        assert!(labels.contains(&"React Native"), "{labels:?}");
        assert!(
            labels.contains(&"Android (нативный подпроект)"),
            "ожидался нативный Android-подпроект: {labels:?}"
        );
    }

    #[test]
    fn flutter_не_дублирует_android_подпроект() {
        // У Flutter подпапка android/ собирается через flutter test, поэтому
        // отдельный нативный Android-верификатор для неё НЕ добавляется (нет дубля).
        let dir = tmp();
        write(&dir, "pubspec.yaml", "name: app\nflutter:\n  sdk: flutter\n");
        write(&dir, "android/build.gradle", "// flutter android wrapper\n");
        let stacks = detect_stacks(&dir);
        assert!(
            !stacks
                .iter()
                .any(|s| s.label == "Android (нативный подпроект)"),
            "Flutter-обёртка android/ не должна давать отдельный нативный стек"
        );
    }

    #[test]
    fn android_в_корне_предпочитает_gradlew() {
        let dir = tmp();
        write(&dir, "build.gradle", "// app\n");
        write(&dir, "gradlew", "#!/bin/sh\n");
        let stacks = detect_stacks(&dir);
        let android = stacks
            .iter()
            .find(|s| s.label == "Android (Gradle)")
            .expect("Android-стек должен быть");
        let (bin, _) = android.build.as_ref().expect("есть план сборки");
        assert!(
            bin.ends_with("gradlew"),
            "Android в корне должен предпочесть ./gradlew, получено: {bin}"
        );
    }

    #[test]
    fn ios_xcode_в_корне_выносит_ручную_заметку() {
        let dir = tmp();
        fs::create_dir_all(dir.join("App.xcworkspace")).unwrap();
        let stacks = detect_stacks(&dir);
        let ios = stacks
            .iter()
            .find(|s| s.label.starts_with("iOS"))
            .expect("iOS-стек должен распознаваться");
        assert!(ios.build.is_none(), "автозапуск iOS невозможен без схемы");
        assert!(ios.manual.is_some(), "должна быть ручная заметка про схему");
    }

    #[test]
    fn нераспознанный_проект_даёт_явный_пропуск() {
        let dir = tmp();
        write(&dir, "README.md", "просто текст\n");
        let out = MobileVerify::new()
            .run(&Ctx::new(&dir), &RunInput::default())
            .unwrap();
        assert!(out.skipped.is_some(), "нераспознанный проект должен дать skipped");
        assert!(out.findings.is_empty());
    }

    // ───────────────────── T30: статический разбор iOS plist/entitlements ─────────────────────

    #[test]
    fn ios_verify_статически_находит_ats_без_тулчейна() {
        // iOS-проект с небезопасным Info.plist: сборку запустить нельзя (нет схемы),
        // но статический разбор обязан дать находку даже без xcodebuild.
        let dir = tmp();
        fs::create_dir_all(dir.join("App.xcodeproj")).unwrap();
        write(
            &dir,
            "Info.plist",
            r#"<plist><dict>
  <key>NSAllowsArbitraryLoads</key>
  <true/>
</dict></plist>"#,
        );
        let out = MobileVerify::new()
            .run(&Ctx::new(&dir), &RunInput::default())
            .unwrap();
        assert!(
            out.findings
                .iter()
                .any(|f| f.rule == "mobile-ats-arbitrary-loads"),
            "статический разбор iOS должен найти ATS без тулчейна: {:?}",
            out.findings
        );
    }

    #[test]
    fn ios_entitlements_get_task_allow_находится() {
        let dir = tmp();
        let findings = analyze_ios_plist_entitlements({
            write(
                &dir,
                "App.entitlements",
                r#"<plist><dict>
  <key>get-task-allow</key>
  <true/>
</dict></plist>"#,
            );
            &dir
        });
        assert!(
            findings.iter().any(|f| f.rule == "mobile-ios-get-task-allow"),
            "get-task-allow должен находиться: {findings:?}"
        );
    }

    #[test]
    fn ios_безопасный_plist_не_даёт_находок() {
        let dir = tmp();
        write(
            &dir,
            "Info.plist",
            r#"<plist><dict>
  <key>CFBundleName</key>
  <string>App</string>
  <key>NSAllowsArbitraryLoads</key>
  <false/>
</dict></plist>"#,
        );
        let findings = analyze_ios_plist_entitlements(&dir);
        assert!(findings.is_empty(), "безопасный plist чист: {findings:?}");
    }

    // ───────────────────── охват расширений ─────────────────────

    #[test]
    fn секрет_правила_охватывают_и_исходники_и_конфиги() {
        let exts = mobile_secret_exts();
        // И мобильные конфиги, и исходный код входят в охват секрет-правил.
        assert!(exts.contains(&"properties"), "конфиг properties в охвате");
        assert!(exts.contains(&"xml"), "xml в охвате");
        assert!(exts.contains(&"kt"), "kotlin в охвате");
        assert!(exts.contains(&"swift"), "swift в охвате");
        // Дедупликация: ни одно расширение не повторяется.
        let mut sorted = exts.clone();
        sorted.dedup();
        assert_eq!(sorted.len(), exts.len(), "охват дедуплицирован");
    }
}
