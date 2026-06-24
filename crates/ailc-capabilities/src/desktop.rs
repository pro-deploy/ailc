//! verify/desktop — проверка десктопных стеков (.NET/Tauri/Electron/C++/Make) по двум
//! независимым осям сразу.
//!
//! Первая ось это ДЕТЕРМИНИРОВАННЫЙ скан небезопасной конфигурации десктопного
//! приложения поверх общего движка [`ScanEngine`]: для Electron разбираются опасные
//! значения webPreferences (nodeIntegration, contextIsolation, enableRemoteModule,
//! webSecurity, allowRunningInsecureContent, sandbox), загрузка удалённого контента по
//! незашифрованному протоколу и отсутствующая политика безопасности контента; для Tauri
//! разбирается tauri.conf.json (allowlist.all, разрешение shell.execute, обнулённая
//! security.csp, доступ удалённого источника к межпроцессному взаимодействию, обновление
//! без открытого ключа подписи или по незашифрованному протоколу). Каждое такое
//! совпадение становится заземлённой на строку находкой и влияет на вердикт, поэтому
//! максимально уязвимый desktop больше не проходит чисто (см. задачу T26).
//!
//! Вторая ось это собственно сборка и тесты. Стек распознаётся РЕКУРСИВНО (до небольшой
//! глубины, исключая служебные каталоги), поэтому смешанный монорепозиторий, где
//! десктопное приложение лежит во вложенном каталоге, тоже виден. Собираются ВСЕ
//! обнаруженные стеки, а не первый по приоритету, поэтому гибридный проект не маскирует
//! одну часть другой. Для каждого стека запускается доступный шаг верификации через
//! [`Runner`] с тайм-аутом; если тулчейн отсутствует, выносится находка, ПОНИЖАЮЩАЯ
//! вердикт, а не нейтральная заметка, иначе непроверенная десктоп-сборка молча выглядела
//! бы зелёной (см. задачу T28). Подпуть прогона берётся из input.target.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Finding, Result, RunInput,
    Severity, Tier,
};
use ailc_core::engines::runner::Runner;
use ailc_core::engines::scan::{Matcher, Rule, ScanEngine};
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::path::{Path, PathBuf};

/// Идентификатор capability и одновременно источник находок скан-оси.
const CAP_ID: &str = "verify/desktop";

/// Предельная глубина рекурсивного поиска маркеров стека. Десктопное приложение в
/// монорепозитории почти всегда лежит не глубже уровня apps/desktop или
/// packages/<name>, поэтому глубины три достаточно, чтобы найти вложенный проект, и
/// при этом обход не уходит в бесконечную раскрутку дерева. Корень считается уровнем
/// нуль, поэтому значение три охватывает корень и три уровня вложенности.
const MAX_DETECT_DEPTH: usize = 3;

/// Каталоги, которые при рекурсивном поиске маркеров стека не раскрываются: это сборка,
/// зависимости и служебные артефакты, где маркеры либо чужие (зависимость со своим
/// package.json), либо сгенерированные. Их пропуск убирает и ложные стеки, и лишний
/// обход. Список совпадает по смыслу со служебными каталогами общего обхода дерева.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "build",
    "dist",
    "out",
    "vendor",
    "__pycache__",
    ".git",
    "Pods",
    "DerivedData",
];

/// Расширения исходников клиентской части Electron, где живут опасные значения
/// webPreferences и стоки. Помимо классических js/ts/jsx/tsx включены современные
/// модульные формы cjs/mjs и их типизированные варианты mts/cts (см. задачу T26):
/// конфигурация главного процесса Electron нередко выносится именно в такой модуль.
const ELECTRON_CODE_EXTS: &[&str] = &[
    "js", "ts", "jsx", "tsx", "cjs", "mjs", "mts", "cts",
];

/// Расширения, где встречается конфигурация Electron в декларативном виде: к
/// исходникам добавлен json (некоторые шаблоны выносят BrowserWindow-опции в JSON).
const ELECTRON_CONF_EXTS: &[&str] = &[
    "js", "ts", "jsx", "tsx", "cjs", "mjs", "mts", "cts", "json",
];

/// Расширение конфигурации Tauri. Файл tauri.conf.json это JSON, поэтому правила Tauri
/// применяются только к json, чтобы не давать ложных совпадений по исходному коду.
const TAURI_CONF_EXTS: &[&str] = &["json"];

/// Какой шаг верификации запускать для распознанного стека.
struct Stack {
    /// Человекочитаемая метка стека для сводки и сообщений.
    label: &'static str,
    /// Каталог, в котором найден маркер стека (относительно корня прогона), для
    /// прозрачности в сводке монорепозитория.
    dir: PathBuf,
    /// Команда верификации: бинарь и аргументы. Запускается в каталоге стека.
    bin: &'static str,
    args: Vec<&'static str>,
}

/// Рекурсивно собрать ВСЕ десктопные стеки под корнем прогона. В отличие от прежней
/// версии не делает ранний возврат на первом маркере: гибридный проект (.NET плюс
/// Electron, Tauri плюс CMake) виден целиком. Обход исключает служебные каталоги и
/// ограничен глубиной [`MAX_DETECT_DEPTH`]. За симлинками не следует, чтобы каталог-
/// ссылка не вывел поиск за пределы корня и не зациклил рекурсию.
fn detect_all(root: &Path) -> Vec<Stack> {
    let mut found = Vec::new();
    detect_in(root, root, 0, &mut found);
    found
}

/// Внутренний рекурсивный шаг сбора стеков. `base` это каталог, который сейчас
/// осматривается; `root` это корень прогона (нужен для относительного пути находки).
fn detect_in(root: &Path, base: &Path, depth: usize, found: &mut Vec<Stack>) {
    detect_markers_here(root, base, found);
    if depth >= MAX_DETECT_DEPTH {
        return;
    }
    let entries = match std::fs::read_dir(base) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Скрытые каталоги (кроме явного отсева ниже) и служебные каталоги не
        // раскрываем: там лежат чужие или сгенерированные маркеры.
        if name.starts_with('.') || SKIP_DIRS.contains(&name.as_ref()) {
            continue;
        }
        // Тип записи берём без следования за симлинком: каталог-ссылка может вести за
        // пределы корня (утечка чужих маркеров) либо образовать цикл.
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            detect_in(root, &entry.path(), depth + 1, found);
        }
    }
}

/// Распознать маркеры стеков НЕПОСРЕДСТВЕННО в каталоге `base` (без рекурсии). Один
/// каталог может дать несколько стеков сразу (например .NET и Electron в одном месте),
/// поэтому ветки не делают ранний возврат.
fn detect_markers_here(root: &Path, base: &Path, found: &mut Vec<Stack>) {
    let rel = base.strip_prefix(root).unwrap_or(base).to_path_buf();

    // .NET: решение или проект в этом каталоге.
    if dir_has_ext(base, ".sln") || dir_has_ext(base, ".csproj") {
        found.push(Stack {
            label: ".NET",
            dir: rel.clone(),
            bin: "dotnet",
            args: vec!["test"],
        });
    }
    // Tauri: каталог src-tauri рядом. Верификатор это cargo test внутри src-tauri.
    if base.join("src-tauri").is_dir() {
        found.push(Stack {
            label: "Tauri",
            dir: rel.join("src-tauri"),
            bin: "cargo",
            args: vec!["test"],
        });
    }
    // Electron: package.json, в зависимостях которого упомянут electron. Шаг
    // верификации это сборка дистрибутива через npm; при её отсутствии шаг
    // деградирует к npm-тесту, см. resolve_npm_step.
    if base.join("package.json").exists() {
        let pkg = std::fs::read_to_string(base.join("package.json")).unwrap_or_default();
        if pkg.contains("\"electron\"") {
            let (bin, args) = resolve_npm_step(&pkg);
            found.push(Stack {
                label: "Electron",
                dir: rel.clone(),
                bin,
                args,
            });
        }
    }
    // C/C++ через CMake: конфигурируем и собираем во временный каталог build.
    if base.join("CMakeLists.txt").exists() {
        found.push(Stack {
            label: "C/C++ (CMake)",
            dir: rel.clone(),
            bin: "cmake",
            args: vec!["-S", ".", "-B", "build"],
        });
    }
    // Make: цель по умолчанию. Канонический проект отвечает на `make` без аргументов.
    if base.join("Makefile").exists() {
        found.push(Stack {
            label: "Make",
            dir: rel,
            bin: "make",
            args: vec![],
        });
    }
}

/// Выбрать команду npm для Electron-проекта по объявленным скриптам. Предпочитается
/// сборка дистрибутива (`dist`), затем обычная сборка (`build`), затем тест: так
/// проверяется максимально близкий к релизу шаг из доступных. Если ни одного скрипта
/// нет, запускается `npm test` как минимальный шаг. Возвращает бинарь и аргументы.
fn resolve_npm_step(pkg: &str) -> (&'static str, Vec<&'static str>) {
    if pkg.contains("\"dist\"") {
        ("npm", vec!["run", "dist"])
    } else if pkg.contains("\"build\"") {
        ("npm", vec!["run", "build"])
    } else {
        ("npm", vec!["test"])
    }
}

/// Есть ли в каталоге файл с указанным расширением (нерекурсивно). Имена сравниваются
/// по суффиксу, поэтому `.sln`/`.csproj` ловятся независимо от базового имени.
fn dir_has_ext(dir: &Path, ext: &str) -> bool {
    std::fs::read_dir(dir).ok().is_some_and(|rd| {
        rd.flatten()
            .any(|e| e.file_name().to_string_lossy().ends_with(ext))
    })
}

/// Детерминированные правила небезопасной конфигурации Electron и Tauri. Это точные
/// структурные сигнатуры над конфигурационными файлами (конкретный флаг с литеральным
/// значением), поэтому ложных срабатываний по обычному коду они практически не дают.
/// Каждое сообщение несёт проверенную ссылку CWE, а где уместно и OWASP.
fn config_rules() -> Vec<Rule> {
    vec![
        // ───────────────────────── Electron ─────────────────────────
        // nodeIntegration: true в рендерере открывает прямой доступ к Node.js из
        // веб-контента, превращая любой XSS в выполнение кода на машине пользователя.
        Rule {
            id: "desktop/electron-node-integration",
            severity: Severity::Critical,
            exts: ELECTRON_CONF_EXTS,
            matcher: Matcher::regex(r"(?i)nodeIntegration\s*:\s*true"),
            message: "Electron: nodeIntegration:true даёт веб-контенту доступ к Node.js, любой XSS превращается в выполнение кода в системе (CWE-829, OWASP A05:2021 Security Misconfiguration). Установите nodeIntegration:false и используйте contextBridge через preload.",
        },
        // contextIsolation: false снимает изоляцию контекста preload и страницы,
        // позволяя странице переопределять привилегированные API.
        Rule {
            id: "desktop/electron-context-isolation-off",
            severity: Severity::Critical,
            exts: ELECTRON_CONF_EXTS,
            matcher: Matcher::regex(r"(?i)contextIsolation\s*:\s*false"),
            message: "Electron: contextIsolation:false снимает изоляцию контекста, веб-страница получает доступ к привилегированным API preload (CWE-653, OWASP A05:2021 Security Misconfiguration). Включите contextIsolation:true и выставляйте API только через contextBridge.",
        },
        // enableRemoteModule: true возвращает устаревший модуль remote, через который
        // рендерер дотягивается до главного процесса и системных возможностей.
        Rule {
            id: "desktop/electron-remote-module",
            severity: Severity::High,
            exts: ELECTRON_CONF_EXTS,
            matcher: Matcher::regex(r"(?i)enableRemoteModule\s*:\s*true"),
            message: "Electron: enableRemoteModule:true открывает рендереру модуль remote и доступ к главному процессу (CWE-749, OWASP A05:2021 Security Misconfiguration). Откажитесь от remote, передавайте данные через безопасный IPC.",
        },
        // webSecurity: false выключает политику одного источника внутри окна, снимая
        // защиту от межсайтовой загрузки ресурсов и обхода CORS.
        Rule {
            id: "desktop/electron-websecurity-off",
            severity: Severity::Critical,
            exts: ELECTRON_CONF_EXTS,
            matcher: Matcher::regex(r"(?i)webSecurity\s*:\s*false"),
            message: "Electron: webSecurity:false отключает политику одного источника, разрешая загрузку и выполнение чужих ресурсов (CWE-942, OWASP A05:2021 Security Misconfiguration). Не отключайте webSecurity в продакшене.",
        },
        // allowRunningInsecureContent: true разрешает подгрузку незашифрованного
        // контента на защищённой странице, открывая канал для подмены кода.
        Rule {
            id: "desktop/electron-insecure-content",
            severity: Severity::High,
            exts: ELECTRON_CONF_EXTS,
            matcher: Matcher::regex(r"(?i)allowRunningInsecureContent\s*:\s*true"),
            message: "Electron: allowRunningInsecureContent:true разрешает подгрузку незашифрованного контента на защищённой странице, открывая подмену скриптов по MITM (CWE-311, OWASP A02:2021 Cryptographic Failures). Загружайте ресурсы только по защищённому протоколу.",
        },
        // sandbox: false снимает песочницу процесса рендерера, поэтому компрометация
        // страницы напрямую затрагивает систему пользователя.
        Rule {
            id: "desktop/electron-sandbox-off",
            severity: Severity::High,
            exts: ELECTRON_CONF_EXTS,
            matcher: Matcher::regex(r"(?i)sandbox\s*:\s*false"),
            message: "Electron: sandbox:false снимает песочницу рендерера, компрометация страницы напрямую затрагивает систему (CWE-265, OWASP A05:2021 Security Misconfiguration). Включите sandbox:true для окон с веб-контентом.",
        },
        // loadURL по незашифрованному протоколу: загрузка содержимого окна по http
        // позволяет внедрить произвольный код через MITM.
        Rule {
            id: "desktop/electron-loadurl-cleartext",
            severity: Severity::High,
            exts: ELECTRON_CODE_EXTS,
            matcher: Matcher::regex(r#"(?i)\.loadURL\s*\(\s*[`"']http://"#),
            message: "Electron: loadURL по незашифрованному http позволяет внедрить код через MITM (CWE-319, OWASP A02:2021 Cryptographic Failures). Загружайте удалённый контент только по защищённому протоколу или из локального ресурса.",
        },
        // ───────────────────────── Tauri ─────────────────────────
        // allowlist.all: true в tauri.conf.json включает ВЕСЬ набор системных API
        // (файловая система, оболочка, процесс) для фронтенда сразу. Контекст
        // allowlist обязателен в совпадении, иначе любое поле «all»:true в чужом JSON
        // дало бы ложную находку; многострочный матч связывает ключ allowlist с
        // вложенным all:true даже при форматировании JSON в несколько строк.
        Rule {
            id: "desktop/tauri-allowlist-all",
            severity: Severity::Critical,
            exts: TAURI_CONF_EXTS,
            matcher: Matcher::multiline_regex(r#"(?is)"allowlist"\s*:\s*\{[^{}]*"all"\s*:\s*true"#),
            message: "Tauri: allowlist.all:true включает весь набор системных API (файловая система, оболочка, процесс) для фронтенда (CWE-272, OWASP A05:2021 Security Misconfiguration). Перечислите минимально необходимые возможности вместо all.",
        },
        // shell.execute разрешён в allowlist: фронтенд может запускать процессы
        // операционной системы, что при XSS даёт выполнение произвольных команд.
        // Многострочный матч связывает ключ shell с вложенным execute:true.
        Rule {
            id: "desktop/tauri-shell-execute",
            severity: Severity::High,
            exts: TAURI_CONF_EXTS,
            matcher: Matcher::multiline_regex(r#"(?is)"shell"\s*:\s*\{[^{}]*"execute"\s*:\s*true"#),
            message: "Tauri: shell.execute:true разрешает фронтенду запуск процессов ОС, при XSS это выполнение произвольных команд (CWE-78, OWASP A03:2021 Injection). Отключите shell.execute или ограничьте scope конкретными командами.",
        },
        // security.csp: null отключает политику безопасности контента, снимая
        // браузерную защиту от внедрения скриптов.
        Rule {
            id: "desktop/tauri-csp-null",
            severity: Severity::High,
            exts: TAURI_CONF_EXTS,
            matcher: Matcher::regex(r#"(?i)"csp"\s*:\s*null"#),
            message: "Tauri: security.csp:null отключает политику безопасности контента, снимая защиту от внедрения скриптов (CWE-1021, OWASP A05:2021 Security Misconfiguration). Задайте строгую политику безопасности контента.",
        },
        // dangerousRemoteDomainIpcAccess: разрешает удалённому домену вызывать
        // команды через межпроцессное взаимодействие, что выводит уязвимость
        // удалённой страницы прямо на привилегированный бэкенд приложения.
        Rule {
            id: "desktop/tauri-remote-ipc",
            severity: Severity::Critical,
            exts: TAURI_CONF_EXTS,
            matcher: Matcher::regex(r"(?i)dangerousRemoteDomainIpcAccess"),
            message: "Tauri: dangerousRemoteDomainIpcAccess открывает удалённому домену доступ к командам через межпроцессное взаимодействие (CWE-749, OWASP A05:2021 Security Misconfiguration). Не предоставляйте удалённым источникам доступ к IPC.",
        },
        // updater по незашифрованному протоколу: канал обновлений по http позволяет
        // подменить устанавливаемый артефакт через MITM.
        Rule {
            id: "desktop/tauri-updater-cleartext",
            severity: Severity::Critical,
            exts: TAURI_CONF_EXTS,
            matcher: Matcher::multiline_regex(
                r#"(?is)"endpoints"\s*:\s*\[[^\]]*http://"#,
            ),
            message: "Tauri: канал обновлений по незашифрованному http позволяет подменить устанавливаемый артефакт через MITM (CWE-319, OWASP A08:2021 Software and Data Integrity Failures). Используйте защищённый протокол для endpoints обновления.",
        },
        // updater без открытого ключа подписи: артефакт обновления не проверяется на
        // подлинность, поэтому злоумышленник может подсунуть своё обновление.
        Rule {
            id: "desktop/tauri-updater-no-pubkey",
            severity: Severity::Critical,
            exts: TAURI_CONF_EXTS,
            matcher: Matcher::Predicate(|l| {
                // Включённый updater без указания открытого ключа подписи. Признак
                // включения и отсутствие непустого pubkey проверяем в одной строке
                // конфигурации, где updater задан компактно (частый шаблон).
                let low = l.to_ascii_lowercase();
                low.contains("\"updater\"")
                    && low.contains("\"active\"")
                    && low.contains("true")
                    && !low.contains("pubkey")
            }),
            message: "Tauri: updater включён без открытого ключа подписи, подлинность обновления не проверяется (CWE-347, OWASP A08:2021 Software and Data Integrity Failures). Задайте pubkey, чтобы принимать только подписанные обновления.",
        },
    ]
}

pub struct DesktopVerify {
    manifest: CapabilityManifest,
}

impl Default for DesktopVerify {
    fn default() -> Self {
        Self::new()
    }
}

impl DesktopVerify {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: CAP_ID,
                family: Family::Verify,
                engine: EngineKind::Runner,
                when_to_use: "Проверить десктопный проект (.NET/Tauri/Electron/C++): небезопасная конфигурация Electron/Tauri детерминированным сканом плюс сборка/тесты всех обнаруженных стеков.",
                input_schema: r#"{"type":"object","properties":{"target":{"type":"string"}}}"#,
                tier: Tier::Core,
                deterministic: false,
                mutates: false,
            },
        }
    }

    /// Ось небезопасной конфигурации: прогон скан-движка по правилам Electron/Tauri.
    /// Находки заземлены на file:line и помечены verified, поэтому учитываются гейтом и
    /// влияют на вердикт. Тесты не сканируем: фикстуры намеренно содержат уязвимые
    /// конфигурации, это не дефекты прод-кода.
    fn scan_config(&self, ctx: &Ctx, input: &RunInput, out: &mut CapabilityOutput) {
        let rules = config_rules();
        match ScanEngine::run(ctx, input, &rules, CAP_ID, true) {
            Ok(scan_out) => {
                out.findings.extend(scan_out.findings);
                out.metrics.extend(scan_out.metrics);
            }
            // Сбой самого скан-движка (например, путь target вне корня) не глотаем:
            // фиксируем как осознанный пропуск этой оси, чтобы он был виден человеку.
            Err(e) => {
                out.skipped = Some(format!(
                    "ось конфигурации Electron/Tauri не выполнена: {e}"
                ));
            }
        }
    }

    /// Ось сборки и тестов: для КАЖДОГО обнаруженного стека запустить доступный шаг
    /// верификации с тайм-аутом. Падение шага и отсутствие тулчейна оба порождают
    /// находку, понижающую вердикт, потому что непроверенная десктоп-сборка не должна
    /// молча выглядеть зелёной (см. задачу T28). Подпуть прогона берётся из input.target.
    fn verify_builds(&self, ctx: &Ctx, input: &RunInput, out: &mut CapabilityOutput) -> usize {
        // База прогона учитывает input.target (валидируется на выход за корень).
        let base = match ctx.base(input) {
            Ok(b) => b,
            Err(e) => {
                out.skipped = Some(format!("ось сборки не выполнена: {e}"));
                return 0;
            }
        };
        let stacks = detect_all(&base);
        if stacks.is_empty() {
            return 0;
        }
        for stack in &stacks {
            let cwd = base.join(&stack.dir);
            let dir_label = stack.dir.to_string_lossy();
            let where_note = if dir_label.is_empty() {
                String::new()
            } else {
                format!(" [{dir_label}]")
            };
            let sub = Ctx::new(cwd);
            let res = Runner::run(&sub, stack.bin, &stack.args);
            if !res.ran {
                // Тулчейн недоступен: вместо нейтрального skip выносим находку,
                // понижающую вердикт. Сборку нельзя считать проверенной, значит её
                // статус не «чисто», а «не подтверждено».
                let reason = res
                    .skipped_reason
                    .unwrap_or_else(|| "нет инструмента".into());
                out.findings.push(Finding {
                    rule: "desktop-build-unverified".into(),
                    severity: Severity::High,
                    message: format!(
                        "{}{}: сборка/тесты НЕ подтверждены ({}) — установите тулчейн или подтвердите сборку вручную, непроверенная сборка не считается зелёной",
                        stack.label, where_note, reason
                    ),
                    location: None,
                    evidence: None,
                    verified: true,
                    source: CAP_ID.into(),
                });
                continue;
            }
            if res.exit_ok {
                out.records.push(format!(
                    "{}{}: сборка/тесты прошли",
                    stack.label, where_note
                ));
            } else {
                out.findings.push(Finding {
                    rule: "desktop-build-fail".into(),
                    severity: Severity::High,
                    message: format!(
                        "{}{}: сборка/тесты не проходят (код {:?})",
                        stack.label, where_note, res.code
                    ),
                    location: None,
                    evidence: None,
                    verified: true,
                    source: CAP_ID.into(),
                });
                for l in res.tail(15) {
                    out.records.push(l);
                }
            }
        }
        stacks.len()
    }
}

impl Capability for DesktopVerify {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        // Ось 1: детерминированный скан небезопасной конфигурации Electron/Tauri.
        let config_before = out.findings.len();
        self.scan_config(ctx, input, &mut out);
        let config_findings = out.findings.len() - config_before;

        // Ось 2: сборка и тесты всех обнаруженных стеков.
        let stacks = self.verify_builds(ctx, input, &mut out);

        // Если ни одна ось ничего не обнаружила (нет стеков и нет конфигурации) — это
        // действительно не десктоп-проект, честно сообщаем причину пропуска.
        if stacks == 0 && config_findings == 0 && out.findings.is_empty() {
            // Сообщение о пропуске не затираем, если его уже выставила какая-то ось
            // (например, target вне корня): такая причина важнее общего «не распознан».
            if out.skipped.is_none() {
                out.skipped = Some(
                    "десктоп-проект не распознан (нет *.sln/*.csproj/src-tauri/electron/CMakeLists/Makefile) и небезопасной конфигурации не найдено"
                        .into(),
                );
            }
            out.summary = "verify/desktop: пропущено (стек не распознан)".into();
            return Ok(out);
        }

        let build_fail = out
            .findings
            .iter()
            .filter(|f| f.rule == "desktop-build-fail")
            .count();
        let build_unverified = out
            .findings
            .iter()
            .filter(|f| f.rule == "desktop-build-unverified")
            .count();
        out.summary = format!(
            "verify/desktop: стеков {stacks}, конфиг-находок {config_findings}, провалов сборки {build_fail}, не подтверждено {build_unverified}"
        );
        out.metrics.push(("desktop_stacks".into(), stacks as f64));
        out.metrics
            .push(("desktop_config_findings".into(), config_findings as f64));
        Ok(out)
    }
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(DesktopVerify::new()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_contracts::Severity;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Уникальная пустая временная папка для файловых фикстур.
    fn tmp() -> PathBuf {
        let n = CNT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ailc-desktop-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }

    /// Прогнать только скан-ось конфигурации (без запуска внешних сборщиков) по корню.
    fn scan_only(dir: &Path) -> CapabilityOutput {
        let cap = DesktopVerify::new();
        let ctx = Ctx::new(dir.to_path_buf());
        let input = RunInput::default();
        let mut out = CapabilityOutput::default();
        cap.scan_config(&ctx, &input, &mut out);
        out
    }

    fn has_rule(out: &CapabilityOutput, rule: &str) -> bool {
        out.findings.iter().any(|f| f.rule == rule)
    }

    // ── T26: Electron webPreferences ──────────────────────────────────────

    #[test]
    fn electron_node_integration_дает_критичную_находку() {
        let dir = tmp();
        write(
            &dir,
            "main.js",
            "const w = new BrowserWindow({ webPreferences: { nodeIntegration: true } });",
        );
        let out = scan_only(&dir);
        assert!(
            has_rule(&out, "desktop/electron-node-integration"),
            "nodeIntegration:true должен дать находку"
        );
        let f = out
            .findings
            .iter()
            .find(|f| f.rule == "desktop/electron-node-integration")
            .unwrap();
        assert_eq!(f.severity, Severity::Critical, "это RCE-класс, severity Critical");
        assert!(f.verified, "находка заземлена на file:line, значит verified");
        assert!(f.message.contains("CWE-829"), "сообщение несёт ссылку CWE");
        assert!(f.location.is_some(), "находка указывает на строку");
    }

    #[test]
    fn electron_context_isolation_off_находится() {
        let dir = tmp();
        write(
            &dir,
            "window.ts",
            "webPreferences: {\n  contextIsolation: false,\n}",
        );
        let out = scan_only(&dir);
        assert!(has_rule(&out, "desktop/electron-context-isolation-off"));
    }

    #[test]
    fn electron_websecurity_off_находится() {
        let dir = tmp();
        write(&dir, "app.cjs", "webPreferences: { webSecurity: false }");
        let out = scan_only(&dir);
        assert!(
            has_rule(&out, "desktop/electron-websecurity-off"),
            "правило должно ловить и в .cjs (T26)"
        );
    }

    #[test]
    fn electron_правила_ловят_в_mts_и_mjs() {
        // T26: современные модульные расширения должны входить в охват.
        let dir = tmp();
        write(&dir, "preload.mts", "const o = { sandbox: false };");
        write(&dir, "main.mjs", "enableRemoteModule: true");
        let out = scan_only(&dir);
        assert!(has_rule(&out, "desktop/electron-sandbox-off"), ".mts в охвате");
        assert!(
            has_rule(&out, "desktop/electron-remote-module"),
            ".mjs в охвате"
        );
    }

    #[test]
    fn electron_loadurl_cleartext_находится() {
        let dir = tmp();
        write(&dir, "main.js", "win.loadURL('http://example.com/app')");
        let out = scan_only(&dir);
        assert!(has_rule(&out, "desktop/electron-loadurl-cleartext"));
    }

    #[test]
    fn electron_allow_insecure_content_находится() {
        let dir = tmp();
        write(&dir, "main.js", "webPreferences: { allowRunningInsecureContent: true }");
        let out = scan_only(&dir);
        assert!(has_rule(&out, "desktop/electron-insecure-content"));
    }

    #[test]
    fn electron_безопасная_конфигурация_не_дает_ложных_находок() {
        // Негатив: значения выставлены безопасно — находок Electron быть не должно.
        let dir = tmp();
        write(
            &dir,
            "main.js",
            "webPreferences: {\n  nodeIntegration: false,\n  contextIsolation: true,\n  sandbox: true,\n  webSecurity: true,\n}\nwin.loadURL('https://example.com/app')",
        );
        let out = scan_only(&dir);
        assert!(
            !out.findings.iter().any(|f| f.rule.starts_with("desktop/electron-")),
            "безопасная конфигурация не должна давать находок Electron, получено: {:?}",
            out.findings.iter().map(|f| &f.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn electron_loadurl_https_не_срабатывает() {
        // Негатив на обход: loadURL по защищённому протоколу не находка.
        let dir = tmp();
        write(&dir, "main.js", "win.loadURL('https://example.com/app')");
        let out = scan_only(&dir);
        assert!(!has_rule(&out, "desktop/electron-loadurl-cleartext"));
    }

    // ── T26: Tauri tauri.conf.json ────────────────────────────────────────

    #[test]
    fn tauri_allowlist_all_дает_критичную_находку() {
        let dir = tmp();
        write(
            &dir,
            "tauri.conf.json",
            r#"{ "tauri": { "allowlist": { "all": true } } }"#,
        );
        let out = scan_only(&dir);
        assert!(has_rule(&out, "desktop/tauri-allowlist-all"));
        let f = out
            .findings
            .iter()
            .find(|f| f.rule == "desktop/tauri-allowlist-all")
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.message.contains("CWE-272"));
    }

    #[test]
    fn tauri_shell_execute_находится() {
        let dir = tmp();
        write(
            &dir,
            "tauri.conf.json",
            r#"{ "allowlist": { "shell": { "execute": true } } }"#,
        );
        let out = scan_only(&dir);
        assert!(has_rule(&out, "desktop/tauri-shell-execute"));
    }

    #[test]
    fn tauri_csp_null_находится() {
        let dir = tmp();
        write(
            &dir,
            "tauri.conf.json",
            r#"{ "tauri": { "security": { "csp": null } } }"#,
        );
        let out = scan_only(&dir);
        assert!(has_rule(&out, "desktop/tauri-csp-null"));
    }

    #[test]
    fn tauri_remote_ipc_находится() {
        let dir = tmp();
        write(
            &dir,
            "tauri.conf.json",
            r#"{ "tauri": { "security": { "dangerousRemoteDomainIpcAccess": [] } } }"#,
        );
        let out = scan_only(&dir);
        assert!(has_rule(&out, "desktop/tauri-remote-ipc"));
    }

    #[test]
    fn tauri_updater_http_находится() {
        let dir = tmp();
        write(
            &dir,
            "tauri.conf.json",
            r#"{ "updater": { "active": true, "endpoints": ["http://releases.example.com/{{target}}"] } }"#,
        );
        let out = scan_only(&dir);
        assert!(has_rule(&out, "desktop/tauri-updater-cleartext"));
    }

    #[test]
    fn tauri_updater_без_pubkey_находится() {
        let dir = tmp();
        write(
            &dir,
            "tauri.conf.json",
            r#"{ "updater": { "active": true, "endpoints": ["https://r.example.com"] }"#,
        );
        let out = scan_only(&dir);
        assert!(
            has_rule(&out, "desktop/tauri-updater-no-pubkey"),
            "включённый updater без pubkey должен дать находку"
        );
    }

    #[test]
    fn tauri_updater_с_pubkey_и_https_не_срабатывает() {
        // Негатив: безопасный updater (https + pubkey) не должен давать находок.
        let dir = tmp();
        write(
            &dir,
            "tauri.conf.json",
            r#"{ "updater": { "active": true, "pubkey": "dW50cnVzdGVk", "endpoints": ["https://r.example.com"] } }"#,
        );
        let out = scan_only(&dir);
        assert!(!has_rule(&out, "desktop/tauri-updater-no-pubkey"));
        assert!(!has_rule(&out, "desktop/tauri-updater-cleartext"));
    }

    #[test]
    fn tauri_безопасный_allowlist_не_дает_находок() {
        // Негатив: точечный allowlist без all:true и без обнуления csp — чисто.
        let dir = tmp();
        write(
            &dir,
            "tauri.conf.json",
            r#"{ "tauri": { "allowlist": { "fs": { "readFile": true } }, "security": { "csp": "default-src 'self'" } } }"#,
        );
        let out = scan_only(&dir);
        assert!(
            !out.findings.iter().any(|f| f.rule.starts_with("desktop/tauri-")),
            "безопасный конфиг Tauri не должен давать находок, получено: {:?}",
            out.findings.iter().map(|f| &f.rule).collect::<Vec<_>>()
        );
    }

    // ── T28: рекурсивная детекция и сбор всех стеков ──────────────────────

    #[test]
    fn detect_находит_вложенный_electron_в_монорепо() {
        // T28: десктоп лежит во вложенном каталоге, нерекурсивный поиск его бы упустил.
        let dir = tmp();
        write(
            &dir,
            "apps/desktop/package.json",
            r#"{ "devDependencies": { "electron": "^30" } }"#,
        );
        let stacks = detect_all(dir.as_path());
        assert!(
            stacks.iter().any(|s| s.label == "Electron"),
            "вложенный Electron должен быть найден рекурсивно"
        );
    }

    #[test]
    fn detect_собирает_все_стеки_а_не_первый() {
        // T28: .NET и Electron в одном репозитории — должны быть оба, без раннего return.
        let dir = tmp();
        write(&dir, "App.csproj", "<Project></Project>");
        write(
            &dir,
            "package.json",
            r#"{ "dependencies": { "electron": "30" } }"#,
        );
        let stacks = detect_all(dir.as_path());
        assert!(stacks.iter().any(|s| s.label == ".NET"), "должен быть .NET");
        assert!(
            stacks.iter().any(|s| s.label == "Electron"),
            "должен быть и Electron (без раннего возврата по приоритету)"
        );
    }

    #[test]
    fn detect_не_заходит_в_node_modules() {
        // Маркер внутри node_modules не должен распознаваться как стек проекта.
        let dir = tmp();
        write(
            &dir,
            "node_modules/some-pkg/package.json",
            r#"{ "dependencies": { "electron": "30" } }"#,
        );
        let stacks = detect_all(dir.as_path());
        assert!(
            !stacks.iter().any(|s| s.label == "Electron"),
            "стек из node_modules не должен учитываться"
        );
    }

    #[test]
    fn detect_не_заходит_глубже_предела() {
        // Маркер глубже MAX_DETECT_DEPTH не должен находиться.
        let dir = tmp();
        write(&dir, "a/b/c/d/e/CMakeLists.txt", "project(deep)");
        let stacks = detect_all(dir.as_path());
        assert!(
            !stacks.iter().any(|s| s.label == "C/C++ (CMake)"),
            "слишком глубокий маркер вне охвата детекции"
        );
    }

    #[test]
    fn detect_находит_tauri_по_каталогу_src_tauri() {
        let dir = tmp();
        write(&dir, "src-tauri/Cargo.toml", "[package]\nname=\"app\"");
        let stacks = detect_all(dir.as_path());
        assert!(stacks.iter().any(|s| s.label == "Tauri"));
    }

    #[test]
    fn detect_пустой_для_недесктоп_проекта() {
        let dir = tmp();
        write(&dir, "src/lib.rs", "fn main() {}");
        write(&dir, "README.md", "# проект");
        let stacks = detect_all(dir.as_path());
        assert!(stacks.is_empty(), "обычный Rust-проект не десктоп-стек");
    }

    #[test]
    fn detect_electron_только_при_упоминании_зависимости() {
        // package.json без electron не должен давать Electron-стек.
        let dir = tmp();
        write(&dir, "package.json", r#"{ "dependencies": { "react": "18" } }"#);
        let stacks = detect_all(dir.as_path());
        assert!(!stacks.iter().any(|s| s.label == "Electron"));
    }

    // ── интеграция: run целиком ───────────────────────────────────────────

    #[test]
    fn run_не_пропускает_проект_с_уязвимой_конфигурацией() {
        // Даже если тулчейна для сборки нет, наличие уязвимой конфигурации обязано
        // дать находки и не дать summary «пропущено» (T26: уязвимый desktop не чист).
        let dir = tmp();
        write(
            &dir,
            "tauri.conf.json",
            r#"{ "tauri": { "allowlist": { "all": true } } }"#,
        );
        let cap = DesktopVerify::new();
        let out = cap
            .run(&Ctx::new(dir.to_path_buf()), &RunInput::default())
            .unwrap();
        assert!(
            out.findings.iter().any(|f| f.rule == "desktop/tauri-allowlist-all"),
            "уязвимая конфигурация обязана попасть в находки"
        );
        assert!(
            !out.summary.contains("пропущено"),
            "проект с уязвимой конфигурацией не должен быть помечен как пропущенный"
        );
    }

    #[test]
    fn run_недесктоп_проект_честно_пропускается() {
        let dir = tmp();
        write(&dir, "src/lib.rs", "fn main() {}");
        let cap = DesktopVerify::new();
        let out = cap
            .run(&Ctx::new(dir.to_path_buf()), &RunInput::default())
            .unwrap();
        assert!(out.skipped.is_some(), "не-десктоп проект честно пропущен с причиной");
        assert!(out.findings.is_empty(), "находок быть не должно");
    }

    #[test]
    fn run_неустановленный_тулчейн_дает_находку_а_не_тихий_skip() {
        // T28: стек распознан, но тулчейн недоступен — это находка desktop-build-unverified,
        // понижающая вердикт, а не нейтральный пропуск. Используем заведомо
        // несуществующий бинарь, эмулируя отсутствие тулчейна через .NET-стек: если
        // dotnet случайно установлен в окружении теста, шаг отработает и находки сборки
        // не будет, поэтому тест устойчив к обоим исходам и проверяет именно отсутствие
        // молчаливого пропуска при распознанном стеке.
        let dir = tmp();
        write(&dir, "App.csproj", "<Project></Project>");
        let cap = DesktopVerify::new();
        let out = cap
            .run(&Ctx::new(dir.to_path_buf()), &RunInput::default())
            .unwrap();
        // Стек распознан, значит summary не «пропущено».
        assert!(
            !out.summary.contains("стек не распознан"),
            "распознанный стек не должен давать summary о нераспознанности"
        );
        // Либо сборка подтверждена (records), либо есть находка о неподтверждённости
        // или провале — в любом случае нет молчаливого зелёного пропуска.
        let unverified = out
            .findings
            .iter()
            .any(|f| f.rule == "desktop-build-unverified" || f.rule == "desktop-build-fail");
        let verified_ok = out.records.iter().any(|r| r.contains("прошли"));
        assert!(
            unverified || verified_ok,
            "распознанный стек обязан дать либо подтверждение, либо находку, а не молчание"
        );
    }
}
