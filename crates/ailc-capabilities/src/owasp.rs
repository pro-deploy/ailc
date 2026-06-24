//! security.scan/owasp — обзор по OWASP Top 10 (2021), заземлённый на код.
//! Матрица A01–A10 (статус + находки [HIGH] + ручные проверки), file:line + фикс.
//!
//! Матчинг делегирован общему `ScanEngine`: тот один раз обходит дерево, применяет
//! таблицу правил, корректно валидирует target через `Ctx::base` (абсолютный путь и
//! `..` не выводят за корень проекта), пропускает тест-фикстуры, отсекает
//! сверхдлинные строки и поддерживает МНОГОСТРОЧНЫЙ режим (окно строк, склейка
//! конкатенируемых литералов) для классов потока данных. Поверх находок движка эта
//! capability строит матрицу покрытия A01–A10, сопоставляя идентификатор правила его
//! категории. Достоверность каждого правила задаётся отдельной картой
//! `contracts::rule_confidence` по идентификатору; severity и сообщения с проверенной
//! ссылкой CWE/OWASP живут в таблице правил здесь.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Severity,
    Tier,
};
use ailc_core::engines::scan::{Matcher, Rule, ScanEngine, SOURCE_CODE};
use ailc_core::registry::Registry;
use ailc_core::Capability;
// Единый источник истины для признака ssrf-internal-host (правило продублировано здесь
// и в web_security.rs; двойной счёт убирает дедуп находок в scan_all).
use crate::web_security::SSRF_INTERNAL_HOST_RE;
use std::collections::BTreeMap;

/// (код, название, только-ручная-проверка)
const CATS: &[(&str, &str, bool)] = &[
    ("A01", "Broken Access Control", false),
    ("A02", "Cryptographic Failures", false),
    ("A03", "Injection", false),
    ("A04", "Insecure Design", true),
    ("A05", "Security Misconfiguration", false),
    ("A06", "Vulnerable & Outdated Components", true),
    ("A07", "Identification & Auth Failures", false),
    ("A08", "Software & Data Integrity Failures", false),
    ("A09", "Security Logging & Monitoring Failures", false),
    ("A10", "Server-Side Request Forgery (SSRF)", false),
];

/// Категория OWASP по идентификатору правила. Таблица правил движка не несёт поля
/// категории (она общая для всех сканеров), поэтому связь «правило -> категория»
/// хранится здесь, рядом с самими правилами. Любое правило, добавленное в [`rules`],
/// обязано иметь запись здесь (тест полноты этого требует).
fn cat_of(rule_id: &str) -> Option<&'static str> {
    Some(match rule_id {
        // A01 Broken Access Control.
        "permissive-authz" | "cors-wildcard" | "cors-reflect-origin" | "idor-direct-ref" => "A01",
        // A02 Cryptographic Failures.
        "weak-hash" | "weak-cipher" | "ecb-mode" | "hardcoded-crypto-material" | "insecure-random"
        | "tls-verify-off" => "A02",
        // A03 Injection.
        "sql-injection" | "dangerous-exec" | "xss-sink" | "ssti" => "A03",
        // A05 Security Misconfiguration.
        "debug-enabled" => "A05",
        // A07 Identification & Auth Failures.
        "jwt-none" | "jwt-alg-confusion" | "weak-pw-hash" => "A07",
        // A08 Software & Data Integrity Failures.
        "insecure-deser" => "A08",
        // A09 Security Logging & Monitoring Failures.
        "pii-in-log" => "A09",
        // A10 Server-Side Request Forgery.
        "ssrf" | "ssrf-internal-host" => "A10",
        _ => return None,
    })
}

/// Таблица правил OWASP. Это обычные правила `ScanEngine` (один движок на все
/// сканеры), поэтому многострочные классы потока задаются матчером окна/файла, а не
/// отдельным полем. Категория каждого правила вынесена в [`cat_of`].
fn rules() -> Vec<Rule> {
    use Severity::{High, Medium};
    let web = &["js", "ts", "jsx", "tsx", "vue", "html"];
    vec![
        // ───────────────── A01 Broken Access Control ─────────────────
        Rule {
            id: "permissive-authz",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r"(?i)permitall\(\)|anyrequest\(\)\s*\.\s*permitall|@permitall|allowanonymous",
            ),
            message: "Излишне разрешающая авторизация — проверь, что эндпоинт ограничен по правам (CWE-285, OWASP A01:2021 Broken Access Control).",
        },
        // CORS-wildcard приведён к web-варианту: класс символов включает равно,
        // поэтому Access-Control-Allow-Origin = "*" тоже ловится.
        Rule {
            id: "cors-wildcard",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)access-control-allow-origin["'\s:=]+\*|allowallorigins\s*[:=]\s*true|cors\s*\([^)\n]*origins?\s*[:=]\s*["']\*"#,
            ),
            message: "CORS разрешает любой источник (*) — ограничь доверенные источники allow-list (CWE-942, OWASP A01:2021).",
        },
        // CORS reflection: динамическое отражение заголовка Origin, опаснее «*»
        // вместе с Allow-Credentials. Согласовано с web-вариантом cors-reflect-origin.
        Rule {
            id: "cors-reflect-origin",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)access-control-allow-origin["'\s:=]+(?:request|req|origin|\$http_origin)|cors\s*\([^)\n]*origin\s*:\s*true|@CrossOrigin\b"#,
            ),
            message: "CORS отражает заголовок Origin — вместе с Allow-Credentials:true позволяет кражу с учётными данными, используй статический allow-list (CWE-942/CWE-346, OWASP A01:2021).",
        },
        // IDOR: выборка записи по идентификатору из запроса БЕЗ проверки владельца в
        // том же окне. Эвристика на типовой паттерн ORM-выборки по id из ввода;
        // достоверность Heuristic (см. rule_confidence). Окно из трёх строк, чтобы
        // охватить запрос id и следующий вызов выборки.
        Rule {
            id: "idor-direct-ref",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::window_regex(
                r"(?is)(?:request\.|req\.|params|query|getParameter|@PathVariable)[^;{]{0,80}?\b(?:id|user_?id|account_?id|object_?id)\b[^;{]{0,160}?(?:\.(?:get|find|find_by_id|findById|get_object_or_404|filter|where|query)|objects\.get|findOne)\s*\(",
                3,
            ),
            message: "Возможный IDOR — выборка объекта по идентификатору из запроса без проверки владельца (CWE-639, OWASP A01:2021 Broken Access Control). Сопоставь объект с текущим пользователем перед доступом. Эвристика, требуется ручной обзор.",
        },
        // ───────────────── A02 Cryptographic Failures ─────────────────
        // Слабый хеш во ВСЕХ типовых формах: прямой вызов md5(/sha1(, имя
        // алгоритма в строковом литерале фабрики (getInstance/createHash/new), а
        // также DigestUtils.md5Hex и .NET MD5.Create/SHA1.Create. Раньше ловилось
        // только md5(/sha1( вплотную к скобке.
        Rule {
            id: "weak-hash",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)\b(?:md5|sha-?1)\s*\(|(?:hashlib\.new|createHash|getInstance|MessageDigest\.getInstance)\s*\(\s*["'](?:md5|sha-?1)["']|DigestUtils\.(?:md5|sha1)(?:Hex)?\s*\(|(?:MD5|SHA1)\.Create\s*\("#,
            ),
            message: "Слабый хеш (MD5/SHA1) — используй SHA-256+ для целостности и argon2id/bcrypt для паролей (CWE-327, OWASP A02:2021 Cryptographic Failures).",
        },
        // Устаревший симметричный шифр: DES/3DES/RC4/Blowfish/RC2. Ловим имя
        // алгоритма в строке фабрики (getInstance/Cipher) и прямые вызовы.
        Rule {
            id: "weak-cipher",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)getInstance\s*\(\s*["'](?:des|3des|desede|tripledes|rc4|arcfour|blowfish|rc2)\b|Cipher\.getInstance\s*\(\s*["'](?:des|desede|rc2|blowfish)|\b(?:DES|TripleDES|RC2|RC4)CryptoServiceProvider\b|crypto\.create(?:Cipher|Cipheriv)\s*\(\s*["'](?:des|des-ede3|rc4|bf|rc2)"#,
            ),
            message: "Устаревший слабый шифр (DES/3DES/RC4/Blowfish/RC2) — перейди на AES-GCM или ChaCha20-Poly1305 (CWE-327, OWASP A02:2021 Cryptographic Failures).",
        },
        // Режим ECB: блочный шифр в режиме электронной кодовой книги раскрывает
        // повторяющиеся блоки открытого текста.
        Rule {
            id: "ecb-mode",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)getInstance\s*\(\s*["'][A-Z0-9]+/ECB/|/ECB/|\bMODE_ECB\b|\bAES\.MODE_ECB\b|CipherMode\.ECB"#,
            ),
            message: "Режим ECB раскрывает структуру открытого текста (одинаковые блоки дают одинаковый шифртекст) — используй аутентифицированный режим (GCM) (CWE-327, OWASP A02:2021 Cryptographic Failures).",
        },
        // Захардкоженные криптоматериалы: постоянные соль, IV или ключ в литерале.
        // Окно из двух строк, чтобы поймать инициализацию из соседней строки.
        Rule {
            id: "hardcoded-crypto-material",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::window_regex(
                r#"(?is)\b(?:salt|iv|initialization[_-]?vector|secret[_-]?key|crypto[_-]?key|aes[_-]?key|encryption[_-]?key)\b\s*[:=]\s*(?:b?["'][^"'\n]{4,}["']|new\s+byte\s*\[\s*\]\s*\{|bytes\s*\(\s*["'])"#,
                2,
            ),
            message: "Захардкоженный криптоматериал (соль/IV/ключ в коде) — генерируй случайные значения и храни ключи в секрет-хранилище (CWE-329 для статического IV, CWE-760 для статической соли, CWE-321 для зашитого ключа, OWASP A02:2021).",
        },
        // Непригодный для секретов ГСЧ (псевдослучайность для токенов/ключей).
        Rule {
            id: "insecure-random",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r"(?i)math/rand|math\.random|random\.(?:random|randint|randrange|getrandbits|uniform|normalvariate|gauss|betavariate|expovariate|triangular|lognormvariate)\s*\(|new\s+Random\s*\(|np(?:\.|umpy\.)random\.",
            ),
            message: "Непригодный для секретов генератор случайных чисел — используй криптостойкий источник (crypto/rand, secrets, SecureRandom) для токенов и ключей (CWE-338, OWASP A02:2021 Cryptographic Failures).",
        },
        // Отключённая проверка TLS — A02 (защита передаваемых данных). Согласовано с
        // web-вариантом по многим стекам; граница перед verify убирает email_verify.
        Rule {
            id: "tls-verify-off",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)InsecureSkipVerify\s*[:=]\s*true|rejectUnauthorized\s*[:=]\s*false|\bverify\s*=\s*False|ssl\._create_unverified_context|setHostnameVerifier\s*\(|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|ServerCertificateValidationCallback\s*[:=+]|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0|CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:0|false)"#,
            ),
            message: "Проверка TLS-сертификата отключена — не выключай проверку сертификата/имени хоста в проде, это открывает MITM (CWE-295, OWASP A02:2021 Cryptographic Failures).",
        },
        // ───────────────── A03 Injection ─────────────────
        Rule {
            id: "sql-injection",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::Predicate(|l| {
                let s = l.to_lowercase();
                (s.contains("select ")
                    || s.contains("insert ")
                    || s.contains("update ")
                    || s.contains("delete "))
                    && (l.contains("\" +")
                        || l.contains("' +")
                        || l.contains("+ \"")
                        || s.contains(".format(")
                        || s.contains("f\""))
            }),
            message: "Возможная SQL-инъекция (конкатенация ввода в запрос) — используй параметризованные запросы (CWE-89, OWASP A03:2021 Injection).",
        },
        // Опасное исполнение команды ОС: os.system( и Java-стоки Runtime.getRuntime().exec
        // и ProcessBuilder (класс [^.\w] раньше пропускал точку перед exec). Голые eval(/
        // exec( из паттерна УБРАНЫ: построчный матч флагует и eval(bar), где ветвь свёрнута
        // константой либо ввод не доходит до стока (на корпусе кодовой инъекции это давало
        // 100% ложных). Поток к eval/exec теперь строит потоковый сток
        // `sast/taint-dynamic-exec`, срабатывающий лишь при доказанном потоке источник→сток.
        Rule {
            id: "dangerous-exec",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r"(?i)os\.system\s*\(|\bRuntime\b[^\n]{0,40}\.exec\s*\(|\bgetRuntime\s*\(\s*\)\s*\.exec\s*\(|\bnew\s+ProcessBuilder\s*\(",
            ),
            message: "Опасное исполнение команды ОС (os.system/Runtime.exec/ProcessBuilder) — не собирай команду из недоверенного ввода, передавай аргументы массивом (CWE-78, OWASP A03:2021 Injection).",
        },
        // XSS-вставка в DOM. Границы слова перед innerHTML/outerHTML убирают
        // ложные совпадения внутри других идентификаторов.
        Rule {
            id: "xss-sink",
            severity: Medium,
            exts: web,
            matcher: Matcher::regex(
                r"(?i)\b(?:inner|outer)html\s*=|dangerouslysetinnerhtml|document\.write\s*\(|\binsertadjacenthtml\s*\(",
            ),
            message: "Вставка в DOM без экранирования (XSS) — используй textContent или DOMPurify (CWE-79, OWASP A03:2021 Injection).",
        },
        // SSTI — рендер шаблона из недоверенной строки по многим движкам (Flask,
        // Jinja from_string, Twig, Freemarker, ERB, Handlebars).
        Rule {
            id: "ssti",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r"(?i)\brender_template_string\s*\(|\b(?:env(?:ironment)?)\.from_string\s*\(|\bTemplate\s*\([^)]*\)\s*\.\s*render\s*\(|\bERB\.new\s*\(|\bHandlebars\.compile\s*\(|\bnew\s+Template\s*\(",
            ),
            message: "Server-Side Template Injection — рендер шаблона из строки (CWE-1336, OWASP A03:2021 Injection). Не подставляй ввод в тело шаблона; используй контекстные переменные.",
        },
        // ───────────────── A05 Security Misconfiguration ─────────────────
        Rule {
            id: "debug-enabled",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(r"(?i)\bdebug\s*=\s*true"),
            message: "Debug-режим включён — выключи debug в проде (риск утечки трассировок и внутренней информации) (CWE-489, OWASP A05:2021 Security Misconfiguration).",
        },
        // ───────────────── A07 Identification & Auth Failures ─────────────────
        // JWT без проверки подписи: alg=none/None/[], none в массиве,
        // verify_signature=false. Требуем JWT-маркер рядом (jwt/jose/decode/HS256),
        // чтобы не ловить «compression algorithm: none». Окно из двух строк.
        // Три ветви, как в security.scan/api (T21, единый паттерн): ветвь с
        // JWT-маркером ловит любую alg=none форму; ветвь с закавыченным "none" как
        // значением алгоритма срабатывает без маркера (кавычки исключают конфиг
        // сжатия «algorithm: none»); ветвь verify_signature=false самодостаточна.
        Rule {
            id: "jwt-none",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::window_regex(
                r#"(?is)(?:jwt|jose|jws|\bdecode\b|HS256|RS256|verify_signature)[^;]{0,80}?(?:alg(?:orithm)?s?\s*["'\s:=\[{]+\s*["']?(?:none|None|NONE)\b|algorithms?\s*[:=]\s*(?:None|\[\s*\]))|alg(?:orithm)?s?\s*["'\s:=\[{,]+\s*["'](?:none|None|NONE)["']|verify_signature\s*["'\s:=]+\s*(?:false|False)"#,
                2,
            ),
            // ailc:ignore[jwt-none,jwt-none-alg] — текст СООБЩЕНИЯ правила, самосовпадение на ruleset
            message: "JWT без проверки подписи (alg=none/None/[] или verify off) — всегда проверяй подпись и жёстко задавай алгоритм (CWE-347, OWASP A07:2021 Identification & Authentication Failures).",
        },
        // JWT алгоритмическая путаница: смешение асимметричного и HMAC в одном
        // списке допустимых алгоритмов.
        Rule {
            id: "jwt-alg-confusion",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)(?:jwt|jose|jws|algorithms?)[^\n]{0,80}(?:HS\d{3}[^\n]{0,40}(?:RS|ES|PS)\d{3}|(?:RS|ES|PS)\d{3}[^\n]{0,40}HS\d{3})"#,
            ),
            message: "JWT алгоритмическая путаница — в списке допустимых алгоритмов смешаны асимметричный и HMAC; токен, подписанный публичным ключом как HMAC, пройдёт проверку (CWE-347, OWASP A07:2021). Разрешай ровно один алгоритм.",
        },
        Rule {
            id: "weak-pw-hash",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r"(?i)(?:md5|sha-?1)[^\n]{0,40}(?:password|passwd|pwd)|(?:password|passwd|pwd)[^\n]{0,40}(?:md5|sha-?1)\s*\(",
            ),
            message: "Слабое хеширование паролей (MD5/SHA1) — используй argon2id или bcrypt с солью (CWE-916, OWASP A07:2021 Identification & Authentication Failures).",
        },
        // ───────────────── A08 Software & Data Integrity Failures ─────────────────
        // Небезопасная десериализация по многим экосистемам.
        Rule {
            id: "insecure-deser",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r"(?i)pickle\.loads?\s*\(|yaml\.load\s*\(|objectinputstream|\.readObject\s*\(|\bunserialize\s*\(|marshal\.loads?\s*\(|\bMarshal\.load\s*\(|\bBinaryFormatter\b|\bNetDataContractSerializer\b",
            ),
            message: "Небезопасная десериализация недоверенных данных — выполнение кода (CWE-502, OWASP A08:2021 Software & Data Integrity Failures). Используй safe_load/SafeLoader, JSON или allow-list типов.",
        },
        // ───────────────── A09 Security Logging & Monitoring Failures ─────────────────
        Rule {
            id: "pii-in-log",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::Predicate(|l| {
                let s = l.to_lowercase();
                (s.contains("console.log")
                    || s.contains("print(")
                    || s.contains("println")
                    || s.contains("logger.")
                    || s.contains("log.info"))
                    && (s.contains("password")
                        || s.contains("token")
                        || s.contains("secret")
                        || s.contains("email")
                        || s.contains("ssn"))
            }),
            message: "Логирование чувствительного поля (PII/секрет) — маскируй перед записью в лог (CWE-532, OWASP A09:2021 Security Logging & Monitoring Failures).",
        },
        // ───────────────── A10 Server-Side Request Forgery ─────────────────
        // SSRF-сток: HTTP-клиент с URL из недоверенного ввода. Источник распознаётся
        // шире (включая имена url/target/link/endpoint/host), окно из трёх строк
        // связывает источник и сток через перенос. Severity High, согласовано с web.
        Rule {
            id: "ssrf",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::window_regex(
                // Та же двойная форма, что и в security.scan/web (T18, единый
                // паттерн): клиент с аргументом-источником/URL-именем на строке, либо
                // оконная связь «явный источник ... клиент».
                r"(?is)(?:(?:requests\.(?:get|post|put|delete|head|patch|request)|httpx\.(?:get|post|put|delete|head|request)|urllib\.request\.urlopen|urlopen|axios(?:\.(?:get|post|put|delete|head|request))?|\bfetch|http\.(?:Get|Post|NewRequest)|HttpClient|WebClient)\s*\(\s*(?:request\.|req\.|params|query|user_input|user\.|\b(?:url|uri|target|link|endpoint|host|dest|destination|location|redirect|callback)\b)|(?:request\.|req\.|params|query|getParameter|user_input)[^;{]{0,160}?(?:requests\.(?:get|post|put|delete|head|patch|request)|httpx\.(?:get|post|request)|urlopen|axios(?:\.(?:get|post|request))?|\bfetch|http\.(?:Get|Post|NewRequest)|HttpClient|WebClient)\s*\()",
                3,
            ),
            message: "SSRF — запрос по управляемому пользователем URL (CWE-918, OWASP A10:2021 Server-Side Request Forgery). Валидируй хост по allow-list, запрети внутренние и метаданные-адреса.",
        },
        // SSRF по опасному литеральному хосту: облачные метаданные, loopback,
        // RFC1918, decimal/hex/octal представления адреса.
        Rule {
            id: "ssrf-internal-host",
            severity: High,
            exts: SOURCE_CODE,
            // Точность вместо шума: общий с web_security паттерн (SSRF_INTERNAL_HOST_RE)
            // ловит метаданные литералом, а обычный внутренний хост — только в окне с
            // вызовом HTTP-клиента, поэтому конфиги, логи и базы URL не флагаются.
            matcher: Matcher::window_regex(SSRF_INTERNAL_HOST_RE, 3),
            // ailc:ignore[ssrf-internal-host] — адрес в ТЕКСТЕ СООБЩЕНИЯ правила, не живой вызов
            message: "SSRF — обращение к внутреннему/метаданным-адресу из кода HTTP-клиента (CWE-918, OWASP A10:2021 Server-Side Request Forgery). Облачные метаданные (169.254.169.254), loopback и RFC1918 недоступны извне; блокируй и обходные формы (decimal/hex/octal IP).",
        },
    ]
}

pub struct OwaspCheck {
    manifest: CapabilityManifest,
}

impl Default for OwaspCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl OwaspCheck {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "security.scan/owasp",
                family: Family::Security,
                engine: EngineKind::Scan,
                when_to_use: "Обзор по OWASP Top 10 (A01–A10) с матрицей покрытия, file:line и рекомендациями. Покрытие паттерновое: пустая категория означает «по ограниченному набору паттернов», а не доказанное отсутствие уязвимостей; ручной обзор остаётся желательным.",
                input_schema: r#"{"type":"object","properties":{"target":{"type":"string"}}}"#,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for OwaspCheck {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        // Матчинг и обход дерева делегированы движку: он валидирует target через
        // Ctx::base (абсолютный путь и `..` отвергаются), пропускает тест-фикстуры,
        // отсекает сверхдлинные строки и ведёт многострочные правила. Тем самым
        // устранено расхождение T42 (ручной ctx.root.join уводил за корень).
        let rules = rules();
        let mut out = ScanEngine::run(ctx, input, &rules, self.manifest.id, true)?;

        // Если движок честно пропустил прогон (нет файлов), сохраняем его причину и
        // не строим матрицу: пустая матрица создавала бы ложную уверенность.
        if out.skipped.is_some() {
            return Ok(out);
        }

        // ── Сводка по категориям: число находок и из них High ──────────────────
        let mut by_cat: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
        let (mut high, mut med) = (0u32, 0u32);
        for f in &out.findings {
            if let Some(cat) = cat_of(&f.rule) {
                let e = by_cat.entry(cat).or_default();
                e.0 += 1;
                if f.severity >= Severity::High {
                    e.1 += 1;
                }
            }
            if f.severity >= Severity::High {
                high += 1;
            } else {
                med += 1;
            }
        }

        // ── Матрица A01–A10 ────────────────────────────────────────────────────
        // Сводку движка («N файлов, M находок») заменяем человекочитаемой матрицей и
        // итогом, сохраняя находки и метрики движка.
        let mut records: Vec<String> = Vec::new();
        records.push("OWASP Top 10 (2021) — матрица:".to_string());
        let mut cats_with = 0u32;
        for (cat, name, manual) in CATS {
            let (c, h) = by_cat.get(cat).copied().unwrap_or((0, 0));
            let status = if c > 0 {
                cats_with += 1;
                format!("⚠ {c} находок [HIGH:{h}]")
            } else if *manual {
                // Категории, для которых статического правила нет в принципе.
                "◻ только ручная проверка".to_string()
            } else {
                // T25: НЕ утверждаем «чисто». Пустая категория = «по ограниченному
                // набору паттернов», что честно отражает слабость regex и не маскирует
                // ложноотрицательные результаты для пользователя и гейта.
                "⚪ проверено ограниченным набором паттернов, рекомендуется ручной обзор"
                    .to_string()
            };
            records.push(format!("  {cat} {name:<40} {status}"));
        }

        // Детализация находок с file:line.
        for f in &out.findings {
            let cat = cat_of(&f.rule).unwrap_or("—");
            let loc = f
                .location
                .as_ref()
                .map(|l| format!("{}:{}", l.file, l.line))
                .unwrap_or_default();
            records.push(format!("  [{}] {cat} {} ({loc})", f.severity, f.message));
        }

        // Движок записей не формирует (только находки, метрики и сводку), поэтому
        // матрица становится содержимым records; метрики охвата движка (files_scanned
        // и прочие) сохраняются в out.metrics для прозрачности пропусков.
        out.records = records;

        out.metrics.push(("owasp_high".into(), high as f64));
        out.metrics.push(("owasp_medium".into(), med as f64));
        out.summary = format!(
            "security.scan/owasp: HIGH={high} MEDIUM={med}, категорий с находками {cats_with}/10"
        );
        Ok(out)
    }
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(OwaspCheck::new()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Найти правило по идентификатору.
    fn rule_by_id(id: &str) -> Rule {
        rules()
            .into_iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("правило {id} должно существовать"))
    }

    /// Сработал ли матчер правила на тексте (с учётом многострочности).
    fn hits(id: &str, text: &str) -> bool {
        let r = rule_by_id(id);
        if r.matcher.is_multiline() {
            r.matcher.is_match(text)
        } else {
            text.lines().any(|l| r.matcher.is_match(l))
        }
    }

    /// Уникальная пустая временная папка для файловых фикстур.
    fn tmp() -> PathBuf {
        let n = CNT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ailc-owasp-{}-{}", std::process::id(), n));
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

    // ───────────────────────── T42 ctx.base ─────────────────────────

    #[test]
    fn target_абсолютный_путь_отвергается() {
        let dir = tmp();
        let input = RunInput {
            target: Some("/etc".to_string()),
            ..Default::default()
        };
        let res = OwaspCheck::new().run(&Ctx::new(&dir), &input);
        assert!(res.is_err(), "абсолютный target должен отвергаться через ctx.base");
    }

    #[test]
    fn target_с_двумя_точками_отвергается() {
        let dir = tmp();
        let input = RunInput {
            target: Some("../../etc".to_string()),
            ..Default::default()
        };
        let res = OwaspCheck::new().run(&Ctx::new(&dir), &input);
        assert!(res.is_err(), "target с .. должен отвергаться через ctx.base");
    }

    // ───────────────────────── полнота карт ─────────────────────────

    #[test]
    fn каждое_правило_имеет_категорию() {
        for r in rules() {
            assert!(
                cat_of(r.id).is_some(),
                "правило {} должно быть сопоставлено категории в cat_of",
                r.id
            );
        }
    }

    #[test]
    fn каждое_сообщение_несёт_cwe() {
        for r in rules() {
            assert!(
                r.message.contains("CWE-"),
                "правило {} должно ссылаться на CWE",
                r.id
            );
        }
    }

    #[test]
    fn нет_дублей_идентификаторов() {
        let mut ids: Vec<&str> = rules().iter().map(|r| r.id).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "идентификаторы правил OWASP должны быть уникальны");
    }

    // ───────────────────────── T19 крипта ─────────────────────────

    #[test]
    fn weak_hash_во_всех_формах() {
        assert!(hits("weak-hash", "h = hashlib.md5(data)"), "прямой md5(");
        assert!(hits("weak-hash", "MessageDigest.getInstance(\"MD5\")"), "java getInstance MD5");
        assert!(hits("weak-hash", "crypto.createHash('sha1')"), "node createHash sha1");
        assert!(hits("weak-hash", "DigestUtils.md5Hex(s)"), "apache DigestUtils");
        assert!(hits("weak-hash", "var h = MD5.Create();"), "dotnet MD5.Create");
        assert!(hits("weak-hash", "d = hashlib.new('md5')"), "python hashlib.new");
    }

    #[test]
    fn weak_hash_не_трогает_sha256() {
        assert!(!hits("weak-hash", "h = hashlib.sha256(data)"), "sha256 не слабый");
        assert!(!hits("weak-hash", "getInstance(\"SHA-256\")"), "SHA-256 не слабый");
    }

    #[test]
    fn weak_cipher_des_rc4_blowfish() {
        assert!(hits("weak-cipher", "Cipher.getInstance(\"DES/CBC/PKCS5Padding\")"), "DES");
        assert!(hits("weak-cipher", "c = getInstance('3des')"), "3des");
        assert!(hits("weak-cipher", "crypto.createCipheriv('rc4', k, iv)"), "rc4");
        assert!(hits("weak-cipher", "getInstance('blowfish')"), "blowfish");
        assert!(!hits("weak-cipher", "Cipher.getInstance(\"AES/GCM/NoPadding\")"), "AES-GCM не слабый");
    }

    #[test]
    fn ecb_mode() {
        assert!(hits("ecb-mode", "Cipher.getInstance(\"AES/ECB/PKCS5Padding\")"), "java ecb");
        assert!(hits("ecb-mode", "cipher = AES.new(key, AES.MODE_ECB)"), "pycrypto ecb");
        assert!(!hits("ecb-mode", "Cipher.getInstance(\"AES/GCM/NoPadding\")"), "gcm не ecb");
    }

    #[test]
    fn hardcoded_crypto_material() {
        assert!(hits("hardcoded-crypto-material", "iv = b'1234567890123456'"), "статический IV");
        assert!(hits("hardcoded-crypto-material", "salt = 'fixed-salt-value'"), "статическая соль");
        assert!(hits("hardcoded-crypto-material", "aes_key = 'hardcoded-secret-key'"), "зашитый ключ");
        assert!(!hits("hardcoded-crypto-material", "salt = os.urandom(16)"), "случайная соль не находка");
    }

    // ───────────────────────── T18 SSRF ─────────────────────────

    #[test]
    fn ssrf_сток_именованный_url_и_окно() {
        assert!(hits("ssrf", "resp = requests.get(target)"), "target");
        assert!(hits("ssrf", "u = request.args.get('u')\nresp = requests.get(u)"), "окно");
        assert!(!hits("ssrf", "requests.get('https://api.example.com')"), "доверенный литерал");
    }

    #[test]
    fn ssrf_литеральный_хост() {
        // Метаданные облака — находка даже голым литералом (однозначно подозрительны).
        assert!(hits("ssrf-internal-host", "url = 'http://169.254.169.254/'"), "imds");
        // Внутренний хост — находка ТОЛЬКО в контексте вызова HTTP-клиента.
        assert!(hits("ssrf-internal-host", "requests.get('http://10.0.0.1/')"), "rfc1918 в запросе");
        // Голый внутренний литерал (конфиг/дефолт) и публичный адрес — НЕ находка.
        assert!(!hits("ssrf-internal-host", "base = 'http://10.0.0.1/'"), "конфиг не SSRF");
        assert!(!hits("ssrf-internal-host", "u = 'http://8.8.8.8/'"), "публичный");
    }

    #[test]
    fn ssrf_severity_high_в_owasp() {
        // T18: owasp SSRF приведён к High (раньше Medium), согласован с web.
        assert_eq!(rule_by_id("ssrf").severity, Severity::High);
        assert_eq!(rule_by_id("ssrf-internal-host").severity, Severity::High);
    }

    // ───────────────────────── T20 TLS ─────────────────────────

    #[test]
    fn tls_многие_стеки_и_без_email_verify() {
        assert!(hits("tls-verify-off", "tls.Config{InsecureSkipVerify: true}"), "go");
        assert!(hits("tls-verify-off", "conn.setHostnameVerifier((h,s)->true)"), "java");
        assert!(hits("tls-verify-off", "NODE_TLS_REJECT_UNAUTHORIZED = '0'"), "node");
        assert!(hits("tls-verify-off", "requests.get(u, verify=False)"), "python");
        assert!(!hits("tls-verify-off", "email_verify=False"), "email_verify не TLS");
    }

    // ───────────────────────── T21 JWT ─────────────────────────

    #[test]
    fn jwt_none_формы_и_маркер() {
        assert!(hits("jwt-none", "jwt.decode(t, algorithms=['none'])"), "массив none");
        assert!(hits("jwt-none", "jwt.decode(t, algorithms=None)"), "None");
        assert!(!hits("jwt-none", "compression algorithm: none"), "сжатие без JWT-маркера");
    }

    #[test]
    fn jwt_alg_confusion() {
        assert!(hits("jwt-alg-confusion", "jwt.decode(t, algorithms=['HS256','RS256'])"), "смешение");
        assert!(!hits("jwt-alg-confusion", "algorithms=['RS256']"), "один класс");
    }

    // ───────────────────────── T22 CORS ─────────────────────────

    #[test]
    fn cors_wildcard_через_равно() {
        assert!(hits("cors-wildcard", "Access-Control-Allow-Origin = \"*\""), "равно");
        assert!(hits("cors-wildcard", "Access-Control-Allow-Origin: *"), "двоеточие");
    }

    #[test]
    fn cors_reflection_high() {
        assert!(hits("cors-reflect-origin", "Access-Control-Allow-Origin: $http_origin"), "echo");
        assert!(hits("cors-reflect-origin", "cors({origin: true})"), "origin true");
        assert_eq!(rule_by_id("cors-reflect-origin").severity, Severity::High);
    }

    // ───────────────────────── T23 расширения ─────────────────────────

    #[test]
    fn dangerous_exec_включает_runtime() {
        // T23: класс [^.\w] раньше пропускал .exec(; Runtime/ProcessBuilder покрыты.
        assert!(hits("dangerous-exec", "Runtime.getRuntime().exec(cmd)"), "runtime");
        assert!(hits("dangerous-exec", "new ProcessBuilder(cmd).start()"), "processbuilder");
        assert!(hits("dangerous-exec", "os.system(c)"), "os.system");
        // Голые eval/exec ВЫВЕДЕНЫ из паттерна в потоковый сток sast/taint-dynamic-exec:
        // построчный матч флагует eval(bar) и там, где ввод не доходит до стока. Паттерн
        // оставляет только исполнители команд ОС с самодостаточно подозрительной формой.
        assert!(!hits("dangerous-exec", "eval(code)"), "eval без потока — не паттерн");
        assert!(!hits("dangerous-exec", "exec(code)"), "exec без потока — не паттерн");
        // Бенайн regex.exec не должен ловиться (точка перед exec, не Runtime).
        assert!(!hits("dangerous-exec", "const m = re.exec(input)"), "regex.exec бенайн");
    }

    #[test]
    fn xss_sink_границы_слова() {
        assert!(hits("xss-sink", "el.innerHTML = data"), "innerHTML");
        assert!(hits("xss-sink", "el.outerHTML = data"), "outerHTML");
        assert!(hits("xss-sink", "el.insertAdjacentHTML('beforeend', data)"), "insertAdjacentHTML");
    }

    #[test]
    fn ssti_многие_движки() {
        assert!(hits("ssti", "render_template_string(t)"), "flask");
        assert!(hits("ssti", "env.from_string(t).render()"), "jinja");
        assert!(hits("ssti", "ERB.new(t).result(b)"), "erb");
    }

    #[test]
    fn deser_многие_экосистемы() {
        assert!(hits("insecure-deser", "obj = pickle.loads(d)"), "pickle");
        assert!(hits("insecure-deser", "new ObjectInputStream(in)"), "java");
        assert!(hits("insecure-deser", "$o = unserialize($d)"), "php");
        assert!(hits("insecure-deser", "o = Marshal.load(d)"), "ruby");
        assert!(hits("insecure-deser", "new BinaryFormatter().Deserialize(s)"), "dotnet");
    }

    // ───────────────────────── T25 матрица ─────────────────────────

    #[test]
    fn матрица_не_печатает_чисто_для_пустой_категории() {
        let dir = tmp();
        // Файл без уязвимостей по нашим правилам, но валидный исходник.
        write(&dir, "ok.py", "def add(a, b):\n    return a + b\n");
        let out = OwaspCheck::new()
            .run(&Ctx::new(&dir), &RunInput::default())
            .unwrap();
        let joined = out.records.join("\n");
        assert!(
            !joined.contains("чисто (по паттернам)"),
            "T25: формулировка «чисто (по паттернам)» должна быть убрана"
        );
        assert!(
            joined.contains("ограниченным набором паттернов"),
            "T25: пустая категория должна честно предупреждать о ручном обзоре"
        );
    }

    #[test]
    fn idor_эвристика_срабатывает_и_по_окну() {
        assert!(
            hits(
                "idor-direct-ref",
                "uid = request.args.get('user_id')\nuser = User.objects.get(id=uid)"
            ),
            "T25: IDOR-эвристика связывает id из запроса и выборку"
        );
    }

    #[test]
    fn матрица_помечает_находку_и_итог() {
        let dir = tmp();
        write(&dir, "vuln.py", "import hashlib\nh = hashlib.md5(data)\n");
        let out = OwaspCheck::new()
            .run(&Ctx::new(&dir), &RunInput::default())
            .unwrap();
        assert!(out.findings.iter().any(|f| f.rule == "weak-hash"), "должна быть находка weak-hash");
        assert!(out.summary.contains("HIGH="), "итог содержит счётчик HIGH");
        let joined = out.records.join("\n");
        assert!(joined.contains("A02"), "матрица отмечает категорию A02 с находкой");
    }

    #[test]
    fn пустой_проект_честно_пропускается() {
        let dir = tmp();
        let out = OwaspCheck::new()
            .run(&Ctx::new(&dir), &RunInput::default())
            .unwrap();
        assert!(out.skipped.is_some(), "нет исходников = честный пропуск, не пустая матрица");
    }
}
