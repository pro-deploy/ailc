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
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Severity, Tier,
};
use ailc_core::engines::scan::{Matcher, Rule, ScanEngine, SOURCE_CODE};
use ailc_core::engines::walk::WalkMode;
use ailc_core::registry::Registry;
use ailc_core::Capability;
// Единый источник истины для признака ssrf-internal-host (правило продублировано здесь
// и в web_security.rs; двойной счёт убирает дедуп находок в scan_all).
use crate::web_security::{
    CORS_REFLECT_ORIGIN_RE, CORS_WILDCARD_RE, SSRF_INTERNAL_HOST_RE, SSTI_RE,
};
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
        "permissive-authz"
        | "cors-wildcard"
        | "cors-reflect-origin"
        | "idor-direct-ref"
        | "archive-path-traversal" => "A01",
        // A02 Cryptographic Failures.
        "weak-hash"
        | "weak-cipher"
        | "ecb-mode"
        | "hardcoded-crypto-material"
        | "insecure-random"
        | "tls-verify-off"
        | "timing-unsafe-compare"
        | "static-iv"
        | "weak-kdf-params" => "A02",
        // A03 Injection.
        "sql-injection"
        | "dangerous-exec"
        | "shell-injection"
        | "xss-sink"
        | "ssti"
        | "nosql-injection"
        | "header-crlf-injection" => "A03",
        // A04 Insecure Design.
        "rate-limit-disabled"
        | "integer-overflow-alloc"
        | "null-deref-after-alloc"
        | "toctou-file-race" => "A04",
        // A05 Security Misconfiguration.
        "debug-enabled"
        | "world-writable-permissions"
        | "insecure-temp-file"
        | "weak-security-headers"
        | "stack-trace-exposed"
        | "directory-listing-enabled" => "A05",
        // A07 Identification & Auth Failures.
        "jwt-none"
        | "jwt-alg-confusion"
        | "weak-pw-hash"
        | "jwt-expiration-ignored"
        | "session-id-in-url" => "A07",
        // A08 Software & Data Integrity Failures.
        "insecure-deser" | "missing-subresource-integrity" | "unpinned-dependency-ref" => "A08",
        // A09 Security Logging & Monitoring Failures.
        "pii-in-log" | "log-injection" => "A09",
        // A10 Server-Side Request Forgery.
        "ssrf" | "ssrf-internal-host" => "A10",
        _ => return None,
    })
}

/// Таблица правил OWASP. Это обычные правила `ScanEngine` (один движок на все
/// сканеры), поэтому многострочные классы потока задаются матчером окна/файла, а не
/// отдельным полем. Категория каждого правила вынесена в [`cat_of`].
/// Таблица правил категорийного набора OWASP. Публична РАДИ ТЕСТА ПОЛНОТЫ: он обязан
/// проверять набор, который реально поставляется, а не удобную для вызова копию. Прежде тест
/// полноты обходил плоский `owasp_scan`, который в реестр не регистрировался, и потому
/// охранял код, отсутствующий в продукте.
pub fn rules() -> Vec<Rule> {
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
            matcher: Matcher::regex(CORS_WILDCARD_RE),
            message: "CORS разрешает любой источник (*) — ограничь доверенные источники allow-list (CWE-942, OWASP A01:2021).",
        },
        // CORS reflection: динамическое отражение заголовка Origin, опаснее «*»
        // вместе с Allow-Credentials. Согласовано с web-вариантом cors-reflect-origin.
        Rule {
            id: "cors-reflect-origin",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(CORS_REFLECT_ORIGIN_RE),
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
        // Запуск подпроцесса через оболочку. Правило перенесено сюда из плоского набора
        // `owasp_scan`, который в реестр не регистрировался и был удалён: до переноса
        // `shell-injection` не мог сработать ни при каком прогоне, хотя присутствовал в
        // карте достоверности и в контрольных списках тестов. Форма `shell=True`
        // (Python `subprocess`) и её эквиваленты в Node передают строку команды оболочке,
        // из-за чего любой недоверенный фрагмент строки становится исполняемым.
        Rule {
            id: "shell-injection",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r"(?i)shell\s*=\s*true|\bexecSync\s*\(|\bchild_process\s*\.\s*exec\s*\(",
            ),
            // Формулировка намеренно НЕ содержит саму искомую форму (флаг оболочки со
            // значением «истина» записан словами): иначе правило совпадает с текстом
            // собственного сообщения, и сканер докладывает находку о себе. Такое
            // самосовпадение по тексту сообщения не отсекается автоматически, поскольку
            // отличить его по форме от присваивания уязвимой константы нельзя.
            message: "Запуск подпроцесса через оболочку (флаг shell в значении истина, вызовы exec без массива аргументов): оболочка сама разбирает строку команды, поэтому любой недоверенный фрагмент этой строки становится исполняемым. Передавай программу и её аргументы отдельным массивом и без оболочки (CWE-78, OWASP A03:2021 Injection).",
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
            matcher: Matcher::regex(SSTI_RE),
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
                r"(?is)(?:(?:requests\.(?:get|post|put|delete|head|patch|request)|httpx\.(?:get|post|put|delete|head|request)|urllib\.request\.urlopen|urlopen|axios(?:\.(?:get|post|put|delete|head|request))?|\bfetch|http\.(?:Get|Post|NewRequest)|HttpClient|WebClient)\s*\(\s*(?:request\.|req\.|params|query|user_input|user\.|\b(?:url|uri|target|link|endpoint|host|dest|destination|location|redirect|callback)\b)|(?:(?:^|[^.\w])(?:request|req)\.|params|query|getParameter|user_input)[^;{]{0,160}?(?:requests\.(?:get|post|put|delete|head|patch|request)|httpx\.(?:get|post|request)|urlopen|axios(?:\.(?:get|post|request))?|\bfetch|http\.(?:Get|Post|NewRequest)|HttpClient|WebClient)\s*\()",
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
        // ───────────────── A02: сравнение секретов не за постоянное время ─────────────
        // Сравнение секрета обычным оператором прекращается на первом несовпавшем байте,
        // поэтому время ответа зависит от того, сколько символов угадано. Это позволяет
        // подобрать токен побайтово, не зная его целиком (CWE-208). Ловим сравнение
        // значений с именами-маркерами секрета; сравнение прочих величин не трогаем.
        Rule {
            id: "timing-unsafe-compare",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)\b(?:if|assert|return|while)\b[^\n;{]{0,60}\b(?:token|secret|signature|hmac|digest|api_?key|password|passwd|otp|nonce)\b\s*(?:==|===|!=|!==)\s*[A-Za-z_$"'`]"#,
            )
            .except(r#"(?i)\b(?:hmac|crypto|hash|secrets|subtle|constant_time|timingsafe)\.\w*(?:compare|equal)"#),
            message: "Секрет сравнивается обычным оператором: время сравнения зависит от числа совпавших символов, что позволяет подобрать значение побайтово (CWE-208, OWASP A02:2021 Cryptographic Failures). Сравнивай за постоянное время (hmac.compare_digest, crypto.timingSafeEqual, subtle.ConstantTimeCompare).",
        },
        // ───────────────── A02: постоянный вектор инициализации ─────────────────
        // Вектор инициализации обязан быть непредсказуемым и НЕ повторяться для одного
        // ключа. Литеральный вектор в коде повторяется всегда, что для режима счётчика и
        // для GCM означает полную потерю конфиденциальности и подделываемость (CWE-329).
        Rule {
            id: "static-iv",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)\b(?:iv|nonce|initialization_?vector)\b\s*[:=]\s*(?:b?["'][^"'\n]{8,}["']|Buffer\.from\s*\(\s*["'][^"'\n]{8,}["']|new\s+byte\s*\[\s*\]\s*\{)"#,
            ),
            message: "Постоянный вектор инициализации: он обязан быть непредсказуемым и не повторяться для одного ключа, иначе шифрование в режимах счётчика и GCM теряет смысл (CWE-329, OWASP A02:2021 Cryptographic Failures). Генерируй вектор случайно на каждое сообщение.",
        },
        // ───────────────── A01: распаковка архива без проверки пути ─────────────────
        // Имя записи в архиве задаёт тот, кто архив прислал. Если склеить его с целевым
        // каталогом без проверки, запись вида `../../etc/cron.d/x` перезапишет чужой файл
        // (CWE-22, «zip slip»). Ловим склейку имени записи с путём назначения.
        Rule {
            id: "archive-path-traversal",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::window_regex(
                r#"(?is)(?:zipfile\.ZipFile|tarfile\.open|ZipInputStream|ZipFile\(|AdmZip|unzipper|tar\.x\()[^;{}]{0,200}?(?:extractall\s*\(|os\.path\.join\s*\(|Path\s*\(|new\s+File\s*\(|path\.join\s*\()"#,
                4,
            )
            .except(r#"(?i)(?:startswith|starts_with|is_relative_to|canonicalize|realpath|resolve\(\)\.starts|normalize)"#),
            message: "Распаковка архива без проверки пути записи: имя внутри архива задаёт отправитель, и запись вида `../../` перезапишет файл вне целевого каталога (CWE-22, OWASP A01:2021 Broken Access Control). Приводи путь к каноническому виду и проверяй, что он лежит внутри каталога назначения.",
        },
        // ───────────────── A05: файл, доступный на запись всем ─────────────────
        Rule {
            id: "world-writable-permissions",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)\b(?:chmod|fchmod|set_mode|setPermissions|from_mode)\s*\(\s*[^)\n]{0,40}?(?:0o?7[0-7]7\b|0o?6[0-7]6\b|["'](?:777|666)["'])"#,
            ),
            message: "Права доступа разрешают запись всем пользователям системы: любой локальный процесс сможет подменить содержимое (CWE-732, OWASP A05:2021 Security Misconfiguration). Выдавай минимально необходимые права (0o600 для секретов, 0o644 для обычных файлов).",
        },
        // ───────────────── A05: предсказуемое имя временного файла ─────────────────
        // Предсказуемое имя во временном каталоге позволяет посторонним заранее создать
        // файл или ссылку по этому пути и получить содержимое либо подменить его (CWE-377).
        Rule {
            id: "insecure-temp-file",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)(?:\btempnam\s*\(|\bmktemp\s*\(|\btmpnam\s*\(|["'`]/tmp/[A-Za-z0-9._-]+["'`]|os\.path\.join\s*\(\s*["'`]/tmp["'`])"#,
            )
            .except(r#"(?i)(?:mkstemp|NamedTemporaryFile|TempDir::new|tempfile::|mkdtemp)"#),
            message: "Предсказуемое имя временного файла: посторонний может заранее занять этот путь символической ссылкой и прочитать или подменить данные (CWE-377, OWASP A05:2021 Security Misconfiguration). Создавай временный файл безопасным средством (mkstemp, NamedTemporaryFile, tempfile).",
        },
        // ───────────────── A08: внешний сценарий без контроля целостности ─────────────
        Rule {
            id: "missing-subresource-integrity",
            severity: Medium,
            exts: &["html", "htm", "vue", "svelte", "jsx", "tsx"],
            matcher: Matcher::regex(
                r#"(?i)<script[^>]+src\s*=\s*["']https?://[^"']+["'][^>]*>"#,
            )
            .except(r#"(?i)integrity\s*="#),
            message: "Внешний сценарий подключён без контроля целостности: подмена на стороне поставщика или посредника выполнится в вашем приложении (CWE-353, OWASP A08:2021 Software and Data Integrity Failures). Добавь атрибуты integrity и crossorigin либо размещай сценарий у себя.",
        },
        // ───────────────── A05: ослабленные заголовки безопасности ─────────────────
        // Определяется НЕ отсутствие заголовка (его по одной строке кода не увидеть), а
        // ЯВНОЕ ослабление: выключенная политика содержимого, разрешение произвольного
        // источника, нулевой срок обязательного шифрования, разрешение встраивания в
        // чужой фрейм. Именно явное ослабление и встречается в реальных настройках, тогда
        // как отсутствие заголовка чаще означает, что его ставит обратный прокси-сервер.
        Rule {
            id: "weak-security-headers",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?ix)
                (?: contentSecurityPolicy \s* : \s* false
                  | helmet \s* \( \s* \{ [^}]{0,80} csp \s* : \s* false
                  | Content-Security-Policy [^\n]{0,120} (?: unsafe-inline | unsafe-eval | default-src \s+ \* )
                  | frame-ancestors \s+ \*
                  | X-Frame-Options \s* [:=] \s* ["']? (?: ALLOWALL | ALLOW-FROM \s+ \* )
                  | X_FRAME_OPTIONS \s* = \s* ["'] ALLOWALL
                  | Strict-Transport-Security [^\n]{0,60} max-age \s* = \s* 0 \b
                  | SECURE_HSTS_SECONDS \s* = \s* 0 \b
                  | SECURE_CONTENT_TYPE_NOSNIFF \s* = \s* False
                  | SECURE_BROWSER_XSS_FILTER \s* = \s* False
                )"#,
            ),
            message: "Заголовки безопасности ответа ослаблены явно: выключенная политика содержимого, разрешение встраивания в чужой фрейм или нулевой срок обязательного шифрования снимают защиту браузера (CWE-693, OWASP A05:2021 Security Misconfiguration). Задай политику содержимого без unsafe-inline, HSTS с ненулевым сроком и запрет встраивания.",
        },
        // ───────────────── A03: инъекция в запрос к документной базе ─────────────────
        // Две реальные формы. Первая: выражение `$where` собирается склейкой или
        // интерполяцией, то есть в базу уходит исполняемый JavaScript с пользовательским
        // фрагментом. Вторая: в запрос передаётся ЦЕЛИКОМ объект запроса, и клиент может
        // прислать вместо строки оператор (`{"$ne": null}`), обойдя условие.
        Rule {
            id: "nosql-injection",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?ix)
                (?: \$where \s* [:=] [^\n]{0,80} (?: \+ | \$\{ | % s | f["'] | \.format \( | \| \| )
                  | \. (?: find | findOne | findAndModify | deleteOne | deleteMany | updateOne | updateMany | count | aggregate )
                    \s* \( \s* (?: req \. (?: body | query | params ) | request \. (?: json | args | form ) )
                    \s* [,)]
                )"#,
            ),
            message: "Инъекция в запрос к документной базе: выражение `$where` собирается из пользовательских данных либо в запрос передаётся объект запроса целиком, и клиент может прислать оператор вместо значения (CWE-943, OWASP A03:2021 Injection). Приводи значения к ожидаемому типу и не передавай тело запроса в базу напрямую.",
        },
        // ───────────────── A09: подделка записей журнала ─────────────────
        // Недоверенное значение попадает в сообщение журнала СКЛЕЙКОЙ или интерполяцией.
        // Перевод строки внутри такого значения создаёт поддельную запись, из-за чего
        // журнал перестаёт быть доказательством, а разбор журналов даёт ложную картину.
        // Параметризованная форма (`logger.info("x=%s", v)`) правилом не затрагивается:
        // в ней значение не попадает в разметку сообщения.
        Rule {
            id: "log-injection",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?ix)
                (?: console \. (?: log | info | warn | error )
                  | logger? \s* \. (?: info | warn | error | debug | trace )
                  | logging \. (?: info | warning | error | debug )
                  | log \. (?: Print | Printf | Info | Warn | Error )
                )
                \s* \( [^)\n]{0,120}
                (?: \+ \s* (?: req | request ) \. | \$\{ \s* (?: req | request ) \.
                  | f["'][^"'\n]{0,80} \{ \s* (?: request | req ) \.
                  | % \s* \( [^)\n]{0,40} request
                )"#,
            )
            .except(r#"(?i)(?:sanitiz|escape|replace\s*\(\s*["']\\n|strip|quote|repr\s*\()"#),
            message: "Недоверенное значение попадает в сообщение журнала склейкой: перевод строки внутри значения создаёт поддельную запись, и журнал перестаёт быть доказательством (CWE-117, OWASP A09:2021 Security Logging and Monitoring Failures). Экранируй переводы строки либо передавай значение отдельным параметром структурного журналирования.",
        },
        // ───────────────── A02: слабые параметры выработки ключа ─────────────────
        // Алгоритм может быть верным, а параметры — нет. Малое число итераций и низкая
        // стоимость хеширования делают перебор дешёвым, короткий ключ RSA не отвечает
        // современным требованиям. Проверяются именно ЧИСЛА в местах их задания.
        Rule {
            id: "weak-kdf-params",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?ix)
                (?: (?: iterations | rounds | work_factor | n_iter ) \s* [:=] \s* \d{1,4} \b
                  | gensalt \s* \( \s* [0-9] \s* \)
                  | bcrypt [^\n]{0,40} (?: rounds | cost ) \s* [:=] \s* [0-9] \b
                  | (?: key_size | keysize | key_length | modulus_size ) \s* [:=] \s* (?: 512 | 768 | 1024 ) \b
                  | (?: RSA | DSA ) \.? generate (?: _private_key )? \s* \( \s* (?: 512 | 768 | 1024 ) \b
                  | PBKDF2 [^\n]{0,60} , \s* \d{1,4} \s* \)
                )"#,
            ),
            message: "Слабые параметры выработки ключа: малое число итераций, низкая стоимость хеширования или короткий ключ делают перебор дешёвым (CWE-916 и CWE-326, OWASP A02:2021 Cryptographic Failures). Для PBKDF2 бери не менее ста тысяч итераций, для bcrypt стоимость не ниже двенадцати, для RSA длину не меньше 2048 бит.",
        },
        // ───────────────── A07: срок действия токена не проверяется ─────────────────
        // Токен без проверки срока действует вечно: украденный однажды, он остаётся
        // пригодным и после смены пароля. Отдельно ловится разбор токена БЕЗ проверки
        // подписи (`decode` вместо `verify`), который часто применяют «чтобы посмотреть
        // содержимое», а затем на этом содержимом принимают решение о доступе.
        Rule {
            id: "jwt-expiration-ignored",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?ix)
                (?: ignoreExpiration \s* : \s* true
                  | verify_exp ["']? \s* [:=] \s* (?: False | false )
                  | verify_expiration ["']? \s* [:=] \s* (?: False | false )
                  | ExpiresAt \s* : \s* nil
                  | \{ [^}\n]{0,60} "exp" \s* : \s* (?: False | false )
                  | SkipClaimsValidation \s* : \s* true
                )"#,
            ),
            message: "Проверка срока действия токена отключена: украденный токен остаётся пригодным неограниченно долго, в том числе после смены пароля (CWE-613, OWASP A07:2021 Identification and Authentication Failures). Проверяй срок действия и задавай его коротким.",
        },
        // ───────────────── A03: инъекция перевода строки в заголовок ответа ─────────────
        // Значение заголовка задаётся недоверенными данными. Перевод строки внутри
        // значения завершает заголовок и позволяет дописать свои заголовки или тело
        // ответа, то есть подделать ответ целиком (разделение ответа, CWE-113).
        Rule {
            id: "header-crlf-injection",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?ix)
                (?: res \. (?: setHeader | header | append ) \s* \(
                  | response \. (?: headers | setHeader ) \s* [\[(]
                  | \w+ \. Header \s* \( \s* \) \s* \. (?: Set | Add ) \s* \(
                  | resp \. headers \s* \. (?: add | append ) \s* \(
                  | setHeader \s* \(
                )
                [^)\n]{0,120}
                (?: req \. (?: query | body | params | headers ) \.
                  | request \. (?: args | form | json | GET | POST | headers ) [\[.]
                  | r \. (?: FormValue | URL \. Query ) \s* \(
                  | getParameter \s* \(
                )"#,
            )
            .except(r#"(?i)(?:sanitiz|escape|replace\s*\(|strip|urlencode|quote_plus|encodeURIComponent)"#),
            message: "Значение заголовка ответа задаётся недоверенными данными: перевод строки внутри значения завершает заголовок и позволяет дописать свои заголовки или тело ответа (CWE-113, OWASP A03:2021 Injection). Убирай управляющие символы из значения либо используй интерфейс, который делает это сам.",
        },
        // ───────────────── A07: идентификатор сессии в адресе страницы ─────────────────
        // Адрес попадает в журналы прокси-серверов, в историю браузера и в заголовок
        // источника перехода при клике на внешнюю ссылку. Идентификатор сессии в нём
        // утекает всеми тремя путями сразу (CWE-598).
        Rule {
            id: "session-id-in-url",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?ix)
                (?: [?&] \s* (?: session_?id | sid | jsessionid | phpsessid | auth_?token | access_?token | api_?key ) \s* =
                  | ; \s* jsessionid \s* =
                )"#,
            )
            .except(r#"(?i)(?:oauth|/authorize|/token\b|client_id=|redirect_uri=)"#),
            message: "Идентификатор сессии или токен передаётся в адресе страницы: адрес попадает в журналы прокси-серверов, в историю браузера и в заголовок источника перехода при клике на внешнюю ссылку (CWE-598, OWASP A07:2021 Identification and Authentication Failures). Передавай его в заголовке или в cookie с флагами Secure и HttpOnly.",
        },
        // ───────────────── A04: ограничение частоты запросов выключено ─────────────────
        // Проверяется именно ЯВНОЕ выключение: отсутствие ограничения по одной строке кода
        // не увидеть, а вот снятое ограничение встречается регулярно и означает, что подбор
        // пароля и перебор кода подтверждения ничем не сдерживаются (CWE-307).
        Rule {
            id: "rate-limit-disabled",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?ix)
                (?: rate_?limit (?: ing )? \s* [:=] \s* (?: false | False | None | null | off | 0 \b )
                  | throttl (?: e | ing ) \s* [:=] \s* (?: false | False | None | null | off )
                  | (?: max | limit ) \s* : \s* 0 \s* , [^\n]{0,40} windowMs
                  | windowMs [^\n]{0,40} (?: max | limit ) \s* : \s* 0 \b
                  | @ RateLimit (?: er )? \s* \( [^)\n]{0,60} (?: disabled | enabled \s* = \s* false )
                  | DEFAULT_THROTTLE_RATES \s* = \s* \{ \s* \}
                )"#,
            ),
            message: "Ограничение частоты запросов выключено явно: подбор пароля, перебор кода подтверждения и исчерпание ресурса ничем не сдерживаются (CWE-307, OWASP A04:2021 Insecure Design). Оставь ограничение хотя бы на входе, восстановлении пароля и подтверждении по одноразовому коду.",
        },
        // ───────────────── A05: трассировка стека в ответе пользователю ─────────────────
        // Трассировка раскрывает пути файловой системы, версии библиотек и внутреннее
        // устройство приложения, чем существенно облегчает подготовку атаки (CWE-209).
        Rule {
            id: "stack-trace-exposed",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?ix)
                (?: (?: res | response | reply ) \s* \.
                    (?: status \s* \( [^)\n]{0,20} \) \s* \. )?
                    (?: send | json | write | end | body )
                    \s* \( [^)\n]{0,120} (?: \. stack \b | traceback \. format_exc | getStackTrace \s* \( | \. printStackTrace )
                  | (?: jsonify | JsonResponse | HttpResponse | make_response ) \s* \( [^)\n]{0,120} traceback \. format_exc
                  | abort \s* \( [^)\n]{0,80} traceback \. format_exc
                )"#,
            ),
            message: "Трассировка стека уходит пользователю: она раскрывает пути файловой системы, версии библиотек и внутреннее устройство приложения, чем облегчает подготовку атаки (CWE-209, OWASP A05:2021 Security Misconfiguration). Пиши подробности в журнал, а пользователю отдавай обезличенное сообщение и идентификатор обращения.",
        },
        // ───────────────── A05: листинг каталога включён ─────────────────
        Rule {
            id: "directory-listing-enabled",
            severity: Medium,
            exts: &[
                "conf", "nginx", "htaccess", "js", "ts", "mjs", "cjs", "go", "py", "yaml", "yml",
            ],
            matcher: Matcher::regex(
                r#"(?ix)
                (?: autoindex \s+ on \b
                  | Options [^\n]{0,60} \+ Indexes \b
                  | serve-?[Ii]ndex \s* \(
                  | (?: directory | listDir | DirectoryListing | browse ) \s* [:=] \s* true \b
                )"#,
            ),
            message: "Листинг каталога включён: посетитель видит полный перечень файлов, включая резервные копии, дампы и черновики, которые не предназначались для публикации (CWE-548, OWASP A05:2021 Security Misconfiguration). Отключи листинг и раздавай только явно разрешённые файлы.",
        },
        // ───────────────── A08: зависимость по ветке без фиксации ─────────────────
        // Ссылка на ветку означает, что содержимое зависимости меняется без изменения
        // манифеста: сегодня собирается одно, завтра другое, а компрометация ветки у
        // поставщика немедленно доезжает до сборки (CWE-1357).
        Rule {
            id: "unpinned-dependency-ref",
            severity: Medium,
            exts: &["json", "toml", "yaml", "yml", "txt", "lock", "gradle", "rb"],
            matcher: Matcher::regex(
                r#"(?ix)
                (?: git \+ [^\s"']+ \# (?: main | master | develop | dev | trunk | HEAD ) \b
                  | git \+ [^\s"']+ @ (?: main | master | develop | dev | trunk | HEAD ) \b
                  | uses \s* : \s* [\w.-]+ / [\w.-]+ @ (?: main | master | develop | dev | latest | HEAD ) \b
                  | branch \s* = \s* ["'] (?: main | master | develop | dev | trunk ) ["']
                  | ref \s* : \s* ["']? (?: main | master | develop | HEAD ) ["']? \s* $
                )"#,
            ),
            message: "Зависимость закреплена за веткой, а не за версией или коммитом: её содержимое меняется без изменения манифеста, поэтому сборка невоспроизводима, а компрометация ветки у поставщика немедленно доезжает до вас (CWE-1357, OWASP A08:2021 Software and Data Integrity Failures). Фиксируй версию или хеш коммита.",
        },
        // ───────────────── Целочисленное переполнение в размере выделения ─────────────
        // Произведение или сумма в аргументе выделения памяти переполняется молча, после
        // чего выделяется буфер меньше нужного, а запись в него выходит за границу
        // (CWE-190, ведущий к CWE-787).
        Rule {
            id: "integer-overflow-alloc",
            severity: High,
            exts: &["c", "cc", "cpp", "h", "hpp", "cxx", "hh", "hxx"],
            matcher: Matcher::regex(
                r#"(?ix)
                (?: malloc | calloc | realloc | alloca | new \s+ \w+ \s* \[ )
                \s* \(? [^;)\n]{0,60} (?: \* | \+ ) [^;)\n]{0,40} \)"#,
            )
            .except(r#"(?i)(?:sizeof\s*\([^)]*\)\s*\*\s*\d+\s*\)|SIZE_MAX|__builtin_mul_overflow|checked_mul|reallocarray)"#),
            message: "Размер выделения вычисляется умножением или сложением: переполнение произойдёт молча, буфер окажется меньше нужного, и запись выйдет за его границу (CWE-190 и CWE-787). Проверяй переполнение явно (__builtin_mul_overflow, reallocarray) либо ограничивай сомножители сверху.",
        },
        // ───────────────── Разыменование результата выделения без проверки ─────────────
        // Функции выделения памяти возвращают нулевой указатель при нехватке памяти.
        // Немедленная запись по нему это аварийное завершение процесса, а в отдельных
        // средах и управляемая запись по нулевому адресу (CWE-476).
        Rule {
            id: "null-deref-after-alloc",
            severity: Medium,
            exts: &["c", "cc", "cpp", "h", "hpp", "cxx", "hh", "hxx"],
            matcher: Matcher::window_regex(
                // Крейт `regex` не поддерживает обратные ссылки, поэтому совпадение имени
                // переменной не выражается напрямую. Связывание обеспечивается узостью
                // окна: разыменование должно стоять непосредственно следующим оператором,
                // а любая проверка на нулевой указатель внутри окна снимает находку.
                r#"(?isx)
                \* \s* \w+ \s* = \s* (?: malloc | calloc | realloc | strdup ) \s* \( [^;\n]{0,80} \) \s* ; \s*\n
                \s* (?: \* \s* \w+ | \w+ \s* (?: \[ | -> ) ) \s* ="#,
                3,
            )
            .except(r#"(?i)(?:if\s*\(\s*!?\s*\w+\s*(?:==\s*NULL|!=\s*NULL|\))|assert\s*\(|ASSERT)"#),
            message: "Результат выделения памяти используется без проверки на нулевой указатель: при нехватке памяти функция вернёт NULL, и первое же обращение завершит процесс (CWE-476). Проверяй возвращённый указатель до использования.",
        },
        // ───────────────── Гонка между проверкой и использованием ─────────────────
        // Между проверкой свойства файла и действием над ним посторонний успевает
        // подменить путь символической ссылкой, и действие выполняется над чужим файлом
        // (CWE-367). Классическая пара «проверил, затем открыл по имени».
        Rule {
            id: "toctou-file-race",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::window_regex(
                r#"(?isx)
                (?: os \.path \.exists | os \.access | \.exists \s* \( | stat \s* \( | \.is_file \s* \( | access \s* \( )
                [^;{}\n]{0,80} \n
                [^;{}\n]{0,120}
                (?: open \s* \( | fopen \s* \( | \.write_text \s* \( | unlink \s* \( | remove \s* \( | chmod \s* \( )"#,
                3,
            )
            .except(r#"(?i)(?:O_NOFOLLOW|O_EXCL|openat|NamedTemporaryFile|mkstemp|with\s+open\s*\(\s*fd)"#),
            message: "Свойство файла проверяется отдельно от действия над ним: между проверкой и использованием посторонний подменит путь символической ссылкой, и действие выполнится над чужим файлом (CWE-367). Открывай файл один раз и работай с дескриптором, а не с именем.",
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
        let mut out = ScanEngine::run(ctx, input, &rules, self.manifest.id, true, WalkMode::Code)?;

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
    use ailc_testkit::TempTree;

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

    // ───────────────────────── T42 ctx.base ─────────────────────────

    #[test]
    fn target_абсолютный_путь_отвергается() {
        let t = TempTree::new("owasp");
        let input = RunInput {
            target: Some("/etc".to_string()),
            ..Default::default()
        };
        let res = OwaspCheck::new().run(&Ctx::new(t.path()), &input);
        assert!(
            res.is_err(),
            "абсолютный target должен отвергаться через ctx.base"
        );
    }

    #[test]
    fn target_с_двумя_точками_отвергается() {
        let t = TempTree::new("owasp");
        let input = RunInput {
            target: Some("../../etc".to_string()),
            ..Default::default()
        };
        let res = OwaspCheck::new().run(&Ctx::new(t.path()), &input);
        assert!(
            res.is_err(),
            "target с .. должен отвергаться через ctx.base"
        );
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
        assert_eq!(
            ids.len(),
            n,
            "идентификаторы правил OWASP должны быть уникальны"
        );
    }

    // ───────────────────────── T19 крипта ─────────────────────────

    #[test]
    fn weak_hash_во_всех_формах() {
        assert!(hits("weak-hash", "h = hashlib.md5(data)"), "прямой md5(");
        assert!(
            hits("weak-hash", "MessageDigest.getInstance(\"MD5\")"),
            "java getInstance MD5"
        );
        assert!(
            hits("weak-hash", "crypto.createHash('sha1')"),
            "node createHash sha1"
        );
        assert!(
            hits("weak-hash", "DigestUtils.md5Hex(s)"),
            "apache DigestUtils"
        );
        assert!(
            hits("weak-hash", "var h = MD5.Create();"),
            "dotnet MD5.Create"
        );
        assert!(
            hits("weak-hash", "d = hashlib.new('md5')"),
            "python hashlib.new"
        );
    }

    #[test]
    fn weak_hash_не_трогает_sha256() {
        assert!(
            !hits("weak-hash", "h = hashlib.sha256(data)"),
            "sha256 не слабый"
        );
        assert!(
            !hits("weak-hash", "getInstance(\"SHA-256\")"),
            "SHA-256 не слабый"
        );
    }

    #[test]
    fn weak_cipher_des_rc4_blowfish() {
        assert!(
            hits(
                "weak-cipher",
                "Cipher.getInstance(\"DES/CBC/PKCS5Padding\")"
            ),
            "DES"
        );
        assert!(hits("weak-cipher", "c = getInstance('3des')"), "3des");
        assert!(
            hits("weak-cipher", "crypto.createCipheriv('rc4', k, iv)"),
            "rc4"
        );
        assert!(hits("weak-cipher", "getInstance('blowfish')"), "blowfish");
        assert!(
            !hits("weak-cipher", "Cipher.getInstance(\"AES/GCM/NoPadding\")"),
            "AES-GCM не слабый"
        );
    }

    #[test]
    fn ecb_mode() {
        assert!(
            hits("ecb-mode", "Cipher.getInstance(\"AES/ECB/PKCS5Padding\")"),
            "java ecb"
        );
        assert!(
            hits("ecb-mode", "cipher = AES.new(key, AES.MODE_ECB)"),
            "pycrypto ecb"
        );
        assert!(
            !hits("ecb-mode", "Cipher.getInstance(\"AES/GCM/NoPadding\")"),
            "gcm не ecb"
        );
    }

    #[test]
    fn hardcoded_crypto_material() {
        assert!(
            hits("hardcoded-crypto-material", "iv = b'1234567890123456'"),
            "статический IV"
        );
        assert!(
            hits("hardcoded-crypto-material", "salt = 'fixed-salt-value'"),
            "статическая соль"
        );
        assert!(
            hits(
                "hardcoded-crypto-material",
                "aes_key = 'hardcoded-secret-key'"
            ),
            "зашитый ключ"
        );
        assert!(
            !hits("hardcoded-crypto-material", "salt = os.urandom(16)"),
            "случайная соль не находка"
        );
    }

    // ───────────────────────── T18 SSRF ─────────────────────────

    #[test]
    fn ssrf_сток_именованный_url_и_окно() {
        assert!(hits("ssrf", "resp = requests.get(target)"), "target");
        assert!(
            hits("ssrf", "u = request.args.get('u')\nresp = requests.get(u)"),
            "окно"
        );
        assert!(
            !hits("ssrf", "requests.get('https://api.example.com')"),
            "доверенный литерал"
        );
    }

    #[test]
    fn ssrf_литеральный_хост() {
        // Метаданные облака — находка даже голым литералом (однозначно подозрительны).
        assert!(
            hits("ssrf-internal-host", "url = 'http://169.254.169.254/'"),
            "imds"
        );
        // Внутренний хост — находка ТОЛЬКО в контексте вызова HTTP-клиента.
        assert!(
            hits("ssrf-internal-host", "requests.get('http://10.0.0.1/')"),
            "rfc1918 в запросе"
        );
        // Голый внутренний литерал (конфиг/дефолт) и публичный адрес — НЕ находка.
        assert!(
            !hits("ssrf-internal-host", "base = 'http://10.0.0.1/'"),
            "конфиг не SSRF"
        );
        assert!(
            !hits("ssrf-internal-host", "u = 'http://8.8.8.8/'"),
            "публичный"
        );
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
        assert!(
            hits("tls-verify-off", "tls.Config{InsecureSkipVerify: true}"),
            "go"
        );
        assert!(
            hits("tls-verify-off", "conn.setHostnameVerifier((h,s)->true)"),
            "java"
        );
        assert!(
            hits("tls-verify-off", "NODE_TLS_REJECT_UNAUTHORIZED = '0'"),
            "node"
        );
        assert!(
            hits("tls-verify-off", "requests.get(u, verify=False)"),
            "python"
        );
        assert!(
            !hits("tls-verify-off", "email_verify=False"),
            "email_verify не TLS"
        );
    }

    // ───────────────────────── T21 JWT ─────────────────────────

    #[test]
    fn jwt_none_формы_и_маркер() {
        assert!(
            hits("jwt-none", "jwt.decode(t, algorithms=['none'])"),
            "массив none"
        );
        assert!(hits("jwt-none", "jwt.decode(t, algorithms=None)"), "None");
        assert!(
            !hits("jwt-none", "compression algorithm: none"),
            "сжатие без JWT-маркера"
        );
    }

    #[test]
    fn jwt_alg_confusion() {
        assert!(
            hits(
                "jwt-alg-confusion",
                "jwt.decode(t, algorithms=['HS256','RS256'])"
            ),
            "смешение"
        );
        assert!(
            !hits("jwt-alg-confusion", "algorithms=['RS256']"),
            "один класс"
        );
    }

    // ───────────────────────── T22 CORS ─────────────────────────

    #[test]
    fn cors_wildcard_через_равно() {
        assert!(
            hits("cors-wildcard", "Access-Control-Allow-Origin = \"*\""),
            "равно"
        );
        assert!(
            hits("cors-wildcard", "Access-Control-Allow-Origin: *"),
            "двоеточие"
        );
    }

    #[test]
    fn cors_reflection_high() {
        assert!(
            hits(
                "cors-reflect-origin",
                "Access-Control-Allow-Origin: $http_origin"
            ),
            "echo"
        );
        assert!(
            hits("cors-reflect-origin", "cors({origin: true})"),
            "origin true"
        );
        assert_eq!(rule_by_id("cors-reflect-origin").severity, Severity::High);
    }

    // ───────────────────────── T23 расширения ─────────────────────────

    #[test]
    fn dangerous_exec_включает_runtime() {
        // T23: класс [^.\w] раньше пропускал .exec(; Runtime/ProcessBuilder покрыты.
        assert!(
            hits("dangerous-exec", "Runtime.getRuntime().exec(cmd)"),
            "runtime"
        );
        assert!(
            hits("dangerous-exec", "new ProcessBuilder(cmd).start()"),
            "processbuilder"
        );
        assert!(hits("dangerous-exec", "os.system(c)"), "os.system");
        // Голые eval/exec ВЫВЕДЕНЫ из паттерна в потоковый сток sast/taint-dynamic-exec:
        // построчный матч флагует eval(bar) и там, где ввод не доходит до стока. Паттерн
        // оставляет только исполнители команд ОС с самодостаточно подозрительной формой.
        assert!(
            !hits("dangerous-exec", "eval(code)"),
            "eval без потока — не паттерн"
        );
        assert!(
            !hits("dangerous-exec", "exec(code)"),
            "exec без потока — не паттерн"
        );
        // Бенайн regex.exec не должен ловиться (точка перед exec, не Runtime).
        assert!(
            !hits("dangerous-exec", "const m = re.exec(input)"),
            "regex.exec бенайн"
        );
    }

    #[test]
    fn xss_sink_границы_слова() {
        assert!(hits("xss-sink", "el.innerHTML = data"), "innerHTML");
        assert!(hits("xss-sink", "el.outerHTML = data"), "outerHTML");
        assert!(
            hits("xss-sink", "el.insertAdjacentHTML('beforeend', data)"),
            "insertAdjacentHTML"
        );
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
        assert!(
            hits("insecure-deser", "new BinaryFormatter().Deserialize(s)"),
            "dotnet"
        );
    }

    // ───────────────────────── T25 матрица ─────────────────────────

    #[test]
    fn матрица_не_печатает_чисто_для_пустой_категории() {
        let t = TempTree::new("owasp");
        // Файл без уязвимостей по нашим правилам, но валидный исходник.
        t.write("ok.py", "def add(a, b):\n    return a + b\n");
        let out = OwaspCheck::new()
            .run(&Ctx::new(t.path()), &RunInput::default())
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
        let t = TempTree::new("owasp");
        t.write("vuln.py", "import hashlib\nh = hashlib.md5(data)\n");
        let out = OwaspCheck::new()
            .run(&Ctx::new(t.path()), &RunInput::default())
            .unwrap();
        assert!(
            out.findings.iter().any(|f| f.rule == "weak-hash"),
            "должна быть находка weak-hash"
        );
        assert!(out.summary.contains("HIGH="), "итог содержит счётчик HIGH");
        let joined = out.records.join("\n");
        assert!(
            joined.contains("A02"),
            "матрица отмечает категорию A02 с находкой"
        );
    }

    #[test]
    fn пустой_проект_честно_пропускается() {
        let t = TempTree::new("owasp");
        let out = OwaspCheck::new()
            .run(&Ctx::new(t.path()), &RunInput::default())
            .unwrap();
        assert!(
            out.skipped.is_some(),
            "нет исходников = честный пропуск, не пустая матрица"
        );
    }
    // ── Новые классы правил: на каждое правило ДВА теста — срабатывание и молчание.
    // Правило без второго теста не принимается: для этого продукта точность важнее
    // полноты, а без контроля молчания новое правило легко становится источником шума.

    #[test]
    fn timing_unsafe_compare_ловит_и_молчит() {
        assert!(hits(
            "timing-unsafe-compare",
            "if (token == expected) { grant(); }"
        ));
        assert!(hits(
            "timing-unsafe-compare",
            "if signature != provided:\n    abort()"
        ));
        assert!(
            !hits(
                "timing-unsafe-compare",
                "if hmac.compare_digest(signature, provided):\n    ok()"
            ),
            "сравнение за постоянное время безопасно"
        );
        assert!(
            !hits("timing-unsafe-compare", "if (count == 0) { return; }"),
            "сравнение обычных величин правилом не затрагивается"
        );
    }

    #[test]
    fn static_iv_ловит_и_молчит() {
        assert!(hits("static-iv", r#"let iv = "0123456789abcdef";"#));
        assert!(hits("static-iv", r#"nonce = b"fixednonce12""#));
        assert!(
            !hits("static-iv", "let iv = random_bytes(16);"),
            "случайный вектор инициализации корректен"
        );
        assert!(
            !hits("static-iv", r#"let ivan = "Иван";"#),
            "похожее имя переменной не является вектором инициализации"
        );
    }

    #[test]
    fn archive_path_traversal_ловит_и_молчит() {
        assert!(hits(
            "archive-path-traversal",
            "with zipfile.ZipFile(src) as z:\n    z.extractall(dest)\n"
        ));
        assert!(
            !hits(
                "archive-path-traversal",
                "with zipfile.ZipFile(src) as z:\n    for m in z.namelist():\n        p = os.path.realpath(os.path.join(dest, m))\n        if not p.startswith(dest):\n            raise ValueError('обход каталога')\n"
            ),
            "проверка принадлежности каталогу снимает риск"
        );
        assert!(
            !hits("archive-path-traversal", "path.join(base, name)"),
            "склейка путей вне распаковки архива правилом не затрагивается"
        );
    }

    #[test]
    fn world_writable_permissions_ловит_и_молчит() {
        assert!(hits("world-writable-permissions", "os.chmod(path, 0o777)"));
        assert!(hits("world-writable-permissions", r#"fs.chmod(p, "666")"#));
        assert!(
            !hits("world-writable-permissions", "os.chmod(path, 0o600)"),
            "минимальные права корректны"
        );
        assert!(
            !hits("world-writable-permissions", "let mode = 0o777;"),
            "константа без выдачи прав не является находкой"
        );
    }

    #[test]
    fn insecure_temp_file_ловит_и_молчит() {
        assert!(hits("insecure-temp-file", r#"path = "/tmp/upload.dat""#));
        assert!(hits("insecure-temp-file", "f = tempnam(NULL, \"pre\");"));
        assert!(
            !hits(
                "insecure-temp-file",
                "with tempfile.NamedTemporaryFile() as f:\n    f.write(data)"
            ),
            "безопасное создание временного файла корректно"
        );
        assert!(
            !hits("insecure-temp-file", "let dir = TempDir::new()?;"),
            "безопасный временный каталог корректен"
        );
    }

    #[test]
    fn missing_subresource_integrity_ловит_и_молчит() {
        assert!(hits(
            "missing-subresource-integrity",
            r#"<script src="https://cdn.example.com/lib.js"></script>"#
        ));
        assert!(
            !hits(
                "missing-subresource-integrity",
                r#"<script src="https://cdn.example.com/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>"#
            ),
            "контроль целостности задан"
        );
        assert!(
            !hits(
                "missing-subresource-integrity",
                r#"<script src="/static/app.js"></script>"#
            ),
            "собственный сценарий подменить со стороны нельзя"
        );
    }
    #[test]
    fn weak_security_headers_ловит_и_молчит() {
        assert!(hits(
            "weak-security-headers",
            "app.use(helmet({ contentSecurityPolicy: false }))"
        ));
        assert!(hits("weak-security-headers", "SECURE_HSTS_SECONDS = 0"));
        assert!(hits(
            "weak-security-headers",
            "res.setHeader('Content-Security-Policy', \"default-src 'self'; script-src 'unsafe-inline'\")"
        ));
        assert!(
            !hits("weak-security-headers", "app.use(helmet())"),
            "включённая защита корректна"
        );
        assert!(
            !hits("weak-security-headers", "SECURE_HSTS_SECONDS = 31536000"),
            "ненулевой срок обязательного шифрования корректен"
        );
    }

    #[test]
    fn nosql_injection_ловит_и_молчит() {
        assert!(hits(
            "nosql-injection",
            r#"db.users.find({ $where: "this.name == '" + name + "'" })"#
        ));
        assert!(hits("nosql-injection", "User.findOne(req.body)"));
        assert!(
            !hits(
                "nosql-injection",
                "User.findOne({ name: String(req.body.name) })"
            ),
            "приведение к типу и явное поле безопасны"
        );
        assert!(
            !hits("nosql-injection", "db.users.find({ active: true })"),
            "постоянный запрос безопасен"
        );
    }

    #[test]
    fn log_injection_ловит_и_молчит() {
        assert!(hits(
            "log-injection",
            r#"logger.info("вход: " + req.query.user)"#
        ));
        assert!(hits(
            "log-injection",
            r#"console.log(`вход: ${req.body.name}`)"#
        ));
        assert!(
            !hits("log-injection", r#"logger.info("вход: %s", user)"#),
            "параметризованная запись безопасна"
        );
        assert!(
            !hits(
                "log-injection",
                r#"logger.info("вход: " + sanitize(req.query.user))"#
            ),
            "экранирование снимает риск"
        );
    }

    #[test]
    fn weak_kdf_params_ловит_и_молчит() {
        assert!(hits(
            "weak-kdf-params",
            "kdf = PBKDF2(password, salt, iterations=1000)"
        ));
        assert!(hits(
            "weak-kdf-params",
            "hashed = bcrypt.hashpw(pw, bcrypt.gensalt(4))"
        ));
        assert!(hits(
            "weak-kdf-params",
            "key = rsa.generate_private_key(key_size=1024)"
        ));
        assert!(
            !hits(
                "weak-kdf-params",
                "kdf = PBKDF2(password, salt, iterations=210000)"
            ),
            "достаточное число итераций корректно"
        );
        assert!(
            !hits(
                "weak-kdf-params",
                "key = rsa.generate_private_key(key_size=4096)"
            ),
            "достаточная длина ключа корректна"
        );
    }

    #[test]
    fn jwt_expiration_ignored_ловит_и_молчит() {
        assert!(hits(
            "jwt-expiration-ignored",
            "jwt.verify(token, secret, { ignoreExpiration: true })"
        ));
        assert!(hits(
            "jwt-expiration-ignored",
            r#"jwt.decode(token, key, options={"verify_exp": False})"#
        ));
        assert!(
            !hits("jwt-expiration-ignored", "jwt.verify(token, secret)"),
            "проверка по умолчанию корректна"
        );
        assert!(
            !hits(
                "jwt-expiration-ignored",
                r#"jwt.decode(token, key, options={"verify_exp": True})"#
            ),
            "явно включённая проверка корректна"
        );
    }
    #[test]
    fn header_crlf_injection_ловит_и_молчит() {
        assert!(hits(
            "header-crlf-injection",
            "res.setHeader('Location', req.query.next)"
        ));
        assert!(hits(
            "header-crlf-injection",
            "w.Header().Set(\"X-User\", r.FormValue(\"u\"))"
        ));
        assert!(
            !hits(
                "header-crlf-injection",
                "res.setHeader('Location', encodeURIComponent(req.query.next))"
            ),
            "экранирование снимает риск"
        );
        assert!(
            !hits(
                "header-crlf-injection",
                "res.setHeader('Cache-Control', 'no-store')"
            ),
            "постоянное значение заголовка безопасно"
        );
    }

    #[test]
    fn session_id_in_url_ловит_и_молчит() {
        assert!(hits(
            "session-id-in-url",
            r#"url = "/panel?session_id=" + sid"#
        ));
        assert!(hits(
            "session-id-in-url",
            r#"redirect("/app;jsessionid=" + id)"#
        ));
        assert!(
            !hits("session-id-in-url", r#"url = "/panel?page=2&sort=name""#),
            "обычные параметры адреса безопасны"
        );
        assert!(
            !hits(
                "session-id-in-url",
                r#"url = "https://id.example.org/authorize?client_id=abc&redirect_uri=/cb&access_token=x""#
            ),
            "поток авторизации по протоколу OAuth правилом не затрагивается"
        );
    }

    #[test]
    fn rate_limit_disabled_ловит_и_молчит() {
        assert!(hits(
            "rate-limit-disabled",
            "const opts = { rateLimit: false };"
        ));
        assert!(hits("rate-limit-disabled", "THROTTLING = None"));
        assert!(
            !hits(
                "rate-limit-disabled",
                "const opts = { rateLimit: { max: 5 } };"
            ),
            "заданное ограничение корректно"
        );
        assert!(
            !hits("rate-limit-disabled", "limiter = RateLimiter(max_calls=10)"),
            "включённый ограничитель корректен"
        );
    }

    #[test]
    fn stack_trace_exposed_ловит_и_молчит() {
        assert!(hits(
            "stack-trace-exposed",
            "res.status(500).send(err.stack)"
        ));
        assert!(hits(
            "stack-trace-exposed",
            "return jsonify({\"error\": traceback.format_exc()})"
        ));
        assert!(
            !hits(
                "stack-trace-exposed",
                "res.status(500).send('внутренняя ошибка')"
            ),
            "обезличенное сообщение безопасно"
        );
        assert!(
            !hits(
                "stack-trace-exposed",
                "logger.error(traceback.format_exc())"
            ),
            "трассировка в журнале, а не в ответе, безопасна"
        );
    }

    #[test]
    fn directory_listing_enabled_ловит_и_молчит() {
        assert!(hits("directory-listing-enabled", "        autoindex on;"));
        assert!(hits(
            "directory-listing-enabled",
            "app.use(serveIndex('/public'))"
        ));
        assert!(
            !hits("directory-listing-enabled", "        autoindex off;"),
            "выключенный листинг корректен"
        );
        assert!(
            !hits(
                "directory-listing-enabled",
                "app.use(express.static('/public'))"
            ),
            "раздача файлов без листинга корректна"
        );
    }

    #[test]
    fn unpinned_dependency_ref_ловит_и_молчит() {
        assert!(hits(
            "unpinned-dependency-ref",
            r#"    "lib": "git+https://github.com/acme/lib.git#main","#
        ));
        assert!(hits(
            "unpinned-dependency-ref",
            "      uses: actions/checkout@main"
        ));
        assert!(hits(
            "unpinned-dependency-ref",
            r#"acme = { git = "https://github.com/acme/lib", branch = "master" }"#
        ));
        assert!(
            !hits("unpinned-dependency-ref", "      uses: actions/checkout@v4"),
            "закрепление за версией корректно"
        );
        assert!(
            !hits(
                "unpinned-dependency-ref",
                r#"acme = { git = "https://github.com/acme/lib", rev = "9f2c1ab" }"#
            ),
            "закрепление за коммитом корректно"
        );
    }
    #[test]
    fn integer_overflow_alloc_ловит_и_молчит() {
        assert!(hits("integer-overflow-alloc", "buf = malloc(n * width);"));
        assert!(hits(
            "integer-overflow-alloc",
            "p = realloc(p, count + extra);"
        ));
        assert!(
            !hits("integer-overflow-alloc", "buf = malloc(len);"),
            "постоянный размер без арифметики безопасен"
        );
        assert!(
            !hits("integer-overflow-alloc", "buf = reallocarray(p, n, width);"),
            "функция с проверкой переполнения безопасна"
        );
    }

    #[test]
    fn null_deref_after_alloc_ловит_и_молчит() {
        assert!(hits(
            "null-deref-after-alloc",
            "char *p = malloc(n);\n*p = 'x';\n"
        ));
        assert!(
            !hits(
                "null-deref-after-alloc",
                "char *p = malloc(n);\nif (p == NULL) return -1;\n*p = 'x';\n"
            ),
            "проверка на нулевой указатель снимает риск"
        );
    }

    #[test]
    fn toctou_file_race_ловит_и_молчит() {
        assert!(hits(
            "toctou-file-race",
            "if os.path.exists(path):\n    open(path, 'w').write(data)\n"
        ));
        assert!(
            !hits(
                "toctou-file-race",
                "with tempfile.NamedTemporaryFile() as f:\n    f.write(data)\n"
            ),
            "безопасное создание файла снимает гонку"
        );
        assert!(
            !hits("toctou-file-race", "data = open(path).read()\n"),
            "открытие без предварительной проверки гонки не создаёт"
        );
    }
}
