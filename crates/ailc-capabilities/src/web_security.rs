//! Web/API security-capability — корзина «детектируется в коде» поверх общего
//! `ScanEngine`. Тонкие конфиги (таблицы правил), без новой логики обхода/матча.
//!
//! ПРИНЦИП тот же, что и в корне крейта: инструмент = таблица правил. Паттерны
//! СТРОГИЕ — требуют реальной формы вызова (sink + источник недоверенного ввода на
//! строке либо в пределах окна, конкретный флаг/заголовок), чтобы не ловить
//! случайные вхождения слова. Каждое сообщение несёт ПРОВЕРЕННУЮ ссылку на класс
//! слабости (CWE) и, где уместно, рубрику OWASP.
//!
//! Многострочный охват. Для классов потока данных (SSRF, открытый редирект, обход
//! пути) источник недоверенного ввода и сток-вызов нередко стоят на соседних
//! строках из-за переноса аргумента форматтером. Такие правила используют
//! `Matcher::window_regex`, поэтому связывают источник и сток в пределах окна строк.
//! Литеральные признаки (опасный хост SSRF, флаг отключения TLS, заголовок CORS)
//! остаются построчными, так как присутствуют на одной строке.
//!
//! Анти-дублирование: XSS-вставки разметки уже в `security.scan/injection`,
//! слабая крипта — в `security.scan/owasp`; здесь они НЕ повторяются. SSRF, JWT,
//! CORS, TLS приведены к единому более полному паттерну с owasp-вариантом.

use ailc_contracts::{Family, Severity};
use ailc_core::engines::scan::{Matcher, Rule, SOURCE_CODE};
use ailc_core::registry::Registry;

use crate::{scan_manifest, ScanCapability};

/// Признак SSRF по внутреннему адресу. ЕДИНЫЙ источник истины для правила
/// `ssrf-internal-host`, которое исторически продублировано в `owasp.rs` и
/// `web_security.rs`; поведение синхронизируется через эту константу, а двойной счёт
/// убирает дедуп находок в `scan_all`. Точность вместо шума: адреса облачных метаданных
/// и обфусцированные формы фиксируются как литерал (однозначно подозрительны), а обычный
/// внутренний или RFC1918 хост признаётся находкой ТОЛЬКО рядом с вызовом HTTP-клиента
/// (fetch/axios/requests/http.Get/curl и т.п.). Иначе это конфигурационный дефолт, строка
/// лога, список CORS или база для разбора URL, а не SSRF, и фиксировать это нельзя.
pub(crate) const SSRF_INTERNAL_HOST_RE: &str = r"(?is)(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|0x[Aa]9[Ff][Ee][Aa]9[Ff][Ee]|\b2852039166\b|\b0177\.0\.0\.1\b)|(?:fetch|axios|got|http\.get|http\.request|https\.get|https\.request|requests\.|urlopen|urllib|httpx|HttpClient|WebClient|RestTemplate|HttpURLConnection|URLConnection|Net::HTTP|open-uri|Faraday|file_get_contents|curl_exec|curl_init|GuzzleHttp|reqwest|hyper|URLSession|Alamofire|http\.Client|http\.NewRequest|client\.Do|\.get\(|\.post\(|\.request\()[^;{]{0,160}(?:127\.0\.0\.1|\blocalhost\b|\b0\.0\.0\.0\b|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})";

// ───────────────────────── security.scan/web ─────────────────────────

/// Типовые web-уязвимости, выразимые в коде: SSRF (включая опасный литеральный
/// хост: облачные метаданные, loopback, RFC1918, decimal/hex/octal IP), открытый
/// редирект, обход пути (path traversal), SSTI (Jinja/Twig/Freemarker/ERB/
/// Handlebars/Thymeleaf и env.from_string), XXE (явное включение сущностей и
/// небезопасные по умолчанию парсеры), небезопасная десериализация (pickle/marshal/
/// ObjectInputStream/unserialize/Marshal.load/BinaryFormatter), отключённая проверка
/// TLS-сертификата (verify/HostnameVerifier/X509TrustManager/ServerCertificate
/// ValidationCallback/NODE_TLS_REJECT_UNAUTHORIZED), небезопасные cookie,
/// CORS-wildcard и reflection-CORS, выключенный CSRF. Sink + источник недоверенного
/// ввода на строке или в пределах окна строк.
pub fn web_scan() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "security.scan/web",
            Family::Security,
            "Web-уязвимости в коде: SSRF (в том числе опасный литеральный хост и облачные метаданные), открытый редирект, обход пути (path traversal), SSTI по многим шаблонизаторам, XXE (явные сущности и небезопасные по умолчанию парсеры), небезопасная десериализация по многим экосистемам, отключённая проверка TLS-сертификата (Python/Java/.NET/Node/cURL), небезопасные cookie, CORS-wildcard и reflection-CORS, выключенный CSRF. Покрытие паттерновое: связывает источник и сток в пределах строки или окна строк, ручной обзор остаётся желательным.",
        ),
        web_rules(),
    )
}

/// Таблица правил `security.scan/web`. Вынесена отдельно, чтобы тесты могли брать
/// конкретное правило по идентификатору и проверять его матчер без обхода файлов.
fn web_rules() -> Vec<Rule> {
    use Severity::{High, Medium};
    vec![
        // ── SSRF: HTTP-клиент, чей URL берётся из недоверенного ввода ──────────
        // Две формы. Первая: клиент вызван прямо с аргументом-переменной типичного
        // URL-имени (url/uri/target/link/endpoint/host/dest/location/redirect/
        // callback) или явным недоверенным выражением (request./req./params/query/
        // user_input) на той же строке. Вторая (оконная): явный недоверенный
        // источник присвоен переменной на одной строке, а клиент вызван на соседней,
        // что связывает источник и сток через перенос. Клиенты покрывают requests/
        // httpx/aiohttp/urllib/axios/fetch/http.Get/HttpClient/OkHttp/WebClient.
        Rule {
            id: "ssrf-sink",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::window_regex(
                // Группа клиента, далее в его аргументах либо явный недоверенный
                // источник, либо переменная URL-имени; ИЛИ оконная форма «явный
                // источник ... клиент».
                r"(?is)(?:(?:requests\.(?:get|post|put|delete|head|patch|request)|httpx\.(?:get|post|put|delete|head|request|client)|aiohttp\.[A-Za-z_]*\.(?:get|post|request)|urllib\.request\.urlopen|urlopen|axios(?:\.(?:get|post|put|delete|head|request))?|\bfetch|http\.(?:Get|Post|NewRequest)|HttpClient|OkHttpClient|WebClient)\s*\(\s*(?:request\.|req\.|params|query|user_input|user\.|\b(?:url|uri|target|link|endpoint|host|dest|destination|location|redirect|next|callback)\b)|(?:request\.|req\.|params|query|getParameter|user_input)[^;{]{0,160}?(?:requests\.(?:get|post|put|delete|head|patch|request)|httpx\.(?:get|post|request)|urlopen|axios(?:\.(?:get|post|request))?|\bfetch|http\.(?:Get|Post|NewRequest)|HttpClient|WebClient)\s*\()",
                3,
            ),
            message: "SSRF — запрос по управляемому пользователем URL (CWE-918, OWASP A10:2021 SSRF). Валидируйте хост по allow-list, запретите внутренние и метаданные-адреса.",
        },
        // SSRF по опасному ЛИТЕРАЛЬНОМУ хосту: облачные метаданные, loopback,
        // 0.0.0.0, RFC1918, а также обходные представления адреса (decimal/hex/
        // octal IP). Такой адрес в коде HTTP-клиента почти всегда означает доступ к
        // внутреннему ресурсу. Эти представления невозможно поймать через taint, их
        // ловит отдельный литеральный признак.
        Rule {
            id: "ssrf-internal-host",
            severity: High,
            exts: SOURCE_CODE,
            // Точность вместо шума (см. SSRF_INTERNAL_HOST_RE): метаданные облака и
            // обфусцированные формы ловим литералом, обычный внутренний хост — только в
            // окне с вызовом HTTP-клиента, чтобы не флагать конфиги, логи и базы URL.
            matcher: Matcher::window_regex(SSRF_INTERNAL_HOST_RE, 3),
            // ailc:ignore[ssrf-internal-host] — адрес в ТЕКСТЕ СООБЩЕНИЯ правила, не живой вызов
            message: "SSRF — обращение к внутреннему/метаданным-адресу из кода HTTP-клиента (CWE-918, OWASP A10:2021 SSRF). Облачные метаданные (169.254.169.254), loopback и RFC1918 недоступны извне; обходные формы (decimal/hex/octal IP) также блокируйте.",
        },
        // ── Открытый редирект: переход по адресу из ввода ─────────────────────
        Rule {
            id: "open-redirect",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::window_regex(
                r"(?is)(?:\bredirect|sendRedirect|res\.redirect|HttpResponseRedirect|RedirectResponse|header\s*\(\s*[\x22']Location)\s*\(?[^;{]*?(?:request\.|req\.|params|query|getParameter|\$_GET|\$_REQUEST|\buser\b)",
                3,
            ),
            message: "Открытый редирект — переход по адресу из ввода (CWE-601, OWASP A01:2021). Разрешайте только относительные пути или allow-list доменов.",
        },
        // ── Обход пути: открытие/отправка файла по имени из запроса ───────────
        // Стоки расширены: open/fopen/readfile/read_file/sendfile/send_file/
        // sendFile/readFileSync/File.new/Files.read. Источники: request./req./
        // params/query/getParameter/@PathVariable/$_GET/user_input, а также явный
        // признак обхода в литерале (../ и его URL-кодировка %2e%2e).
        Rule {
            id: "path-traversal",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::window_regex(
                r"(?is)\b(?:open|fopen|readfile|read_file|sendfile|send_file|sendFile|readFileSync|createReadStream|File\.(?:new|open|read)|Files\.(?:read|newInputStream)|new\s+File)\s*\([^;{]*?(?:request\.|req\.|params|query|getParameter|@PathVariable|\$_GET|\$_REQUEST|user_input|\.\./|%2e%2e)",
                3,
            ),
            message: "Обход пути (path traversal) — путь к файлу из ввода (CWE-22, OWASP A01:2021). Канонизируйте путь и держите внутри разрешённого каталога.",
        },
        // ── SSTI: рендер шаблона из недоверенной строки по многим движкам ─────
        // Flask render_template_string, Jinja Environment.from_string/Template(...),
        // Twig createTemplate, Freemarker new Template, ERB.new, Handlebars.compile,
        // Thymeleaf process с inline-выражением, Velocity evaluate.
        Rule {
            id: "ssti",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r"(?i)\brender_template_string\s*\(|\b(?:env(?:ironment)?|jinja2?\.Environment\(\))\.from_string\s*\(|\bTemplate\s*\([^)]*\)\s*\.\s*render\s*\(|\bTwig[A-Za-z]*->createTemplate\s*\(|\bnew\s+Template\s*\(|\bERB\.new\s*\(|\bHandlebars\.compile\s*\(|\bvelocityEngine\.evaluate\s*\(",
            ),
            message: "Server-Side Template Injection — рендер шаблона из строки (CWE-1336, OWASP A03:2021). Не подставляйте ввод в тело шаблона; используйте контекстные переменные.",
        },
        // ── XXE: явное включение внешних сущностей ────────────────────────────
        Rule {
            id: "xxe",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r"(?i)resolve_entities\s*=\s*True|\bno_network\s*=\s*False|noent\s*=\s*True|external-general-entities[^\n]*true|external-parameter-entities[^\n]*true|feature_external_(?:ges|pes)\s*,\s*True|setFeature\s*\([^)]*external[^)]*,\s*True|setExpandEntityReferences\s*\(\s*true|XMLConstants\.[A-Z_]*\s*,\s*false",
            ),
            message: "XXE — XML-парсер с включёнными внешними сущностями (CWE-611, OWASP A05:2021). Отключите DTD/внешние сущности (defusedxml, FEATURE_SECURE_PROCESSING, disallow-doctype-decl).",
        },
        // XXE по умолчанию: Java-фабрика парсера создана без защитных настроек.
        // DocumentBuilderFactory/SAXParserFactory/XMLInputFactory/SAXReader без
        // последующего setFeature(disallow-doctype-decl). Эвристика по факту создания
        // фабрики небезопасного класса, поэтому достоверность Pattern.
        //
        // lxml `etree.parse/fromstring/XML` УБРАН: современный lxml по умолчанию НЕ
        // разворачивает внешние сущности, поэтому голый etree.parse это не XXE. Прежний
        // паттерн садился на lxml.etree.* в файлах XPath-инъекции и ложно метил их как
        // XXE, а настоящие XXE на `xml.sax` с feature_external_ges=True пропускал.
        // Реальное включение сущностей (lxml resolve_entities=True, SAX
        // feature_external_ges=True) ловит правило `xxe` выше.
        Rule {
            id: "xxe-parser-default",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r"(?i)DocumentBuilderFactory\.newInstance\s*\(|SAXParserFactory\.newInstance\s*\(|XMLInputFactory\.newInstance\s*\(|new\s+SAXReader\s*\(|new\s+XMLReader\s*\(",
            ),
            message: "XXE — XML-парсер с настройками по умолчанию (CWE-611, OWASP A05:2021). По умолчанию DTD/внешние сущности часто включены; задайте disallow-doctype-decl (Java) или используйте defusedxml (Python).",
        },
        // ── Небезопасная десериализация по многим экосистемам ─────────────────
        // pickle/cPickle/marshal (Python), ObjectInputStream.readObject (Java),
        // unserialize (PHP), Marshal.load (Ruby), BinaryFormatter.Deserialize и
        // NetDataContractSerializer (.NET), node-serialize unserialize.
        Rule {
            id: "insecure-deserialize",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r"(?i)\b(?:pickle|cPickle)\.loads?\s*\(|\bmarshal\.loads?\s*\(|\bObjectInputStream\b|\.readObject\s*\(|\bunserialize\s*\(|\bMarshal\.load\s*\(|\bBinaryFormatter\b|\bNetDataContractSerializer\b|\bLosFormatter\b",
            ),
            message: "Небезопасная десериализация недоверенных данных — выполнение кода (CWE-502, OWASP A08:2021). Используйте JSON или подписанные данные; для Java/.NET примените allow-list типов.",
        },
        // yaml.load без SafeLoader: regex не умеет «отрицание» (lookahead),
        // поэтому предикат — флагуем yaml.load, если в строке нет Safe-загрузчика.
        Rule {
            id: "unsafe-yaml-load",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::Predicate(|l| {
                l.contains("yaml.load(")
                    && !l.contains("Safe")
                    && !l.contains("SafeLoader")
                    && !l.contains("Loader=")
            }),
            message: "yaml.load без SafeLoader — выполнение кода из YAML (CWE-502, OWASP A08:2021). Используйте yaml.safe_load.",
        },
        // ── Опасное исполнение команды ОС (Runtime/ProcessBuilder) ────────────
        // owasp.rs ловит eval/exec/os.system; здесь покрываем Java-стоки
        // Runtime.getRuntime().exec и new ProcessBuilder, которые owasp-класс
        // [^.\w] перед exec пропускает (точка перед exec).
        Rule {
            id: "command-exec-runtime",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r"(?i)\bRuntime\b[^\n]{0,40}\.exec\s*\(|\bgetRuntime\s*\(\s*\)\s*\.exec\s*\(|\bnew\s+ProcessBuilder\s*\(",
            ),
            message: "Исполнение команды ОС (Runtime.exec/ProcessBuilder) (CWE-78, OWASP A03:2021). Не собирайте команду из недоверенного ввода; передавайте аргументы массивом, а не строкой через оболочку.",
        },
        // ── Отключённая проверка TLS-сертификата (многие стеки) ───────────────
        // Граница слова перед verify убирает ложные срабатывания вида
        // email_verify=False. Добавлены Java (HostnameVerifier-лямбда true, пустой
        // checkServerTrusted, ALLOW_ALL_HOSTNAME_VERIFIER), .NET (ServerCertificate
        // ValidationCallback), Node (NODE_TLS_REJECT_UNAUTHORIZED=0). Разделитель
        // равно и двоеточие охвачены классом символов.
        Rule {
            id: "tls-verify-disabled",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)\bverify\s*=\s*False|InsecureSkipVerify\s*[:=]\s*true|rejectUnauthorized\s*[:=]\s*false|CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:0|false)|ssl\._create_unverified_context|setHostnameVerifier\s*\(|HostnameVerifier[^\n]{0,60}return\s+true|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|checkServerTrusted\s*\([^)]*\)\s*(?:throws[^\{]*)?\{\s*\}|ServerCertificateValidationCallback\s*[:=+]|ServicePointManager\.ServerCertificateValidationCallback|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0|TrustAllCerts|trustAllCerts"#,
            ),
            message: "Проверка TLS-сертификата отключена (CWE-295, OWASP A07:2021). Не отключайте проверку сертификата/имени хоста в проде — это открывает MITM.",
        },
        // ── CORS: разрешён любой источник (wildcard) ──────────────────────────
        // owasp-вариант приведён сюда: класс символов включает «равно», поэтому
        // Access-Control-Allow-Origin = "*" тоже ловится.
        Rule {
            id: "cors-wildcard",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)access-control-allow-origin["'\s:=]+\*|cors\s*\([^)\n]*origins?\s*[:=]\s*["']\*|AllowAllOrigins\s*[:=]\s*true|allowedOrigins?\s*[:(=]\s*["']\*"#,
            ),
            message: "CORS разрешает любой источник (*) (CWE-942, OWASP A05:2021). Перечислите доверенные домены явным allow-list.",
        },
        // CORS reflection: заголовок Origin отражается обратно (динамически), что
        // эквивалентно «*», но в сочетании с Allow-Credentials позволяет кражу с
        // учётными данными. Покрыты echo Origin (request/req/origin/$http_origin),
        // cors({origin:true}), Spring @CrossOrigin без списка, Go-рефлексия.
        // Severity High: reflection с credentials опаснее простого wildcard.
        Rule {
            id: "cors-reflect-origin",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)access-control-allow-origin["'\s:=]+(?:request|req|origin|\$http_origin|\$\{?origin)|cors\s*\([^)\n]*origin\s*:\s*true|@CrossOrigin\b|setHeader\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*(?:request|req|origin)"#,
            ),
            message: "CORS отражает заголовок Origin (CWE-942/CWE-346, OWASP A05:2021). Динамическое отражение Origin вместе с Allow-Credentials:true позволяет кражу данных с учётными данными; используйте статический allow-list.",
        },
        // ── Небезопасная кука: secure/httpOnly выключены ──────────────────────
        // Ловим КОДОВУЮ форму ключевого аргумента/опции `secure=False`/`httponly:false`
        // у вызова установки cookie, а не упоминание слов в строке. Прежний предикат
        // (cookie И secure/httponly И false на одной строке) флагал описательную строку
        // ответа вида «… and secure flag set to false.», которая присутствует и в
        // безопасных файлах с secure=True, давая 100% ложных. Оператор присваивания перед
        // `false` (`=`/`:`) отделяет код от прозы; окно связывает многострочный вызов
        // `set_cookie(...)`, где аргумент secure=False стоит на отдельной строке.
        Rule {
            id: "insecure-cookie",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::window_regex(
                r#"(?is)(?:set_?cookie|setcookie|\.cookie\s*\(|httpcookie|new\s+cookie|samesite)[^;]{0,200}?(?:secure|http_?only)\s*[:=]\s*(?:false|0)\b"#,
                4,
            ),
            message: "Небезопасная cookie (Secure/HttpOnly = false) (CWE-614/CWE-1004, OWASP A05:2021). Включите Secure и HttpOnly для сессионных кук.",
        },
        // ── CSRF-защита явно отключена ────────────────────────────────────────
        Rule {
            id: "csrf-disabled",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r"(?i)@csrf_exempt|csrf_exempt|csrfProtection\s*[:=]\s*(?:false|off)|WTF_CSRF_ENABLED\s*=\s*False|\.csrf\s*\(\s*\)\s*\.disable\s*\(|csrf\s*[:=]\s*(?:false|off|disabled)",
            ),
            message: "CSRF-защита отключена (CWE-352, OWASP A01:2021). Не отключайте CSRF для изменяющих состояние эндпоинтов.",
        },
    ]
}

// ───────────────────────── security.scan/api ─────────────────────────

/// Уязвимости API: подпись JWT (алгоритмическая путаница, alg=none, отключённая
/// проверка), включённая в проде GraphQL-интроспекция, mass assignment из тела
/// запроса.
pub fn api_scan() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "security.scan/api",
            Family::Security,
            // ailc:ignore[jwt-none,jwt-none-alg] — текст ОПИСАНИЯ capability, самосовпадение на ruleset
            "Уязвимости API: JWT с алгоритмической путаницей (смешение асимметричного и HMAC), alg=none/None/[] или отключённой проверкой подписи, открытая GraphQL-интроспекция в проде, mass assignment (биндинг тела запроса в модель). Срабатывание JWT-правил требует JWT-маркера рядом, чтобы не шуметь на конфигах сжатия и моделях.",
        ),
        api_rules(),
    )
}

/// Таблица правил `security.scan/api`. Вынесена отдельно для адресных тестов.
fn api_rules() -> Vec<Rule> {
    use Severity::{High, Medium};
    vec![
        // JWT без проверки подписи: alg=none/None/[] либо verify off. Три ветви,
        // балансирующие охват и шум (T21). Ветвь 1 (с JWT-маркером рядом: jwt/jose/
        // jws/decode/HS256/RS256/verify_signature) ловит ЛЮБУЮ форму alg=none, в том
        // числе незакавыченную None (Python). Ветвь 2 (закавыченное "none"/'none' как
        // значение алгоритма) срабатывает БЕЗ маркера: кавычки задают именно строковый
        // алгоритм «none», тогда как конфиг сжатия пишет «algorithm: none» без кавычек,
        // поэтому ложного срабатывания на нём нет. Ветвь 3 (verify_signature=false):
        // термин специфичен для JWT и сам по себе достаточен. Окно из двух строк
        // связывает маркер и алгоритм, разнесённые переносом.
        Rule {
            id: "jwt-none-alg",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::window_regex(
                r#"(?is)(?:jwt|jose|jws|jwk|\bdecode\b|HS256|RS256|ES256|verify_signature)[^;]{0,80}?(?:alg(?:orithm)?s?\s*["'\s:=\[{]+\s*["']?(?:none|None|NONE)\b|algorithms?\s*[:=]\s*(?:None|\[\s*\])|verify\s*=\s*False)|alg(?:orithm)?s?\s*["'\s:=\[{,]+\s*["'](?:none|None|NONE)["']|verify_signature\s*["'\s:=]+\s*(?:false|False)"#,
                2,
            ),
            // ailc:ignore[jwt-none,jwt-none-alg] — текст СООБЩЕНИЯ правила, самосовпадение на ruleset
            message: "JWT с alg=none/None/[] или без проверки подписи (CWE-347, OWASP API2:2023 Broken Authentication). Жёстко задайте алгоритм и проверяйте подпись.",
        },
        // JWT алгоритмическая путаница: в одном списке допустимых алгоритмов
        // смешаны асимметричный (RS/ES/PS) и симметричный (HS). Тогда токен,
        // подписанный публичным RSA-ключом как HMAC, проходит проверку. Требуем
        // JWT-маркер рядом.
        Rule {
            id: "jwt-alg-confusion",
            severity: High,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r#"(?i)(?:jwt|jose|jws|algorithms?)[^\n]{0,80}(?:HS\d{3}[^\n]{0,40}(?:RS|ES|PS)\d{3}|(?:RS|ES|PS)\d{3}[^\n]{0,40}HS\d{3})"#,
            ),
            message: "JWT алгоритмическая путаница — в списке допустимых алгоритмов смешаны асимметричный и HMAC (CWE-347, OWASP API2:2023). Токен, подписанный публичным ключом как HMAC, пройдёт проверку; разрешайте ровно один алгоритм.",
        },
        // GraphQL: интроспекция включена (раскрытие схемы атакующему).
        Rule {
            id: "graphql-introspection",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(r"(?i)introspection\s*[:=]\s*(?:true|enabled)"),
            message: "GraphQL-интроспекция включена (CWE-200, OWASP API9:2023). Отключайте интроспекцию в проде.",
        },
        // Mass assignment: тело запроса напрямую в модель/ORM.
        Rule {
            id: "mass-assignment",
            severity: Medium,
            exts: SOURCE_CODE,
            matcher: Matcher::regex(
                r"(?i)(?:\.update_attributes|\.create|\bbind\b|\.assign)\s*\(\s*(?:request\.(?:body|POST|json|params)|req\.body|params)\b",
            ),
            message: "Mass assignment — тело запроса связано с моделью без allow-list (CWE-915, OWASP API6:2023). Явно перечислите разрешённые поля.",
        },
    ]
}

/// Регистрирует web/API security-capability.
pub fn register(reg: &mut Registry) {
    reg.register(Box::new(web_scan())); // E1 Scan — web-уязвимости
    reg.register(Box::new(api_scan())); // E1 Scan — уязвимости API
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Найти правило по идентификатору в указанной таблице.
    fn rule<'a>(rules: &'a [Rule], id: &str) -> &'a Rule {
        rules
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("правило {id} должно существовать"))
    }

    /// Истина, если матчер правила срабатывает на тексте. Для построчных матчеров
    /// текст проверяется построчно; для оконных/файловых матчеров берётся весь
    /// фрагмент сразу, как это делает движок по окну/файлу.
    fn hits(r: &Rule, text: &str) -> bool {
        if r.matcher.is_multiline() {
            // Оконный/файловый матчер: движок склеивает строки окна через \n и
            // матчит фрагмент целиком, поэтому здесь подаём весь текст.
            r.matcher.is_match(text)
        } else {
            text.lines().any(|l| r.matcher.is_match(l))
        }
    }

    // ───────────────────────── T18 SSRF ─────────────────────────

    #[test]
    fn ssrf_ловит_клиент_с_именованным_url() {
        let rs = web_rules();
        let r = rule(&rs, "ssrf-sink");
        // Имена переменных, которые раньше пропускались (target/link/endpoint/host).
        assert!(hits(r, "resp = requests.get(target)"), "target");
        assert!(hits(r, "axios.get(endpoint)"), "endpoint axios");
        assert!(hits(r, "r = httpx.get(link)"), "link httpx");
        assert!(hits(r, "fetch(url)"), "fetch url");
    }

    #[test]
    fn ssrf_связывает_источник_и_сток_через_перенос() {
        let rs = web_rules();
        let r = rule(&rs, "ssrf-sink");
        // Источник на одной строке, сток на следующей: оконный матчер связывает.
        let src = "u = request.args.get('u')\nresp = requests.get(u)";
        assert!(hits(r, src), "окно должно связать request. и requests.get");
    }

    #[test]
    fn ssrf_не_срабатывает_на_доверенном_литерале() {
        let rs = web_rules();
        let r = rule(&rs, "ssrf-sink");
        // Постоянный доверенный адрес без признака недоверенного источника.
        assert!(
            !hits(r, "requests.get('https://api.example.com/health')"),
            "литерал без источника не должен давать SSRF-сток"
        );
    }

    #[test]
    fn ssrf_литеральный_хост_метаданные_и_приватные() {
        let rs = web_rules();
        let r = rule(&rs, "ssrf-internal-host");
        // Метаданные облака и обфусцированные формы — находка даже голым литералом.
        assert!(hits(r, "url = 'http://169.254.169.254/latest/meta-data/'"), "AWS IMDS");
        assert!(hits(r, "host = 'metadata.google.internal'"), "GCP metadata");
        assert!(hits(r, "u = 'http://2852039166/'"), "decimal IMDS");
        assert!(hits(r, "u = 'http://0xA9FEA9FE/'"), "hex IMDS");
        // Внутренний/loopback/RFC1918 — находка ТОЛЬКО в окне с вызовом HTTP-клиента.
        assert!(hits(r, "requests.get('http://127.0.0.1:8080/admin')"), "loopback в запросе");
        assert!(hits(r, "axios.get('http://10.0.0.5/internal')"), "RFC1918 10/8 в запросе");
        assert!(hits(r, "fetch('http://192.168.1.1/')"), "RFC1918 192.168 в запросе");
        assert!(hits(r, "client.Do('http://172.16.0.1/')"), "RFC1918 172.16 в запросе");
    }

    #[test]
    fn ssrf_литеральный_хост_не_трогает_публичный() {
        let rs = web_rules();
        let r = rule(&rs, "ssrf-internal-host");
        assert!(!hits(r, "requests.get('http://93.184.216.34/')"), "публичный IP в запросе");
        assert!(!hits(r, "u = 'http://172.32.0.1/'"), "172.32 вне RFC1918");
        assert!(!hits(r, "u = 'http://11.0.0.1/'"), "11.x не RFC1918");
        // Голый внутренний литерал без вызова HTTP-клиента (конфиг/дефолт/лог/CORS) — НЕ
        // SSRF. Раньше каждая такая строка давала ложное срабатывание (см. бенчмарк).
        assert!(!hits(r, "const base = 'http://127.0.0.1:5173'"), "конфиг-дефолт");
        assert!(!hits(r, "console.log('listening on http://localhost:3000')"), "строка лога");
        assert!(!hits(r, "ALLOWED = 'http://localhost:5173,http://127.0.0.1:3000'"), "список CORS");
    }

    #[test]
    fn ssrf_severity_согласован_high_с_owasp() {
        // T18: web и owasp должны давать SSRF одинаковый класс High.
        let rs = web_rules();
        assert_eq!(rule(&rs, "ssrf-sink").severity, Severity::High);
        assert_eq!(rule(&rs, "ssrf-internal-host").severity, Severity::High);
    }

    // ───────────────────────── T20 TLS ─────────────────────────

    #[test]
    fn tls_ловит_все_стеки() {
        let rs = web_rules();
        let r = rule(&rs, "tls-verify-disabled");
        assert!(hits(r, "requests.get(u, verify=False)"), "python verify");
        assert!(hits(r, "tr := &tls.Config{InsecureSkipVerify: true}"), "go");
        assert!(hits(r, "const a = new https.Agent({rejectUnauthorized: false})"), "node agent");
        assert!(hits(r, "conn.setHostnameVerifier((h, s) -> true);"), "java hostnameverifier");
        assert!(hits(r, "ServicePointManager.ServerCertificateValidationCallback += (s,c,ch,e) => true;"), "dotnet");
        assert!(hits(r, "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'"), "node env");
        assert!(hits(r, "public void checkServerTrusted(X509Certificate[] c, String a) {}"), "пустой checkServerTrusted");
    }

    #[test]
    fn tls_verify_не_ловит_email_verify() {
        // T20: граница перед verify убирает ложное срабатывание email_verify=False.
        let rs = web_rules();
        let r = rule(&rs, "tls-verify-disabled");
        assert!(!hits(r, "email_verify=False"), "email_verify не TLS");
        assert!(!hits(r, "auto_verify = False"), "auto_verify не TLS");
        // Но настоящий флаг с границей перед verify должен ловиться.
        assert!(hits(r, "session.verify=False"), "session.verify это TLS");
    }

    // ───────────────────────── T21 JWT ─────────────────────────

    #[test]
    fn jwt_none_в_разных_формах() {
        let rs = api_rules();
        let r = rule(&rs, "jwt-none-alg");
        assert!(hits(r, "jwt.decode(t, algorithms=['none'])"), "массив none");
        assert!(hits(r, "jwt.decode(t, algorithms=None)"), "algorithms=None");
        assert!(hits(r, "jwt.decode(token, options={'algorithm': 'none'})"), "словарь alg none");
        assert!(hits(r, "jwt.decode(t, verify_signature=False)"), "verify_signature false");
    }

    #[test]
    fn jwt_none_требует_маркер_не_ловит_сжатие() {
        // T21: «compression algorithm: none» вне контекста JWT не должно срабатывать.
        let rs = api_rules();
        let r = rule(&rs, "jwt-none-alg");
        assert!(!hits(r, "compression algorithm: none"), "сжатие не JWT");
        assert!(!hits(r, "scaling algorithm = none"), "ML-конфиг не JWT");
    }

    #[test]
    fn jwt_alg_confusion_смешение_асим_и_hmac() {
        let rs = api_rules();
        let r = rule(&rs, "jwt-alg-confusion");
        assert!(hits(r, "jwt.decode(t, algorithms=['HS256', 'RS256'])"), "HS+RS");
        assert!(hits(r, "algorithms: ['RS256', 'HS256']"), "RS+HS");
        // Один симметричный или один асимметричный класс — не путаница.
        assert!(!hits(r, "algorithms=['HS256', 'HS384']"), "только HMAC");
        assert!(!hits(r, "algorithms=['RS256']"), "только RSA");
    }

    // ───────────────────────── T22 CORS ─────────────────────────

    #[test]
    fn cors_wildcard_с_равно() {
        // T22: класс символов включает равно, как в owasp-варианте.
        let rs = web_rules();
        let r = rule(&rs, "cors-wildcard");
        assert!(hits(r, "Access-Control-Allow-Origin = \"*\""), "через равно");
        assert!(hits(r, "Access-Control-Allow-Origin: *"), "через двоеточие");
        assert!(hits(r, "cors(app, origins='*')"), "origins '*'");
    }

    #[test]
    fn cors_reflection_origin_high() {
        let rs = web_rules();
        let r = rule(&rs, "cors-reflect-origin");
        assert!(hits(r, "Access-Control-Allow-Origin: $http_origin"), "nginx echo");
        assert!(hits(r, "res.setHeader('Access-Control-Allow-Origin', req.headers.origin)"), "node echo");
        assert!(hits(r, "cors({origin: true})"), "origin true");
        assert!(hits(r, "@CrossOrigin"), "spring crossorigin");
        assert_eq!(r.severity, Severity::High, "reflection опаснее wildcard");
    }

    #[test]
    fn insecure_cookie_код_не_проза() {
        let rs = web_rules();
        let r = rule(&rs, "insecure-cookie");
        // Кодовый флаг secure=False у вызова set_cookie (в т.ч. многострочного) — находка.
        assert!(hits(r, "resp.set_cookie('s', v, secure=False)"), "secure=False");
        assert!(
            hits(r, "RESPONSE.set_cookie(cookie, value,\n  path=request.path,\n  secure=False,\n  httponly=True)"),
            "многострочный set_cookie secure=False"
        );
        assert!(hits(r, "res.cookie('s', v, { httpOnly: false })"), "node httpOnly:false");
        // Описательная проза «secure flag set to false» БЕЗ оператора и при secure=True —
        // НЕ находка (раньше предикат ложно срабатывал на ней во всех файлах корпуса).
        assert!(
            !hits(r, "RESPONSE += 'Created cookie with secure flag set to false.'"),
            "проза про cookie не находка"
        );
        assert!(
            !hits(r, "resp.set_cookie('s', v,\n  secure=True,\n  httponly=True)"),
            "secure=True безопасен"
        );
    }

    // ───────────────────────── T23 расширения ─────────────────────────

    #[test]
    fn ssti_по_многим_движкам() {
        let rs = web_rules();
        let r = rule(&rs, "ssti");
        assert!(hits(r, "render_template_string(tpl)"), "flask");
        assert!(hits(r, "env.from_string(user_tpl).render()"), "jinja from_string");
        assert!(hits(r, "ERB.new(tpl).result(binding)"), "erb");
        assert!(hits(r, "Handlebars.compile(src)"), "handlebars");
        assert!(hits(r, "Template tpl = new Template(\"n\", src, cfg);"), "freemarker new Template");
    }

    #[test]
    fn deserialize_по_многим_экосистемам() {
        let rs = web_rules();
        let r = rule(&rs, "insecure-deserialize");
        assert!(hits(r, "obj = pickle.loads(data)"), "python pickle");
        assert!(hits(r, "ObjectInputStream ois = new ObjectInputStream(in);"), "java OIS");
        assert!(hits(r, "$obj = unserialize($_POST['d']);"), "php unserialize");
        assert!(hits(r, "obj = Marshal.load(data)"), "ruby marshal");
        assert!(hits(r, "var o = new BinaryFormatter().Deserialize(s);"), "dotnet BinaryFormatter");
    }

    #[test]
    fn path_traversal_новые_стоки_и_источники() {
        let rs = web_rules();
        let r = rule(&rs, "path-traversal");
        assert!(hits(r, "send_file(request.args.get('f'))"), "send_file + request");
        assert!(hits(r, "fs.readFileSync(req.query.path)"), "readFileSync + req");
        assert!(hits(r, "open(user_input)"), "open + user_input");
        assert!(hits(r, "return File.new(params[:name])"), "ruby File.new + params");
    }

    #[test]
    fn path_traversal_ловит_литеральный_обход() {
        let rs = web_rules();
        let r = rule(&rs, "path-traversal");
        assert!(hits(r, "open('../../etc/passwd')"), "буквальный ../");
        assert!(hits(r, "readfile('%2e%2e/secret')"), "URL-кодированный обход");
    }

    #[test]
    fn xxe_по_умолчанию_и_явно() {
        let rs = web_rules();
        let xxe = rule(&rs, "xxe");
        assert!(hits(xxe, "parser = etree.XMLParser(resolve_entities=True)"), "явные сущности lxml");
        // Реальный XXE на xml.sax с включёнными внешними сущностями (раньше пропускался).
        assert!(
            hits(xxe, "parser.setFeature(xml.sax.handler.feature_external_ges, True)"),
            "sax feature_external_ges=True"
        );
        let def = rule(&rs, "xxe-parser-default");
        assert!(hits(def, "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();"), "java фабрика");
        // lxml etree.parse БОЛЬШЕ не считается XXE по умолчанию: современный lxml не
        // разворачивает внешние сущности, а паттерн ложно метил XPath-файлы как XXE.
        assert!(!hits(def, "tree = etree.parse(xml_input)"), "голый etree.parse не XXE");
    }

    #[test]
    fn command_exec_runtime_ловит_java_стоки() {
        // T23: owasp-класс [^.\w] перед exec пропускает .exec(, здесь покрываем.
        let rs = web_rules();
        let r = rule(&rs, "command-exec-runtime");
        assert!(hits(r, "Runtime.getRuntime().exec(cmd)"), "Runtime.exec");
        assert!(hits(r, "new ProcessBuilder(cmd).start();"), "ProcessBuilder");
    }

    // ───────────────────────── общие инварианты ─────────────────────────

    #[test]
    fn все_правила_имеют_cwe_в_сообщении() {
        for r in web_rules().into_iter().chain(api_rules()) {
            assert!(
                r.message.contains("CWE-"),
                "правило {} должно ссылаться на CWE",
                r.id
            );
        }
    }

    #[test]
    fn нет_дублей_идентификаторов_правил() {
        let mut ids: Vec<&str> = web_rules().iter().map(|r| r.id).collect();
        ids.extend(api_rules().iter().map(|r| r.id));
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "идентификаторы правил web/api должны быть уникальны");
    }
}
