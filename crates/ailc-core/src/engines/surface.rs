//! Извлечение «поверхности» проекта из кода: HTTP-роуты, переменные окружения,
//! внешние сервисы (БД/очереди/хранилища), модели данных.
//!
//! Это НЕ находки (не проблемы) — это ФАКТЫ для спеки и C4-Context: что система
//! принимает на вход (эндпоинты), от чего зависит (сервисы/ENV), какими данными
//! оперирует (модели). Регекс-слой по популярным фреймворкам поверх общего `walk`;
//! генераторы Фазы 3 (`generate/spec`, `generate/c4`, `generate/data-model`) зовут
//! `extract()` напрямую. Тест-файлы пропускаются — документируем продукт, не фикстуры.

use super::scan::SOURCE_CODE;
use super::walk::{blank_rust_test_modules, ext_of, is_test_path, walk};
use ailc_contracts::{Ctx, Result, RunInput};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// Синтаксис комментариев и строковых литералов по расширению файла.
///
/// Нужен маскировщику [`mask_comments`]: чтобы убрать комментарий, надо сначала
/// достоверно знать, что найденная последовательность не находится внутри строки.
struct CommentSyntax {
    /// Строчный `//` и блочный `/* … */`.
    slashes: bool,
    /// Строчный `#` до конца строки.
    hash: bool,
    /// Строчный `--` до конца строки.
    dashes: bool,
    /// Тройные кавычки Python как документирующая строка.
    py_triple: bool,
    /// Одиночная кавычка открывает строку (а не символьный литерал и не время жизни).
    single_quote: bool,
    /// Обратная кавычка открывает строку (шаблонная строка JS, сырая строка Go).
    backtick: bool,
    /// Сырые строки Rust вида `r"…"`, `r#"…"#`, `br#"…"#`.
    rust_raw: bool,
}

fn comment_syntax(ext: &str) -> CommentSyntax {
    CommentSyntax {
        slashes: matches!(
            ext,
            "rs" | "go"
                | "js"
                | "jsx"
                | "mjs"
                | "cjs"
                | "ts"
                | "tsx"
                | "java"
                | "kt"
                | "kts"
                | "swift"
                | "cs"
                | "c"
                | "cc"
                | "cpp"
                | "cxx"
                | "h"
                | "hpp"
                | "hh"
                | "hxx"
                | "scala"
                | "sc"
                | "php"
                | "dart"
                | "proto"
                | "gradle"
                | "groovy"
        ),
        // GraphQL и PHP комментируют решёткой; PHP умеет и то, и другое.
        hash: matches!(
            ext,
            "py" | "rb"
                | "sh"
                | "bash"
                | "zsh"
                | "yaml"
                | "yml"
                | "toml"
                | "pl"
                | "pm"
                | "r"
                | "ex"
                | "exs"
                | "cr"
                | "nim"
                | "jl"
                | "tf"
                | "graphql"
                | "gql"
                | "conf"
                | "cfg"
                | "ini"
                | "properties"
                | "php"
        ),
        dashes: matches!(ext, "sql" | "lua" | "hs" | "elm" | "adb" | "ads"),
        py_triple: ext == "py",
        // Rust и Go исключены намеренно: там одиночная кавычка это время жизни `'a`
        // и руническая константа, и приняв её за строку, маскировщик проглотил бы
        // остаток строки вместе с настоящими фактами.
        single_quote: matches!(
            ext,
            "py" | "rb"
                | "js"
                | "jsx"
                | "mjs"
                | "cjs"
                | "ts"
                | "tsx"
                | "php"
                | "sql"
                | "sh"
                | "bash"
                | "zsh"
                | "dart"
                | "yaml"
                | "yml"
                | "toml"
                | "pl"
                | "pm"
                | "ex"
                | "exs"
                | "lua"
                | "r"
        ),
        backtick: matches!(ext, "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "go"),
        rust_raw: ext == "rs",
    }
}

/// Состояние разбора при маскировании комментариев.
enum Lex {
    /// Код вне литерала.
    Code,
    /// Обычная строка до указанного закрывающего символа.
    Str(char),
    /// Сырая строка Rust, закрываемая кавычкой и указанным числом решёток.
    Raw(usize),
    /// Тройные кавычки Python до повторения того же символа трижды.
    Triple(char),
}

/// Заменить содержимое комментариев пробелами, СОХРАНИВ строковые литералы.
///
/// Строки сохраняются намеренно: маршрут `app.get("/users")`, строка подключения
/// `postgres://host/db` и имя переменной окружения живут именно в строковом литерале,
/// поэтому их маскирование уничтожило бы саму поверхность системы. Комментарии же
/// являются массовым источником ложных фактов: именно в них живут примеры употребления,
/// которыми документированы таблицы правил самого анализатора, и такой пример
/// неотличим от настоящего объявления маршрута.
///
/// Отслеживание строк обязательно и по обратной причине: последовательность `//`
/// внутри `postgres://host` не должна приниматься за начало комментария.
///
/// Нумерация строк сохраняется: содержимое заменяется пробелами, переводы строк
/// остаются на местах. Незакрытая обычная строка сбрасывается на переводе строки,
/// поэтому ошибка разбора одной строки не распространяется на остаток файла.
fn mask_comments(ext: &str, content: &str) -> String {
    let cs = comment_syntax(ext);
    if !(cs.slashes || cs.hash || cs.dashes || cs.py_triple) {
        return content.to_string(); // языку нечего маскировать (например JSON)
    }
    let mut out = String::with_capacity(content.len());
    let mut st = Lex::Code;
    let mut i = 0usize;
    // Предыдущий значащий символ кода: нужен, чтобы `r"` распознавалось как начало
    // сырой строки, а не как хвост идентификатора вида `for"…`.
    let mut prev_code: char = ' ';
    while i < content.len() {
        let rest = &content[i..];
        let Some(ch) = rest.chars().next() else { break };
        match st {
            Lex::Code => {
                // Комментарии.
                if cs.slashes && rest.starts_with("//") {
                    let n = skip_to_eol(rest, &mut out);
                    i += n;
                    continue;
                }
                if cs.slashes && rest.starts_with("/*") {
                    let n = mask_block(rest, "*/", &mut out);
                    i += n;
                    continue;
                }
                if cs.hash && ch == '#' {
                    let n = skip_to_eol(rest, &mut out);
                    i += n;
                    continue;
                }
                if cs.dashes && rest.starts_with("--") {
                    let n = skip_to_eol(rest, &mut out);
                    i += n;
                    continue;
                }
                // Литералы.
                if cs.py_triple && (rest.starts_with("\"\"\"") || rest.starts_with("'''")) {
                    // Документирующая строка Python маскируется как комментарий: на
                    // практике это проза с примерами, а не поверхность системы.
                    out.push_str("   ");
                    st = Lex::Triple(ch);
                    i += 3;
                    continue;
                }
                if cs.rust_raw && !prev_code.is_alphanumeric() && prev_code != '_' {
                    if let Some(n) = rust_raw_open(rest) {
                        // Содержимое сырой строки сохраняется: это литерал, а не комментарий.
                        out.push_str(&rest[..n]);
                        st = Lex::Raw(rest[..n].matches('#').count());
                        i += n;
                        continue;
                    }
                }
                if ch == '"' || (cs.single_quote && ch == '\'') || (cs.backtick && ch == '`') {
                    st = Lex::Str(ch);
                }
                if !ch.is_whitespace() {
                    prev_code = ch;
                }
                out.push(ch);
                i += ch.len_utf8();
            }
            Lex::Str(delim) => {
                // Экранирование: обратная косая уводит следующий символ из-под разбора.
                if ch == '\\' && delim != '`' {
                    out.push(ch);
                    i += ch.len_utf8();
                    if let Some(next) = content[i..].chars().next() {
                        out.push(next);
                        i += next.len_utf8();
                    }
                    continue;
                }
                if ch == delim {
                    st = Lex::Code;
                } else if ch == '\n' && delim != '`' {
                    // Незакрытая однострочная строка: ошибка разбора не должна
                    // распространяться дальше своей строки.
                    st = Lex::Code;
                }
                out.push(ch);
                i += ch.len_utf8();
            }
            Lex::Raw(hashes) => {
                let close = format!("\"{}", "#".repeat(hashes));
                if rest.starts_with(&close) {
                    out.push_str(&close);
                    i += close.len();
                    st = Lex::Code;
                    continue;
                }
                out.push(ch);
                i += ch.len_utf8();
            }
            Lex::Triple(delim) => {
                let close: String = std::iter::repeat_n(delim, 3).collect();
                if rest.starts_with(&close) {
                    out.push_str("   ");
                    i += 3;
                    st = Lex::Code;
                    continue;
                }
                out.push(if ch == '\n' { '\n' } else { ' ' });
                i += ch.len_utf8();
            }
        }
    }
    out
}

/// Замаскировать пробелами остаток строки (перевод строки сохраняется).
/// Возвращает число поглощённых байтов.
fn skip_to_eol(rest: &str, out: &mut String) -> usize {
    let mut n = 0usize;
    for ch in rest.chars() {
        if ch == '\n' {
            break;
        }
        out.push(' ');
        n += ch.len_utf8();
    }
    n
}

/// Замаскировать пробелами блочный комментарий вместе с закрывающей меткой.
/// Незакрытый блок поглощает остаток файла: это консервативно и безопасно.
fn mask_block(rest: &str, close: &str, out: &mut String) -> usize {
    let end = rest
        .find(close)
        .map(|p| p + close.len())
        .unwrap_or(rest.len());
    for ch in rest[..end].chars() {
        out.push(if ch == '\n' { '\n' } else { ' ' });
    }
    end
}

/// Длина открывающей последовательности сырой строки Rust (`r"`, `r#"`, `br##"`),
/// либо None, если строка начинается не с неё.
fn rust_raw_open(rest: &str) -> Option<usize> {
    let body = rest.strip_prefix("br").or_else(|| rest.strip_prefix('r'))?;
    let hashes = body.len() - body.trim_start_matches('#').len();
    if body[hashes..].starts_with('"') {
        Some(rest.len() - body.len() + hashes + 1)
    } else {
        None
    }
}

/// Один извлечённый факт: его значение и где он найден (для перехода).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceItem {
    pub value: String,
    pub file: String,
    pub line: u32,
}

/// Поверхность проекта: эндпоинты, окружение, внешние сервисы, модели данных.
#[derive(Debug, Default)]
pub struct Surface {
    pub routes: Vec<SurfaceItem>,
    pub env: Vec<SurfaceItem>,
    pub services: Vec<SurfaceItem>,
    pub models: Vec<SurfaceItem>,
}

impl Surface {
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
            && self.env.is_empty()
            && self.services.is_empty()
            && self.models.is_empty()
    }
}

/// Откуда берётся HTTP-метод роута.
enum Method {
    Group(usize),
    Fixed(&'static str),
}

struct RouteRe {
    re: Regex,
    method: Method,
    path_g: usize,
    /// Требовать, чтобы путь начинался с «/» (отсекает `cache.get("key")` от роута).
    /// Django/Rails используют относительные пути — для них false.
    require_slash: bool,
    /// Расширения, к которым применять (пусто = любые). Нужно для `app.get`-паттернов,
    /// которые без слэша валидны лишь в конкретном языке (Vapor — Swift).
    exts: &'static [&'static str],
}

fn route_res() -> &'static Vec<RouteRe> {
    static R: OnceLock<Vec<RouteRe>> = OnceLock::new();
    R.get_or_init(|| {
        // Невалидный встроенный паттерн исключает СВОЁ правило и не завершает процесс:
        // сервер живёт одним процессом на весь сеанс среды разработки, поэтому цена паники
        // несоизмерима с ценой пропуска одного правила (см. модуль `crate::re`). Полнота
        // набора закреплена тестом `все_встроенные_паттерны_компилируются`.
        let mk_ext = |p: &str,
                      method: Method,
                      path_g: usize,
                      require_slash: bool,
                      exts: &'static [&'static str]| {
            crate::re::compile(p).map(|re| RouteRe {
                re,
                method,
                path_g,
                require_slash,
                exts,
            })
        };
        let mk = |p: &str, method: Method, path_g: usize, require_slash: bool| {
            mk_ext(p, method, path_g, require_slash, &[])
        };
        vec![
            // Express/Gin/обобщённо: obj.method("/path")
            mk(
                r#"(?i)\b(?:app|router|r|mux|api|srv|server|bp)\.(get|post|put|delete|patch|head|options)\s*\(\s*["'`]([^"'`]+)["'`]"#,
                Method::Group(1),
                2,
                true,
            ),
            // FastAPI/Flask: @app.get("/path")
            mk(
                r#"(?i)@(?:app|router|bp)\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']"#,
                Method::Group(1),
                2,
                true,
            ),
            // Flask: @app.route("/path")
            mk(
                r#"(?i)@(?:app|bp)\.route\s*\(\s*["']([^"']+)["']"#,
                Method::Fixed("ANY"),
                1,
                true,
            ),
            // Spring: @GetMapping("/path")
            mk(
                r#"@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']"#,
                Method::Group(1),
                2,
                false,
            ),
            // axum/actix: .route("/path", get(handler))
            mk(
                r#"(?i)\.route\s*\(\s*["']([^"']+)["']\s*,\s*(get|post|put|delete|patch)\b"#,
                Method::Group(2),
                1,
                true,
            ),
            // Django: path("users/", view) / re_path(r"^x$", view)
            mk(
                r#"(?i)\b(?:path|re_path)\s*\(\s*r?["']([^"']*)["']"#,
                Method::Fixed("URL"),
                1,
                false,
            ),
            // Spring: @RequestMapping(value="/x", method=…)
            mk(
                r#"@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']"#,
                Method::Fixed("REQUEST"),
                1,
                false,
            ),
            // NestJS/декораторы метода: @Get("x")  (не путать с Spring @GetMapping)
            mk(
                r#"@(Get|Post|Put|Delete|Patch)\s*\(\s*["']([^"']+)["']"#,
                Method::Group(1),
                2,
                false,
            ),
            // ASP.NET: [HttpGet("x")]
            mk(
                r#"\[Http(Get|Post|Put|Delete|Patch)\s*\(\s*["']([^"']+)["']"#,
                Method::Group(1),
                2,
                false,
            ),
            // Laravel: Route::get("/x", …)
            mk(
                r#"(?i)Route::(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']"#,
                Method::Group(1),
                2,
                false,
            ),
            // Rails routes.rb: get "/users"
            mk(
                r#"(?i)^\s*(get|post|put|patch|delete)\s+["']([^"']+)["']"#,
                Method::Group(1),
                2,
                false,
            ),
            // Swift Vapor: app.get("users") / routes.post("x") — относительный путь легитимен.
            mk_ext(
                r#"(?i)\b(?:app|routes)\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']"#,
                Method::Group(1),
                2,
                false,
                &["swift"],
            ),
            // Kotlin Ktor: routing { get("/users") { … } } — голый метод, путь со «/».
            mk_ext(
                r#"\b(get|post|put|delete|patch)\s*\(\s*["'](/[^"']*)["']"#,
                Method::Group(1),
                2,
                false,
                &["kt", "kts"],
            ),
            // Go echo: ВЕРХНИЙ регистр метода на любом приёмнике (e.GET, g.POST). Имя
            // переменной у echo произвольно, но методы — заглавные, что отличает их от
            // обычного `obj.get("ключ")` (T69). Применяем только к Go.
            mk_ext(
                r#"\b[A-Za-z_]\w*\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["'`]([^"'`]+)["'`]"#,
                Method::Group(1),
                2,
                true,
                &["go"],
            ),
            // Express/fiber/chi с ПРОИЗВОЛЬНЫМ именем переменной (не только из белого
            // списка): любой идентификатор, у которого вызывается http-метод нижним
            // регистром с путём, начинающимся со «/» (T69). Слэш отсекает `cache.get`.
            // Ограничено JS/TS-семейством, где такой паттерн идиоматичен, чтобы не ловить
            // `obj.get("/x")` в других языках.
            mk_ext(
                r#"\b[A-Za-z_]\w*\.(get|post|put|delete|patch|head|options|all)\s*\(\s*["'`](/[^"'`]*)["'`]"#,
                Method::Group(1),
                2,
                true,
                &["js", "jsx", "ts", "tsx", "mjs", "cjs"],
            ),
            // Rails resources/resource: resources :users [, only: …]. Метод обобщён до
            // REST-набора пометкой RESOURCES, путь — имя ресурса (T69). Только Ruby.
            mk_ext(
                r#"^\s*resources?\s+:([A-Za-z_]\w*)"#,
                Method::Fixed("RESOURCES"),
                1,
                false,
                &["rb"],
            ),
            // ASP.NET Minimal API: app.MapGet("/x", …) / MapPost / MapPut / MapDelete (T69).
            // Только C#.
            mk_ext(
                r#"\b[A-Za-z_]\w*\.Map(Get|Post|Put|Delete|Patch)\s*\(\s*["']([^"']+)["']"#,
                Method::Group(1),
                2,
                false,
                &["cs"],
            ),
            // gRPC сервис в .proto: rpc MethodName(Req) returns (Resp). Путь — имя метода,
            // метод помечается RPC (T69). Применяем к proto-файлам.
            mk_ext(
                r#"^\s*rpc\s+([A-Za-z_]\w*)\s*\("#,
                Method::Fixed("RPC"),
                1,
                false,
                &["proto"],
            ),
        ]
        .into_iter()
        .flatten()
        .collect()
    })
}

/// Имя поля верхнего уровня в типе GraphQL Query/Mutation/Subscription (T69). Извлечение
/// GraphQL делается с учётом блока (внутри какого типа находится поле), поэтому реализовано
/// отдельно от построчных `route_res`: иначе поля обычных объектных типов давали бы шум.
fn gql_field_re() -> Option<&'static Regex> {
    static R: OnceLock<Option<Regex>> = OnceLock::new();
    R.get_or_init(|| crate::re::compile(r#"^\s*([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*:\s*[A-Za-z_\[]"#))
        .as_ref()
}

/// Открытие блока типа GraphQL: `type Query {` / `type Mutation {` (и Subscription).
/// Группа 1 — операционный корень (Query/Mutation/Subscription).
fn gql_root_re() -> Option<&'static Regex> {
    static R: OnceLock<Option<Regex>> = OnceLock::new();
    R.get_or_init(|| {
        crate::re::compile(r#"^\s*(?:extend\s+)?type\s+(Query|Mutation|Subscription)\b"#)
    })
    .as_ref()
}

fn env_res() -> &'static Vec<Regex> {
    static R: OnceLock<Vec<Regex>> = OnceLock::new();
    R.get_or_init(|| {
        [
            r#"(?i)os\.getenv\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
            r#"os\.environ(?:\.get)?\[?\(?\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
            r#"process\.env\.([A-Za-z_][A-Za-z0-9_]*)"#,
            r#"process\.env\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
            r#"(?:std::)?env::var\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
            r#"env!\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
            r#"os\.Getenv\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
            r#"System\.getenv\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
            // PHP/C: bare getenv("X")  (PHP getenv, C getenv); $_ENV['X'] — PHP.
            r#"\bgetenv\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
            r#"\$_ENV\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
            // Ruby: ENV['X'] / ENV.fetch('X').
            r#"\bENV(?:\.fetch)?\s*[\[\(]\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
            // C#: Environment.GetEnvironmentVariable("X").
            r#"Environment\.GetEnvironmentVariable\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
            // Swift: ProcessInfo.processInfo.environment["X"].
            r#"ProcessInfo\.processInfo\.environment\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
            // Dart: Platform.environment['X'].
            r#"Platform\.environment\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
            // Scala: sys.env("X") / sys.env.get("X").
            r#"sys\.env(?:\.get)?\s*\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
        ]
        .into_iter()
        .filter_map(crate::re::compile)
        .collect()
    })
}

fn service_res() -> &'static Vec<Regex> {
    static R: OnceLock<Vec<Regex>> = OnceLock::new();
    R.get_or_init(|| {
        [
            // Базы данных и брокеры по схеме URI.
            r#"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqp|amqps|kafka|clickhouse)://[^\s"'`]+"#,
            // Облачные хранилища объектов.
            r#"(?i)\b(?:s3|gs|gcs|wasb)://[A-Za-z0-9._\-/]+"#,
            // Дополнительные транспорты/сервисы (T69): gRPC, NATS, AWS SQS-эндпоинт,
            // Elasticsearch, а также обобщённый https-эндпоинт внешнего API.
            r#"(?i)\b(?:grpc|grpcs|nats|nats-streaming|stan)://[^\s"'`]+"#,
            r#"(?i)\bhttps://sqs\.[a-z0-9-]+\.amazonaws\.com[^\s"'`]*"#,
            r#"(?i)\b(?:elasticsearch|elastic|es)://[^\s"'`]+"#,
            r#"(?i)\bhttps://[a-z0-9.\-]+\.amazonaws\.com[^\s"'`]*"#,
        ]
        .into_iter()
        .filter_map(crate::re::compile)
        .collect()
    })
}

/// Имена переменных окружения, чьи ЗНАЧЕНИЯ указывают на внешний сервис (T69):
/// строки подключения и адреса хостов. Само имя такой переменной попадает в `env` через
/// `env_res`, но факт наличия внешней зависимости (например очередь/БД через ENV)
/// дополнительно фиксируется как сервис, чтобы межсервисный взгляд не терял зависимость,
/// сконфигурированную через окружение, а не зашитую URL-строкой.
///
/// Применяется к УЖЕ ИЗВЛЕЧЁННОМУ имени переменной, а не к произвольной строке файла:
/// сопоставление с сырым текстом давало самосовпадение внутри таблицы правил самого
/// анализатора и приписывало продукту несуществующие зависимости.
fn service_env_re() -> Option<&'static Regex> {
    static R: OnceLock<Option<Regex>> = OnceLock::new();
    R.get_or_init(|| {
        // Префикс необязателен (`[A-Z0-9_]*`), чтобы совпадало и голое `DATABASE_URL`,
        // и `MY_DATABASE_URL`. Регистр игнорируется.
        crate::re::compile(
            r#"(?i)\b([A-Z0-9_]*(?:DATABASE_URL|DB_URL|REDIS_URL|AMQP_URL|KAFKA_BROKERS?|MONGO_URL|RABBITMQ_URL|NATS_URL|SQS_QUEUE_URL|ELASTICSEARCH_URL|ES_URL|BROKER_URL|QUEUE_URL|RABBIT_URL))\b"#,
        )
    })
    .as_ref()
}

/// (расширение, регекс, группа-имя) для моделей данных.
fn model_res() -> &'static Vec<(&'static str, Regex)> {
    static R: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    R.get_or_init(|| {
        // Пара, чей паттерн не собрался, из таблицы исключается: одна проверка молча
        // деградирует, а процесс продолжает работу (см. `crate::re`).
        let pairs: Vec<(&'static str, Option<Regex>)> = vec![
            ("prisma", crate::re::compile(r"^\s*model\s+([A-Za-z_]\w*)\s*\{")),
            (
                "sql",
                crate::re::compile(
r#"(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?[`"']?([A-Za-z_]\w*)"#,
),
            ),
            // Django ORM-модель.
            (
                "py",
                crate::re::compile(
r"^\s*class\s+([A-Za-z_]\w*)\s*\([^)]*models\.Model",
),
            ),
            // SQLAlchemy declarative (наследование Base).
            (
                "py",
                crate::re::compile(
r"^\s*class\s+([A-Za-z_]\w*)\s*\([^)]*\bBase\b",
),
            ),
            // Rails ActiveRecord: class X < ApplicationRecord / ActiveRecord::Base.
            (
                "rb",
                crate::re::compile(
r"^\s*class\s+([A-Za-z_]\w*)\s*<\s*(?:ActiveRecord::Base|ApplicationRecord)",
),
            ),
            // PHP Eloquent: class X extends Model / Authenticatable.
            (
                "php",
                crate::re::compile(
r"^\s*(?:final\s+|abstract\s+)?class\s+([A-Za-z_]\w*)\s+extends\s+(?:Model|Authenticatable)",
),
            ),
            // C# EF Core: DbSet<X> Xs.
            ("cs", crate::re::compile(r"DbSet<\s*([A-Za-z_]\w*)\s*>")),
            // Swift SwiftData/Core Data: @Model [final] class X.
            (
                "swift",
                crate::re::compile(
r"@Model\s+(?:final\s+)?class\s+([A-Za-z_]\w*)",
),
            ),
            // Dart drift/floor: class X extends Table.
            ("dart", crate::re::compile(r"^\s*class\s+([A-Za-z_]\w*)\s+extends\s+Table")),
            // Scala Slick: class X(...) extends Table.
            (
                "scala",
                crate::re::compile(
r"^\s*(?:final\s+)?class\s+([A-Za-z_]\w*).*extends\s+Table",
),
            ),
        ];
        pairs
            .into_iter()
            .filter_map(|(ext, re)| re.map(|re| (ext, re)))
            .collect()
    })
}

/// Аннотационные/деривные модели данных, где имя на ОТДЕЛЬНОЙ строке от метки
/// (`@Entity`/`#[derive(FromRow)]`). Берём по паре (предыдущая строка, текущая).
/// Покрывает JPA/TypeORM (`@Entity` + class) и Rust sqlx (`derive(FromRow)` + struct).
fn annotation_model(prev: &str, line: &str, ext: &str) -> Option<String> {
    static CLS: OnceLock<Option<Regex>> = OnceLock::new();
    static ST: OnceLock<Option<Regex>> = OnceLock::new();
    static DSL: OnceLock<Option<Regex>> = OnceLock::new();
    let cls = CLS
        .get_or_init(|| crate::re::compile(r"\bclass\s+([A-Za-z_]\w*)"))
        .as_ref()?;
    let st = ST
        .get_or_init(|| crate::re::compile(r"\bstruct\s+([A-Za-z_]\w*)"))
        .as_ref()?;
    let dsl = DSL
        .get_or_init(|| crate::re::compile(r"^\s*([A-Za-z_]\w*)\s*\("))
        .as_ref()?;
    let p = prev.trim_start();
    match ext {
        "java" | "kt" | "kts" | "ts" | "tsx" | "js" if p.starts_with("@Entity") => {
            cls.captures(line)?.get(1).map(|m| m.as_str().to_string())
        }
        "rs" if p.contains("derive(") && p.contains("FromRow") => {
            st.captures(line)?.get(1).map(|m| m.as_str().to_string())
        }
        // diesel: table! {\n  users (id) { … — имя таблицы на текущей строке.
        "rs" if p.starts_with("table!") => {
            dsl.captures(line)?.get(1).map(|m| m.as_str().to_string())
        }
        _ => None,
    }
}

/// Регекс определения Go-структуры (для распознавания gorm-моделей по тегам/embed).
fn go_type_re() -> Option<&'static Regex> {
    static R: OnceLock<Option<Regex>> = OnceLock::new();
    R.get_or_init(|| crate::re::compile(r"^\s*type\s+([A-Za-z_]\w*)\s+struct\b"))
        .as_ref()
}

/// Строка Play-роута в файле conf/routes: «GET   /users   controllers.Users.list».
fn play_re() -> Option<&'static Regex> {
    static R: OnceLock<Option<Regex>> = OnceLock::new();
    R.get_or_init(|| crate::re::compile(r"^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/\S*)"))
        .as_ref()
}

fn routes_in_line(line: &str, ext: &str) -> Vec<String> {
    let mut out = Vec::new();
    for rr in route_res() {
        if !rr.exts.is_empty() && !rr.exts.contains(&ext) {
            continue;
        }
        if let Some(c) = rr.re.captures(line) {
            let Some(path) = c.get(rr.path_g).map(|m| m.as_str().to_string()) else {
                continue;
            };
            // Защита от ложных `obj.get("ключ")` — только для обобщённого Express-паттерна
            // (require_slash). Декораторные паттерны (@Get/@…Mapping/[HttpGet]/Route::/path())
            // синтаксически специфичны — относительный путь без «/» у них легитимен.
            if rr.require_slash && !path.starts_with('/') {
                continue;
            }
            let method = match rr.method {
                Method::Group(g) => c
                    .get(g)
                    .map(|m| m.as_str().to_uppercase())
                    .unwrap_or_else(|| "?".into()),
                Method::Fixed(s) => s.to_string(),
            };
            out.push(format!("{method} {path}"));
        }
    }
    out
}

/// Убираем учётные данные из строки подключения (mongodb://user:pass@host → …@host).
fn sanitize_service(s: &str) -> String {
    let trimmed: String = s.chars().take(120).collect();
    match (trimmed.find("://"), trimmed.find('@')) {
        (Some(p), Some(at)) if at > p + 3 => {
            format!("{}//{}", &trimmed[..p + 1], &trimmed[at + 1..])
        }
        _ => trimmed,
    }
}

/// Извлечь поверхность проекта (или подпути `input.target`).
pub fn extract(ctx: &Ctx, input: &RunInput) -> Result<Surface> {
    let base = ctx.base(input)?;
    let root = ctx.root.clone();
    let mut s = Surface::default();
    let mut seen: BTreeSet<(u8, String, String, u32)> = BTreeSet::new();

    walk(&base, &mut |path| {
        let ext = ext_of(path);
        // Чтение устойчиво к кодировке (T68): не-UTF-8/BOM/одиночный CR раньше молча
        // искажали извлечение поверхности; единый ридер из codeintel чинит это.
        let content = match super::codeintel::read_source(path) {
            Some(c) => c,
            None => return,
        };
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_path(&rel) {
            return;
        }
        // Не сканируем СГЕНЕРИРОВАННУЮ документацию: иначе URL сервиса из docs/СПЕЦИФИКАЦИЯ.md
        // попадёт обратно в surface — самозагрязнение и неидемпотентная регенерация.
        // Markdown в принципе не источник поверхности (это проза, не код/конфиг).
        if ext == "md" || ext == "markdown" || rel.starts_with("docs/") || rel.starts_with("docs\\")
        {
            return;
        }
        let is_source = SOURCE_CODE.contains(&ext);
        // Контрактные схемы межсервисного взаимодействия (gRPC .proto, GraphQL SDL):
        // не входят в SOURCE_CODE, но являются полноценной «поверхностью» сервиса (T69).
        // Роуты из них извлекаем, переменные окружения — нет (там их нет).
        let is_contract = matches!(ext, "proto" | "graphql" | "gql");
        let is_play = path.file_name().and_then(|n| n.to_str()) == Some("routes");

        // Комментарии маскируются, строковые литералы сохраняются: пример употребления
        // в комментарии («// FastAPI: @app.get("/path")») неотличим от настоящего
        // объявления маршрута и попадал в документы как эндпоинт продукта.
        let masked = mask_comments(ext, &content);
        let mut lines: Vec<&str> = masked.lines().collect();
        // Rust держит тесты ВНУТРИ исходного файла, поэтому путь-ориентированный
        // `is_test_path` их не видит: строки подключения из тестовых фикстур попадали
        // в документ как внешние зависимости продукта. Гасим модули под `#[cfg(test)]`.
        if ext == "rs" {
            blank_rust_test_modules(&mut lines);
        }

        let mut prev: &str = "";
        let mut go_type: Option<String> = None;
        // Текущий операционный корень GraphQL (Query/Mutation/Subscription) или None вне
        // такого блока. Глубина фигурных скобок отслеживает выход из блока.
        let mut gql_root: Option<String> = None;
        let mut gql_depth: i32 = 0;
        for (i, line) in lines.iter().copied().enumerate() {
            let ln = (i as u32) + 1;
            let mut push = |cat: u8, value: String, bucket: &mut Vec<SurfaceItem>| {
                if seen.insert((cat, value.clone(), rel.clone(), ln)) {
                    bucket.push(SurfaceItem {
                        value,
                        file: rel.clone(),
                        line: ln,
                    });
                }
            };

            if is_source || is_contract {
                for r in routes_in_line(line, ext) {
                    push(0, r, &mut s.routes);
                }
            }
            if is_source {
                for re in env_res() {
                    if let Some(c) = re.captures(line) {
                        if let Some(m) = c.get(1) {
                            push(1, m.as_str().to_string(), &mut s.env);
                        }
                    }
                }
            }
            // Сервисы — в любом текстовом файле (часто в конфигах/yaml).
            for re in service_res() {
                if let Some(m) = re.find(line) {
                    push(2, sanitize_service(m.as_str()), &mut s.services);
                }
            }
            // Модели данных — по расширению файла.
            for (mext, re) in model_res() {
                if *mext == ext {
                    if let Some(c) = re.captures(line) {
                        if let Some(m) = c.get(1) {
                            push(3, m.as_str().to_string(), &mut s.models);
                        }
                    }
                }
            }
            // Аннотационные/деривные модели: имя на отдельной строке от @Entity/derive.
            if is_source {
                if let Some(name) = annotation_model(prev, line, ext) {
                    push(3, name, &mut s.models);
                }
            }
            // Go gorm: имя модели — последняя `type X struct`, помеченная gorm-тегом/embed.
            if ext == "go" {
                if let Some(c) = go_type_re().and_then(|re| re.captures(line)) {
                    go_type = Some(c[1].to_string());
                } else if line.contains("gorm.Model") || line.contains("gorm:\"") {
                    if let Some(name) = go_type.take() {
                        push(3, name, &mut s.models);
                    }
                }
            }
            // Scala Play: роуты в conf/routes (файл без расширения).
            if is_play {
                if let Some(c) = play_re().and_then(|re| re.captures(line)) {
                    push(
                        0,
                        format!("{} {}", c[1].to_uppercase(), &c[2]),
                        &mut s.routes,
                    );
                }
            }
            // GraphQL SDL: поля внутри type Query/Mutation/Subscription как операции (T69).
            // Учёт блока (а не построчно), чтобы не ловить поля обычных объектных типов.
            if matches!(ext, "graphql" | "gql") {
                if gql_root.is_none() {
                    if let Some(c) = gql_root_re().and_then(|re| re.captures(line)) {
                        gql_root = Some(c[1].to_string());
                        gql_depth =
                            line.matches('{').count() as i32 - line.matches('}').count() as i32;
                    }
                } else {
                    let opens = line.matches('{').count() as i32;
                    let closes = line.matches('}').count() as i32;
                    // Поле операции на текущем уровне блока.
                    if let Some(c) = gql_field_re().and_then(|re| re.captures(line)) {
                        if let (Some(root), Some(m)) = (gql_root.as_ref(), c.get(1)) {
                            let op = match root.as_str() {
                                "Query" => "QUERY",
                                "Mutation" => "MUTATION",
                                _ => "SUBSCRIPTION",
                            };
                            push(0, format!("{op} {}", m.as_str()), &mut s.routes);
                        }
                    }
                    gql_depth += opens - closes;
                    if gql_depth <= 0 {
                        gql_root = None;
                        gql_depth = 0;
                    }
                }
            }
            prev = line;
        }
    })?;

    // Внешний сервис, сконфигурированный через переменную окружения (T69): зависимость
    // выводится ИЗ УЖЕ ИЗВЛЕЧЁННЫХ переменных окружения, а не сканированием сырого
    // текста. Прежний порядок ловил характерное имя где угодно, в том числе внутри
    // собственной таблицы правил анализатора (перечисление имён в теле регулярного
    // выражения совпадало само с собой), и продукт получал несуществующую зависимость.
    // Извлечение переменной требует настоящего обращения к окружению, поэтому вывод из
    // него самосовпадением не страдает.
    if let Some(re) = service_env_re() {
        let derived: Vec<SurfaceItem> = s
            .env
            .iter()
            .filter(|it| re.is_match(&it.value))
            .map(|it| SurfaceItem {
                value: format!("env:{}", it.value),
                file: it.file.clone(),
                line: it.line,
            })
            .collect();
        for item in derived {
            if !s.services.iter().any(|x| x.value == item.value) {
                s.services.push(item);
            }
        }
    }

    // Детерминированный порядок (обход ФС не сортирован) — иначе регенерация доков не
    // идемпотентна: один и тот же код давал бы разный порядок и «обновлён» каждый раз.
    sort_items(&mut s.routes);
    sort_items(&mut s.env);
    sort_items(&mut s.services);
    sort_items(&mut s.models);
    Ok(s)
}

fn sort_items(v: &mut [SurfaceItem]) {
    v.sort_by(|a, b| {
        (a.file.as_str(), a.line, a.value.as_str()).cmp(&(
            b.file.as_str(),
            b.line,
            b.value.as_str(),
        ))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_testkit::TempTree;
    use std::path::Path;

    fn route_values(dir: &Path) -> Vec<String> {
        let ctx = Ctx::new(dir);
        let s = extract(&ctx, &RunInput::default()).unwrap();
        s.routes.into_iter().map(|i| i.value).collect()
    }

    fn service_values(dir: &Path) -> Vec<String> {
        let ctx = Ctx::new(dir);
        let s = extract(&ctx, &RunInput::default()).unwrap();
        s.services.into_iter().map(|i| i.value).collect()
    }

    fn env_values(dir: &Path) -> Vec<String> {
        let ctx = Ctx::new(dir);
        let s = extract(&ctx, &RunInput::default()).unwrap();
        s.env.into_iter().map(|i| i.value).collect()
    }

    // ────────────── Чистота фактов: комментарии, встроенные тесты, самосовпадение ──────────────

    /// Пример употребления в комментарии не является поверхностью продукта. Именно так
    /// в документы попадали несуществующие эндпоинты: таблицы правил самого анализатора
    /// документированы примерами вида `@app.get("/path")`.
    #[test]
    fn пример_маршрута_в_комментарии_не_становится_фактом() {
        let t = TempTree::new("surface");
        t.write(
            "src/app.py",
            "# FastAPI/Flask: @app.get(\"/пример-из-комментария\")\n@app.get(\"/настоящий\")\ndef h(): pass\n",
        );
        let routes = route_values(t.path());
        assert!(
            routes.iter().any(|r| r.contains("/настоящий")),
            "настоящий маршрут обязан извлекаться: {routes:?}"
        );
        assert!(
            !routes.iter().any(|r| r.contains("из-комментария")),
            "пример из комментария маршрутом не является: {routes:?}"
        );
    }

    /// Строка подключения в комментарии не делает продукт зависимым от базы данных,
    /// а такая же строка в коде делает. Проверяется заодно, что `//` внутри схемы URI
    /// не принимается за начало строчного комментария.
    #[test]
    fn строка_подключения_из_комментария_не_становится_зависимостью() {
        let t = TempTree::new("surface");
        t.write(
            "src/main.rs",
            "// пример: postgres://из-комментария:5432/app\nfn main() { let u = \"postgres://настоящий:5432/app\"; let _ = u; }\n",
        );
        let services = service_values(t.path());
        assert!(
            services.iter().any(|s| s.contains("настоящий")),
            "строка подключения из кода обязана извлекаться: {services:?}"
        );
        assert!(
            !services.iter().any(|s| s.contains("из-комментария")),
            "строка подключения из комментария зависимостью не является: {services:?}"
        );
    }

    /// Rust держит тесты внутри исходного файла, поэтому путь-ориентированное исключение
    /// их не видит: фикстуры тестов попадали в документ как поверхность продукта.
    #[test]
    fn встроенный_тестовый_модуль_фактов_не_даёт() {
        let t = TempTree::new("surface");
        t.write(
            "src/lib.rs",
            "pub fn f() { let _ = \"postgres://прод:5432/app\"; }\n\
             #[cfg(test)]\n\
             mod tests {\n\
             \x20   #[test]\n\
             \x20   fn t() { let _ = \"postgres://фикстура:5432/app\"; }\n\
             }\n",
        );
        let services = service_values(t.path());
        assert!(
            services.iter().any(|s| s.contains("прод")),
            "поверхность прод-кода обязана извлекаться: {services:?}"
        );
        assert!(
            !services.iter().any(|s| s.contains("фикстура")),
            "фикстура встроенного теста поверхностью не является: {services:?}"
        );
    }

    /// Зависимость через переменную окружения выводится из настоящего обращения к
    /// окружению. Голое имя в тексте (например перечисление имён внутри таблицы правил)
    /// зависимостью продукта не является.
    #[test]
    fn зависимость_через_окружение_выводится_из_обращения_а_не_из_упоминания() {
        let t = TempTree::new("surface");
        t.write(
            "src/config.py",
            "url = os.getenv(\"DATABASE_URL\")\nизвестные = \"DATABASE_URL|REDIS_URL|AMQP_URL\"\n",
        );
        let services = service_values(t.path());
        let env = env_values(t.path());
        assert!(
            env.contains(&"DATABASE_URL".to_string()),
            "обращение к окружению обязано извлекаться: {env:?}"
        );
        assert_eq!(
            services
                .iter()
                .filter(|s| s.starts_with("env:"))
                .collect::<Vec<_>>(),
            vec!["env:DATABASE_URL"],
            "перечисление имён в строке зависимостями не является: {services:?}"
        );
    }

    /// Документирующая строка Python это проза с примерами, а не поверхность системы.
    #[test]
    fn документирующая_строка_python_фактов_не_даёт() {
        let t = TempTree::new("surface");
        t.write(
            "src/views.py",
            "def h():\n    \"\"\"Пример: @app.get(\"/из-документации\")\"\"\"\n    return 1\n\n@app.get(\"/настоящий\")\ndef g(): pass\n",
        );
        let routes = route_values(t.path());
        assert!(
            routes.iter().any(|r| r.contains("/настоящий")),
            "настоящий маршрут обязан извлекаться: {routes:?}"
        );
        assert!(
            !routes.iter().any(|r| r.contains("из-документации")),
            "пример из документирующей строки маршрутом не является: {routes:?}"
        );
    }

    // ───────────────────────── T69: расширение роутов ─────────────────────────

    #[test]
    fn echo_routes_extracted() {
        // Go echo: e.GET/g.POST (верхний регистр метода на произвольном приёмнике).
        assert!(routes_in_line(r#"    e.GET("/users", listUsers)"#, "go")
            .iter()
            .any(|r| r == "GET /users"));
        assert!(routes_in_line(r#"    g.POST("/orders", create)"#, "go")
            .iter()
            .any(|r| r == "POST /orders"));
    }

    #[test]
    fn express_arbitrary_var_name() {
        // Имя переменной не из белого списка (myApp), но JS и путь со «/».
        assert!(routes_in_line(r#"myApp.get("/health", h)"#, "ts")
            .iter()
            .any(|r| r == "GET /health"));
    }

    #[test]
    fn rails_resources_extracted() {
        assert!(routes_in_line("  resources :users", "rb")
            .iter()
            .any(|r| r == "RESOURCES users"));
        // resources :x в не-Ruby не должно срабатывать.
        assert!(routes_in_line("  resources :users", "go").is_empty());
    }

    #[test]
    fn aspnet_minimal_api_extracted() {
        assert!(routes_in_line(r#"app.MapGet("/api/x", () => "ok")"#, "cs")
            .iter()
            .any(|r| r == "GET /api/x"));
    }

    #[test]
    fn grpc_proto_routes() {
        let t = TempTree::new("surface");
        t.write(
            "api/svc.proto",
            "service Billing {\n  rpc Charge(ChargeReq) returns (ChargeResp);\n}\n",
        );
        let routes = route_values(t.path());
        assert!(routes.iter().any(|r| r == "RPC Charge"), "{routes:?}");
    }

    #[test]
    fn graphql_query_fields() {
        let t = TempTree::new("surface");
        t.write(
            "schema.graphql",
            "type User { id: ID }\ntype Query {\n  users: [User]\n  user(id: ID): User\n}\n",
        );
        let routes = route_values(t.path());
        // Поля Query извлекаются как операции.
        assert!(routes.iter().any(|r| r == "QUERY users"), "{routes:?}");
        assert!(routes.iter().any(|r| r == "QUERY user"), "{routes:?}");
        // Поле обычного типа User НЕ должно попадать (учёт блока).
        assert!(!routes.iter().any(|r| r == "QUERY id"), "{routes:?}");
    }

    #[test]
    fn existing_spring_mapping_still_works() {
        // Регрессия: @PostMapping/@GetMapping/chi должны остаться рабочими (не ломаем).
        assert!(routes_in_line(r#"@PostMapping("/login")"#, "java")
            .iter()
            .any(|r| r == "POST /login"));
        assert!(routes_in_line(r#"r.Get("/items", h)"#, "go")
            .iter()
            .any(|r| r == "GET /items"));
    }

    // ───────────────────────── T69: расширение сервисов ─────────────────────────

    #[test]
    fn extended_service_schemes() {
        let t = TempTree::new("surface");
        t.write(
            "config.yaml",
            "nats: nats://broker:4222\nes: elasticsearch://es:9200\ndb: postgres://h/db\n",
        );
        let svcs = service_values(t.path());
        assert!(svcs.iter().any(|s| s.starts_with("nats://")), "{svcs:?}");
        assert!(
            svcs.iter().any(|s| s.starts_with("elasticsearch://")),
            "{svcs:?}"
        );
        assert!(
            svcs.iter().any(|s| s.starts_with("postgres://")),
            "{svcs:?}"
        );
    }

    #[test]
    fn env_based_service_dependency() {
        let t = TempTree::new("surface");
        t.write("app.py", "import os\nurl = os.getenv(\"DATABASE_URL\")\n");
        let svcs = service_values(t.path());
        assert!(svcs.iter().any(|s| s == "env:DATABASE_URL"), "{svcs:?}");
    }

    // ───────────────────────── T68: устойчивость к кодировке ─────────────────────────

    #[test]
    fn bom_does_not_hide_first_route() {
        let t = TempTree::new("surface");
        // Файл с ведущим BOM: первый роут на первой строке не должен теряться.
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(br#"app.get("/first", h)"#);
        std::fs::write(t.path().join("server.js"), &bytes).unwrap();
        let routes = route_values(t.path());
        assert!(routes.iter().any(|r| r == "GET /first"), "{routes:?}");
    }

    // ───────────────────────── T70: компиляция статических паттернов ─────────────────────────

    #[test]
    fn all_static_patterns_compile() {
        // Принудительная инициализация всех ленивых таблиц паттернов: опечатка в любом
        // regex упадёт этим тестом, а не паникой MCP-сервера в проде (T70).
        assert!(!route_res().is_empty());
        assert!(!env_res().is_empty());
        assert!(!service_res().is_empty());
        assert!(!model_res().is_empty());
        let _ = service_env_re();
        let _ = gql_field_re();
        let _ = gql_root_re();
        let _ = go_type_re();
        let _ = play_re();
    }
    /// T-05: таблицы встроенных паттернов собираются целиком. Компиляция больше не
    /// завершает процесс, поэтому опечатка в литерале молча уменьшила бы таблицу; тест
    /// делает такую деградацию видимой в непрерывной интеграции.
    #[test]
    fn таблицы_встроенных_паттернов_собираются_целиком() {
        assert!(
            route_res().len() >= 14,
            "правил роутов: {}",
            route_res().len()
        );
        assert!(env_res().len() >= 8, "паттернов ENV: {}", env_res().len());
        assert!(
            service_res().len() >= 6,
            "паттернов сервисов: {}",
            service_res().len()
        );
        assert!(
            model_res().len() >= 10,
            "паттернов моделей: {}",
            model_res().len()
        );
        assert!(gql_field_re().is_some(), "паттерн поля GraphQL собран");
        assert!(gql_root_re().is_some(), "паттерн корня GraphQL собран");
        assert!(service_env_re().is_some(), "паттерн env-сервиса собран");
        assert!(go_type_re().is_some(), "паттерн Go-структуры собран");
        assert!(play_re().is_some(), "паттерн Play-роута собран");
    }
}
