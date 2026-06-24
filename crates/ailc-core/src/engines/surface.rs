//! Извлечение «поверхности» проекта из кода: HTTP-роуты, переменные окружения,
//! внешние сервисы (БД/очереди/хранилища), модели данных.
//!
//! Это НЕ находки (не проблемы) — это ФАКТЫ для спеки и C4-Context: что система
//! принимает на вход (эндпоинты), от чего зависит (сервисы/ENV), какими данными
//! оперирует (модели). Регекс-слой по популярным фреймворкам поверх общего `walk`;
//! генераторы Фазы 3 (`generate/spec`, `generate/c4`, `generate/data-model`) зовут
//! `extract()` напрямую. Тест-файлы пропускаются — документируем продукт, не фикстуры.

use super::scan::SOURCE_CODE;
use super::walk::{ext_of, is_test_path, walk};
use ailc_contracts::{Ctx, Result, RunInput};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::OnceLock;

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
        let mk = |p: &str, method: Method, path_g: usize, require_slash: bool| RouteRe {
            re: Regex::new(p).expect("встроенный паттерн роута валиден"),
            method,
            path_g,
            require_slash,
            exts: &[],
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
            RouteRe {
                re: Regex::new(
                    r#"(?i)\b(?:app|routes)\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']"#,
                )
                .expect("встроенный паттерн Vapor валиден"),
                method: Method::Group(1),
                path_g: 2,
                require_slash: false,
                exts: &["swift"],
            },
            // Kotlin Ktor: routing { get("/users") { … } } — голый метод, путь со «/».
            RouteRe {
                re: Regex::new(r#"\b(get|post|put|delete|patch)\s*\(\s*["'](/[^"']*)["']"#)
                    .expect("встроенный паттерн Ktor валиден"),
                method: Method::Group(1),
                path_g: 2,
                require_slash: false,
                exts: &["kt", "kts"],
            },
            // Go echo: ВЕРХНИЙ регистр метода на любом приёмнике (e.GET, g.POST). Имя
            // переменной у echo произвольно, но методы — заглавные, что отличает их от
            // обычного `obj.get("ключ")` (T69). Применяем только к Go.
            RouteRe {
                re: Regex::new(
                    r#"\b[A-Za-z_]\w*\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["'`]([^"'`]+)["'`]"#,
                )
                .expect("встроенный паттерн echo валиден"),
                method: Method::Group(1),
                path_g: 2,
                require_slash: true,
                exts: &["go"],
            },
            // Express/fiber/chi с ПРОИЗВОЛЬНЫМ именем переменной (не только из белого
            // списка): любой идентификатор, у которого вызывается http-метод нижним
            // регистром с путём, начинающимся со «/» (T69). Слэш отсекает `cache.get`.
            // Ограничено JS/TS-семейством, где такой паттерн идиоматичен, чтобы не ловить
            // `obj.get("/x")` в других языках.
            RouteRe {
                re: Regex::new(
                    r#"\b[A-Za-z_]\w*\.(get|post|put|delete|patch|head|options|all)\s*\(\s*["'`](/[^"'`]*)["'`]"#,
                )
                .expect("встроенный паттерн Express-any валиден"),
                method: Method::Group(1),
                path_g: 2,
                require_slash: true,
                exts: &["js", "jsx", "ts", "tsx", "mjs", "cjs"],
            },
            // Rails resources/resource: resources :users [, only: …]. Метод обобщён до
            // REST-набора пометкой RESOURCES, путь — имя ресурса (T69). Только Ruby.
            RouteRe {
                re: Regex::new(r#"^\s*resources?\s+:([A-Za-z_]\w*)"#)
                    .expect("встроенный паттерн Rails resources валиден"),
                method: Method::Fixed("RESOURCES"),
                path_g: 1,
                require_slash: false,
                exts: &["rb"],
            },
            // ASP.NET Minimal API: app.MapGet("/x", …) / MapPost / MapPut / MapDelete (T69).
            // Только C#.
            RouteRe {
                re: Regex::new(
                    r#"\b[A-Za-z_]\w*\.Map(Get|Post|Put|Delete|Patch)\s*\(\s*["']([^"']+)["']"#,
                )
                .expect("встроенный паттерн Minimal API валиден"),
                method: Method::Group(1),
                path_g: 2,
                require_slash: false,
                exts: &["cs"],
            },
            // gRPC сервис в .proto: rpc MethodName(Req) returns (Resp). Путь — имя метода,
            // метод помечается RPC (T69). Применяем к proto-файлам.
            RouteRe {
                re: Regex::new(r#"^\s*rpc\s+([A-Za-z_]\w*)\s*\("#)
                    .expect("встроенный паттерн gRPC валиден"),
                method: Method::Fixed("RPC"),
                path_g: 1,
                require_slash: false,
                exts: &["proto"],
            },
        ]
    })
}

/// Имя поля верхнего уровня в типе GraphQL Query/Mutation/Subscription (T69). Извлечение
/// GraphQL делается с учётом блока (внутри какого типа находится поле), поэтому реализовано
/// отдельно от построчных `route_res`: иначе поля обычных объектных типов давали бы шум.
fn gql_field_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"^\s*([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*:\s*[A-Za-z_\[]"#)
            .expect("встроенный паттерн поля GraphQL валиден")
    })
}

/// Открытие блока типа GraphQL: `type Query {` / `type Mutation {` (и Subscription).
/// Группа 1 — операционный корень (Query/Mutation/Subscription).
fn gql_root_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"^\s*(?:extend\s+)?type\s+(Query|Mutation|Subscription)\b"#)
            .expect("встроенный паттерн корня GraphQL валиден")
    })
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
        .iter()
        .map(|p| Regex::new(p).expect("встроенный паттерн ENV валиден"))
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
        .iter()
        .map(|p| Regex::new(p).expect("встроенный паттерн сервиса валиден"))
        .collect()
    })
}

/// Имена переменных окружения, чьи ЗНАЧЕНИЯ указывают на внешний сервис (T69):
/// строки подключения и адреса хостов. Само имя такой переменной попадает в `env` через
/// `env_res`, но факт наличия внешней зависимости (например очередь/БД через ENV)
/// дополнительно фиксируется как сервис, чтобы межсервисный взгляд не терял зависимость,
/// сконфигурированную через окружение, а не зашитую URL-строкой.
fn service_env_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // Префикс необязателен (`[A-Z0-9_]*`), чтобы совпадало и голое `DATABASE_URL`,
        // и `MY_DATABASE_URL`. Регистр игнорируется.
        Regex::new(
            r#"(?i)\b([A-Z0-9_]*(?:DATABASE_URL|DB_URL|REDIS_URL|AMQP_URL|KAFKA_BROKERS?|MONGO_URL|RABBITMQ_URL|NATS_URL|SQS_QUEUE_URL|ELASTICSEARCH_URL|ES_URL|BROKER_URL|QUEUE_URL|RABBIT_URL))\b"#,
        )
        .expect("встроенный паттерн env-сервиса валиден")
    })
}

/// (расширение, регекс, группа-имя) для моделей данных.
fn model_res() -> &'static Vec<(&'static str, Regex)> {
    static R: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    R.get_or_init(|| {
        vec![
            ("prisma", Regex::new(r"^\s*model\s+([A-Za-z_]\w*)\s*\{").unwrap()),
            (
                "sql",
                Regex::new(r#"(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?[`"']?([A-Za-z_]\w*)"#)
                    .unwrap(),
            ),
            // Django ORM-модель.
            (
                "py",
                Regex::new(r"^\s*class\s+([A-Za-z_]\w*)\s*\([^)]*models\.Model").unwrap(),
            ),
            // SQLAlchemy declarative (наследование Base).
            (
                "py",
                Regex::new(r"^\s*class\s+([A-Za-z_]\w*)\s*\([^)]*\bBase\b").unwrap(),
            ),
            // Rails ActiveRecord: class X < ApplicationRecord / ActiveRecord::Base.
            (
                "rb",
                Regex::new(r"^\s*class\s+([A-Za-z_]\w*)\s*<\s*(?:ActiveRecord::Base|ApplicationRecord)")
                    .unwrap(),
            ),
            // PHP Eloquent: class X extends Model / Authenticatable.
            (
                "php",
                Regex::new(r"^\s*(?:final\s+|abstract\s+)?class\s+([A-Za-z_]\w*)\s+extends\s+(?:Model|Authenticatable)")
                    .unwrap(),
            ),
            // C# EF Core: DbSet<X> Xs.
            ("cs", Regex::new(r"DbSet<\s*([A-Za-z_]\w*)\s*>").unwrap()),
            // Swift SwiftData/Core Data: @Model [final] class X.
            (
                "swift",
                Regex::new(r"@Model\s+(?:final\s+)?class\s+([A-Za-z_]\w*)").unwrap(),
            ),
            // Dart drift/floor: class X extends Table.
            ("dart", Regex::new(r"^\s*class\s+([A-Za-z_]\w*)\s+extends\s+Table").unwrap()),
            // Scala Slick: class X(...) extends Table.
            (
                "scala",
                Regex::new(r"^\s*(?:final\s+)?class\s+([A-Za-z_]\w*).*extends\s+Table").unwrap(),
            ),
        ]
    })
}

/// Аннотационные/деривные модели данных, где имя на ОТДЕЛЬНОЙ строке от метки
/// (`@Entity`/`#[derive(FromRow)]`). Берём по паре (предыдущая строка, текущая).
/// Покрывает JPA/TypeORM (`@Entity` + class) и Rust sqlx (`derive(FromRow)` + struct).
fn annotation_model(prev: &str, line: &str, ext: &str) -> Option<String> {
    static CLS: OnceLock<Regex> = OnceLock::new();
    static ST: OnceLock<Regex> = OnceLock::new();
    static DSL: OnceLock<Regex> = OnceLock::new();
    let cls = CLS.get_or_init(|| Regex::new(r"\bclass\s+([A-Za-z_]\w*)").unwrap());
    let st = ST.get_or_init(|| Regex::new(r"\bstruct\s+([A-Za-z_]\w*)").unwrap());
    let dsl = DSL.get_or_init(|| Regex::new(r"^\s*([A-Za-z_]\w*)\s*\(").unwrap());
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
fn go_type_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^\s*type\s+([A-Za-z_]\w*)\s+struct\b").unwrap())
}

/// Строка Play-роута в файле conf/routes: «GET   /users   controllers.Users.list».
fn play_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/\S*)").unwrap()
    })
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
            .to_string();
        if is_test_path(&rel) {
            return;
        }
        // Не сканируем СГЕНЕРИРОВАННУЮ документацию: иначе URL сервиса из docs/СПЕЦИФИКАЦИЯ.md
        // попадёт обратно в surface — самозагрязнение и неидемпотентная регенерация.
        // Markdown в принципе не источник поверхности (это проза, не код/конфиг).
        if ext == "md" || ext == "markdown" || rel.starts_with("docs/") || rel.starts_with("docs\\") {
            return;
        }
        let is_source = SOURCE_CODE.contains(&ext);
        // Контрактные схемы межсервисного взаимодействия (gRPC .proto, GraphQL SDL):
        // не входят в SOURCE_CODE, но являются полноценной «поверхностью» сервиса (T69).
        // Роуты из них извлекаем, переменные окружения — нет (там их нет).
        let is_contract = matches!(ext, "proto" | "graphql" | "gql");
        let is_play = path.file_name().and_then(|n| n.to_str()) == Some("routes");

        let mut prev: &str = "";
        let mut go_type: Option<String> = None;
        // Текущий операционный корень GraphQL (Query/Mutation/Subscription) или None вне
        // такого блока. Глубина фигурных скобок отслеживает выход из блока.
        let mut gql_root: Option<String> = None;
        let mut gql_depth: i32 = 0;
        for (i, line) in content.lines().enumerate() {
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
            // Внешний сервис, сконфигурированный через переменную окружения (T69):
            // фиксируем зависимость по характерному имени ENV (DATABASE_URL и так далее).
            if let Some(c) = service_env_re().captures(line) {
                if let Some(m) = c.get(1) {
                    push(2, format!("env:{}", m.as_str()), &mut s.services);
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
                if let Some(c) = go_type_re().captures(line) {
                    go_type = Some(c[1].to_string());
                } else if line.contains("gorm.Model") || line.contains("gorm:\"") {
                    if let Some(name) = go_type.take() {
                        push(3, name, &mut s.models);
                    }
                }
            }
            // Scala Play: роуты в conf/routes (файл без расширения).
            if is_play {
                if let Some(c) = play_re().captures(line) {
                    push(0, format!("{} {}", c[1].to_uppercase(), &c[2]), &mut s.routes);
                }
            }
            // GraphQL SDL: поля внутри type Query/Mutation/Subscription как операции (T69).
            // Учёт блока (а не построчно), чтобы не ловить поля обычных объектных типов.
            if matches!(ext, "graphql" | "gql") {
                if gql_root.is_none() {
                    if let Some(c) = gql_root_re().captures(line) {
                        gql_root = Some(c[1].to_string());
                        gql_depth = line.matches('{').count() as i32
                            - line.matches('}').count() as i32;
                    }
                } else {
                    let opens = line.matches('{').count() as i32;
                    let closes = line.matches('}').count() as i32;
                    // Поле операции на текущем уровне блока.
                    if let Some(c) = gql_field_re().captures(line) {
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
        (a.file.as_str(), a.line, a.value.as_str()).cmp(&(b.file.as_str(), b.line, b.value.as_str()))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    fn tmp() -> std::path::PathBuf {
        let n = CNT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ailc-surface-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }

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
        let dir = tmp();
        write(
            &dir,
            "api/svc.proto",
            "service Billing {\n  rpc Charge(ChargeReq) returns (ChargeResp);\n}\n",
        );
        let routes = route_values(&dir);
        assert!(routes.iter().any(|r| r == "RPC Charge"), "{routes:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn graphql_query_fields() {
        let dir = tmp();
        write(
            &dir,
            "schema.graphql",
            "type User { id: ID }\ntype Query {\n  users: [User]\n  user(id: ID): User\n}\n",
        );
        let routes = route_values(&dir);
        // Поля Query извлекаются как операции.
        assert!(routes.iter().any(|r| r == "QUERY users"), "{routes:?}");
        assert!(routes.iter().any(|r| r == "QUERY user"), "{routes:?}");
        // Поле обычного типа User НЕ должно попадать (учёт блока).
        assert!(!routes.iter().any(|r| r == "QUERY id"), "{routes:?}");
        let _ = fs::remove_dir_all(&dir);
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
        let dir = tmp();
        write(
            &dir,
            "config.yaml",
            "nats: nats://broker:4222\nes: elasticsearch://es:9200\ndb: postgres://h/db\n",
        );
        let svcs = service_values(&dir);
        assert!(svcs.iter().any(|s| s.starts_with("nats://")), "{svcs:?}");
        assert!(
            svcs.iter().any(|s| s.starts_with("elasticsearch://")),
            "{svcs:?}"
        );
        assert!(svcs.iter().any(|s| s.starts_with("postgres://")), "{svcs:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_based_service_dependency() {
        let dir = tmp();
        write(&dir, "app.py", "import os\nurl = os.getenv(\"DATABASE_URL\")\n");
        let svcs = service_values(&dir);
        assert!(svcs.iter().any(|s| s == "env:DATABASE_URL"), "{svcs:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    // ───────────────────────── T68: устойчивость к кодировке ─────────────────────────

    #[test]
    fn bom_does_not_hide_first_route() {
        let dir = tmp();
        // Файл с ведущим BOM: первый роут на первой строке не должен теряться.
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(br#"app.get("/first", h)"#);
        fs::write(dir.join("server.js"), &bytes).unwrap();
        let routes = route_values(&dir);
        assert!(routes.iter().any(|r| r == "GET /first"), "{routes:?}");
        let _ = fs::remove_dir_all(&dir);
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
}
