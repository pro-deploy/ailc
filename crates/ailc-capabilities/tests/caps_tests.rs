//! Тесты capability через реестр (реальный путь). Замораживают: dead_code исключает
//! тесты/использованное, OWASP категоризирует находки A01–A10.

use ailc_contracts::{Ctx, RunInput};
use ailc_core::registry::Registry;
use ailc_testkit::TempTree;

/// Временное дерево-проект с заданными файлами. Возвращает пару из самого дерева и
/// контекста проверки с корнем в этом дереве. Дерево возвращается наружу намеренно: оно
/// убирает свой каталог при разрушении, поэтому обязано быть связано переменной и дожить
/// до конца теста; если его не связать, каталог исчезнет ещё до запуска проверок.
fn tree(files: &[(&str, &str)]) -> (TempTree, Ctx) {
    let t = TempTree::new("caps");
    for (rel, content) in files {
        t.write(rel, content);
    }
    let ctx = t.ctx();
    (t, ctx)
}

fn reg() -> Registry {
    let mut r = Registry::new();
    ailc_capabilities::register_core(&mut r);
    r
}

/// РЕГРЕССИЯ. Сканер секретов обязан читать скрытые файлы из своего allow-list. Режим обхода
/// `WalkMode::Secrets` и список `is_secret_dotfile` существовали, но не были подключены ни к
/// одной capability: `ScanEngine::run` всегда ходил в режиме кода, который отбрасывает все
/// скрытые файлы. Итог проверялся запуском: ключ доступа в `.env` давал «0 находок, вне
/// охвата 1 скрытых», тогда как тот же ключ в обычном файле давал находки. Тест обходчика
/// при этом проходил, потому что проверял обходчик в изоляции, а не через продукт, поэтому
/// эта проверка идёт ЧЕРЕЗ РЕАЛЬНУЮ capability из реестра.
#[test]
fn сканер_секретов_читает_скрытые_файлы_из_allow_list() {
    const AWS: &str = "AKIAZ7QH4D2KLMNP9RS3";
    const NPM: &str = "npm_wJ8kL2mN4pQ6rS8tU0vW2xY4zA6bC8dE0fG2";
    let (_t, ctx) = tree(&[
        ("src/main.rs", "fn main() {}\n"),
        (".env", &format!("AWS_ACCESS_KEY_ID={AWS}\n")),
        (
            ".aws/credentials",
            &format!("[default]\naws_access_key_id = {AWS}\n"),
        ),
        (
            ".npmrc",
            &format!("//registry.npmjs.org/:_authToken={NPM}\n"),
        ),
        // Скрытый файл ВНЕ allow-list читаться не должен: расширять охват на весь
        // служебный мусор мы не собираемся.
        (".eslintrc", &format!("{{\"key\":\"{AWS}\"}}\n")),
    ]);
    let r = reg();
    let out = r
        .get("security.scan/secret")
        .expect("сканер секретов зарегистрирован")
        .run(&ctx, &RunInput::default())
        .expect("сканер отработал");
    let files: Vec<String> = out
        .findings
        .iter()
        .filter_map(|f| f.location.as_ref().map(|l| l.file.clone()))
        .collect();
    for expected in [".env", ".aws/credentials", ".npmrc"] {
        assert!(
            files.iter().any(|f| f.contains(expected)),
            "секрет в {expected} обязан быть найден; найдено: {files:?}"
        );
    }
    assert!(
        !files.iter().any(|f| f.contains(".eslintrc")),
        "скрытый файл вне allow-list не читается: {files:?}"
    );
}

/// Сценарный сэмплер для агента: на PLAN отдаёт заданный план, на REFLECT — «done».
/// Так строгость (strict) и набор инструментов задаются тестом, а не keyword.
struct Scripted {
    plan: String,
}
impl ailc_core::orchestrator::Sampler for Scripted {
    fn sample(&mut self, system: &str, _user: &str) -> Option<String> {
        if system.contains("планировщик") {
            Some(self.plan.clone())
        } else {
            Some("{\"action\":\"done\"}".to_string())
        }
    }
}

/// План из одного шага с заданной строгостью.
fn one_step_plan(id: &str, strict: bool) -> String {
    format!("{{\"steps\":[{{\"id\":\"{id}\",\"why\":\"x\"}}],\"strict\":{strict},\"fix\":false}}")
}

#[test]
fn dead_code_excludes_tests_and_used() {
    // UnusedExport — реально мёртвый; UsedExport — вызывается; TestThing — тест-функция.
    let (_t, ctx) = tree(&[
        ("lib.go", "func UnusedExport(){}\nfunc UsedExport(){}\n"),
        ("use.go", "func caller(){ UsedExport() }\n"),
        ("x_test.go", "func TestThing(){}\n"),
    ]);
    let r = reg();
    let cap = r
        .get("quality.check/dead-code")
        .expect("dead-code зарегистрирован");
    let out = cap.run(&ctx, &RunInput::default()).unwrap();
    let names: Vec<&str> = out.findings.iter().map(|f| f.message.as_str()).collect();
    assert_eq!(out.findings.len(), 1, "ровно один мёртвый: {names:?}");
    assert!(
        out.findings[0].message.contains("UnusedExport"),
        "помечен именно неиспользуемый экспорт, не тест/используемое"
    );
}

#[test]
fn dead_code_excludes_framework_entry_points() {
    // Точка входа фреймворка (Next.js page.tsx) и конфиг сборки вызываются фреймворком,
    // а не кодом, поэтому отсутствие ссылок не делает их мёртвыми. Обычный же
    // неиспользуемый экспорт остаётся кандидатом.
    let (_t, ctx) = tree(&[
        (
            "app/page.tsx",
            "export function HomePage(){ return null }\n",
        ),
        (
            "next.config.ts",
            "export function defineConfig(){ return {} }\n",
        ),
        (
            "util.ts",
            "export function reallyUnusedHelper(){ return 1 }\n",
        ),
    ]);
    let r = reg();
    let cap = r
        .get("quality.check/dead-code")
        .expect("dead-code зарегистрирован");
    let out = cap.run(&ctx, &RunInput::default()).unwrap();
    let msgs: Vec<String> = out.findings.iter().map(|f| f.message.clone()).collect();
    assert!(
        msgs.iter().any(|m| m.contains("reallyUnusedHelper")),
        "обычный неиспользуемый экспорт должен быть кандидатом: {msgs:?}"
    );
    assert!(
        !msgs.iter().any(|m| m.contains("HomePage")),
        "page.tsx это точка входа фреймворка, не мёртвый код: {msgs:?}"
    );
    assert!(
        !msgs.iter().any(|m| m.contains("defineConfig")),
        "*.config.ts это конфиг сборки, не мёртвый код: {msgs:?}"
    );
}

#[test]
fn compliance_ru_detectors() {
    let (_t, ctx) = tree(&[
        ("app.py", "logging.info(\"user passport_number=%s\", p)\nurl = \"x.mongodb.net\"\nt = \"https://www.google-analytics.com/c\"\n"),
        ("form.jsx", "<input type=\"checkbox\" defaultChecked name=\"agree\" />\n"),
        ("safe.py", "logging.info(\"order created id=%s\", oid)\n"),
    ]);
    let r = reg();
    let hit = |id: &str| {
        r.get(id)
            .unwrap()
            .run(&ctx, &RunInput::default())
            .unwrap()
            .findings
            .len()
    };
    assert_eq!(
        hit("compliance.ru/pdn-logs"),
        1,
        "ПДн в логах (не безопасный лог)"
    );
    assert_eq!(hit("compliance.ru/localization"), 1, "зарубежный хост БД");
    assert_eq!(hit("compliance.ru/cross-border"), 1, "иностранный трекер");
    assert_eq!(hit("compliance.ru/consent"), 1, "предзаполненное согласие");
}

#[test]
fn owasp_categorizes_findings() {
    // os.system — паттерн опасного исполнения команды ОС. Голый eval/exec выведен в
    // потоковый сток sast/taint-dynamic-exec, поэтому паттерн dangerous-exec на него
    // больше не реагирует (см. owasp::dangerous-exec).
    let (_t, ctx) = tree(&[("v.py", "x = md5(data)\ny = os.system(code)\n")]);
    let r = reg();
    let cap = r.get("security.scan/owasp").expect("owasp зарегистрирован");
    let out = cap.run(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = out.findings.iter().map(|f| f.rule.as_str()).collect();
    assert!(
        rules.contains(&"weak-hash"),
        "A02 слабый хеш найден: {rules:?}"
    );
    assert!(
        rules.contains(&"dangerous-exec"),
        "A03 опасное исполнение найдено: {rules:?}"
    );
    // матрица A01–A10 присутствует в выводе
    assert!(
        out.records
            .iter()
            .any(|r| r.contains("A01") || r.contains("матрица")),
        "есть матрица OWASP"
    );
}

#[test]
fn secret_scan_catches_new_providers() {
    let (_t, ctx) = tree(&[(
        "config.py",
        concat!(
            "gl = \"glpat-aBcDeFgHiJkLmNoPqRsT\"\n",
            "sl = \"xoxb-291283764418-aGqLkPwR\"\n",
            "sg = \"SG.aBcDeFgHiJkLmNoP.qRsTuVwXyZaBcDeF\"\n",
            "az = \"AccountKey=aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6kM9oR2tU5wX8zA1cD4f==\"\n",
        ),
    )]);
    let r = reg();
    let cap = r
        .get("security.scan/secret")
        .expect("secret зарегистрирован");
    let out = cap.run(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = out.findings.iter().map(|f| f.rule.as_str()).collect();
    for expected in [
        "gitlab-token",
        "slack-token",
        "sendgrid-key",
        "azure-account-key",
    ] {
        assert!(rules.contains(&expected), "{expected} найден: {rules:?}");
    }
}

#[test]
fn test_run_distinguishes_empty_sections_from_no_tests() {
    use ailc_capabilities::some_tests_passed;
    // cargo workspace: юнит-тесты прошли, но doc-test секции печатают «running 0 tests».
    let cargo_mixed =
        "running 13 tests\ntest result: ok. 13 passed; 0 failed\nrunning 0 tests\ntest result: ok. 0 passed; 0 failed";
    assert!(
        some_tests_passed(cargo_mixed),
        "13 passed перевешивает пустые секции"
    );
    // Действительно пустой прогон.
    let empty = "running 0 tests\ntest result: ok. 0 passed; 0 failed";
    assert!(!some_tests_passed(empty), "0 passed = тестов не было");
    // pytest / jest формы.
    assert!(some_tests_passed("==== 7 passed in 0.2s ===="));
    assert!(!some_tests_passed("no tests ran in 0.01s"));
}

#[test]
fn web_security_detectors() {
    // По одной строке на правило: SSRF, отключённый TLS, pickle, SSTI, редирект, путь.
    let (_t, ctx) = tree(&[(
        "web.py",
        concat!(
            "r = requests.get(request.args.get('u'))\n",
            "ctx = ssl._create_unverified_context()\n",
            "data = pickle.loads(blob)\n",
            "html = render_template_string(request.args.get('t'))\n",
            "nxt = redirect(request.args.get('next'))\n",
            "f = open(request.args.get('path'))\n",
        ),
    )]);
    let r = reg();
    let out = r
        .get("security.scan/web")
        .expect("web-сканер зарегистрирован")
        .run(&ctx, &RunInput::default())
        .unwrap();
    let rules: Vec<&str> = out.findings.iter().map(|f| f.rule.as_str()).collect();
    for expected in [
        "ssrf-sink",
        "tls-verify-disabled",
        "insecure-deserialize",
        "ssti",
        "open-redirect",
        "path-traversal",
    ] {
        assert!(rules.contains(&expected), "{expected} найден: {rules:?}");
    }
}

#[test]
fn api_security_detectors() {
    let (_t, ctx) = tree(&[(
        "api.js",
        concat!(
            "const o = { algorithm: 'none' }\n",
            "const s = new ApolloServer({ introspection: true })\n",
            "User.update_attributes(request.body)\n",
        ),
    )]);
    let r = reg();
    let out = r
        .get("security.scan/api")
        .expect("api-сканер зарегистрирован")
        .run(&ctx, &RunInput::default())
        .unwrap();
    let rules: Vec<&str> = out.findings.iter().map(|f| f.rule.as_str()).collect();
    for expected in ["jwt-none-alg", "graphql-introspection", "mass-assignment"] {
        assert!(rules.contains(&expected), "{expected} найден: {rules:?}");
    }
}

#[test]
fn ai_security_detectors() {
    // LLM01: промпт из недоверенного ввода; LLM02: исполнение вывода модели.
    let (_t, ctx) = tree(&[
        (
            "llm.py",
            "resp = openai.ChatCompletion.create(messages=[{\"content\": f\"Do {user_input}\"}])\n",
        ),
        ("agent.py", "out = eval(completion.choices[0].text)\n"),
    ]);
    let r = reg();
    let hit = |id: &str, rule: &str| {
        r.get(id)
            .unwrap()
            .run(&ctx, &RunInput::default())
            .unwrap()
            .findings
            .iter()
            .any(|f| f.rule == rule)
    };
    assert!(
        hit(
            "security.ai/prompt-injection",
            "llm-prompt-untrusted-concat"
        ),
        "промпт-инъекция найдена"
    );
    assert!(
        hit("security.ai/insecure-output", "llm-output-exec"),
        "исполнение вывода LLM найдено"
    );
}

#[test]
fn secret_scan_catches_llm_keys() {
    let (_t, ctx) = tree(&[(
        "keys.py",
        concat!(
            "oai = \"sk-proj-AbCdEfGhIjKlMnOpQrStUv1234\"\n",
            "ant = \"sk-ant-api03-AbCdEfGhIjKlMnOpQr0123\"\n",
        ),
    )]);
    let r = reg();
    let out = r
        .get("security.scan/secret")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    let rules: Vec<&str> = out.findings.iter().map(|f| f.rule.as_str()).collect();
    assert!(rules.contains(&"llm-api-key"), "ключ LLM найден: {rules:?}");
}

#[test]
fn gost_crypto_detector() {
    let (_t, ctx) = tree(&[("crypto.py", "h = hashlib.sha256(data).hexdigest()\n")]);
    let r = reg();
    let out = r
        .get("compliance.ru/gost-crypto")
        .expect("ГОСТ-детектор зарегистрирован")
        .run(&ctx, &RunInput::default())
        .unwrap();
    assert_eq!(out.findings.len(), 1, "иностранная крипта (КИИ) найдена");
    assert_eq!(out.findings[0].rule, "foreign-crypto-primitive");
}

#[test]
fn compliance_pdn_logs_ast_registered_and_runs() {
    let (_t, ctx) = tree(&[(
        "svc.py",
        "logger.info(\n    user.passport\n)\nlogger.info(mask(user.passport))\n",
    )]);
    let r = reg();
    let cap = r
        .get("compliance.ru/pdn-logs-ast")
        .expect("AST-проверка ПДн зарегистрирована");
    let out = cap.run(&ctx, &RunInput::default()).unwrap();
    assert_eq!(
        out.findings.len(),
        1,
        "многострочный лог ПДн найден, маскированный — нет"
    );
    assert_eq!(out.findings[0].rule, "pdn-log-dynamic");
}

#[test]
fn scan_all_collects_and_sarif_reports() {
    use ailc_core::orchestrator::Orchestrator;
    // Сплошной скан собирает находки разных семейств; SARIF их сериализует.
    let (_t, ctx) = tree(&[("web.py", "r = requests.get(request.args.get('u'))\n")]);
    let r = reg();
    let report = Orchestrator::scan_all(&r, &ctx, &RunInput::default());
    assert!(
        report.findings.iter().any(|f| f.rule == "ssrf-sink"),
        "сплошной скан нашёл SSRF: {:?}",
        report
            .findings
            .iter()
            .map(|f| f.rule.as_str())
            .collect::<Vec<_>>()
    );
    let sarif = ailc_core::sarif::to_sarif(
        &report.findings,
        "0.2.0",
        report.refuted,
        report.suppressed,
        &report.checks_run,
        &report.checks_skipped,
    );
    assert!(
        sarif.contains("\"version\": \"2.1.0\""),
        "SARIF версии 2.1.0"
    );
    assert!(sarif.contains("ssrf-sink"), "правило в отчёте");
    assert!(
        sarif.contains("refutedFalsePositives"),
        "честность охвата в properties"
    );
}

#[test]
fn taint_capability_registered_and_runs() {
    // Реальный путь через реестр: capability зарегистрирован и ловит межоператорный поток.
    let (_t, ctx) = tree(&[(
        "svc.py",
        "import os\ndef h():\n    p = request.args.get('p')\n    os.system(p)\n",
    )]);
    let r = reg();
    let out = r
        .get("security.scan/taint")
        .expect("taint зарегистрирован")
        .run(&ctx, &RunInput::default())
        .unwrap();
    assert_eq!(out.findings.len(), 1, "поток источник→сток найден");
    assert_eq!(out.findings[0].rule, "sast/taint-command-exec");
}

#[test]
fn completeness_detects_unfinished() {
    // Заглушки, пустые обработчики, пустая функция — и чистый код без срабатываний.
    let (_t, ctx) = tree(&[
        ("a.rs", "fn a(){ unimplemented!() }\nfn b(){ todo!() }\n"),
        ("k.kt", "fun stub() = TODO()\n"),
        (
            "c.java",
            "void f(){ try { x(); } catch (Exception e) {} }\n",
        ),
        (
            "d.py",
            "def stub(x): pass\ntry:\n    risky()\nexcept ValueError: pass\n",
        ),
        ("clean.go", "func Compute(a int) int { return a + 1 }\n"),
    ]);
    let r = reg();
    let out = r
        .get("quality.check/completeness")
        .expect("completeness зарегистрирован")
        .run(&ctx, &RunInput::default())
        .unwrap();
    let rules: Vec<&str> = out.findings.iter().map(|f| f.rule.as_str()).collect();
    for e in [
        "unimplemented-stub",
        "empty-catch",
        "empty-function",
        "empty-except",
    ] {
        assert!(rules.contains(&e), "{e} найден: {rules:?}");
    }
    // Чистый код не порождает находок недоделанности.
    assert!(
        !out.findings
            .iter()
            .any(|f| f.location.as_ref().is_some_and(|l| l.file == "clean.go")),
        "чистый файл не помечен: {rules:?}"
    );
}

#[test]
fn completeness_stub_in_comment_refuted() {
    use ailc_core::verify::Verifier;
    // Заглушка в КОММЕНТАРИИ ложна (код не исполняется), в коде — реальна.
    let (_t, ctx) = tree(&[(
        "a.rs",
        "// здесь был бы unimplemented!() как пример\nfn real(){ unimplemented!() }\n",
    )]);
    let r = reg();
    let out = r
        .get("quality.check/completeness")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    assert_eq!(
        out.findings.len(),
        2,
        "сырой скан помечает и комментарий, и код"
    );
    let (confirmed, refuted) = Verifier::verify(&ctx, out.findings);
    assert_eq!(
        confirmed.len(),
        1,
        "после verify остаётся только реальная заглушка"
    );
    assert_eq!(refuted.len(), 1, "заглушка в комментарии опровергнута");
}

#[test]
fn undocumented_flags_public_api_without_docs() {
    // Documented — с doc-комментарием; Exported/Another/Third — без; helper — приватный.
    let (_t, ctx) = tree(&[(
        "api.go",
        "// Documented делает дело.\nfunc Documented(){}\nfunc Exported(){}\nfunc Another(){}\nfunc Third(){}\nfunc helper(){}\n",
    )]);
    let r = reg();
    let out = r
        .get("quality.check/undocumented")
        .expect("undocumented зарегистрирован")
        .run(&ctx, &RunInput::default())
        .unwrap();
    assert!(
        out.findings.iter().any(|f| f.rule == "undocumented-api"),
        "низкое покрытие → агрегатная находка: {:?}",
        out.findings
            .iter()
            .map(|f| f.rule.as_str())
            .collect::<Vec<_>>()
    );
    let undoc = out
        .metrics
        .iter()
        .find(|(k, _)| k == "public_symbols")
        .map(|(_, v)| *v);
    assert_eq!(
        undoc,
        Some(4.0),
        "приватный helper не считается публичным API"
    );
}

#[test]
fn unfinished_blocks_on_release_but_warns_midbuild() {
    use ailc_core::agent::AgentOrchestrator;
    let (_t, ctx) = tree(&[("src.rs", "pub fn pay(){ unimplemented!() }\n")]);
    let r = reg();
    // Строгость теперь решает ПЛАН агента (strict), а не keyword в намерении.
    // Мид-билд (strict=false): заглушка — предупреждение, сдавать не мешает.
    let mut s_mid = Scripted {
        plan: one_step_plan("quality.check/completeness", false),
    };
    let mid = AgentOrchestrator::run(
        &r,
        &ctx,
        &RunInput::default(),
        "проверь качество",
        &mut s_mid,
        1,
    );
    assert!(mid.passed, "мид-билд: незавершённое не блокирует");
    assert!(mid.warning >= 1, "но видно как предупреждение");
    // Сдача (strict=true): то же незавершённое БЛОКИРУЕТ.
    let mut s_ship = Scripted {
        plan: one_step_plan("quality.check/completeness", true),
    };
    let ship = AgentOrchestrator::run(
        &r,
        &ctx,
        &RunInput::default(),
        "хочу выкатить",
        &mut s_ship,
        1,
    );
    assert!(!ship.passed, "сдача: незавершённое блокирует");
    assert!(ship.blocking >= 1, "переведено из предупреждения в блокер");
}

#[test]
fn surface_extracts_routes_env_services_models() {
    let (_t, ctx) = tree(&[
        (
            "api.py",
            "import os\n@app.get(\"/users/{id}\")\ndef get_user(id): return id\nDB = os.getenv(\"DATABASE_URL\")\nconn = \"postgres://u:p@db.example.com:5432/app\"\n",
        ),
        ("routes.js", "router.post(\"/login\", h)\nconst k = process.env.SECRET_KEY\n"),
        ("schema.prisma", "model User {\n  id Int @id\n}\n"),
    ]);
    let r = reg();
    let out = r
        .get("code.intel/surface")
        .expect("surface зарегистрирован")
        .run(&ctx, &RunInput::default())
        .unwrap();
    let blob = out.records.join("\n");
    assert!(blob.contains("GET /users/{id}"), "FastAPI роут: {blob}");
    assert!(blob.contains("POST /login"), "Express роут: {blob}");
    assert!(blob.contains("DATABASE_URL"), "ENV python: {blob}");
    assert!(blob.contains("SECRET_KEY"), "ENV js: {blob}");
    assert!(
        blob.contains("db.example.com"),
        "внешний сервис postgres: {blob}"
    );
    assert!(
        !blob.contains("u:p@"),
        "учётные данные сервиса вырезаны: {blob}"
    );
    assert!(blob.contains("User"), "модель данных Prisma: {blob}");
}

#[test]
fn документы_по_стандартам_выпускаются_идемпотентно() {
    let (_t, ctx) = tree(&[
        (
            "src/api.py",
            "import os\n@app.get(\"/items\")\ndef items(): return []\nK = os.getenv(\"API_KEY\")\nDB = \"postgres://u:p@h:5432/db\"\n",
        ),
        ("schema.prisma", "model Item {\n  id Int @id\n}\n"),
    ]);
    let r = reg();
    let gen = r.get("generate/doc").expect("generate/doc зарегистрирован");

    let тз = RunInput {
        target: None,
        query: Some("тз-гост-19".into()),
    };
    let o1 = gen.run(&ctx, &тз).unwrap();
    assert!(!o1.artifacts.is_empty(), "документ создаёт артефакт");
    let doc = std::fs::read_to_string(ctx.root.join("docs/ТЗ-ГОСТ-19.201.md")).unwrap();
    assert!(
        doc.contains("ГОСТ 19.201-78"),
        "документ ссылается на свой стандарт"
    );
    assert!(
        doc.contains("Обозначение документа"),
        "титульные реквизиты обязательны"
    );
    assert!(
        doc.contains("GET /items"),
        "маршрут из кода попал в документ: {doc}"
    );
    assert!(
        doc.contains("h:5432") && !doc.contains("u:p@"),
        "внешний сервис приведён без учётных данных"
    );
    assert!(
        doc.contains("Лист регистрации изменений") && doc.contains("Отметка о полноте"),
        "обязательные части документа на месте"
    );
    assert!(
        !doc.contains("заполни"),
        "заглушек в документе не остаётся, только записи об отсутствии"
    );

    // Идемпотентность: повторный выпуск без изменений кода файл не трогает.
    let o2 = gen.run(&ctx, &тз).unwrap();
    assert!(
        o2.records.iter().any(|s| s.contains("без изменений")),
        "повторный выпуск идемпотентен: {:?}",
        o2.records
    );

    // Модель C4: диаграммы, а не перечни, и с обязательными элементами нотации.
    gen.run(
        &ctx,
        &RunInput {
            target: None,
            query: Some("архитектура-c4".into()),
        },
    )
    .unwrap();
    let c4 = std::fs::read_to_string(ctx.root.join("docs/C4.md")).unwrap();
    assert!(
        c4.contains("```mermaid"),
        "диаграммы выводятся разметкой Mermaid"
    );
    for уровень in [
        "Диаграмма контекста системы",
        "Диаграмма контейнеров",
        "Диаграмма компонентов",
    ] {
        assert!(
            c4.contains(уровень),
            "уровень «{уровень}» обязан присутствовать"
        );
    }
    assert!(
        c4.contains("Легенда"),
        "модель C4 требует легенду для каждой диаграммы"
    );
    assert!(
        c4.contains("[Программная система]") && c4.contains("[Внешняя система]"),
        "тип каждого элемента указан явно: {c4}"
    );
}

#[test]
fn приписка_человека_переживает_регенерацию() {
    let (_t, ctx) = tree(&[("src/a.py", "def feature(): return 1\n")]);
    let r = reg();
    let gen = r.get("generate/doc").unwrap();
    let тз = RunInput {
        target: None,
        query: Some("тз-гост-19".into()),
    };
    gen.run(&ctx, &тз).unwrap();

    // Человек дописывает абзац в отведённую для этого зону документа.
    let p = ctx.root.join("docs/ТЗ-ГОСТ-19.201.md");
    let было = std::fs::read_to_string(&p).unwrap();
    let метка = "<!-- ailc:free:start тз.назначение -->";
    assert!(
        было.contains(метка),
        "в документе есть зона свободной прозы"
    );
    let стало = было.replace(
        метка,
        &format!("{метка}\nСогласовано с заказчиком на совещании."),
    );
    std::fs::write(&p, стало).unwrap();

    gen.run(&ctx, &тз).unwrap();
    let после = std::fs::read_to_string(&p).unwrap();
    assert!(
        после.contains("Согласовано с заказчиком на совещании."),
        "приписка человека обязана пережить регенерацию"
    );
}

#[test]
fn дрейф_различает_отсутствие_устаревание_и_свежесть() {
    let (_t, ctx) = tree(&[(
        "src/api.py",
        "import os\n@app.get(\"/a\")\ndef a(): return 1\n@app.get(\"/b\")\ndef b(): return 2\n@app.get(\"/c\")\ndef c(): return 3\nK=os.getenv(\"X\")\n",
    )]);
    let r = reg();
    let drift = r.get("spec.check/drift").expect("drift зарегистрирован");
    let gen = r.get("generate/doc").unwrap();
    let тз = RunInput {
        target: None,
        query: Some("тз-гост-19".into()),
    };

    // Документа нет: расхождения ещё нет, но отсутствие видно в записях.
    let o1 = drift.run(&ctx, &RunInput::default()).unwrap();
    assert!(
        o1.records.iter().any(|s| s.contains("не выпущен")),
        "невыпущенный документ обязан быть виден: {:?}",
        o1.records
    );

    // Документ выпущен: расхождения нет.
    gen.run(&ctx, &тз).unwrap();
    let o2 = drift.run(&ctx, &RunInput::default()).unwrap();
    assert!(
        !o2.findings
            .iter()
            .any(|f| f.rule == "doc-drift" && f.message.contains("ТЗ-ГОСТ-19.201")),
        "свежевыпущенный документ в расхождении не значится: {:?}",
        o2.records
    );

    // Код изменился: документ разошёлся с ним, и это блокирующая находка, поскольку
    // документ по стандарту, отставший от кода, врёт о системе.
    let api = ctx.root.join("src/api.py");
    let more = std::fs::read_to_string(&api).unwrap() + "@app.delete(\"/d\")\ndef d(): return 4\n";
    std::fs::write(&api, more).unwrap();
    let o3 = drift.run(&ctx, &RunInput::default()).unwrap();
    let находка = o3
        .findings
        .iter()
        .find(|f| f.rule == "doc-drift" && f.message.contains("ТЗ-ГОСТ-19.201"));
    assert!(
        находка.is_some(),
        "после правки кода документ устарел: {:?}",
        o3.records
    );
    assert_eq!(
        находка.unwrap().severity,
        ailc_contracts::Severity::High,
        "расхождение документа с кодом блокирует, а не предупреждает"
    );
}

#[test]
fn feature_design_scaffolds_spec_and_adr() {
    let (_t, ctx) = tree(&[("src/app.py", "def existing(): return 1\n")]);
    let r = reg();
    let cap = r.get("spec/feature").expect("spec/feature зарегистрирован");
    let q = RunInput {
        target: None,
        query: Some("корзина покупок".into()),
    };
    let out = cap.run(&ctx, &q).unwrap();
    assert_eq!(
        out.artifacts.len(),
        2,
        "заготовка спеки + ADR: {:?}",
        out.artifacts
    );
    let doc = std::fs::read_to_string(ctx.root.join("docs/фичи/корзина-покупок.md")).unwrap();
    assert!(doc.contains("Критерии приёмки"), "секция DoD есть");
    assert!(doc.contains("Затрагиваемые части"), "карта кода есть");
    let adr = std::fs::read_to_string(ctx.root.join(".ailc/decisions/1.md")).unwrap();
    assert!(
        adr.contains("## Решение") && adr.contains("корзина покупок"),
        "ADR Nygard"
    );
    // Идемпотентно: повторный вызов не плодит файлы и НЕ создаёт лишний ADR.
    let out2 = cap.run(&ctx, &q).unwrap();
    assert!(
        out2.skipped.is_some(),
        "повторное проектирование не дублирует"
    );
    assert!(
        !ctx.root.join(".ailc/decisions/2.md").exists(),
        "лишний ADR не создан"
    );
}

#[test]
fn surface_extracts_more_frameworks() {
    let (_t, ctx) = tree(&[
        (
            "Ctrl.java",
            "@RequestMapping(value = \"/api/users\", method = RequestMethod.GET)\npublic void users() {}\n",
        ),
        ("ctrl.ts", "@Get(\"profile\")\ngetProfile() {}\n"),
        ("Home.cs", "[HttpPost(\"/login\")]\npublic void Login() {}\n"),
        ("routes.php", "<?php\nRoute::get('/dashboard', 'C@m');\n"),
    ]);
    let r = reg();
    let out = r
        .get("code.intel/surface")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    let blob = out.records.join("\n");
    assert!(
        blob.contains("/api/users"),
        "Spring @RequestMapping: {blob}"
    );
    assert!(blob.contains("profile"), "NestJS @Get: {blob}");
    assert!(blob.contains("/login"), "ASP.NET [HttpPost]: {blob}");
    assert!(blob.contains("/dashboard"), "Laravel Route::get: {blob}");
}

#[test]
fn completeness_stubs_polyglot() {
    // Заглушки по идиомам разных языков + Ruby rescue nil + Dart пустой catch.
    let (_t, ctx) = tree(&[
        (
            "a.js",
            "function f(){ throw new Error(\"not implemented\") }\n",
        ),
        (
            "b.php",
            "<?php\nfunction f(){ throw new \\Exception(\"not implemented\"); }\n",
        ),
        (
            "c.rb",
            "def f\n  raise NotImplementedError\nend\nx = risky() rescue nil\n",
        ),
        ("d.scala", "def f: Int = ???\n"),
        ("e.swift", "func f() { fatalError(\"unimplemented\") }\n"),
        (
            "g.dart",
            "void f() { throw UnimplementedError(); }\ntry { x(); } catch (e) {}\n",
        ),
    ]);
    let r = reg();
    let out = r
        .get("quality.check/completeness")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    let by_file: Vec<String> = out
        .findings
        .iter()
        .filter_map(|f| {
            f.location
                .as_ref()
                .map(|l| format!("{}:{}", l.file, f.rule))
        })
        .collect();
    let blob = by_file.join(" ");
    for (file, rule) in [
        ("a.js", "unimplemented-stub"),
        ("b.php", "unimplemented-stub"),
        ("c.rb", "unimplemented-stub"),
        ("d.scala", "unimplemented-stub"),
        ("e.swift", "unimplemented-stub"),
        ("g.dart", "unimplemented-stub"),
        ("c.rb", "swallowed-rescue"),
        ("g.dart", "empty-catch"),
    ] {
        assert!(
            blob.contains(&format!("{file}:{rule}")),
            "{file} → {rule}: {blob}"
        );
    }
}

#[test]
fn surface_env_and_models_polyglot() {
    let (_t, ctx) = tree(&[
        ("conf.php", "<?php\n$h = getenv(\"DB_HOST\");\n"),
        ("cfg.rb", "s = ENV['SECRET']\n"),
        (
            "Cfg.cs",
            "var t = Environment.GetEnvironmentVariable(\"TOKEN\");\n",
        ),
        (
            "cfg.swift",
            "let u = ProcessInfo.processInfo.environment[\"API_URL\"]\n",
        ),
        ("cfg.dart", "final m = Platform.environment[\"MODE\"];\n"),
        ("cfg.c", "char* p = getenv(\"PATH_VAR\");\n"),
        ("model.rb", "class User < ApplicationRecord\nend\n"),
        ("Account.java", "@Entity\npublic class Account {}\n"),
        (
            "order.rs",
            "#[derive(sqlx::FromRow)]\nstruct Order { id: i32 }\n",
        ),
    ]);
    let r = reg();
    let out = r
        .get("code.intel/surface")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    let blob = out.records.join("\n");
    for needle in [
        "DB_HOST", "SECRET", "TOKEN", "API_URL", "MODE",
        "PATH_VAR", // ENV по 6 языкам
        "User", "Account", "Order", // модели: Rails AR, JPA, sqlx
    ] {
        assert!(blob.contains(needle), "{needle} извлечён: {blob}");
    }
}

#[test]
fn parity_closes_remaining_gaps() {
    let (_t, ctx) = tree(&[
        (
            "impl.cpp",
            "void f() { assert(0 && \"not implemented\"); }\n",
        ),
        (
            "user.go",
            "type User struct {\n  gorm.Model\n  Name string\n}\n",
        ),
        (
            "schema.rs",
            "table! {\n  posts (id) {\n    id -> Int4,\n  }\n}\n",
        ),
        (
            "conf/routes",
            "GET     /health      controllers.Health.check\n",
        ),
        ("routes.swift", "app.get(\"widgets\") { req in [] }\n"),
    ]);
    let r = reg();
    let comp = r
        .get("quality.check/completeness")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    assert!(
        comp.findings.iter().any(|f| f.rule == "unimplemented-stub"
            && f.location.as_ref().is_some_and(|l| l.file == "impl.cpp")),
        "C++ заглушка через assert-сообщение"
    );
    let surf = r
        .get("code.intel/surface")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    let blob = surf.records.join("\n");
    assert!(blob.contains("User"), "Go gorm модель: {blob}");
    assert!(blob.contains("posts"), "diesel модель: {blob}");
    assert!(blob.contains("/health"), "Scala Play роут: {blob}");
    assert!(blob.contains("widgets"), "Swift Vapor роут: {blob}");
}

#[test]
fn стек_проекта_попадает_в_документ() {
    // По одному манифесту на стек: метка обязана попасть в раздел об условиях
    // эксплуатации и о технических средствах, который строится из окружения.
    for (manifest, label) in [
        ("Package.swift", "Swift/SwiftPM"),
        ("build.sbt", "Scala/sbt"),
        ("build.gradle.kts", "Kotlin/Gradle"),
        ("app.csproj", "C#/.NET"), // переменное имя, распознаётся по расширению
        ("CMakeLists.txt", "C/C++ (CMake)"),
    ] {
        let (_t, ctx) = tree(&[(manifest, "x\n"), ("src/m.py", "def f(): return 1\n")]);
        let r = reg();
        r.get("generate/doc")
            .unwrap()
            .run(
                &ctx,
                &RunInput {
                    target: None,
                    query: Some("тз-гост-19".into()),
                },
            )
            .unwrap();
        let doc = std::fs::read_to_string(ctx.root.join("docs/ТЗ-ГОСТ-19.201.md")).unwrap();
        assert!(
            doc.contains(label),
            "{manifest}: стек «{label}» не распознан"
        );
    }
}

#[test]
fn drift_blocks_on_release() {
    use ailc_core::agent::AgentOrchestrator;
    // Существенный проект (≥5 публичных символов) без документации.
    let (_t, ctx) = tree(&[(
        "api.go",
        "package x\nfunc A(){}\nfunc B(){}\nfunc C(){}\nfunc D(){}\nfunc E(){}\n",
    )]);
    let r = reg();
    let mut s_mid = Scripted {
        plan: one_step_plan("spec.check/drift", false),
    };
    let mid = AgentOrchestrator::run(
        &r,
        &ctx,
        &RunInput::default(),
        "проверь качество",
        &mut s_mid,
        1,
    );
    assert!(mid.passed, "мид-билд: отсутствие доков не блокирует");
    let mut s_ship = Scripted {
        plan: one_step_plan("spec.check/drift", true),
    };
    let ship = AgentOrchestrator::run(
        &r,
        &ctx,
        &RunInput::default(),
        "хочу выкатить в прод",
        &mut s_ship,
        1,
    );
    assert!(
        !ship.passed,
        "сдача: устаревшие/отсутствующие доки блокируют"
    );
    assert!(ship.blocking >= 1, "дрейф эскалирован в блокер");
}

#[test]
fn agent_loop_adaptively_calls_more_and_respects_budget() {
    use ailc_core::agent::AgentOrchestrator;
    // PLAN: один шаг. REFLECT: всегда просит довызвать реальный инструмент — петля
    // должна довызвать его, потом СОЙТИСЬ по бюджету (не зациклиться).
    struct Loopy;
    impl ailc_core::orchestrator::Sampler for Loopy {
        fn sample(&mut self, system: &str, _user: &str) -> Option<String> {
            if system.contains("планировщик") {
                Some(one_step_plan("security.scan/secret", false))
            } else {
                Some("{\"action\":\"more\",\"more\":[\"quality.check/smell\"]}".to_string())
            }
        }
    }
    let (_t, ctx) = tree(&[("a.py", "x = 1\n")]);
    let r = reg();
    let mut s = Loopy;
    let ledger = AgentOrchestrator::run(&r, &ctx, &RunInput::default(), "проверь", &mut s, 3);
    assert!(
        ledger.rounds.iter().any(|x| x.contains("довызов")),
        "агент довызвал инструмент: {:?}",
        ledger.rounds
    );
    let exec_rounds = ledger
        .rounds
        .iter()
        .filter(|x| x.starts_with("раунд"))
        .count();
    assert!(
        exec_rounds <= 3,
        "не превысил бюджет раундов: {exec_rounds}"
    );
    assert!(
        ledger.checks.iter().any(|c| c == "security.scan/secret"),
        "запланированный инструмент выполнен: {:?}",
        ledger.checks
    );
}

#[test]
fn surface_coverage_completed_all_langs() {
    let (_t, ctx) = tree(&[
        ("env.scala", "val k = sys.env(\"SECRET_KEY\")\n"),
        ("routes.kt", "fun r() { get(\"/users\") { ok() } }\n"),
        ("User.php", "<?php\nclass User extends Model {}\n"),
        ("Ctx.cs", "public DbSet<Order> Orders { get; set; }\n"),
        ("Item.swift", "@Model final class Item {}\n"),
        (
            "table.scala",
            "class Users(tag: Tag) extends Table[User] {}\n",
        ),
    ]);
    let r = reg();
    let blob = r
        .get("code.intel/surface")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap()
        .records
        .join("\n");
    assert!(blob.contains("SECRET_KEY"), "Scala sys.env: {blob}");
    assert!(blob.contains("/users"), "Kotlin Ktor роут: {blob}");
    for m in ["User", "Order", "Item", "Users"] {
        assert!(blob.contains(m), "модель {m}: {blob}");
    }
}

#[test]
fn store_memory_and_backlog_roundtrip() {
    let (_t, ctx) = tree(&[]);
    let r = reg();
    let q = |s: &str| RunInput {
        target: None,
        query: Some(s.into()),
    };
    assert!(
        !r.get("memory/update")
            .unwrap()
            .run(&ctx, &q("важный факт о проекте"))
            .unwrap()
            .artifacts
            .is_empty(),
        "заметка записана на диск"
    );
    let rd = r
        .get("memory/read")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    assert!(
        rd.records.iter().any(|x| x.contains("важный факт")),
        "заметка прочитана: {:?}",
        rd.records
    );
    r.get("backlog/add")
        .unwrap()
        .run(&ctx, &q("сделать корзину"))
        .unwrap();
    let lst = r
        .get("backlog/list")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    assert!(
        lst.records.iter().any(|x| x.contains("сделать корзину")),
        "задача в бэклоге: {:?}",
        lst.records
    );
    assert!(
        !r.get("memory/decision-log")
            .unwrap()
            .run(&ctx, &q("решили использовать Postgres"))
            .unwrap()
            .artifacts
            .is_empty(),
        "решение записано"
    );
}

#[test]
fn workflow_adr_branchname_setup() {
    let (_t, ctx) = tree(&[("src/a.go", "package x\nfunc A(){}\n")]);
    let r = reg();
    let q = |s: &str| RunInput {
        target: None,
        query: Some(s.into()),
    };
    r.get("generate/adr")
        .unwrap()
        .run(&ctx, &q("Выбор хранилища"))
        .unwrap();
    let adr = std::fs::read_to_string(ctx.root.join(".ailc/decisions/1.md")).unwrap();
    assert!(
        adr.contains("Выбор хранилища") && adr.contains("## Решение"),
        "ADR Nygard: {adr}"
    );
    let bn = r
        .get("deliver/branch-name")
        .unwrap()
        .run(&ctx, &q("Сделать корзину покупок"))
        .unwrap();
    assert!(
        bn.records.iter().any(|x| x.contains("korzin")),
        "слаг ветки: {:?}",
        bn.records
    );
    assert!(
        !r.get("setup/init")
            .unwrap()
            .run(&ctx, &RunInput::default())
            .unwrap()
            .artifacts
            .is_empty(),
        "setup/init развернул скелет .ailc"
    );
}

#[test]
fn governance_constitution_and_layers() {
    let (_t, ctx) = tree(&[
        (".ailc/constitution.md", "FORBID eval(\n"),
        ("app.py", "x = eval(user_input)\n"),
    ]);
    let r = reg();
    let cons = r
        .get("quality.check/constitution")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    assert!(
        cons.findings
            .iter()
            .any(|f| f.message.to_lowercase().contains("eval") || f.rule.contains("forbid")),
        "конституция поймала FORBID: {:?}",
        cons.findings
            .iter()
            .map(|f| f.rule.as_str())
            .collect::<Vec<_>>()
    );
    let lay = r
        .get("quality.check/layers")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    assert!(
        lay.skipped.is_some(),
        "нет .ailc/layers.txt → явный skip, не молчание"
    );
}

#[test]
fn diagram_generates_mermaid() {
    let (_t, ctx) = tree(&[
        ("core/a.go", "package core\nfunc A(){}\n"),
        (
            "api/b.go",
            "package api\nimport \"core\"\nfunc B(){ core.A() }\n",
        ),
    ]);
    let r = reg();
    assert!(
        !r.get("code.intel/diagram")
            .unwrap()
            .run(&ctx, &RunInput::default())
            .unwrap()
            .records
            .is_empty(),
        "диаграмма-просмотр непуста"
    );
    r.get("generate/diagram")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    let md = std::fs::read_to_string(ctx.root.join("docs/ДИАГРАММА.md")).unwrap();
    assert!(md.contains("mermaid"), "mermaid-блок в ДИАГРАММА.md");
}

#[test]
fn mobile_desktop_recognize_stacks() {
    let r = reg();
    let (_t1, ctx_m) = tree(&[("pubspec.yaml", "name: app\ndependencies:\n  flutter:\n")]);
    let m = r
        .get("verify/mobile")
        .unwrap()
        .run(&ctx_m, &RunInput::default())
        .unwrap();
    let mt = format!("{} {}", m.summary, m.skipped.unwrap_or_default());
    assert!(!mt.contains("не распознан"), "mobile распознал стек: {mt}");
    let (_t2, ctx_d) = tree(&[("App.csproj", "<Project></Project>\n")]);
    let d = r
        .get("verify/desktop")
        .unwrap()
        .run(&ctx_d, &RunInput::default())
        .unwrap();
    let dt = format!("{} {}", d.summary, d.skipped.unwrap_or_default());
    assert!(!dt.contains("не распознан"), "desktop распознал стек: {dt}");
}

#[test]
fn thresholds_come_from_policy() {
    // Кастомный порог вложенности из ailc.policy.toml меняет поведение (governance-данные).
    let (_t, ctx) = tree(&[
        (
            "ailc.policy.toml",
            "name = \"strict\"\n[thresholds]\nmax_nesting = 2\n",
        ),
        (
            "deep.go",
            "package x\nfunc f() {\n\tif a {\n\t\tif b {\n\t\t\tif c { x() }\n\t\t}\n\t}\n}\n",
        ),
    ]);
    let r = reg();
    let strict = r
        .get("quality.check/antipattern")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    assert!(
        strict.findings.iter().any(|f| f.rule == "deep-nesting"),
        "порог max_nesting=2 ловит вложенность 3 (при дефолте 6 — не ловил бы): {:?}",
        strict
            .findings
            .iter()
            .map(|f| f.rule.as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn api_break_detects_removed_public_symbol() {
    let (_t, ctx) = tree(&[("lib.go", "package x\nfunc Alpha(){}\nfunc Beta(){}\n")]);
    let r = reg();
    // Снимок: Alpha + Beta.
    r.get("generate/api-baseline")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    // Удаляем Beta — слом контракта.
    std::fs::write(ctx.root.join("lib.go"), "package x\nfunc Alpha(){}\n").unwrap();
    let out = r
        .get("verify/api-break")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    assert!(
        out.findings
            .iter()
            .any(|f| f.rule == "api-break" && f.message.contains("Beta")),
        "удаление публичного Beta поймано: {:?}",
        out.findings
            .iter()
            .map(|f| f.message.as_str())
            .collect::<Vec<_>>()
    );
    // Без снимка — честный skip, не молчание.
    let (_t2, ctx2) = tree(&[("a.go", "package x\nfunc A(){}\n")]);
    assert!(
        r.get("verify/api-break")
            .unwrap()
            .run(&ctx2, &RunInput::default())
            .unwrap()
            .skipped
            .is_some(),
        "без baseline — явный skip"
    );
}

#[test]
fn diff_scope_skips_without_git() {
    let (_t, ctx) = tree(&[("a.go", "package x\nfunc A(){}\n")]);
    let r = reg();
    let out = r
        .get("code.intel/diff-scope")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    // Не git-репозиторий → явный skip (нет молчаливого пропуска).
    assert!(
        out.skipped.is_some(),
        "вне git — явный skip: {:?}",
        out.summary
    );
}

#[test]
fn sbom_from_lockfile() {
    let (_t, ctx) = tree(&[(
        "Cargo.lock",
        "[[package]]\nname = \"foo\"\nversion = \"1.2.3\"\n",
    )]);
    let r = reg();
    r.get("generate/sbom")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    let sbom = std::fs::read_to_string(ctx.root.join("sbom.json")).unwrap();
    assert!(
        sbom.contains("CycloneDX") && sbom.contains("pkg:cargo/foo@1.2.3"),
        "SBOM: {sbom}"
    );
}

#[test]
fn licenses_flag_copyleft() {
    let (_t, ctx) = tree(&[(
        "package-lock.json",
        r#"{"packages":{"":{},"node_modules/gpl-lib":{"version":"1.0.0","license":"GPL-3.0"},"node_modules/ok-lib":{"version":"2.0.0","license":"MIT"}}}"#,
    )]);
    let r = reg();
    let out = r
        .get("security.scan/licenses")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    assert!(
        out.findings
            .iter()
            .any(|f| f.rule == "copyleft-license" && f.message.contains("gpl-lib")),
        "GPL помечен: {:?}",
        out.findings
            .iter()
            .map(|f| f.message.as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn cicd_creates_workflow() {
    let (_t, ctx) = tree(&[]);
    let r = reg();
    r.get("setup/cicd")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    let wf = std::fs::read_to_string(ctx.root.join(".github/workflows/ailc.yml")).unwrap();
    assert!(
        wf.contains("ailc dod") && wf.contains("sarif"),
        "workflow: {wf}"
    );
}

#[test]
fn release_notes_skips_without_git() {
    let (_t, ctx) = tree(&[("a.rs", "fn main(){}\n")]);
    let r = reg();
    let out = r
        .get("generate/release-notes")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    assert!(
        out.skipped.is_some(),
        "вне git — явный skip: {:?}",
        out.summary
    );
}

// Контролируемый бенчмарк по ВСЕМ семействам на реалистичном коде (без синтетических
// opaque-предикатов). Измеряет TP/FP/FN/TN, делая упор на false-positive rate на
// безопасном коде — ключевое заявление ailc. Реальный путь: scan_all (+verify) и taint.
// Тест ВЫПОЛНЯЕТСЯ в непрерывной интеграции. Прежде он был помечен `#[ignore]` и потому
// не запускался никогда, а на момент включения оказался красным: обнаружился пропуск
// канонической инъекции кода `x = eval(user_input)`. Скрытая метрика точности хуже
// отсутствующей, поскольку создаёт видимость измерения, поэтому пометка снята, пропуск
// устранён, а сама метрика печатается в журнале сборки.
//   cargo test -p ailc-capabilities --test caps_tests _bench_controlled -- --nocapture
#[test]
fn _bench_controlled() {
    use ailc_core::orchestrator::Orchestrator;
    use std::collections::BTreeMap;
    // (группа, файл, содержимое, ожидаем_находку, через_taint)
    let cases: &[(&str, &str, &str, bool, bool)] = &[
        // ── уязвимые (ждём находку) ──
        ("secret", "c.py", "aws = \"AKIAZ3KQ9XF7TYVBNW2P\"\n", true, false),
        ("secret", "k.py", "oai = \"sk-proj-aB3xK9qLzR7tWvN8mP4dF6hJ2sQ\"\n", true, false),
        ("web", "w.py", "import requests\nx = requests.get(request.args.get('u'))\n", true, false),
        ("owasp", "o.py", "x = eval(user_input)\n", true, false),
        ("iac", "d.yaml", "spec:\n  containers:\n  - securityContext:\n      privileged: true\n", true, false),
        ("inject", "i.js", "el.innerHTML = userData\n", true, false),
        ("compliance", "p.py", "import logging\nlogging.info(\"user passport_number=%s\", p)\n", true, false),
        ("pii", "s.go", "ssn := \"123-45-6789\"\n", true, false),
        ("taint", "tv.py", "import os\ndef h():\n    c = request.args.get('c')\n    os.system(c)\n", true, true),
        ("taint", "tv.php", "<?php\nfunction h(){ system($_GET['c']); }\n", true, true),
        ("taint", "tv.go", "func h(r *Request){\n  n := r.FormValue(\"n\")\n  exec.Command(\"sh\",\"-c\",n)\n}\n", true, true),
        ("taint", "tv.java", "class C{ void v(HttpServletRequest req){ String c=req.getParameter(\"c\"); Runtime.getRuntime().exec(c); } }\n", true, true),
        // Новые классы правил: каждый представлен и уязвимым, и безопасным случаем,
        // поэтому расширение покрытия сразу отражается в измеряемой точности.
        ("owasp", "tc.py", "if token == provided:\n    grant()\n", true, false),
        ("owasp", "iv.js", "const iv = \"0123456789abcdef\";\n", true, false),
        ("owasp", "zs.py", "import zipfile\nwith zipfile.ZipFile(src) as z:\n    z.extractall(dest)\n", true, false),
        ("owasp", "wp.py", "import os\nos.chmod(path, 0o777)\n", true, false),
        ("owasp", "tf.py", "path = \"/tmp/upload.dat\"\n", true, false),
        ("owasp", "sri.html", "<script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>\n", true, false),

        ("owasp", "hdr.js", "app.use(helmet({ contentSecurityPolicy: false }))\n", true, false),
        ("owasp", "nsq.js", "User.findOne(req.body)\n", true, false),
        ("owasp", "lgi.js", "logger.info(\"вход: \" + req.query.user)\n", true, false),
        ("owasp", "kdf.py", "kdf = PBKDF2(password, salt, iterations=1000)\n", true, false),
        ("owasp", "jwtx.js", "jwt.verify(token, secret, { ignoreExpiration: true })\n", true, false),

        ("owasp", "crlf.js", "res.setHeader('Location', req.query.next)\n", true, false),
        ("owasp", "sid.js", "const url = \"/panel?session_id=\" + sid;\n", true, false),
        ("owasp", "rl.js", "const opts = { rateLimit: false };\n", true, false),
        ("owasp", "trace.js", "res.status(500).send(err.stack)\n", true, false),
        ("owasp", "idx.conf", "location / {\n    autoindex on;\n}\n", true, false),
        ("owasp", "pin.yml", "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@main\n", true, false),

        ("ai", "lp.py", "import openai\nopenai.chat.completions.create(messages=[{\"role\":\"user\",\"content\": f\"ключ {api_key}\"}])\n", true, false),
        ("ai", "la.py", "resp = client.messages.create(model=m)\nopen(\"out.txt\", \"w\").write(resp.content)\n", true, false),
        ("cpp", "io.c", "void f(size_t n, size_t w){ char *b = malloc(n * w); }\n", true, false),
        ("cpp", "nd.c", "void f(size_t n){ char *p = malloc(n);\n*q = 'x';\n}\n", true, false),
        ("race", "tt.py", "import os\nif os.path.exists(path):\n    open(path, 'w').write(data)\n", true, false),

        // ── безопасные (НЕ должны срабатывать — тест на ложные) ──
        ("secret", "s1.py", "password = \"changeme\"\n", false, false),
        ("secret", "s2.py", "api_key = \"your_api_key_here\"\n", false, false),
        ("secret", "s3.py", "# пример: aws = \"AKIAIOSFODNN7EXAMPLE\"\n", false, false),
        ("web", "sw.py", "import requests\nx = requests.get(\"https://api.example.com/v1\")\n", false, false),
        ("owasp", "so.py", "result = compute(a, b)\n", false, false),
        ("iac", "sd.yaml", "spec:\n  securityContext:\n    runAsNonRoot: true\n", false, false),
        ("inject", "si.js", "el.textContent = userData\n", false, false),
        ("compliance", "sp.py", "import logging\nlogging.info(\"order id=%s\", oid)\n", false, false),
        ("owasp", "stc.py", "import hmac\nif hmac.compare_digest(token, provided):\n    grant()\n", false, false),
        ("owasp", "siv.js", "const iv = crypto.randomBytes(16);\n", false, false),
        ("owasp", "szs.py", "import os\np = os.path.realpath(os.path.join(dest, name))\nif not p.startswith(dest):\n    raise ValueError(\"обход каталога\")\n", false, false),
        ("owasp", "swp.py", "import os\nos.chmod(path, 0o600)\n", false, false),
        ("owasp", "stf.py", "import tempfile\nwith tempfile.NamedTemporaryFile() as f:\n    f.write(data)\n", false, false),
        ("owasp", "ssri.html", "<script src=\"/static/app.js\"></script>\n", false, false),
        ("owasp", "shdr.js", "app.use(helmet())\n", false, false),
        ("owasp", "snsq.js", "User.findOne({ name: String(req.body.name) })\n", false, false),
        ("owasp", "slgi.js", "logger.info(\"вход: %s\", user)\n", false, false),
        ("owasp", "skdf.py", "kdf = PBKDF2(password, salt, iterations=210000)\n", false, false),
        ("owasp", "sjwt.js", "jwt.verify(token, secret)\n", false, false),
        ("owasp", "scrlf.js", "res.setHeader('Cache-Control', 'no-store')\n", false, false),
        ("owasp", "ssid.js", "const url = \"/panel?page=2&sort=name\";\n", false, false),
        ("owasp", "srl.js", "const opts = { rateLimit: { max: 5 } };\n", false, false),
        ("owasp", "strace.js", "res.status(500).send('внутренняя ошибка')\n", false, false),
        ("owasp", "sidx.conf", "location / {\n    autoindex off;\n}\n", false, false),
        // Безопасный образец рабочего процесса ЗАКРЕПЛЁН ПО ОТПЕЧАТКУ КОММИТА. Прежде
        // здесь стояла подвижная метка `@v4`, и образец считался безопасным. С появлением
        // правила `ci-action-unpinned` это стало неверным: подмена содержимого метки
        // меняет исполняемый код без изменения рабочего процесса, что и есть класс
        // CWE-494. Образец приведён к действительно безопасному виду, а подвижная метка
        // вынесена отдельным положительным случаем ниже.
        (
            "owasp",
            "spin.yml",
            "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3\n",
            false,
            false,
        ),
        (
            "ci",
            "vunpin.yml",
            "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n",
            true,
            false,
        ),
        (
            "ci",
            "vevent.yml",
            "on: issues\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n",
            true,
            false,
        ),
        (
            "ci",
            "sci.yml",
            "on: pull_request\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test\n",
            false,
            false,
        ),
        // Хост образца НАМЕРЕННО не из документационных доменов: верификатор опровергает
        // находки на `example.com` и `example.test`, справедливо считая их образцами из
        // документации, и уязвимый случай тогда учитывался бы как пропуск.
        (
            "shell",
            "vsh.sh",
            "#!/bin/sh\ncurl -k https://cdn.acme.io/install.sh | sh\n",
            true,
            false,
        ),
        (
            "shell",
            "ssh.sh",
            "#!/bin/sh\nset -e\ntmp=$(mktemp)\ncurl -fsSL https://example.test/f -o \"$tmp\"\n",
            false,
            false,
        ),
        (
            "tf",
            "vtf.tf",
            "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\n",
            true,
            false,
        ),
        (
            "tf",
            "stf.tf",
            "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"private\"\n}\n",
            false,
            false,
        ),
        ("ai", "slp.py", "import openai\nopenai.chat.completions.create(messages=[{\"role\":\"user\",\"content\": text}])\n", false, false),
        ("ai", "sla.py", "resp = client.messages.create(model=m)\nif resp.content in allow_list:\n    apply(resp.content)\n", false, false),
        ("cpp", "sio.c", "void f(size_t len){ char *b = malloc(len); }\n", false, false),
        ("cpp", "snd.c", "void f(size_t n){ char *p = malloc(n);\nif (p == NULL) return;\n*p = 'x';\n}\n", false, false),
        ("race", "stt.py", "import tempfile\nwith tempfile.NamedTemporaryFile() as f:\n    f.write(data)\n", false, false),
        ("pii", "ss.go", "count := computeTotal()\n", false, false),
        ("taint", "ts.py", "import os, shlex\ndef h():\n    c = request.args.get('c')\n    os.system(shlex.quote(c))\n", false, true),
        ("taint", "ts2.py", "import os\ndef h():\n    c = \"ls\"\n    os.system(c)\n", false, true),
        ("taint", "ts.java", "class C{ void v(java.sql.Connection con){ con.prepareStatement(\"SELECT * FROM t WHERE id=?\"); } }\n", false, true),
    ];

    let r = reg();
    let mut stats: BTreeMap<&str, [u64; 4]> = BTreeMap::new(); // [TP,FP,FN,TN]
    let mut misses: Vec<String> = Vec::new();
    for (group, file, content, expect, use_taint) in cases {
        let (_t, ctx) = tree(&[(file, content)]);
        let flagged = if *use_taint {
            !r.get("security.scan/taint")
                .unwrap()
                .run(&ctx, &RunInput::default())
                .unwrap()
                .findings
                .is_empty()
        } else {
            !Orchestrator::scan_all(&r, &ctx, &RunInput::default())
                .findings
                .is_empty()
        };
        let e = stats.entry(group).or_insert([0; 4]);
        match (*expect, flagged) {
            (true, true) => e[0] += 1,
            (false, true) => {
                e[1] += 1;
                misses.push(format!("ЛОЖНОЕ (FP): {file} ({group})"));
            }
            (true, false) => {
                e[2] += 1;
                misses.push(format!("ПРОПУСК (FN): {file} ({group})"));
            }
            (false, false) => e[3] += 1,
        }
    }

    eprintln!("\n=== Контролируемый бенчмарк ailc (реалистичный код, через scan_all+verify) ===");
    let prow = |k: &str, e: &[u64; 4]| {
        let (tp, fp, fn_, tn) = (e[0] as f64, e[1] as f64, e[2] as f64, e[3] as f64);
        let rec = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 1.0 };
        let fpr = if fp + tn > 0.0 { fp / (fp + tn) } else { 0.0 };
        eprintln!(
            "{k:<12} TP={} FP={} FN={} TN={} | recall={:>5.1}% FPR={:>5.1}%",
            e[0],
            e[1],
            e[2],
            e[3],
            rec * 100.0,
            fpr * 100.0
        );
    };
    let mut tot = [0u64; 4];
    for (k, e) in &stats {
        for i in 0..4 {
            tot[i] += e[i];
        }
        prow(k, e);
    }
    prow("ИТОГО", &tot);
    for m in &misses {
        eprintln!("  ⚠ {m}");
    }
    // На реалистичном корпусе ailc должен быть идеален: всё уязвимое найдено, ноль ложных.
    assert_eq!(
        tot[1], 0,
        "false-positive на реалистичном безопасном коде: {misses:?}"
    );
    assert_eq!(tot[2], 0, "пропуск реальной уязвимости: {misses:?}");
}

/// T-13 и T-14: документация не должна расходиться с кодом.
///
/// README называет конкретные числа (объём каталога возможностей, число правил поиска
/// секретов) и конкретные идентификаторы инструментов. Раньше эти сведения
/// поддерживались вручную и разошлись: в тексте значились несуществующие
/// `security.scan/mobile` и `security.scan/desktop`, тридцать одно правило секретов при
/// фактических двадцати восьми и семьдесят четыре возможности при фактических
/// семидесяти шести. Настоящий тест делает расхождение невозможным: он читает README и
/// сверяет его с реестром. При осознанном изменении состава возможностей README
/// обновляется вместе с кодом, иначе тест падает.
#[test]
fn readme_matches_registry() {
    let readme = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md"),
    )
    .expect("README.md должен читаться");

    let r = reg();
    let ids: Vec<&str> = r.all().iter().map(|c| c.manifest().id).collect();
    // Префиксы реальных идентификаторов («security.scan», «quality.check», «verify» и
    // прочие) отличают упоминание инструмента от пути к файлу или маски вида `security.ai/*`.
    let prefixes: std::collections::BTreeSet<&str> =
        ids.iter().filter_map(|id| id.split('/').next()).collect();

    let mut unknown: Vec<String> = Vec::new();
    for raw in readme.split('`') {
        let cand = raw.trim();
        let Some((prefix, _)) = cand.split_once('/') else {
            continue;
        };
        if cand.ends_with('*') || !prefixes.contains(prefix) {
            continue;
        }
        if !ids.contains(&cand) {
            unknown.push(cand.to_string());
        }
    }
    unknown.sort();
    unknown.dedup();
    assert!(
        unknown.is_empty(),
        "README упоминает идентификаторы, которых нет в реестре: {unknown:?}"
    );

    let caps = ids.len();
    // Форма слова после числительного зависит от самого числительного («из 80
    // возможностей», но «из 81 возможности»), поэтому сверяется само число, а не
    // фиксированная фраза целиком: инвариант в том, что README называет фактический
    // размер каталога, а не в том, каким падежом он это делает.
    assert!(
        readme.contains(&format!("каталог из {caps} возможност")),
        "README должен называть фактический размер каталога: {caps}"
    );
    let rules = ailc_capabilities::secret_rule_count();
    assert!(
        readme.contains(&format!("по {rules} правилам")),
        "README должен называть фактическое число правил поиска секретов: {rules}"
    );
}

/// T-05: ни одно встроенное правило не выключено из-за несобравшегося паттерна.
///
/// Компиляция паттернов больше не завершает процесс: невалидный литерал выключает своё
/// правило (`Matcher::Never`), поскольку обрыв сеанса среды разработки из-за опечатки
/// несоизмерим с ценой пропуска одной проверки. Чтобы такая деградация не осталась
/// незамеченной, полнота проверяется здесь: опечатка валит непрерывную интеграцию, а не
/// работу пользователя.
#[test]
fn ни_одно_встроенное_правило_не_выключено() {
    // Проверяются ВСЕ публичные сканеры, а не один: именно так ловится опечатка в
    // литерале нового правила. Урок из практики: правило с обратной ссылкой в паттерне
    // (крейт `regex` их не поддерживает) молча выключалось, и заметил это лишь тест
    // самого правила. Теперь такую поломку ловит общий тест полноты.
    let scanners: Vec<(&str, ailc_capabilities::ScanCapability)> = vec![
        ("security.scan/secret", ailc_capabilities::secret_scan()),
        ("security.scan/pii", ailc_capabilities::pii_scan()),
        ("security.scan/web", ailc_capabilities::web_scan()),
        ("security.scan/api", ailc_capabilities::api_scan()),
        (
            "security.scan/injection",
            ailc_capabilities::injection_scan(),
        ),
        ("security.scan/iac", ailc_capabilities::iac_scan()),
        (
            "security.ai/prompt-injection",
            ailc_capabilities::prompt_injection_scan(),
        ),
        (
            "security.ai/insecure-output",
            ailc_capabilities::insecure_output_scan(),
        ),
    ];
    let mut disabled: Vec<String> = Vec::new();
    for (id, cap) in &scanners {
        for rule in cap.rules() {
            if rule.matcher.is_disabled() {
                disabled.push(format!("{id}:{}", rule.id));
            }
        }
    }
    // Категорийный набор OWASP (A01–A10) регистрируется отдельным модулем, а не через
    // `ScanCapability`, поэтому его правила берутся напрямую из таблицы модуля. Прежде здесь
    // проверялся плоский `owasp_scan`, который в реестр НЕ попадал: тест полноты охранял код,
    // отсутствующий в продукте, а живые 43 правила OWASP не проверялись вовсе.
    for rule in ailc_capabilities::owasp::rules() {
        if rule.matcher.is_disabled() {
            disabled.push(format!("security.scan/owasp:{}", rule.id));
        }
    }
    assert!(
        disabled.is_empty(),
        "паттерны этих правил не скомпилировались: {disabled:?}"
    );
}

/// Таблицы движков не должны схлопываться из-за невалидных литералов: пустая или
/// подозрительно короткая таблица означает, что проверки молча деградировали.
#[test]
fn таблицы_паттернов_движков_не_пусты() {
    let r = reg();
    let secret = r
        .get("security.scan/secret")
        .expect("сканер секретов зарегистрирован");
    // Дерево связывается отдельной переменной, а не передаётся временным значением: временное
    // дерево убирает свой каталог при разрушении, и внутри одного выражения оно исчезло бы
    // раньше, чем сканер успел бы прочитать образец.
    let (_t, ctx) = tree(&[("conf.env", "AWS=AKIAZ3KQ9XF7TYVBNW2P\n")]);
    let out = secret
        .run(&ctx, &RunInput::default())
        .expect("сканер отрабатывает");
    assert!(
        out.findings.iter().any(|f| f.rule == "aws-access-key"),
        "правило точной формы токена обязано работать: {:?}",
        out.findings
    );
}

// ───────── Полнота классификации достоверности: выводится ИЗ КОДА, а не из списка ─────────

/// Семейства capability: идентификатор вида `семейство/имя` является идентификатором
/// CAPABILITY, а не правила, и класса достоверности не требует.
const CAPABILITY_FAMILIES: &[&str] = &[
    "code.intel",
    "security.scan",
    "security.ai",
    "quality.check",
    "quality.ui",
    "verify",
    "spec",
    "spec.check",
    "generate",
    "backlog",
    "memory",
    "deliver",
    "setup",
    "governance",
    "compliance.ru",
];

/// Собрать все идентификаторы правил, которые код РЕАЛЬНО излучает.
///
/// Источником служит сам исходный код, а не рукописный перечень, и это принципиально.
/// Прежде полнота классификации проверялась обходом константы `KNOWN_RULES` в
/// `ailc-contracts`, то есть РУЧНОЙ КОПИИ имён правил. Такой тест вакуумен по построению:
/// правило, забытое в карте достоверности, столь же вероятно забыто и в копии, поэтому
/// проверка проходила, а правило молча получало достоверность Medium и попадало в вердикт
/// как сигнал. Измерение показало масштаб: 78 излучаемых правил не имели класса вовсе.
///
/// Вывести перечень из типов невозможно: `ailc-contracts` не видит правил, поскольку
/// зависимость направлена от возможностей к контрактам, а не наоборот, и часть правил
/// вообще не описана таблицами (модули строят находки напрямую). Поэтому источником истины
/// берётся текст исходников: он не может разойтись с тем, что исполняется.
///
/// Тестовые области (`#[cfg(test)]`) отсекаются: в фикстурах встречаются выдуманные имена
/// правил. В этом репозитории таблицы правил всегда объявлены ДО тестового модуля файла,
/// поэтому отсечения по первому вхождению атрибута достаточно.
fn emitted_rule_ids() -> std::collections::BTreeMap<String, Vec<String>> {
    fn collect(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            let name = e.file_name();
            let name = name.to_string_lossy();
            if p.is_dir() {
                // Обходим ТОЛЬКО исходники продукта. Каталоги `tests` и `examples` содержат
                // фикстуры с выдуманными именами правил (`todo`, `x`, `r`), и включение их в
                // выборку давало ложные требования классифицировать несуществующие правила.
                if name == "tests" || name == "examples" || name == "target" {
                    continue;
                }
                collect(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("корень рабочего пространства")
        .join("crates");
    let mut files = Vec::new();
    collect(&root, &mut files);
    assert!(
        files.len() > 20,
        "исходники не найдены, тест бесполезен: {} файлов",
        files.len()
    );

    let mut found: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // Отсечение по НАЧАЛУ СТРОКИ, а не по вхождению подстроки: атрибут `#[cfg(test)]`
        // упоминается и в доккомментариях (например там, где описано распознавание тестовых
        // блоков), и обрезка по такому упоминанию отбрасывала бы почти весь файл вместе с
        // объявлениями правил. Именно так из выборки выпадало правило, объявленное ниже
        // такого комментария, и тест обратной проверки объявлял его «призраком».
        // Смещение считается по `split_inclusive`, который отдаёт строку ВМЕСТЕ с её
        // завершителем: длина слагается точно и для LF, и для CRLF. Прежний подсчёт через
        // `lines()` прибавлял ровно один байт на перевод строки, на выкладке с CRLF (git с
        // autocrlf на раннере Windows) смещение отставало на число пройденных строк, и срез
        // попадал в середину многобайтового символа кириллицы с паникой процесса.
        let cut = {
            let mut off = 0usize;
            let mut at = None;
            for l in text.split_inclusive('\n') {
                if l.trim_start().starts_with("#[cfg(test)]") {
                    at = Some(off);
                    break;
                }
                off += l.len();
            }
            at
        };
        let body = match cut {
            Some(c) => &text[..c],
            None => &text[..],
        };
        let file = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // Формы, которыми код называет правило. Помимо полей структур (`rule:`/`id:`)
        // существуют ПОЗИЦИОННЫЕ вызовы: движок структурного анализа зовёт
        // `push(out, rel, line, "sast/…", …)`, а конституция и метрики передают имя правила
        // аргументом хелпера. Без этих форм перечень получался неполным, и обратная проверка
        // объявляла настоящие правила «призраками».
        for marker in [
            "rule: \"",
            "id: \"",
            "line, \"",
            "rule_verified(\"",
            "emit(out, \"",
            "finding(\"",
        ] {
            let mut from = 0usize;
            while let Some(pos) = body[from..].find(marker) {
                let start = from + pos + marker.len();
                let Some(len) = body[start..].find('"') else {
                    break;
                };
                let id = &body[start..start + len];
                from = start + len;
                // Идентификатор правила состоит из строчных букв, цифр и разделителей.
                let plausible = !id.is_empty()
                    && id.len() < 60
                    && id.chars().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || "./_-".contains(c)
                    });
                if !plausible {
                    continue;
                }
                // Идентификатор capability классу достоверности не подлежит.
                if id
                    .split_once('/')
                    .is_some_and(|(fam, _)| CAPABILITY_FAMILIES.contains(&fam))
                {
                    continue;
                }
                found.entry(id.to_string()).or_default().push(file.clone());
            }
        }
    }
    found
}

/// Каждое правило, которое код излучает, обязано иметь ЯВНЫЙ класс достоверности.
/// Без класса правило по умолчанию становится Medium-сигналом, то есть попадает в вердикт и
/// снижает балл, хотя автор об этом решения не принимал.
#[test]
fn каждое_излучаемое_правило_классифицировано() {
    let emitted = emitted_rule_ids();
    let mut missing: Vec<String> = emitted
        .iter()
        .filter(|(id, _)| ailc_contracts::rule_confidence(id).is_none())
        .map(|(id, files)| format!("{id} (в {})", files.join(", ")))
        .collect();
    missing.sort();
    assert!(
        missing.is_empty(),
        "правила без класса достоверности ({}): они молча станут Medium-сигналом; \
         добавь их в rule_confidence (Heuristic/Pattern/Precise):\n  {}",
        missing.len(),
        missing.join("\n  ")
    );
}

/// Обратная сторона той же согласованности: в карте достоверности не должно быть правил,
/// которых код не излучает. Такая запись означает либо опечатку, либо удалённый детектор, за
/// которым остался «призрак»: тесты и списки продолжают его упоминать, создавая видимость
/// покрытия. Именно так в карте жило правило `weak-crypto`, объявленное внутри неиспользуемой
/// функции и потому не способное сработать ни при каком прогоне.
#[test]
fn в_карте_достоверности_нет_правил_призраков() {
    // Здесь нужна ПОЛНОТА, а не точность, поэтому вопрос ставится проще, чем в прямой
    // проверке: встречается ли имя правила в исходниках продукта ХОТЬ ГДЕ-НИБУДЬ. Причина в
    // многообразии форм излучения: помимо полей структур имя правила передаётся элементом
    // кортежа (`("sast/taint-sql", Severity::High, …)` в движке структурного анализа) и
    // аргументом хелперов (`taint_finding("taint-llm-output-exec", …)`). Перечислять эти формы
    // означало бы гоняться за синтаксисом и выдавать настоящие правила за призраков.
    // Отсутствие имени во всех исходниках сразу однозначно: излучать его нечему.
    let mut literals: std::collections::BTreeSet<String> = Default::default();
    for (id, _) in emitted_rule_ids() {
        literals.insert(id);
    }
    // Дополнительно к «маркерным» формам собираем ВСЕ строковые литералы продукта.
    fn collect_src(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            let name = e.file_name();
            let name = name.to_string_lossy();
            if p.is_dir() {
                if name == "tests" || name == "examples" || name == "target" {
                    continue;
                }
                collect_src(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("корень рабочего пространства")
        .join("crates");
    let mut files = Vec::new();
    collect_src(&root, &mut files);
    // Карта достоверности живёт в `ailc-contracts` и упоминает каждое правило по имени,
    // поэтому сам этот файл из выборки исключается: иначе призраков не нашлось бы никогда.
    let mut text = String::new();
    for p in files {
        if p.ends_with("ailc-contracts/src/lib.rs") {
            continue;
        }
        if let Ok(t) = std::fs::read_to_string(&p) {
            text.push_str(&t);
            text.push('\n');
        }
    }

    let mut ghosts: Vec<&str> = ailc_contracts::classified_rule_ids()
        .iter()
        .filter(|id| !literals.contains(**id) && !text.contains(&format!("\"{id}\"")))
        .copied()
        .collect();
    ghosts.sort_unstable();
    assert!(
        ghosts.is_empty(),
        "в rule_confidence есть правила, которых код не излучает ({}): {ghosts:?}. \
         Такая запись создаёт видимость покрытия: списки и тесты продолжают упоминать \
         правило, которое не может сработать. Либо реализуй детектор, либо убери запись.",
        ghosts.len()
    );
}

/// Правило, объявленное в ДВУХ модулях, обязано вести себя одинаково.
///
/// Дублирование само по себе допустимо: категорийный набор OWASP и набор веб-безопасности
/// сознательно пересекаются, а двойной счёт убирает дедупликация находок. Недопустимо
/// РАСХОЖДЕНИЕ: правки вносят в одну копию, вторая продолжает жить своей жизнью, и полнота
/// начинает зависеть от того, какая capability попала в прогон. Так и случилось с правилом
/// об инъекции шаблона: версия в категорийном наборе не знала ни `Twig…->createTemplate`, ни
/// `velocityEngine.evaluate`, поэтому жёсткая ось OWASP этих форм не видела.
///
/// Проверяется поведение, а не текст образца: обе capability обязаны находить один и тот же
/// набор форм. Так тест не привязан к тому, вынесен ли образец в общую константу.
/// Случай сверки копий правила: идентификатор правила, пара capability, объявляющих это
/// правило, и набор фрагментов «имя файла плюс содержимое», каждый из которых обязан
/// срабатывать в ОБЕИХ capability. Псевдоним введён, чтобы объявление таблицы читалось и не
/// разрасталось во вложенный кортеж из четырёх уровней.
type СлучайДублированияПравила = (
    &'static str,
    [&'static str; 2],
    &'static [(&'static str, &'static str)],
);

#[test]
fn дублированные_правила_ведут_себя_одинаково() {
    // (правило, пара capability, набор фрагментов, каждый из которых обязан срабатывать)
    let cases: &[СлучайДублированияПравила] = &[
        (
            "ssti",
            ["security.scan/owasp", "security.scan/web"],
            &[
                ("twig.php", "<?php $t = $twig->createTemplate($_GET['n']);"),
                (
                    "jinja.py",
                    "from jinja2 import Environment\nt = Environment().from_string(user)\n",
                ),
                (
                    "velocity.java",
                    "velocityEngine.evaluate(ctx, w, \"t\", user);",
                ),
            ],
        ),
        (
            "cors-wildcard",
            ["security.scan/owasp", "security.scan/web"],
            &[
                ("go.go", "cfg := cors.Config{AllowAllOrigins: true}"),
                ("j.java", "allowedOrigins(\"*\")"),
            ],
        ),
        (
            "cors-reflect-origin",
            ["security.scan/owasp", "security.scan/web"],
            &[
                (
                    "n.js",
                    "res.setHeader('Access-Control-Allow-Origin', request.headers.origin)",
                ),
                (
                    "t.js",
                    "const h = { 'Access-Control-Allow-Origin': ${origin} };",
                ),
            ],
        ),
    ];

    let r = reg();
    for (rule, caps, fixtures) in cases {
        for (file, code) in *fixtures {
            let (_t, ctx) = tree(&[(file, code)]);
            for cap_id in caps {
                let out = r
                    .get(cap_id)
                    .unwrap_or_else(|| panic!("{cap_id} зарегистрирован"))
                    .run(&ctx, &RunInput::default())
                    .unwrap_or_else(|e| panic!("{cap_id} отработал: {e}"));
                assert!(
                    out.findings.iter().any(|f| f.rule == *rule),
                    "правило «{rule}» обязано срабатывать в {cap_id} на фрагменте {file}; \
                     копии правила разошлись. Найдено: {:?}",
                    out.findings.iter().map(|f| &f.rule).collect::<Vec<_>>()
                );
            }
        }
    }
}

// ═══════════════════════ Парное покрытие правил без единого теста ═══════════════════════
//
// Замер по исходникам показал, что часть правил, которые детекторы реально излучают, не
// была названа ни в одном тесте. Правило без теста есть правило, о котором неизвестно,
// работает ли оно: соседняя правка образца может молча его выключить, и вердикт продукта
// тихо потеряет целый класс находок. Блок ниже закрывает такие правила ПАРОЙ утверждений.
//
// Положительное утверждение требует находки на минимальной заведомо уязвимой фикстуре.
// Отрицательное требует молчания на похожем по форме, но безопасном коде, и оно важнее:
// именно оно ловит правило, которое срабатывает на всём подряд и потому бесполезно.
// Отрицательные фикстуры выбраны намеренно близкими к положительным (тот же вызов, то же
// имя поля, тот же элемент разметки), чтобы проверка била по существу признака, а не по
// отсутствию ключевого слова.

/// Идентификаторы правил, сработавших у заданной capability на заданном проекте.
fn сработавшие_правила(ctx: &Ctx, cap_id: &str) -> Vec<String> {
    reg()
        .get(cap_id)
        .unwrap_or_else(|| panic!("capability «{cap_id}» обязана быть зарегистрирована"))
        .run(ctx, &RunInput::default())
        .unwrap_or_else(|e| panic!("capability «{cap_id}» обязана отработать: {e}"))
        .findings
        .iter()
        .map(|f| f.rule.clone())
        .collect()
}

/// Пара утверждений для одного правила: срабатывание на уязвимом образце и молчание на
/// безопасном. Каждый образец кладётся в СВОЙ временный каталог, поэтому параллельный
/// запуск тестов не создаёт гонки за общий каталог (`tree` выдаёт уникальное имя).
fn правило_ловит_и_молчит(
    cap_id: &str,
    rule: &str,
    уязвимый: (&str, &str),
    безопасный: (&str, &str),
) {
    let (_t1, ctx_плохой) = tree(&[уязвимый]);
    let на_уязвимом = сработавшие_правила(&ctx_плохой, cap_id);
    assert!(
        на_уязвимом.iter().any(|r| r == rule),
        "правило «{rule}» ({cap_id}) обязано срабатывать на уязвимом образце {}; найдено: {на_уязвимом:?}",
        уязвимый.0
    );

    let (_t2, ctx_хороший) = tree(&[безопасный]);
    let на_безопасном = сработавшие_правила(&ctx_хороший, cap_id);
    assert!(
        !на_безопасном.iter().any(|r| r == rule),
        "правило «{rule}» ({cap_id}) обязано молчать на безопасном образце {}, иначе оно \
         срабатывает на всём подряд и его находки обесценены; найдено: {на_безопасном:?}",
        безопасный.0
    );
}

// ───────────────────────── security.scan/secret ─────────────────────────

/// Секретный ключ доступа AWS. Отрицательный образец сохраняет то же имя поля и ту же
/// строку присваивания, но значение берётся из окружения, то есть в исходниках секрета нет.
#[test]
fn правило_aws_secret_key_ловит_ключ_и_молчит_на_чтении_из_окружения() {
    правило_ловит_и_молчит(
        "security.scan/secret",
        "aws-secret-key",
        (
            "conf.py",
            "aws_secret_key = \"kL4pQ8sT2vX6zB0dF3hJ5mN7rU9wY1aC4eG6iK8m\"\n",
        ),
        (
            "safe.py",
            "aws_secret_key = os.environ[\"AWS_SECRET_KEY\"]\n",
        ),
    );
}

/// Токен JWT в исходниках. Отрицательный образец есть строка того же алфавита и того же
/// начала `eyJ`, но из одной части: без двух точек это заголовок, а не готовый токен.
#[test]
fn правило_jwt_ловит_трёхчастный_токен_и_молчит_на_одной_части() {
    правило_ловит_и_молчит(
        "security.scan/secret",
        "jwt",
        (
            "t.py",
            "token = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.\
             dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk\"\n",
        ),
        (
            "st.py",
            "payload = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"\n",
        ),
    );
}

/// Токен npm. Отрицательный образец имеет тот же префикс `npm_`, но вместо тела токена
/// стоит заглушка, то есть форма секрета не выполнена.
#[test]
fn правило_npm_token_ловит_токен_и_молчит_на_заглушке() {
    правило_ловит_и_молчит(
        "security.scan/secret",
        "npm-token",
        (
            "n.js",
            "const t = \"npm_aB3xK9qLzR7tWvN8mP4dF6hJ2sQ1uY5oI0zE\";\n",
        ),
        ("sn.js", "const t = \"npm_TOKEN_PLACEHOLDER\";\n"),
    );
}

/// Секретный ключ Stripe. Отрицательный образец сохраняет префикс `sk_live_`, но тело
/// короче минимальной длины ключа, поэтому это очевидная заглушка в примере настройки.
#[test]
fn правило_stripe_key_ловит_боевой_ключ_и_молчит_на_коротком_префиксе() {
    правило_ловит_и_молчит(
        "security.scan/secret",
        "stripe-key",
        // Положительный образец собирается из двух литералов НАМЕРЕННО: слитная строка вида
        // ключа Stripe `sk_live_<тело>` в исходнике срабатывала бы на защите отправки GitHub
        // (push protection) и блокировала бы отправку всего репозитория, хотя это лишь
        // общеизвестный пример ключа из документации Stripe, а не действующий секрет.
        // Значение в момент исполнения теста собирается целиком, поэтому сканер получает
        // ровно тот же ключ, и проверка обнаружения не ослабляется.
        (
            "s.py",
            concat!(
                "stripe.api_key = \"sk_",
                "live_4eC39HqLyjWDarjtT1zdp7dc\"\n"
            ),
        ),
        ("ss.py", "stripe.api_key = \"sk_live_xxx\"\n"),
    );
}

/// Серверный ключ Firebase Cloud Messaging. Отрицательный образец повторяет узнаваемое
/// начало ключа вместе с двоеточием, но тело короче требуемого, то есть это не ключ.
#[test]
fn правило_firebase_fcm_key_ловит_серверный_ключ_и_молчит_на_обрезке() {
    правило_ловит_и_молчит(
        "security.scan/secret",
        "firebase-fcm-key",
        (
            "f.py",
            "FCM = \"AAAAqR3nK9m:APA91bHqR7tWvN8mP4dF6hJ2sQ1uY5oI0zE3xK9qLzR7tWvN8mP4dF6hJ2sQ\
             1uY5oI0zE3xK9qLzR7tWvN8mP4dF6hJ2sQ1uY5oI0zE3xK9qLzR7tWvN8mP4dF6hJ2sQ1uY5oI0zE3x\
             K9qLz\"\n",
        ),
        ("sf.py", "FCM = \"AAAAqR3nK9m:SHORT\"\n"),
    );
}

/// Токен доступа Twilio. Формы префикса у него нет, поэтому правило опирается на имя поля
/// рядом с тридцатью двумя шестнадцатеричными символами. Отрицательный образец сохраняет
/// то же имя поля, но значение приходит из окружения.
#[test]
fn правило_twilio_auth_token_ловит_токен_и_молчит_на_чтении_из_окружения() {
    правило_ловит_и_молчит(
        "security.scan/secret",
        "twilio-auth-token",
        (
            "tw.py",
            "auth_token = \"9f8e7d6c5b4a39281706f5e4d3c2b1a0\"\n",
        ),
        ("stw.py", "auth_token = os.environ[\"TWILIO_AUTH_TOKEN\"]\n"),
    );
}

// ───────────────────────── security.scan/pii ─────────────────────────

/// Запись чувствительного поля в журнал. Отрицательный образец есть тот же вызов журнала с
/// тем же способом подстановки, но записывается идентификатор заказа, а не пароль.
#[test]
fn правило_pii_in_log_ловит_пароль_в_журнале_и_молчит_на_идентификаторе_заказа() {
    правило_ловит_и_молчит(
        "security.scan/pii",
        "pii-in-log",
        ("l.js", "console.log(\"пароль пользователя: \", password)\n"),
        (
            "sl.js",
            "console.log(\"идентификатор заказа: \", orderId)\n",
        ),
    );
}

// ───────────────────────── security.scan/owasp ─────────────────────────

/// Излишне разрешающая авторизация. Отрицательный образец есть та же цепочка настройки
/// доступа, но завершается требованием аутентификации вместо разрешения всем.
#[test]
fn правило_permissive_authz_ловит_permit_all_и_молчит_на_authenticated() {
    правило_ловит_и_молчит(
        "security.scan/owasp",
        "permissive-authz",
        (
            "S.java",
            "http.authorizeRequests().anyRequest().permitAll();\n",
        ),
        (
            "SS.java",
            "http.authorizeRequests().anyRequest().authenticated();\n",
        ),
    );
}

/// Непригодный для секретов генератор случайных чисел. Отрицательный образец решает ту же
/// задачу выпуска токена, но криптостойким источником.
#[test]
fn правило_insecure_random_ловит_обычный_рандом_и_молчит_на_криптостойком() {
    правило_ловит_и_молчит(
        "security.scan/owasp",
        "insecure-random",
        ("r.py", "import random\ntoken = random.randint(0, 999999)\n"),
        (
            "sr.py",
            "import secrets\ntoken = secrets.token_urlsafe(32)\n",
        ),
    );
}

/// Включённый режим отладки. Отрицательный образец есть то же объявление настройки с
/// противоположным значением.
#[test]
fn правило_debug_enabled_ловит_включённую_отладку_и_молчит_на_выключенной() {
    правило_ловит_и_молчит(
        "security.scan/owasp",
        "debug-enabled",
        ("st.py", "DEBUG = True\n"),
        ("sst.py", "DEBUG = False\n"),
    );
}

/// Слабое хеширование паролей. Отрицательный образец намеренно сохраняет тот же слабый
/// алгоритм, но применяет его к содержимому файла ради контрольной суммы, а не к паролю:
/// правило обязано различать назначение, иначе оно сливается с общим `weak-hash`.
#[test]
fn правило_weak_pw_hash_ловит_md5_пароля_и_молчит_на_контрольной_сумме_файла() {
    правило_ловит_и_молчит(
        "security.scan/owasp",
        "weak-pw-hash",
        ("h.py", "digest = md5(password).hexdigest()\n"),
        ("sh.py", "digest = md5(file_bytes).hexdigest()\n"),
    );
}

// ───────────────────────── security.scan/web ─────────────────────────

/// Отключённая защита от подделки межсайтового запроса. Отрицательный образец подключает ту
/// же защиту с включённым значением флага.
#[test]
fn правило_csrf_disabled_ловит_снятую_защиту_и_молчит_на_включённой() {
    правило_ловит_и_молчит(
        "security.scan/web",
        "csrf-disabled",
        ("v.py", "@csrf_exempt\ndef pay(request):\n    pass\n"),
        ("sv.js", "app.use(csurf({ csrfProtection: true }));\n"),
    );
}

/// Разбор YAML небезопасным загрузчиком. Отрицательный образец использует тот же вызов
/// `yaml.load`, но с явно заданным безопасным загрузчиком.
#[test]
fn правило_unsafe_yaml_load_ловит_загрузку_без_загрузчика_и_молчит_с_safe_loader() {
    правило_ловит_и_молчит(
        "security.scan/web",
        "unsafe-yaml-load",
        ("y.py", "cfg = yaml.load(open('c.yml'))\n"),
        ("sy.py", "cfg = yaml.load(f, Loader=yaml.SafeLoader)\n"),
    );
}

// ───────────────────────── security.ai/* ─────────────────────────

/// Чувствительные данные в подсказке модели. Отрицательный образец собирает подсказку тем
/// же способом склейки, но подставляет номер заказа, а не ключ доступа.
#[test]
fn правило_llm_sensitive_in_prompt_ловит_ключ_в_подсказке_и_молчит_на_номере_заказа() {
    правило_ловит_и_молчит(
        "security.ai/prompt-injection",
        "llm-sensitive-in-prompt",
        ("p.py", "prompt = \"ключ: \" + api_key\n"),
        ("sp.py", "prompt = \"проверь заказ: \" + order_id\n"),
    );
}

/// Избыточные полномочия агента. Отрицательный образец получает ответ модели тем же
/// вызовом, но лишь печатает его, то есть побочного действия из вывода модели не следует.
#[test]
fn правило_llm_excessive_agency_ловит_запуск_процесса_и_молчит_на_печати() {
    правило_ловит_и_молчит(
        "security.ai/prompt-injection",
        "llm-excessive-agency",
        (
            "a.py",
            "response = client.messages.create(model=m)\nsubprocess.run(response.content)\n",
        ),
        (
            "sa.py",
            "response = client.messages.create(model=m)\nprint(response.content)\n",
        ),
    );
}

/// Сырой вывод модели в разметку. Отрицательный образец пишет тот же вывод в тот же узел
/// дерева документа, но безопасным свойством текстового содержимого.
#[test]
fn правило_llm_output_raw_html_ловит_inner_html_и_молчит_на_text_content() {
    правило_ловит_и_молчит(
        "security.ai/insecure-output",
        "llm-output-raw-html",
        ("o.js", "box.innerHTML = completion.text\n"),
        ("so.js", "box.textContent = completion.text\n"),
    );
}

// ───────────────────────── compliance.ru/consent ─────────────────────────

/// Предзаполненное согласие. Отрицательный образец есть тот же предзаполненный флажок, но
/// не согласия на обработку данных, а подписки на рассылку: правило обязано различать
/// назначение поля, иначе оно пометит любой предвыбранный флажок в форме.
#[test]
fn правило_pre_checked_consent_ловит_согласие_и_молчит_на_подписке_на_рассылку() {
    правило_ловит_и_молчит(
        "compliance.ru/consent",
        "pre-checked-consent",
        (
            "f.jsx",
            "<input type=\"checkbox\" name=\"consent\" defaultChecked />\n",
        ),
        (
            "sf.jsx",
            "<input type=\"checkbox\" name=\"newsletter\" defaultChecked />\n",
        ),
    );
}

// ───────────────────────── security.scan/injection ─────────────────────────

/// Сборка разметки конкатенацией строк. Отрицательный образец собирает конкатенацией ту же
/// строку с тем же значением, но без элементов разметки: признаком является тег, а не сама
/// склейка, иначе правило пометило бы любое сложение строк.
#[test]
fn правило_html_string_concat_ловит_склейку_тега_и_молчит_на_обычном_тексте() {
    правило_ловит_и_молчит(
        "security.scan/injection",
        "html-string-concat",
        ("v.js", "const row = \"<li>\" + name + \"</li>\";\n"),
        ("sv.js", "const s = \"привет, \" + name + \"!\";\n"),
    );
}

// ───────────────────────── quality.check/* ─────────────────────────

/// Экспортируемый символ без использований. Отрицательный образец объявляет такой же
/// экспортируемый символ, но вызывает его из соседнего файла.
#[test]
fn правило_dead_export_ловит_неиспользуемый_экспорт_и_молчит_на_вызываемом() {
    правило_ловит_и_молчит(
        "quality.check/dead-code",
        "dead-export",
        ("lib.go", "func НикемНеВызванныйЭкспорт(){}\n"),
        (
            "used.go",
            "func Живой(){}\nfunc caller(){ Живой(); Живой() }\n",
        ),
    );
}

/// Превышение порога цикломатической сложности. Уязвимый образец набирает ветвлений выше
/// порога из набора правил, безопасный содержит ту же функцию без ветвления.
#[test]
fn правило_high_complexity_ловит_ветвистый_файл_и_молчит_на_простом() {
    let mut ветвистый = String::from("package main\nfunc f(x int) int {\n");
    for i in 0..40 {
        ветвистый.push_str(&format!("  if x == {i} && x > 0 {{ return {i} }}\n"));
    }
    ветвистый.push_str("  return 0\n}\n");
    правило_ловит_и_молчит(
        "quality.check/complexity",
        "high-complexity",
        ("hard.go", ветвистый.as_str()),
        ("easy.go", "package main\nfunc f(x int) int { return x }\n"),
    );
}

/// Нарушение архитектурных слоёв. Оба образца несут ОДИН И ТОТ ЖЕ файл правил слоёв, и
/// различаются только направлением зависимости: в уязвимом нижний слой тянет верхний, в
/// безопасном верхний тянет нижний, что правилами разрешено.
#[test]
fn правило_layer_violation_ловит_обратную_зависимость_и_молчит_на_разрешённой() {
    const СЛОИ: &str = "ui: core\ncore:\n";
    const ПРАВИЛО: &str = "layer-violation";

    let (_t1, нарушение) = tree(&[
        (".ailc/layers.txt", СЛОИ),
        ("core/a.py", "import ui\n"),
        ("ui/b.py", "import core\n"),
    ]);
    let на_нарушении = сработавшие_правила(&нарушение, "quality.check/layers");
    assert!(
        на_нарушении.iter().any(|r| r == ПРАВИЛО),
        "нижний слой core тянет верхний ui вопреки файлу слоёв, нарушение обязано \
         находиться; найдено: {на_нарушении:?}"
    );

    let (_t2, порядок) = tree(&[
        (".ailc/layers.txt", СЛОИ),
        ("core/a.py", "value = 1\n"),
        ("ui/b.py", "import core\n"),
    ]);
    let на_порядке = сработавшие_правила(&порядок, "quality.check/layers");
    assert!(
        !на_порядке.iter().any(|r| r == ПРАВИЛО),
        "верхний слой ui тянет нижний core, что файлом слоёв разрешено; правило обязано \
         молчать, иначе оно пометит любую зависимость подряд; найдено: {на_порядке:?}"
    );
}
