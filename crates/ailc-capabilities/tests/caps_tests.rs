//! Тесты capability через реестр (реальный путь). Замораживают: dead_code исключает
//! тесты/использованное, OWASP категоризирует находки A01–A10.

use ailc_contracts::{Ctx, RunInput};
use ailc_core::registry::Registry;
use std::sync::atomic::{AtomicU32, Ordering};

static CNT: AtomicU32 = AtomicU32::new(0);

fn tmp(files: &[(&str, &str)]) -> Ctx {
    let n = CNT.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("ailc-c-{}-{}", std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (rel, content) in files {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }
    Ctx::new(dir)
}

fn reg() -> Registry {
    let mut r = Registry::new();
    ailc_capabilities::register_core(&mut r);
    r
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
    let ctx = tmp(&[
        ("lib.go", "func UnusedExport(){}\nfunc UsedExport(){}\n"),
        ("use.go", "func caller(){ UsedExport() }\n"),
        ("x_test.go", "func TestThing(){}\n"),
    ]);
    let r = reg();
    let cap = r.get("quality.check/dead-code").expect("dead-code зарегистрирован");
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
    let ctx = tmp(&[
        ("app/page.tsx", "export function HomePage(){ return null }\n"),
        ("next.config.ts", "export function defineConfig(){ return {} }\n"),
        ("util.ts", "export function reallyUnusedHelper(){ return 1 }\n"),
    ]);
    let r = reg();
    let cap = r.get("quality.check/dead-code").expect("dead-code зарегистрирован");
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
    let ctx = tmp(&[
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
    assert_eq!(hit("compliance.ru/pdn-logs"), 1, "ПДн в логах (не безопасный лог)");
    assert_eq!(hit("compliance.ru/localization"), 1, "зарубежный хост БД");
    assert_eq!(hit("compliance.ru/cross-border"), 1, "иностранный трекер");
    assert_eq!(hit("compliance.ru/consent"), 1, "предзаполненное согласие");
}

#[test]
fn owasp_categorizes_findings() {
    // os.system — паттерн опасного исполнения команды ОС. Голый eval/exec выведен в
    // потоковый сток sast/taint-dynamic-exec, поэтому паттерн dangerous-exec на него
    // больше не реагирует (см. owasp::dangerous-exec).
    let ctx = tmp(&[("v.py", "x = md5(data)\ny = os.system(code)\n")]);
    let r = reg();
    let cap = r.get("security.scan/owasp").expect("owasp зарегистрирован");
    let out = cap.run(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = out.findings.iter().map(|f| f.rule.as_str()).collect();
    assert!(rules.contains(&"weak-hash"), "A02 слабый хеш найден: {rules:?}");
    assert!(rules.contains(&"dangerous-exec"), "A03 опасное исполнение найдено: {rules:?}");
    // матрица A01–A10 присутствует в выводе
    assert!(
        out.records.iter().any(|r| r.contains("A01") || r.contains("матрица")),
        "есть матрица OWASP"
    );
}

#[test]
fn secret_scan_catches_new_providers() {
    let ctx = tmp(&[(
        "config.py",
        concat!(
            "gl = \"glpat-aBcDeFgHiJkLmNoPqRsT\"\n",
            "sl = \"xoxb-291283764418-aGqLkPwR\"\n",
            "sg = \"SG.aBcDeFgHiJkLmNoP.qRsTuVwXyZaBcDeF\"\n",
            "az = \"AccountKey=aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6kM9oR2tU5wX8zA1cD4f==\"\n",
        ),
    )]);
    let r = reg();
    let cap = r.get("security.scan/secret").expect("secret зарегистрирован");
    let out = cap.run(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = out.findings.iter().map(|f| f.rule.as_str()).collect();
    for expected in ["gitlab-token", "slack-token", "sendgrid-key", "azure-account-key"] {
        assert!(rules.contains(&expected), "{expected} найден: {rules:?}");
    }
}

#[test]
fn test_run_distinguishes_empty_sections_from_no_tests() {
    use ailc_capabilities::some_tests_passed;
    // cargo workspace: юнит-тесты прошли, но doc-test секции печатают «running 0 tests».
    let cargo_mixed =
        "running 13 tests\ntest result: ok. 13 passed; 0 failed\nrunning 0 tests\ntest result: ok. 0 passed; 0 failed";
    assert!(some_tests_passed(cargo_mixed), "13 passed перевешивает пустые секции");
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
    let ctx = tmp(&[(
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
    let ctx = tmp(&[(
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
    let ctx = tmp(&[
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
        hit("security.ai/prompt-injection", "llm-prompt-untrusted-concat"),
        "промпт-инъекция найдена"
    );
    assert!(
        hit("security.ai/insecure-output", "llm-output-exec"),
        "исполнение вывода LLM найдено"
    );
}

#[test]
fn secret_scan_catches_llm_keys() {
    let ctx = tmp(&[(
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
    let ctx = tmp(&[("crypto.py", "h = hashlib.sha256(data).hexdigest()\n")]);
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
    let ctx = tmp(&[(
        "svc.py",
        "logger.info(\n    user.passport\n)\nlogger.info(mask(user.passport))\n",
    )]);
    let r = reg();
    let cap = r
        .get("compliance.ru/pdn-logs-ast")
        .expect("AST-проверка ПДн зарегистрирована");
    let out = cap.run(&ctx, &RunInput::default()).unwrap();
    assert_eq!(out.findings.len(), 1, "многострочный лог ПДн найден, маскированный — нет");
    assert_eq!(out.findings[0].rule, "pdn-log-dynamic");
}

#[test]
fn scan_all_collects_and_sarif_reports() {
    use ailc_core::orchestrator::Orchestrator;
    // Сплошной скан собирает находки разных семейств; SARIF их сериализует.
    let ctx = tmp(&[("web.py", "r = requests.get(request.args.get('u'))\n")]);
    let r = reg();
    let report = Orchestrator::scan_all(&r, &ctx, &RunInput::default());
    assert!(
        report.findings.iter().any(|f| f.rule == "ssrf-sink"),
        "сплошной скан нашёл SSRF: {:?}",
        report.findings.iter().map(|f| f.rule.as_str()).collect::<Vec<_>>()
    );
    let sarif = ailc_core::sarif::to_sarif(
        &report.findings,
        "0.2.0",
        report.refuted,
        &report.checks_run,
        &report.checks_skipped,
    );
    assert!(sarif.contains("\"version\": \"2.1.0\""), "SARIF версии 2.1.0");
    assert!(sarif.contains("ssrf-sink"), "правило в отчёте");
    assert!(sarif.contains("refutedFalsePositives"), "честность охвата в properties");
}

#[test]
fn taint_capability_registered_and_runs() {
    // Реальный путь через реестр: capability зарегистрирован и ловит межоператорный поток.
    let ctx = tmp(&[(
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
    let ctx = tmp(&[
        ("a.rs", "fn a(){ unimplemented!() }\nfn b(){ todo!() }\n"),
        ("k.kt", "fun stub() = TODO()\n"),
        ("c.java", "void f(){ try { x(); } catch (Exception e) {} }\n"),
        ("d.py", "def stub(x): pass\ntry:\n    risky()\nexcept ValueError: pass\n"),
        ("clean.go", "func Compute(a int) int { return a + 1 }\n"),
    ]);
    let r = reg();
    let out = r
        .get("quality.check/completeness")
        .expect("completeness зарегистрирован")
        .run(&ctx, &RunInput::default())
        .unwrap();
    let rules: Vec<&str> = out.findings.iter().map(|f| f.rule.as_str()).collect();
    for e in ["unimplemented-stub", "empty-catch", "empty-function", "empty-except"] {
        assert!(rules.contains(&e), "{e} найден: {rules:?}");
    }
    // Чистый код не порождает находок недоделанности.
    assert!(
        !out.findings.iter().any(|f| f.location.as_ref().is_some_and(|l| l.file == "clean.go")),
        "чистый файл не помечен: {rules:?}"
    );
}

#[test]
fn completeness_stub_in_comment_refuted() {
    use ailc_core::verify::Verifier;
    // Заглушка в КОММЕНТАРИИ ложна (код не исполняется), в коде — реальна.
    let ctx = tmp(&[("a.rs", "// здесь был бы unimplemented!() как пример\nfn real(){ unimplemented!() }\n")]);
    let r = reg();
    let out = r
        .get("quality.check/completeness")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    assert_eq!(out.findings.len(), 2, "сырой скан помечает и комментарий, и код");
    let (confirmed, refuted) = Verifier::verify(&ctx, out.findings);
    assert_eq!(confirmed.len(), 1, "после verify остаётся только реальная заглушка");
    assert_eq!(refuted.len(), 1, "заглушка в комментарии опровергнута");
}

#[test]
fn undocumented_flags_public_api_without_docs() {
    // Documented — с doc-комментарием; Exported/Another/Third — без; helper — приватный.
    let ctx = tmp(&[(
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
        out.findings.iter().map(|f| f.rule.as_str()).collect::<Vec<_>>()
    );
    let undoc = out
        .metrics
        .iter()
        .find(|(k, _)| k == "public_symbols")
        .map(|(_, v)| *v);
    assert_eq!(undoc, Some(4.0), "приватный helper не считается публичным API");
}

#[test]
fn unfinished_blocks_on_release_but_warns_midbuild() {
    use ailc_core::agent::AgentOrchestrator;
    let ctx = tmp(&[("src.rs", "pub fn pay(){ unimplemented!() }\n")]);
    let r = reg();
    // Строгость теперь решает ПЛАН агента (strict), а не keyword в намерении.
    // Мид-билд (strict=false): заглушка — предупреждение, сдавать не мешает.
    let mut s_mid = Scripted {
        plan: one_step_plan("quality.check/completeness", false),
    };
    let mid = AgentOrchestrator::run(&r, &ctx, &RunInput::default(), "проверь качество", &mut s_mid, 1);
    assert!(mid.passed, "мид-билд: незавершённое не блокирует");
    assert!(mid.warning >= 1, "но видно как предупреждение");
    // Сдача (strict=true): то же незавершённое БЛОКИРУЕТ.
    let mut s_ship = Scripted {
        plan: one_step_plan("quality.check/completeness", true),
    };
    let ship = AgentOrchestrator::run(&r, &ctx, &RunInput::default(), "хочу выкатить", &mut s_ship, 1);
    assert!(!ship.passed, "сдача: незавершённое блокирует");
    assert!(ship.blocking >= 1, "переведено из предупреждения в блокер");
}

#[test]
fn surface_extracts_routes_env_services_models() {
    let ctx = tmp(&[
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
    assert!(blob.contains("db.example.com"), "внешний сервис postgres: {blob}");
    assert!(!blob.contains("u:p@"), "учётные данные сервиса вырезаны: {blob}");
    assert!(blob.contains("User"), "модель данных Prisma: {blob}");
}

#[test]
fn generators_produce_structured_docs_idempotently() {
    let ctx = tmp(&[
        (
            "src/api.py",
            "import os\n@app.get(\"/items\")\ndef items(): return []\nK = os.getenv(\"API_KEY\")\nDB = \"postgres://u:p@h:5432/db\"\n",
        ),
        ("schema.prisma", "model Item {\n  id Int @id\n}\n"),
    ]);
    let r = reg();
    let spec = r.get("generate/spec").expect("generate/spec зарегистрирован");
    let o1 = spec.run(&ctx, &RunInput::default()).unwrap();
    assert!(!o1.artifacts.is_empty(), "спека создаёт артефакт");
    let doc = std::fs::read_to_string(ctx.root.join("docs/СПЕЦИФИКАЦИЯ.md")).unwrap();
    assert!(doc.contains("ГОСТ"), "спека по ГОСТ-структуре");
    assert!(doc.contains("GET /items"), "эндпоинт в спеке: {doc}");
    assert!(doc.contains("API_KEY"), "ENV в спеке");
    assert!(doc.contains("h:5432") && !doc.contains("u:p@"), "сервис без учётных данных");
    assert!(doc.contains("Item"), "модель данных в спеке");
    // Идемпотентность: повторная генерация без изменений кода ничего не переписывает.
    let o2 = spec.run(&ctx, &RunInput::default()).unwrap();
    assert!(
        o2.summary.contains("без изменений"),
        "повторная генерация идемпотентна: {}",
        o2.summary
    );
    // C4 — три уровня.
    r.get("generate/c4").unwrap().run(&ctx, &RunInput::default()).unwrap();
    let c4 = std::fs::read_to_string(ctx.root.join("docs/C4.md")).unwrap();
    assert!(
        c4.contains("Уровень 1") && c4.contains("Уровень 2") && c4.contains("Уровень 3"),
        "C4: три уровня"
    );
    assert!(c4.contains("```mermaid"), "C4: Mermaid-блоки");
}

#[test]
fn generated_doc_preserves_human_edits() {
    let ctx = tmp(&[("src/a.py", "def feature(): return 1\n")]);
    let r = reg();
    let spec = r.get("generate/spec").unwrap();
    spec.run(&ctx, &RunInput::default()).unwrap();
    let p = ctx.root.join("docs/СПЕЦИФИКАЦИЯ.md");
    let edited = std::fs::read_to_string(&p)
        .unwrap()
        .replace("_Какую задачу решает, для кого — заполни._", "Магазин одежды.");
    std::fs::write(&p, edited).unwrap();
    // Регенерация обновляет авто-блок, но человеческий раздел не трогает.
    spec.run(&ctx, &RunInput::default()).unwrap();
    let after = std::fs::read_to_string(&p).unwrap();
    assert!(after.contains("Магазин одежды."), "ручная правка пережила регенерацию");
}

#[test]
fn drift_detects_missing_stale_and_in_sync() {
    let ctx = tmp(&[(
        "src/api.py",
        "import os\n@app.get(\"/a\")\ndef a(): return 1\n@app.get(\"/b\")\ndef b(): return 2\n@app.get(\"/c\")\ndef c(): return 3\nK=os.getenv(\"X\")\n",
    )]);
    let r = reg();
    let drift = r.get("spec.check/drift").expect("drift зарегистрирован");
    // (1) Доков нет, проект существенный (есть эндпоинты) → нудж doc-missing.
    let o1 = drift.run(&ctx, &RunInput::default()).unwrap();
    assert!(
        o1.findings.iter().any(|f| f.rule == "doc-missing"),
        "нет доков на существенном проекте → нудж: {:?}",
        o1.records
    );
    // (2) Сгенерировали спеку → по ней дрейфа нет.
    r.get("generate/spec").unwrap().run(&ctx, &RunInput::default()).unwrap();
    let o2 = drift.run(&ctx, &RunInput::default()).unwrap();
    assert!(
        !o2.findings
            .iter()
            .any(|f| f.rule == "doc-drift" && f.message.contains("СПЕЦИФИКАЦИЯ")),
        "свежесгенерированная спека не в дрейфе"
    );
    // (3) Изменили код (новый эндпоинт) → спека устарела → doc-drift.
    let api = ctx.root.join("src/api.py");
    let more = std::fs::read_to_string(&api).unwrap() + "@app.delete(\"/d\")\ndef d(): return 4\n";
    std::fs::write(&api, more).unwrap();
    let o3 = drift.run(&ctx, &RunInput::default()).unwrap();
    assert!(
        o3.findings
            .iter()
            .any(|f| f.rule == "doc-drift" && f.message.contains("СПЕЦИФИКАЦИЯ")),
        "после правки кода спека устарела: {:?}",
        o3.records
    );
}

#[test]
fn feature_design_scaffolds_spec_and_adr() {
    let ctx = tmp(&[("src/app.py", "def existing(): return 1\n")]);
    let r = reg();
    let cap = r.get("spec/feature").expect("spec/feature зарегистрирован");
    let q = RunInput {
        target: None,
        query: Some("корзина покупок".into()),
    };
    let out = cap.run(&ctx, &q).unwrap();
    assert_eq!(out.artifacts.len(), 2, "заготовка спеки + ADR: {:?}", out.artifacts);
    let doc = std::fs::read_to_string(ctx.root.join("docs/фичи/корзина-покупок.md")).unwrap();
    assert!(doc.contains("Критерии приёмки"), "секция DoD есть");
    assert!(doc.contains("Затрагиваемые части"), "карта кода есть");
    let adr = std::fs::read_to_string(ctx.root.join(".ailc/decisions/1.md")).unwrap();
    assert!(adr.contains("## Решение") && adr.contains("корзина покупок"), "ADR Nygard");
    // Идемпотентно: повторный вызов не плодит файлы и НЕ создаёт лишний ADR.
    let out2 = cap.run(&ctx, &q).unwrap();
    assert!(out2.skipped.is_some(), "повторное проектирование не дублирует");
    assert!(!ctx.root.join(".ailc/decisions/2.md").exists(), "лишний ADR не создан");
}

#[test]
fn surface_extracts_more_frameworks() {
    let ctx = tmp(&[
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
    assert!(blob.contains("/api/users"), "Spring @RequestMapping: {blob}");
    assert!(blob.contains("profile"), "NestJS @Get: {blob}");
    assert!(blob.contains("/login"), "ASP.NET [HttpPost]: {blob}");
    assert!(blob.contains("/dashboard"), "Laravel Route::get: {blob}");
}

#[test]
fn completeness_stubs_polyglot() {
    // Заглушки по идиомам разных языков + Ruby rescue nil + Dart пустой catch.
    let ctx = tmp(&[
        ("a.js", "function f(){ throw new Error(\"not implemented\") }\n"),
        ("b.php", "<?php\nfunction f(){ throw new \\Exception(\"not implemented\"); }\n"),
        ("c.rb", "def f\n  raise NotImplementedError\nend\nx = risky() rescue nil\n"),
        ("d.scala", "def f: Int = ???\n"),
        ("e.swift", "func f() { fatalError(\"unimplemented\") }\n"),
        ("g.dart", "void f() { throw UnimplementedError(); }\ntry { x(); } catch (e) {}\n"),
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
        .filter_map(|f| f.location.as_ref().map(|l| format!("{}:{}", l.file, f.rule)))
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
        assert!(blob.contains(&format!("{file}:{rule}")), "{file} → {rule}: {blob}");
    }
}

#[test]
fn surface_env_and_models_polyglot() {
    let ctx = tmp(&[
        ("conf.php", "<?php\n$h = getenv(\"DB_HOST\");\n"),
        ("cfg.rb", "s = ENV['SECRET']\n"),
        ("Cfg.cs", "var t = Environment.GetEnvironmentVariable(\"TOKEN\");\n"),
        ("cfg.swift", "let u = ProcessInfo.processInfo.environment[\"API_URL\"]\n"),
        ("cfg.dart", "final m = Platform.environment[\"MODE\"];\n"),
        ("cfg.c", "char* p = getenv(\"PATH_VAR\");\n"),
        ("model.rb", "class User < ApplicationRecord\nend\n"),
        ("Account.java", "@Entity\npublic class Account {}\n"),
        ("order.rs", "#[derive(sqlx::FromRow)]\nstruct Order { id: i32 }\n"),
    ]);
    let r = reg();
    let out = r
        .get("code.intel/surface")
        .unwrap()
        .run(&ctx, &RunInput::default())
        .unwrap();
    let blob = out.records.join("\n");
    for needle in [
        "DB_HOST", "SECRET", "TOKEN", "API_URL", "MODE", "PATH_VAR", // ENV по 6 языкам
        "User", "Account", "Order", // модели: Rails AR, JPA, sqlx
    ] {
        assert!(blob.contains(needle), "{needle} извлечён: {blob}");
    }
}

#[test]
fn parity_closes_remaining_gaps() {
    let ctx = tmp(&[
        ("impl.cpp", "void f() { assert(0 && \"not implemented\"); }\n"),
        ("user.go", "type User struct {\n  gorm.Model\n  Name string\n}\n"),
        ("schema.rs", "table! {\n  posts (id) {\n    id -> Int4,\n  }\n}\n"),
        ("conf/routes", "GET     /health      controllers.Health.check\n"),
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
fn arch_detects_all_stacks() {
    // По одному манифесту на стек — метка должна попасть в раздел «Развёртывание».
    for (manifest, label) in [
        ("Package.swift", "Swift/SwiftPM"),
        ("build.sbt", "Scala/sbt"),
        ("build.gradle.kts", "Kotlin/Gradle"),
        ("app.csproj", "C#/.NET"), // переменное имя — по расширению
        ("CMakeLists.txt", "C/C++ (CMake)"),
    ] {
        let ctx = tmp(&[(manifest, "x\n"), ("src/m.py", "def f(): return 1\n")]);
        let r = reg();
        r.get("generate/architecture")
            .unwrap()
            .run(&ctx, &RunInput::default())
            .unwrap();
        let doc = std::fs::read_to_string(ctx.root.join("docs/АРХИТЕКТУРА.md")).unwrap();
        assert!(doc.contains(label), "{manifest} → стек «{label}» не распознан");
    }
}

#[test]
fn drift_blocks_on_release() {
    use ailc_core::agent::AgentOrchestrator;
    // Существенный проект (≥5 публичных символов) без документации.
    let ctx = tmp(&[(
        "api.go",
        "package x\nfunc A(){}\nfunc B(){}\nfunc C(){}\nfunc D(){}\nfunc E(){}\n",
    )]);
    let r = reg();
    let mut s_mid = Scripted {
        plan: one_step_plan("spec.check/drift", false),
    };
    let mid = AgentOrchestrator::run(&r, &ctx, &RunInput::default(), "проверь качество", &mut s_mid, 1);
    assert!(mid.passed, "мид-билд: отсутствие доков не блокирует");
    let mut s_ship = Scripted {
        plan: one_step_plan("spec.check/drift", true),
    };
    let ship = AgentOrchestrator::run(&r, &ctx, &RunInput::default(), "хочу выкатить в прод", &mut s_ship, 1);
    assert!(!ship.passed, "сдача: устаревшие/отсутствующие доки блокируют");
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
    let ctx = tmp(&[("a.py", "x = 1\n")]);
    let r = reg();
    let mut s = Loopy;
    let ledger = AgentOrchestrator::run(&r, &ctx, &RunInput::default(), "проверь", &mut s, 3);
    assert!(
        ledger.rounds.iter().any(|x| x.contains("довызов")),
        "агент довызвал инструмент: {:?}",
        ledger.rounds
    );
    let exec_rounds = ledger.rounds.iter().filter(|x| x.starts_with("раунд")).count();
    assert!(exec_rounds <= 3, "не превысил бюджет раундов: {exec_rounds}");
    assert!(
        ledger.checks.iter().any(|c| c == "security.scan/secret"),
        "запланированный инструмент выполнен: {:?}",
        ledger.checks
    );
}

#[test]
fn surface_coverage_completed_all_langs() {
    let ctx = tmp(&[
        ("env.scala", "val k = sys.env(\"SECRET_KEY\")\n"),
        ("routes.kt", "fun r() { get(\"/users\") { ok() } }\n"),
        ("User.php", "<?php\nclass User extends Model {}\n"),
        ("Ctx.cs", "public DbSet<Order> Orders { get; set; }\n"),
        ("Item.swift", "@Model final class Item {}\n"),
        ("table.scala", "class Users(tag: Tag) extends Table[User] {}\n"),
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
    let ctx = tmp(&[]);
    let r = reg();
    let q = |s: &str| RunInput { target: None, query: Some(s.into()) };
    assert!(
        !r.get("memory/update").unwrap().run(&ctx, &q("важный факт о проекте")).unwrap().artifacts.is_empty(),
        "заметка записана на диск"
    );
    let rd = r.get("memory/read").unwrap().run(&ctx, &RunInput::default()).unwrap();
    assert!(rd.records.iter().any(|x| x.contains("важный факт")), "заметка прочитана: {:?}", rd.records);
    r.get("backlog/add").unwrap().run(&ctx, &q("сделать корзину")).unwrap();
    let lst = r.get("backlog/list").unwrap().run(&ctx, &RunInput::default()).unwrap();
    assert!(lst.records.iter().any(|x| x.contains("сделать корзину")), "задача в бэклоге: {:?}", lst.records);
    assert!(
        !r.get("memory/decision-log").unwrap().run(&ctx, &q("решили использовать Postgres")).unwrap().artifacts.is_empty(),
        "решение записано"
    );
}

#[test]
fn workflow_adr_branchname_setup() {
    let ctx = tmp(&[("src/a.go", "package x\nfunc A(){}\n")]);
    let r = reg();
    let q = |s: &str| RunInput { target: None, query: Some(s.into()) };
    r.get("generate/adr").unwrap().run(&ctx, &q("Выбор хранилища")).unwrap();
    let adr = std::fs::read_to_string(ctx.root.join(".ailc/decisions/1.md")).unwrap();
    assert!(adr.contains("Выбор хранилища") && adr.contains("## Решение"), "ADR Nygard: {adr}");
    let bn = r.get("deliver/branch-name").unwrap().run(&ctx, &q("Сделать корзину покупок")).unwrap();
    assert!(bn.records.iter().any(|x| x.contains("korzin")), "слаг ветки: {:?}", bn.records);
    assert!(
        !r.get("setup/init").unwrap().run(&ctx, &RunInput::default()).unwrap().artifacts.is_empty(),
        "setup/init развернул скелет .ailc"
    );
}

#[test]
fn governance_constitution_and_layers() {
    let ctx = tmp(&[(".ailc/constitution.md", "FORBID eval(\n"), ("app.py", "x = eval(user_input)\n")]);
    let r = reg();
    let cons = r.get("quality.check/constitution").unwrap().run(&ctx, &RunInput::default()).unwrap();
    assert!(
        cons.findings.iter().any(|f| f.message.to_lowercase().contains("eval") || f.rule.contains("forbid")),
        "конституция поймала FORBID: {:?}",
        cons.findings.iter().map(|f| f.rule.as_str()).collect::<Vec<_>>()
    );
    let lay = r.get("quality.check/layers").unwrap().run(&ctx, &RunInput::default()).unwrap();
    assert!(lay.skipped.is_some(), "нет .ailc/layers.txt → явный skip, не молчание");
}

#[test]
fn diagram_generates_mermaid() {
    let ctx = tmp(&[
        ("core/a.go", "package core\nfunc A(){}\n"),
        ("api/b.go", "package api\nimport \"core\"\nfunc B(){ core.A() }\n"),
    ]);
    let r = reg();
    assert!(
        !r.get("code.intel/diagram").unwrap().run(&ctx, &RunInput::default()).unwrap().records.is_empty(),
        "диаграмма-просмотр непуста"
    );
    r.get("generate/diagram").unwrap().run(&ctx, &RunInput::default()).unwrap();
    let md = std::fs::read_to_string(ctx.root.join("docs/ДИАГРАММА.md")).unwrap();
    assert!(md.contains("mermaid"), "mermaid-блок в ДИАГРАММА.md");
}

#[test]
fn mobile_desktop_recognize_stacks() {
    let r = reg();
    let ctx_m = tmp(&[("pubspec.yaml", "name: app\ndependencies:\n  flutter:\n")]);
    let m = r.get("verify/mobile").unwrap().run(&ctx_m, &RunInput::default()).unwrap();
    let mt = format!("{} {}", m.summary, m.skipped.unwrap_or_default());
    assert!(!mt.contains("не распознан"), "mobile распознал стек: {mt}");
    let ctx_d = tmp(&[("App.csproj", "<Project></Project>\n")]);
    let d = r.get("verify/desktop").unwrap().run(&ctx_d, &RunInput::default()).unwrap();
    let dt = format!("{} {}", d.summary, d.skipped.unwrap_or_default());
    assert!(!dt.contains("не распознан"), "desktop распознал стек: {dt}");
}

#[test]
fn thresholds_come_from_policy() {
    // Кастомный порог вложенности из ailc.policy.toml меняет поведение (governance-данные).
    let ctx = tmp(&[
        ("ailc.policy.toml", "name = \"strict\"\n[thresholds]\nmax_nesting = 2\n"),
        ("deep.go", "package x\nfunc f() {\n\tif a {\n\t\tif b {\n\t\t\tif c { x() }\n\t\t}\n\t}\n}\n"),
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
        strict.findings.iter().map(|f| f.rule.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn api_break_detects_removed_public_symbol() {
    let ctx = tmp(&[("lib.go", "package x\nfunc Alpha(){}\nfunc Beta(){}\n")]);
    let r = reg();
    // Снимок: Alpha + Beta.
    r.get("generate/api-baseline").unwrap().run(&ctx, &RunInput::default()).unwrap();
    // Удаляем Beta — слом контракта.
    std::fs::write(ctx.root.join("lib.go"), "package x\nfunc Alpha(){}\n").unwrap();
    let out = r.get("verify/api-break").unwrap().run(&ctx, &RunInput::default()).unwrap();
    assert!(
        out.findings.iter().any(|f| f.rule == "api-break" && f.message.contains("Beta")),
        "удаление публичного Beta поймано: {:?}",
        out.findings.iter().map(|f| f.message.as_str()).collect::<Vec<_>>()
    );
    // Без снимка — честный skip, не молчание.
    let ctx2 = tmp(&[("a.go", "package x\nfunc A(){}\n")]);
    assert!(
        r.get("verify/api-break").unwrap().run(&ctx2, &RunInput::default()).unwrap().skipped.is_some(),
        "без baseline — явный skip"
    );
}

#[test]
fn diff_scope_skips_without_git() {
    let ctx = tmp(&[("a.go", "package x\nfunc A(){}\n")]);
    let r = reg();
    let out = r.get("code.intel/diff-scope").unwrap().run(&ctx, &RunInput::default()).unwrap();
    // Не git-репозиторий → явный skip (нет молчаливого пропуска).
    assert!(out.skipped.is_some(), "вне git — явный skip: {:?}", out.summary);
}

#[test]
fn sbom_from_lockfile() {
    let ctx = tmp(&[("Cargo.lock", "[[package]]\nname = \"foo\"\nversion = \"1.2.3\"\n")]);
    let r = reg();
    r.get("generate/sbom").unwrap().run(&ctx, &RunInput::default()).unwrap();
    let sbom = std::fs::read_to_string(ctx.root.join("sbom.json")).unwrap();
    assert!(sbom.contains("CycloneDX") && sbom.contains("pkg:cargo/foo@1.2.3"), "SBOM: {sbom}");
}

#[test]
fn licenses_flag_copyleft() {
    let ctx = tmp(&[(
        "package-lock.json",
        r#"{"packages":{"":{},"node_modules/gpl-lib":{"version":"1.0.0","license":"GPL-3.0"},"node_modules/ok-lib":{"version":"2.0.0","license":"MIT"}}}"#,
    )]);
    let r = reg();
    let out = r.get("security.scan/licenses").unwrap().run(&ctx, &RunInput::default()).unwrap();
    assert!(
        out.findings.iter().any(|f| f.rule == "copyleft-license" && f.message.contains("gpl-lib")),
        "GPL помечен: {:?}",
        out.findings.iter().map(|f| f.message.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn cicd_creates_workflow() {
    let ctx = tmp(&[]);
    let r = reg();
    r.get("setup/cicd").unwrap().run(&ctx, &RunInput::default()).unwrap();
    let wf = std::fs::read_to_string(ctx.root.join(".github/workflows/ailc.yml")).unwrap();
    assert!(wf.contains("ailc dod") && wf.contains("sarif"), "workflow: {wf}");
}

#[test]
fn release_notes_skips_without_git() {
    let ctx = tmp(&[("a.rs", "fn main(){}\n")]);
    let r = reg();
    let out = r.get("generate/release-notes").unwrap().run(&ctx, &RunInput::default()).unwrap();
    assert!(out.skipped.is_some(), "вне git — явный skip: {:?}", out.summary);
}

// Контролируемый бенчмарк по ВСЕМ семействам на реалистичном коде (без синтетических
// opaque-предикатов). Измеряет TP/FP/FN/TN, делая упор на false-positive rate на
// безопасном коде — ключевое заявление ailc. Реальный путь: scan_all (+verify) и taint.
//   cargo test -p ailc-capabilities --test caps_tests _bench_controlled -- --nocapture --ignored
#[test]
#[ignore]
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
        // ── безопасные (НЕ должны срабатывать — тест на ложные) ──
        ("secret", "s1.py", "password = \"changeme\"\n", false, false),
        ("secret", "s2.py", "api_key = \"your_api_key_here\"\n", false, false),
        ("secret", "s3.py", "# пример: aws = \"AKIAIOSFODNN7EXAMPLE\"\n", false, false),
        ("web", "sw.py", "import requests\nx = requests.get(\"https://api.example.com/v1\")\n", false, false),
        ("owasp", "so.py", "result = compute(a, b)\n", false, false),
        ("iac", "sd.yaml", "spec:\n  securityContext:\n    runAsNonRoot: true\n", false, false),
        ("inject", "si.js", "el.textContent = userData\n", false, false),
        ("compliance", "sp.py", "import logging\nlogging.info(\"order id=%s\", oid)\n", false, false),
        ("pii", "ss.go", "count := computeTotal()\n", false, false),
        ("taint", "ts.py", "import os, shlex\ndef h():\n    c = request.args.get('c')\n    os.system(shlex.quote(c))\n", false, true),
        ("taint", "ts2.py", "import os\ndef h():\n    c = \"ls\"\n    os.system(c)\n", false, true),
        ("taint", "ts.java", "class C{ void v(java.sql.Connection con){ con.prepareStatement(\"SELECT * FROM t WHERE id=?\"); } }\n", false, true),
    ];

    let r = reg();
    let mut stats: BTreeMap<&str, [u64; 4]> = BTreeMap::new(); // [TP,FP,FN,TN]
    let mut misses: Vec<String> = Vec::new();
    for (group, file, content, expect, use_taint) in cases {
        let ctx = tmp(&[(file, content)]);
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
            e[0], e[1], e[2], e[3], rec * 100.0, fpr * 100.0
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
    assert_eq!(tot[1], 0, "false-positive на реалистичном безопасном коде: {misses:?}");
    assert_eq!(tot[2], 0, "пропуск реальной уязвимости: {misses:?}");
}
