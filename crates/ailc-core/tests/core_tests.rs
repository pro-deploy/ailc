//! Тесты ядра — сжато по числу, плотно по сути: каждый замораживает инвариант,
//! который мы реально отвоёвывали (анти-гейминг, path-traversal, идемпотентность,
//! нет молчаливых пропусков, полиглот-символы, циклы, состязательный verify).

use ailc_contracts::{Ctx, Finding, GatePolicy, Location, RunInput, Severity};
use ailc_core::engines::codeintel::{CodeIntelEngine, DepGraph};
use ailc_core::engines::gate::GateRunner;
use ailc_core::engines::generator::{Generator, WriteAction};
use ailc_core::engines::scan::{Matcher, Rule, ScanEngine};
use ailc_core::engines::store::Store;
use ailc_core::verify::Verifier;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU32, Ordering};

static CNT: AtomicU32 = AtomicU32::new(0);

/// Уникальная временная папка-проект с заданными файлами.
fn tmp(files: &[(&str, &str)]) -> Ctx {
    let n = CNT.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("ailc-t-{}-{}", std::process::id(), n));
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

fn finding(sev: Severity, verified: bool, file: &str, line: u32, source: &str) -> Finding {
    Finding {
        rule: "r".into(),
        severity: sev,
        message: "m".into(),
        location: Some(Location {
            file: file.into(),
            line,
        }),
        evidence: None,
        verified,
        source: source.into(),
    }
}

#[test]
fn gate_counts_only_verified() {
    let policy = GatePolicy {
        block_at: Severity::High,
        families: vec![],
    };
    let findings = vec![
        finding(Severity::Critical, true, "a.rs", 1, "x"), // verified High+ → blocking
        finding(Severity::Critical, false, "b.rs", 2, "x"), // НЕ verified → игнор (анти-гейминг)
        finding(Severity::Low, true, "c.rs", 3, "x"),      // verified low → warning
    ];
    let t = ailc_contracts::Thresholds::default();
    let r = GateRunner::classify(findings, vec!["x".into()], vec![], &policy, &t);
    assert_eq!(r.blocking.len(), 1, "блокирует только верифицированный critical");
    assert_eq!(r.warning.len(), 1);
    assert!(!r.passed);
}

#[test]
fn store_rejects_path_traversal() {
    let ctx = tmp(&[]);
    assert!(Store::write(&ctx, "ns", "../evil", "x").is_err());
    assert!(Store::write(&ctx, "..", "f", "x").is_err());
    assert!(Store::write(&ctx, "ns", "a/b", "x").is_err());
    assert!(Store::write(&ctx, "ns", "", "x").is_err());
    assert!(Store::append(&ctx, "ns", "../e", "x").is_err());
    assert!(Store::write(&ctx, "ns", "ok.md", "x").is_ok());
}

#[test]
fn generator_idempotent_preserves_manual_and_multiblock() {
    let ctx = tmp(&[]);
    let (_, a1) = Generator::write_block(&ctx, "doc.md", "k", "BLOCK").unwrap();
    assert_eq!(a1, WriteAction::Created);

    let p = ctx.root.join("doc.md");
    let cur = std::fs::read_to_string(&p).unwrap();
    std::fs::write(&p, format!("{cur}\nРУЧНОЕ")).unwrap();

    // Повтор тем же содержимым: блок не меняется, ручной текст жив.
    let (_, a2) = Generator::write_block(&ctx, "doc.md", "k", "BLOCK").unwrap();
    let after = std::fs::read_to_string(&p).unwrap();
    assert_eq!(a2, WriteAction::Unchanged, "идемпотентно");
    assert!(after.contains("РУЧНОЕ") && after.contains("BLOCK"));

    // Второй блок другим ключом не рушит первый; обновление первого не трогает второй.
    Generator::write_block(&ctx, "doc.md", "k2", "SECOND").unwrap();
    Generator::write_block(&ctx, "doc.md", "k", "BLOCK-NEW").unwrap();
    let three = std::fs::read_to_string(&p).unwrap();
    assert!(three.contains("BLOCK-NEW") && three.contains("SECOND") && three.contains("РУЧНОЕ"));
}

#[test]
fn scan_no_silent_skip_on_empty() {
    let ctx = tmp(&[]); // нет файлов → нечего сканировать
    let rules = vec![Rule {
        id: "x",
        severity: Severity::High,
        exts: &["rs"],
        matcher: Matcher::Predicate(|l| l.contains("TODO")),
        message: "m",
    }];
    let out = ScanEngine::run(&ctx, &RunInput::default(), &rules, "t", false).unwrap();
    assert!(out.skipped.is_some(), "0 файлов → ЯВНЫЙ skipped, не тихий ноль");
}

#[test]
fn scan_match_is_grounded_and_verified() {
    let ctx = tmp(&[("a.rs", "fn f(){ /* TODO fix */ }")]);
    let rules = vec![Rule {
        id: "todo",
        severity: Severity::Info,
        exts: &["rs"],
        matcher: Matcher::Predicate(|l| l.contains("TODO")),
        message: "m",
    }];
    let out = ScanEngine::run(&ctx, &RunInput::default(), &rules, "t", false).unwrap();
    assert_eq!(out.findings.len(), 1);
    assert!(out.findings[0].location.is_some(), "находка заземлена на file:line");
    assert!(out.findings[0].verified, "детерминированная находка → verified");
}

#[test]
fn codeintel_symbols_polyglot_and_exported() {
    let ctx = tmp(&[
        ("g.go", "func Exported(){}\nfunc private(){}\n"),
        ("r.rs", "pub fn pub_fn(){}\nfn priv_fn(){}\n"),
        ("p.py", "def hello():\n    pass\n"),
    ]);
    let syms = CodeIntelEngine::symbols(&ctx, &RunInput::default()).unwrap();
    let exp = |n: &str| syms.iter().find(|s| s.name == n).map(|s| s.exported);
    assert_eq!(exp("Exported"), Some(true), "Go заглавная = exported");
    assert_eq!(exp("private"), Some(false));
    assert_eq!(exp("pub_fn"), Some(true), "rust pub = exported");
    assert_eq!(exp("priv_fn"), Some(false));
    assert!(exp("hello").is_some(), "python def найден");
}

#[test]
fn codeintel_ast_languages_coverage() {
    // Каждый язык должен дать символ через tree-sitter (ловит поломку ABI грамматики).
    let ctx = tmp(&[
        ("A.java", "public class A {\n  public void run() {}\n}\n"),
        ("c.cs", "public class S {\n  public void Go() {}\n}\n"),
        ("k.c", "int add(int a){ return a; }\nstatic int hid(){ return 0; }\n"),
        ("w.cpp", "class W {\npublic:\n  void draw() {}\n};\n"),
        ("i.rb", "class Inv\n  def total\n    1\n  end\nend\n"),
        ("u.php", "<?php\nclass U {\n  public function go() {}\n}\n"),
        ("m.scala", "class Svc {\n  def handle(): Int = 1\n}\n"),
    ]);
    let syms = CodeIntelEngine::symbols(&ctx, &RunInput::default()).unwrap();
    let lang_of = |n: &str| syms.iter().find(|s| s.name == n).map(|s| s.lang.as_str());
    assert_eq!(lang_of("run"), Some("java"), "java AST");
    assert_eq!(lang_of("Go"), Some("csharp"), "C# AST (ABI 15)");
    assert_eq!(lang_of("add"), Some("c"), "C AST");
    assert_eq!(lang_of("draw"), Some("cpp"), "C++ AST");
    assert_eq!(lang_of("total"), Some("ruby"), "ruby AST");
    assert_eq!(lang_of("go"), Some("php"), "php AST");
    assert_eq!(lang_of("handle"), Some("scala"), "scala AST");
    // Флаг экспорта из AST: static-функция C — внутренняя.
    let exp = |n: &str| syms.iter().find(|s| s.name == n).map(|s| s.exported);
    assert_eq!(exp("hid"), Some(false), "C static = не экспортирован");
    assert_eq!(exp("add"), Some(true), "C нестатическая = экспортирована");
}

#[test]
fn callgraph_resolves_edges_and_finds_unreachable() {
    let ctx = tmp(&[(
        "a.py",
        "def helper():\n    return 1\ndef caller():\n    return helper()\ndef orphan():\n    return 9\ndef main():\n    caller()\nmain()\n",
    )]);
    let cg = CodeIntelEngine::call_graph(&ctx, &RunInput::default()).unwrap();
    assert!(
        cg.edges.contains(&("caller".to_string(), "helper".to_string())),
        "ребро caller→helper разрешено"
    );
    let unreachable = cg.unreachable();
    assert!(unreachable.contains(&"orphan".to_string()), "orphan недостижима");
    assert!(!unreachable.contains(&"helper".to_string()), "helper вызвана — достижима");
    assert!(!unreachable.contains(&"main".to_string()), "main — точка входа");
}

#[test]
fn osv_matches_vulnerable_versions_offline() {
    // Уязвимая версия ловится, исправленная и неизвестная — нет. Без сети/тулов.
    let ctx = tmp(&[(
        "requirements.txt",
        "requests==2.18.0\nrequests==2.20.0\nflask==2.0.0\n",
    )]);
    let rep = ailc_core::engines::osv::scan(&ctx.root);
    assert_eq!(rep.checked, 3, "три пина разобраны");
    let hits: Vec<&str> = rep
        .findings
        .iter()
        .map(|f| f.evidence.as_deref().unwrap_or(""))
        .collect();
    assert!(
        hits.iter().any(|e| e.contains("requests@2.18.0")),
        "2.18.0 < 2.20.0 — уязвима"
    );
    assert!(
        !hits.iter().any(|e| e.contains("requests@2.20.0")),
        "2.20.0 = фикс — не уязвима"
    );
    assert!(!hits.iter().any(|e| e.contains("flask")), "flask вне базы");
}

#[test]
fn sast_structural_precision() {
    // Литеральный аргумент безопасен, переменная — находка (точность поверх regex).
    // eval/exec выведены в потоковый сток; структурную точность показываем на system.
    let ctx = tmp(&[(
        "a.py",
        "def s():\n    system(\"ls\")\ndef v(x):\n    system(x)\ndef j(d):\n    import json\n    json.loads(d)\ndef p(d):\n    import pickle\n    pickle.loads(d)\n",
    )]);
    let rep = ailc_core::engines::sast::scan(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    let exec_lines: Vec<u32> = rep
        .findings
        .iter()
        .filter(|f| f.rule == "sast/dynamic-exec")
        .map(|f| f.location.as_ref().unwrap().line)
        .collect();
    assert_eq!(exec_lines, vec![4], "помечен только eval(x), не eval(\"1+1\")");
    assert!(
        rules.contains(&"sast/unsafe-deserialize"),
        "pickle.loads помечен"
    );
    assert_eq!(
        rep.findings
            .iter()
            .filter(|f| f.rule == "sast/unsafe-deserialize")
            .count(),
        1,
        "json.loads НЕ помечен, только pickle.loads"
    );
}

#[test]
fn depgraph_detects_cycle() {
    let mut edges = BTreeSet::new();
    edges.insert(("a".to_string(), "b".to_string()));
    edges.insert(("b".to_string(), "a".to_string()));
    let g = DepGraph {
        modules: vec!["a".into(), "b".into()],
        edges,
    };
    let cycles = g.cycles();
    assert_eq!(cycles.len(), 1, "a↔b — ровно один цикл (SCC)");
    assert_eq!(cycles[0].len(), 2);
}

#[test]
fn verifier_refutes_comment_and_placeholder_keeps_real() {
    let ctx = tmp(&[(
        "a.rs",
        "let real = secret;\n// let x = secret;\nlet y = \"changeme\";\n",
    )]);
    let findings = vec![
        finding(Severity::High, true, "a.rs", 1, "security.scan/secret"), // реальный код
        finding(Severity::High, true, "a.rs", 2, "security.scan/secret"), // в комментарии
        finding(Severity::High, true, "a.rs", 3, "security.scan/secret"), // плейсхолдер
    ];
    let (confirmed, refuted) = Verifier::verify(&ctx, findings);
    assert_eq!(confirmed.len(), 1, "остаётся только реальная находка");
    assert_eq!(refuted.len(), 2, "коммент и плейсхолдер опровергнуты");
    assert_eq!(confirmed[0].location.as_ref().unwrap().line, 1);
}

#[test]
fn verifier_refutes_rule_definitions_and_comment_smells() {
    // Сканер находит СВОЙ ruleset (анти-само-скан) + смел panic в комментарии.
    let ctx = tmp(&[(
        "rules.rs",
        // 1: определение regex-правила  2: тело предиката (.contains-цепочка)
        // 3: реальный опасный вызов     4: panic в комментарии (не исполняется)
        // 5: реальный panic в коде
        concat!(
            "Matcher::regex(r\"(?i)md5\\(\")\n",
            "|l| l.contains(\"eval(\") || l.contains(\"exec(\")\n",
            "let h = md5(pw);\n",
            "// тут panic(\"x\") в комментарии\n",
            "panic(\"real\");\n",
        ),
    )]);
    let mk = |rule: &str, line: u32, src: &str| Finding {
        rule: rule.into(),
        severity: Severity::High,
        message: "m".into(),
        location: Some(Location {
            file: "rules.rs".into(),
            line,
        }),
        evidence: None,
        verified: true,
        source: src.into(),
    };
    let findings = vec![
        mk("weak-hash", 1, "security.scan/owasp"), // определение regex → опровергнуть
        mk("dangerous-exec", 2, "security.scan/owasp"), // тело предиката → опровергнуть
        mk("weak-hash", 3, "security.scan/owasp"), // живой вызов → оставить
        mk("panic-path", 4, "quality.check/smell"), // panic в комментарии → опровергнуть
        mk("panic-path", 5, "quality.check/smell"), // живой panic → оставить
    ];
    let (confirmed, refuted) = Verifier::verify(&ctx, findings);
    let lines: Vec<u32> = confirmed
        .iter()
        .map(|f| f.location.as_ref().unwrap().line)
        .collect();
    assert_eq!(lines, vec![3, 5], "остаются только живые вызовы (стр. 3 и 5)");
    assert_eq!(refuted.len(), 3, "2 определения правил + panic в комментарии");
}

#[test]
fn scan_rejects_target_traversal() {
    // target приходит от MCP-клиента — `..` и абсолютные пути не должны выводить
    // сканирование за корень проекта (симметрично защите Store).
    let ctx = tmp(&[("a.rs", "fn f(){}\n")]);
    let rules = vec![Rule {
        id: "todo",
        severity: Severity::Info,
        exts: &[],
        matcher: Matcher::Predicate(|l| l.contains("TODO")),
        message: "m",
    }];
    let input = RunInput {
        target: Some("../evil".into()),
        query: None,
    };
    let err = ScanEngine::run(&ctx, &input, &rules, "t", true);
    assert!(err.is_err(), "target с `..` отвергается");
    assert!(err.unwrap_err().0.contains("корень"), "причина названа явно");

    let abs = RunInput {
        target: Some("/etc".into()),
        query: None,
    };
    assert!(
        ScanEngine::run(&ctx, &abs, &rules, "t", true).is_err(),
        "абсолютный target отвергается"
    );
}

#[test]
fn scan_reports_out_of_scope_files() {
    // Инвариант «нет молчаливых пропусков» для ЧАСТИЧНОГО охвата: скрытые файлы и
    // крупные блобы не сканируются осознанно, но их количество видно в сводке.
    let blob = "x".repeat(1_100_000);
    let ctx = tmp(&[
        ("a.rs", "// TODO later\n"),
        (".env", "SECRET=1\n"),
        ("bundle.min.js", blob.as_str()),
    ]);
    let rules = vec![Rule {
        id: "todo",
        severity: Severity::Info,
        exts: &[],
        matcher: Matcher::Predicate(|l| l.contains("TODO")),
        message: "m",
    }];
    let out = ScanEngine::run(&ctx, &RunInput::default(), &rules, "t", true).unwrap();
    let oos = out
        .metrics
        .iter()
        .find(|(k, _)| k == "files_out_of_scope")
        .map(|(_, v)| *v)
        .unwrap_or(0.0);
    assert!(oos >= 2.0, "скрытый .env + блоб учтены как вне охвата: {oos}");
    assert!(out.summary.contains("вне охвата"), "сводка честно называет пропуски");
}

#[test]
fn rigor_zero_and_headline_honest_when_no_checks_ran() {
    // Ноль выполненных проверок = нулевая тщательность, а не «100 по умолчанию»,
    // и заголовок не имеет права говорить «готово к сдаче».
    use ailc_core::orchestrator::Orchestrator;
    use ailc_core::registry::Registry;
    let ctx = tmp(&[]);
    let reg = Registry::new(); // пустой реестр → ни одна проверка не выполнится
    let ledger = Orchestrator::deterministic_gate(
        &reg,
        &ctx,
        &RunInput::default(),
        "проверь безопасность",
        &[ailc_contracts::Family::Security],
        false,
    );
    assert_eq!(ledger.checks_run, 0);
    assert_eq!(ledger.rigor, 0.0, "rigor не выдаёт 100 за пустой прогон");
    assert!(
        ledger.headline.contains("НЕ подтверждено"),
        "заголовок честен: {}",
        ledger.headline
    );
}

#[test]
fn verifier_refutes_numeric_placeholder() {
    let ctx = tmp(&[(
        "cfg.py",
        concat!(
            "api_key = \"123456789012\"\n", // восходящий ряд → плейсхолдер
            "api_key = \"f8Zk2pQ9vXw7\"\n", // похоже на реальный токен → остаётся
        ),
    )]);
    let findings = vec![
        finding(Severity::High, true, "cfg.py", 1, "security.scan/secret"),
        finding(Severity::High, true, "cfg.py", 2, "security.scan/secret"),
    ];
    let (confirmed, refuted) = Verifier::verify(&ctx, findings);
    assert_eq!(refuted.len(), 1, "числовой ряд опровергнут");
    assert!(refuted[0].1.contains("числовой"), "причина названа: {}", refuted[0].1);
    assert_eq!(confirmed.len(), 1, "реальный токен остаётся");
}

#[test]
fn osv_parses_new_ecosystems_offline() {
    use ailc_core::engines::osv;
    let ctx = tmp(&[
        (
            "go.sum",
            "golang.org/x/text v0.3.7 h1:abc=\ngolang.org/x/text v0.3.7/go.mod h1:def=\n",
        ),
        (
            "gradle.lockfile",
            "# generated\norg.apache.logging.log4j:log4j-core:2.14.1=compileClasspath\n",
        ),
        (
            "pubspec.lock",
            "packages:\n  http:\n    dependency: \"direct main\"\n    version: \"0.13.0\"\n",
        ),
        (
            "Podfile.lock",
            "PODS:\n  - AFNetworking (4.0.1):\n    - AFNetworking/Serialization (= 4.0.1)\n\nDEPENDENCIES:\n  - AFNetworking\n",
        ),
    ]);
    let rep = osv::scan(&ctx.root);
    assert_eq!(rep.checked, 4, "x/text + log4j + http + AFNetworking разобраны");
    let msgs: Vec<&str> = rep.findings.iter().map(|f| f.message.as_str()).collect();
    assert!(
        msgs.iter().any(|m| m.contains("CVE-2022-32149")),
        "go.sum: уязвимый x/text@0.3.7 найден: {msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| m.contains("CVE-2021-44228")),
        "gradle: Log4Shell в log4j-core@2.14.1 найден"
    );
    // Честность покрытия: по Pub/CocoaPods в снимке базы записей нет — это
    // явно сообщается, а не выдаётся как «0 уязвимостей = чисто».
    assert!(rep.uncovered.contains(&"Pub"), "Pub помечен непокрытым");
    assert!(rep.uncovered.contains(&"CocoaPods"), "CocoaPods помечен непокрытым");
    assert!(!rep.uncovered.contains(&"Go"), "Go покрыт базой");
}

#[test]
fn codeintel_ast_kotlin_swift_dart() {
    // Мобильные языки на полноценном AST (раньше — только regex-фолбэк).
    let ctx = tmp(&[
        ("App.kt", "class Session(val id: Int)\nfun connect(s: Session) {}\nprivate fun helper() {}\n"),
        ("View.swift", "class Profile {}\nfunc render(p: Profile) {}\nprotocol Drawable {}\n"),
        ("main.dart", "class Cart {}\nmixin Loggable {}\nvoid checkout(Cart c) {}\nvoid _hidden() {}\n"),
    ]);
    let syms = CodeIntelEngine::symbols(&ctx, &RunInput::default()).unwrap();
    let find = |n: &str| syms.iter().find(|s| s.name == n);
    for (name, lang) in [
        ("Session", "kotlin"),
        ("connect", "kotlin"),
        ("Profile", "swift"),
        ("render", "swift"),
        ("Drawable", "swift"),
        ("Cart", "dart"),
        ("Loggable", "dart"),
        ("checkout", "dart"),
    ] {
        let s = find(name).unwrap_or_else(|| panic!("{name} не найден: {:?}",
            syms.iter().map(|s| (&s.name, &s.lang)).collect::<Vec<_>>()));
        assert_eq!(s.lang, lang, "{name} распознан AST-слоем {lang}");
    }
    assert_eq!(find("_hidden").map(|s| s.exported), Some(false), "dart _имя приватно");
    assert_eq!(find("helper").map(|s| s.exported), Some(false), "kotlin private закрыт");
}

#[test]
fn sast_covers_kotlin_and_swift() {
    use ailc_core::engines::sast;
    // Kotlin: десериализация ObjectInputStream и динамический исполнитель команды;
    // литерал не флагуется. eval/exec выведены в потоковый сток, поэтому структурную
    // точность показываем на system (динамический аргумент против литерала).
    let ctx = tmp(&[
        (
            "Load.kt",
            "fun load(s: java.io.InputStream, x: String) {\n    val o = ObjectInputStream(s)\n    system(x)\n    system(\"1+1\")\n}\n",
        ),
        ("Run.swift", "func run(cmd: String) {\n    system(cmd)\n    system(\"ls\")\n}\n"),
    ]);
    let rep = sast::scan(&ctx, &RunInput::default()).unwrap();
    assert_eq!(rep.files, 2, "оба файла разобраны через AST");
    let rules: Vec<(&str, u32)> = rep
        .findings
        .iter()
        .map(|f| (f.rule.as_str(), f.location.as_ref().unwrap().line))
        .collect();
    assert!(
        rules.contains(&("sast/unsafe-deserialize", 2)),
        "kotlin ObjectInputStream найден: {rules:?}"
    );
    assert!(
        rules.contains(&("sast/dynamic-exec", 3)),
        "kotlin system(x) — динамический аргумент"
    );
    assert!(
        !rules.contains(&("sast/dynamic-exec", 4)),
        "kotlin system(\"1+1\") — литерал, не находка"
    );
    assert!(
        rep.findings.iter().any(|f| f.rule == "sast/dynamic-exec"
            && f.location.as_ref().unwrap().file.ends_with(".swift")),
        "swift system(cmd) — динамический аргумент: {rules:?}"
    );
    let exec_total = rep.findings.iter().filter(|f| f.rule == "sast/dynamic-exec").count();
    assert_eq!(exec_total, 2, "литералы (kotlin/swift) не флагуются: {rules:?}");
}

#[test]
fn compliance_pdn_logs_ast_multiline_and_masked() {
    use ailc_core::engines::sast;
    // Многострочный вызов (line-regex его не видит) + маскированный (не находка).
    let ctx = tmp(&[(
        "svc.py",
        concat!(
            "logger.info(\n",
            "    user.passport\n",
            ")\n",
            "logger.info(mask(user.passport))\n",
            "logger.info(order.total)\n",
        ),
    )]);
    let rep = sast::scan_pii_logs(&ctx, &RunInput::default()).unwrap();
    assert_eq!(
        rep.findings.len(),
        1,
        "ровно одна находка (маскированное и не-ПДн не флагуются): {:?}",
        rep.findings.iter().map(|f| &f.message).collect::<Vec<_>>()
    );
    assert_eq!(rep.findings[0].location.as_ref().unwrap().line, 1, "многострочный вызов найден");
    assert_eq!(rep.findings[0].source, "compliance.ru/pdn-logs-ast");
}

#[test]
fn agent_plan_prompt_includes_project_stack() {
    use ailc_core::agent::AgentOrchestrator;
    use ailc_core::orchestrator::Sampler;
    use ailc_core::registry::Registry;
    // Сэмплер-перехватчик: записывает PLAN-промпт, отвечает None (→ детерм. фолбэк).
    struct Capture(String);
    impl Sampler for Capture {
        fn sample(&mut self, _system: &str, user: &str) -> Option<String> {
            self.0 = user.to_string();
            None
        }
    }
    let ctx = tmp(&[("Cargo.toml", "[package]\nname=\"x\"\n"), ("pubspec.yaml", "name: app\n")]);
    let reg = Registry::new();
    let mut cap = Capture(String::new());
    let _ = AgentOrchestrator::run(&reg, &ctx, &RunInput::default(), "проверь", &mut cap, 0);
    assert!(cap.0.contains("Rust"), "промпт содержит стек: {}", &cap.0[..cap.0.len().min(400)]);
    assert!(cap.0.contains("Flutter"), "pubspec.yaml распознан как Flutter");
    assert!(cap.0.contains("Контекст проекта"), "секция контекста присутствует");
}

#[test]
fn sarif_serializes_findings_2_1_0() {
    use ailc_contracts::{Finding, Location, Severity};
    use ailc_core::sarif::to_sarif;
    let findings = vec![
        Finding {
            rule: "ssrf-sink".into(),
            severity: Severity::High,
            message: "SSRF — запрос по управляемому URL".into(),
            location: Some(Location {
                file: "web.py".into(),
                line: 3,
            }),
            evidence: Some("requests.get(request.args.get('u'))".into()),
            verified: true,
            source: "security.scan/web".into(),
        },
        Finding {
            rule: "import-cycle".into(),
            severity: Severity::Medium,
            message: "Циклическая зависимость".into(),
            location: None,
            evidence: None,
            verified: true,
            source: "quality.check/cycles".into(),
        },
    ];
    let s = to_sarif(
        &findings,
        "0.2.0",
        2,
        &["security.scan/web".into()],
        &[("verify/lint".into(), "нет линтера".into())],
    );
    let v: serde_json::Value = serde_json::from_str(&s).expect("SARIF — валидный JSON");
    assert_eq!(v["version"], "2.1.0");
    assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "ailc");
    let results = v["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2, "две находки");
    // High → error, с локацией и сниппетом.
    assert_eq!(results[0]["level"], "error");
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "web.py"
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
        3
    );
    // Medium → warning, без локации (поле отсутствует).
    assert_eq!(results[1]["level"], "warning");
    assert!(
        results[1].get("locations").is_none(),
        "находка без файла → без locations"
    );
    // Честность охвата: опровергнутые и пропуски — в properties прогона.
    assert_eq!(v["runs"][0]["properties"]["refutedFalsePositives"], 2);
    assert_eq!(
        v["runs"][0]["properties"]["checksSkipped"][0]["check"],
        "verify/lint"
    );
    // Правила дедуплицированы по id.
    assert_eq!(
        v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(),
        2
    );
}

#[test]
fn taint_tracks_cross_statement_flow_precisely() {
    use ailc_core::engines::sast::scan_taint;
    // vuln: источник→переменная→сток (находка). safe_param: параметризованный запрос
    // (НЕ находка — заражён только 2-й аргумент). safe_const: чистая константа (НЕ находка).
    let ctx = tmp(&[(
        "app.py",
        concat!(
            "import os\n",
            "def vuln():\n",
            "    cmd = request.args.get('c')\n",
            "    os.system(cmd)\n",
            "def safe_param(cur):\n",
            "    cur.execute('SELECT * FROM t WHERE id=?', (request.args.get('id'),))\n",
            "def safe_const():\n",
            "    c = 'ls -la'\n",
            "    os.system(c)\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rep.findings.len(), 1, "ровно один реальный поток: {rules:?}");
    assert_eq!(rep.findings[0].rule, "sast/taint-command-exec");
    assert_eq!(
        rep.findings[0].location.as_ref().unwrap().line,
        4,
        "сток — на строке os.system(cmd)"
    );
}

#[test]
fn taint_direct_source_and_scope_isolation() {
    use ailc_core::engines::sast::scan_taint;
    // Прямой источник в стоке (находка) + изоляция scope: заражение из a() не течёт в b().
    let ctx = tmp(&[(
        "h.py",
        concat!(
            "import os\n",
            "def a():\n",
            "    t = request.args.get('x')\n",
            "def b():\n",
            "    os.system(t)\n",            // t здесь чист (другая функция) → НЕ находка
            "def c():\n",
            "    os.system(request.args.get('z'))\n", // прямой источник → находка
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    assert_eq!(rep.findings.len(), 1, "только прямой поток в c(), изоляция scope держит");
    assert_eq!(rep.findings[0].rule, "sast/taint-command-exec");
}

#[test]
fn taint_javascript_flow_and_param_safe() {
    use ailc_core::engines::sast::scan_taint;
    // const-декларатор тянет источник в eval (находка); параметризованный db.query — нет.
    let ctx = tmp(&[(
        "h.js",
        concat!(
            "function vuln(req) {\n",
            "  const cmd = req.query.cmd;\n",
            "  eval(cmd);\n",
            "}\n",
            "function safe(db, req) {\n",
            "  db.query('SELECT * FROM t WHERE id = $1', [req.query.id]);\n",
            "}\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rep.findings.len(), 1, "только eval(cmd): {rules:?}");
    assert_eq!(rep.findings[0].rule, "sast/taint-command-exec");
}

#[test]
fn taint_go_command_arg_and_param_safe() {
    use ailc_core::engines::sast::scan_taint;
    // exec.Command("sh","-c",name): опасен НЕ первый аргумент → проверка всех аргументов.
    // db.Query(sql, source): параметризовано → первый аргумент чист → НЕ находка.
    let ctx = tmp(&[(
        "h.go",
        concat!(
            "package main\n",
            "func vuln(r *Request) {\n",
            "    name := r.FormValue(\"name\")\n",
            "    exec.Command(\"sh\", \"-c\", name)\n",
            "}\n",
            "func safe(db *DB, r *Request) {\n",
            "    db.Query(\"SELECT * FROM t WHERE id=$1\", r.FormValue(\"id\"))\n",
            "}\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rep.findings.len(), 1, "только exec.Command с заражённым 3-м арг: {rules:?}");
    assert_eq!(rep.findings[0].rule, "sast/taint-command-exec");
}

#[test]
fn taint_interprocedural_source_function() {
    use ailc_core::engines::sast::scan_taint;
    // get_input() возвращает источник → её вызов = источник (inter-procedural).
    // chain() возвращает get_input() → тоже source-функция (фикспойнт по цепочке).
    // clean() возвращает константу → НЕ source-функция (точность: safe() не флагуется).
    let ctx = tmp(&[(
        "app.py",
        concat!(
            "import os\n",
            "def get_input():\n",
            "    return request.args.get('q')\n",
            "def chain():\n",
            "    return get_input()\n",
            "def clean():\n",
            "    return 'fixed'\n",
            "def vuln():\n",
            "    x = get_input()\n",
            "    os.system(x)\n",
            "def vuln_chain():\n",
            "    z = chain()\n",
            "    os.system(z)\n",
            "def safe():\n",
            "    y = clean()\n",
            "    os.system(y)\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let lines: Vec<u32> = rep
        .findings
        .iter()
        .filter_map(|f| f.location.as_ref().map(|l| l.line))
        .collect();
    assert_eq!(
        rep.findings.len(),
        2,
        "поток через хелпер и цепочку, но не через константу: строки {lines:?}"
    );
    assert!(rep.findings.iter().all(|f| f.rule == "sast/taint-command-exec"));
}

#[test]
fn taint_sanitizer_clears_flow() {
    use ailc_core::engines::sast::scan_taint;
    // vuln: заражённый ввод напрямую (находка). safe_var/safe_inline: тот же ввод, но
    // через shlex.quote — санитайзер снимает заражение (НЕ находки).
    let ctx = tmp(&[(
        "app.py",
        concat!(
            "import os, shlex\n",
            "def vuln():\n",
            "    cmd = request.args.get('c')\n",
            "    os.system(cmd)\n",
            "def safe_var():\n",
            "    cmd = request.args.get('c')\n",
            "    safe = shlex.quote(cmd)\n",
            "    os.system(safe)\n",
            "def safe_inline():\n",
            "    os.system(shlex.quote(request.args.get('c')))\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let lines: Vec<u32> = rep
        .findings
        .iter()
        .filter_map(|f| f.location.as_ref().map(|l| l.line))
        .collect();
    assert_eq!(rep.findings.len(), 1, "только несанитизированный поток: строки {lines:?}");
    assert_eq!(rep.findings[0].location.as_ref().unwrap().line, 4);
}

#[test]
fn skills_export_generates_agentskills_pack() {
    use ailc_contracts::{CapabilityManifest, EngineKind, Family, Tier};
    use ailc_core::skills::generate;
    let m = CapabilityManifest {
        id: "security.scan/secret",
        family: Family::Security,
        engine: EngineKind::Scan,
        when_to_use: "Найти захардкоженные секреты: токены, ключи (с двоеточием, «кавычками»).",
        input_schema: "{}",
        tier: Tier::Core,
        deterministic: true,
        mutates: false,
    };
    let files = generate(&[&m], "0.2.0");
    // plugin.json + один SKILL.md на capability.
    assert_eq!(files.len(), 2);
    let skill = files
        .iter()
        .find(|f| f.path == "skills/security-scan-secret/SKILL.md")
        .expect("SKILL.md для capability со slug-путём");
    assert!(skill.content.starts_with("---\n"), "есть YAML-frontmatter");
    assert!(skill.content.contains("name: security-scan-secret"));
    assert!(skill.content.contains("# security.scan/secret"), "id в теле");
    assert!(skill.content.contains("ailc cap security.scan/secret"), "команда запуска");
    // plugin.json — валидный JSON с правильным именем.
    let pj = &files
        .iter()
        .find(|f| f.path == ".claude-plugin/plugin.json")
        .unwrap()
        .content;
    let v: serde_json::Value = serde_json::from_str(pj).expect("plugin.json — валидный JSON");
    assert_eq!(v["name"], "ailc");
    assert_eq!(v["mcp"]["command"], "ailc");
}

#[test]
fn taint_java_request_to_runtime_exec() {
    use ailc_core::engines::sast::scan_taint;
    // req.getParameter → cmd → Runtime.getRuntime().exec(cmd): находка.
    // safe: константа в exec → НЕ находка (точность).
    let ctx = tmp(&[(
        "C.java",
        concat!(
            "class C {\n",
            "  void vuln(HttpServletRequest req) throws Exception {\n",
            "    String cmd = req.getParameter(\"cmd\");\n",
            "    Runtime.getRuntime().exec(cmd);\n",
            "  }\n",
            "  void safe() throws Exception {\n",
            "    String cmd = \"ls -la\";\n",
            "    Runtime.getRuntime().exec(cmd);\n",
            "  }\n",
            "}\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rep.findings.len(), 1, "только заражённый exec: {rules:?}");
    assert_eq!(rep.findings[0].rule, "sast/taint-command-exec");
}

#[test]
fn taint_ruby_params_to_system() {
    use ailc_core::engines::sast::scan_taint;
    // params[:cmd] → cmd → system(cmd): находка. Константа в system → НЕ находка.
    let ctx = tmp(&[(
        "h.rb",
        concat!(
            "def vuln\n",
            "  cmd = params[:cmd]\n",
            "  system(cmd)\n",
            "end\n",
            "def safe\n",
            "  cmd = \"ls -la\"\n",
            "  system(cmd)\n",
            "end\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rep.findings.len(), 1, "только заражённый system: {rules:?}");
    assert_eq!(rep.findings[0].rule, "sast/taint-command-exec");
}

// ── Выравнивание: «открытие файла» (path) для JS/Java/Ruby + полный PHP ──

#[test]
fn taint_javascript_path_sink() {
    use ailc_core::engines::sast::scan_taint;
    let ctx = tmp(&[(
        "h.js",
        "function vuln(req) {\n  const p = req.query.file;\n  fs.readFileSync(p);\n}\n",
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    assert_eq!(rep.findings.len(), 1, "fs.readFileSync с заражённым путём");
    assert_eq!(rep.findings[0].rule, "sast/taint-path");
}

#[test]
fn taint_java_path_via_constructor() {
    use ailc_core::engines::sast::scan_taint;
    // new FileInputStream(f) — конструктор как сток открытия файла.
    let ctx = tmp(&[(
        "C.java",
        concat!(
            "class C {\n",
            "  void vuln(HttpServletRequest req) throws Exception {\n",
            "    String f = req.getParameter(\"f\");\n",
            "    new FileInputStream(f);\n",
            "  }\n",
            "}\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    assert_eq!(rep.findings.len(), 1, "конструктор FileInputStream — path-сток");
    assert_eq!(rep.findings[0].rule, "sast/taint-path");
}

#[test]
fn taint_ruby_path_sink() {
    use ailc_core::engines::sast::scan_taint;
    let ctx = tmp(&[(
        "h.rb",
        "def vuln\n  f = params[:file]\n  File.read(f)\nend\n",
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    assert_eq!(rep.findings.len(), 1, "File.read с заражённым путём");
    assert_eq!(rep.findings[0].rule, "sast/taint-path");
}

#[test]
fn taint_php_superglobal_to_system() {
    use ailc_core::engines::sast::scan_taint;
    // $_GET (суперглобал) → $cmd → system($cmd): находка. Константа → НЕ находка.
    // Проверяет поддержку PHP-переменных (узел variable_name) и суперглобалов.
    let ctx = tmp(&[(
        "app.php",
        concat!(
            "<?php\n",
            "function vuln() {\n",
            "    $cmd = $_GET['cmd'];\n",
            "    system($cmd);\n",
            "}\n",
            "function safe() {\n",
            "    $cmd = \"ls\";\n",
            "    system($cmd);\n",
            "}\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rep.findings.len(), 1, "только заражённый system (PHP): {rules:?}");
    assert_eq!(rep.findings[0].rule, "sast/taint-command-exec");
}

// ── Обогащение словарей: новые стоки на уже сделанных языках ──

#[test]
fn taint_enriched_sinks() {
    use ailc_core::engines::sast::scan_taint;
    // Java prepareStatement с конкатенацией → SQL; JS Function(...) → команда;
    // Python os.open(...) → файл. Каждое — новый сток, добавленный при обогащении.
    let ctx = tmp(&[
        (
            "C.java",
            concat!(
                "class C {\n",
                "  void v(HttpServletRequest req, java.sql.Connection con) throws Exception {\n",
                "    String id = req.getParameter(\"id\");\n",
                "    con.prepareStatement(\"SELECT * FROM t WHERE id = \" + id);\n",
                "  }\n",
                "}\n",
            ),
        ),
        (
            "h.js",
            "function v(req) {\n  const code = req.query.code;\n  Function(code);\n}\n",
        ),
        (
            "h.py",
            "def v():\n    p = request.args.get('p')\n    os.open(p, 0)\n",
        ),
    ]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    assert!(rules.contains(&"sast/taint-sql"), "Java prepareStatement: {rules:?}");
    assert!(rules.contains(&"sast/taint-command-exec"), "JS Function(): {rules:?}");
    assert!(rules.contains(&"sast/taint-path"), "Python os.open(): {rules:?}");
    assert_eq!(rep.findings.len(), 3, "ровно три новых стока: {rules:?}");
}

#[test]
fn taint_php_sanitizer_clears_flow() {
    use ailc_core::engines::sast::scan_taint;
    // PHP-санитайзер escapeshellarg снимает заражение (равномерно с другими языками).
    let ctx = tmp(&[(
        "a.php",
        concat!(
            "<?php\n",
            "function vuln() { system($_GET['c']); }\n",
            "function safe() { system(escapeshellarg($_GET['c'])); }\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    assert_eq!(rep.findings.len(), 1, "только несанитизированный PHP-поток");
    assert_eq!(
        rep.findings[0].location.as_ref().unwrap().line,
        2,
        "сток — на строке vuln()"
    );
}

// ── Новые языки: C# (ASP.NET) и Rust ──

#[test]
fn taint_csharp_request_to_process_start() {
    use ailc_core::engines::sast::scan_taint;
    // Request.QueryString → cmd → Process.Start(cmd): находка. Константа → НЕ находка.
    let ctx = tmp(&[(
        "C.cs",
        concat!(
            "class C {\n",
            "  void vuln(HttpRequest Request) {\n",
            "    string cmd = Request.QueryString[\"cmd\"];\n",
            "    System.Diagnostics.Process.Start(cmd);\n",
            "    string id = Request.Query[\"id\"];\n",
            "    string q = \"SELECT \" + id;\n",
            "    new System.Data.SqlClient.SqlCommand(q, conn);\n",
            "  }\n",
            "  void safe() {\n",
            "    string cmd = \"ls\";\n",
            "    System.Diagnostics.Process.Start(cmd);\n",
            "  }\n",
            "}\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    // Process.Start(cmd) → команда; new SqlCommand(q,…) с конкатенацией → SQL (тип квалифицирован).
    assert_eq!(rep.findings.len(), 2, "команда + SQL, но не safe: {rules:?}");
    assert!(rules.contains(&"sast/taint-command-exec"), "{rules:?}");
    assert!(rules.contains(&"sast/taint-sql"), "квалифицированный SqlCommand: {rules:?}");
}

#[test]
fn taint_rust_env_to_command() {
    use ailc_core::engines::sast::scan_taint;
    // std::env::var → cmd → Command::new(cmd): находка. Константа → НЕ находка.
    let ctx = tmp(&[(
        "m.rs",
        concat!(
            "fn vuln() {\n",
            "    let cmd = std::env::var(\"CMD\").unwrap();\n",
            "    std::process::Command::new(cmd);\n",
            "}\n",
            "fn safe() {\n",
            "    let cmd = \"ls\";\n",
            "    std::process::Command::new(cmd);\n",
            "}\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rep.findings.len(), 1, "только заражённый Command::new: {rules:?}");
    assert_eq!(rep.findings[0].rule, "sast/taint-command-exec");
}

#[test]
fn taint_swift_query_to_system() {
    use ailc_core::engines::sast::scan_taint;
    // Vapor req.query → cmd → system(cmd): находка. Константа → НЕ находка.
    let ctx = tmp(&[(
        "V.swift",
        concat!(
            "func vuln(req: Request) {\n",
            "  let cmd = req.query(\"c\")\n",
            "  system(cmd)\n",
            "}\n",
            "func safe() {\n",
            "  let cmd = \"ls\"\n",
            "  system(cmd)\n",
            "}\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rep.findings.len(), 1, "только заражённый system (Swift): {rules:?}");
    assert_eq!(rep.findings[0].rule, "sast/taint-command-exec");
}

#[test]
fn taint_dart_query_to_process_run() {
    use ailc_core::engines::sast::scan_taint;
    // shelf request.url.queryParameters → cmd → Process.run(cmd): находка.
    let ctx = tmp(&[(
        "h.dart",
        concat!(
            "void vuln(Request request) {\n",
            "  var cmd = request.url.queryParameters['c'];\n",
            "  Process.run(cmd, []);\n",
            "}\n",
            "void safe() {\n",
            "  var cmd = \"ls\";\n",
            "  Process.run(cmd, []);\n",
            "}\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rep.findings.len(), 1, "только заражённый Process.run (Dart): {rules:?}");
    assert_eq!(rep.findings[0].rule, "sast/taint-command-exec");
}

#[test]
fn taint_c_env_and_buffer_input() {
    use ailc_core::engines::sast::scan_taint;
    // getenv → system (команда); fgets(buf) → strcpy(dst, buf) (буфер, output-параметр).
    // safe: константа → НЕ находка.
    let ctx = tmp(&[(
        "v.c",
        concat!(
            "void vuln() {\n",
            "  char* p = getenv(\"CMD\");\n",
            "  system(p);\n",
            "  char buf[100];\n",
            "  fgets(buf, 100, stdin);\n",
            "  strcpy(dst, buf);\n",
            "}\n",
            "void safe() {\n",
            "  char* p = \"ls\";\n",
            "  system(p);\n",
            "}\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rep.findings.len(), 2, "команда (getenv) + буфер (fgets): {rules:?}");
    assert!(rules.contains(&"sast/taint-command-exec"), "{rules:?}");
    assert!(rules.contains(&"sast/taint-buffer"), "fgets→strcpy: {rules:?}");
}

#[test]
fn taint_cpp_getenv_to_system() {
    use ailc_core::engines::sast::scan_taint;
    let ctx = tmp(&[(
        "v.cpp",
        "void vuln() {\n  char* cmd = getenv(\"X\");\n  system(cmd);\n}\n",
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    assert_eq!(rep.findings.len(), 1, "C++ getenv → system");
    assert_eq!(rep.findings[0].rule, "sast/taint-command-exec");
}

#[test]
fn taint_scala_request_to_exec() {
    use ailc_core::engines::sast::scan_taint;
    // Play request.getQueryString → cmd → Runtime.exec(cmd): находка. Константа → нет.
    let ctx = tmp(&[(
        "S.scala",
        concat!(
            "def vuln(request: Request) = {\n",
            "  val cmd = request.getQueryString(\"c\")\n",
            "  Runtime.getRuntime().exec(cmd)\n",
            "}\n",
            "def safe() = {\n",
            "  val cmd = \"ls\"\n",
            "  Runtime.getRuntime().exec(cmd)\n",
            "}\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rep.findings.len(), 1, "только заражённый exec (Scala): {rules:?}");
    assert_eq!(rep.findings[0].rule, "sast/taint-command-exec");
}

#[test]
fn taint_kotlin_call_params_to_exec() {
    use ailc_core::engines::sast::scan_taint;
    // Ktor call.parameters → cmd → Runtime.getRuntime().exec(cmd): находка.
    // Проверяет Kotlin-специфику: simple_identifier, navigation_expression, property_declaration.
    let ctx = tmp(&[(
        "K.kt",
        concat!(
            "fun vuln(call: ApplicationCall) {\n",
            "    val cmd = call.parameters[\"cmd\"]\n",
            "    Runtime.getRuntime().exec(cmd)\n",
            "}\n",
            "fun safe() {\n",
            "    val cmd = \"ls\"\n",
            "    Runtime.getRuntime().exec(cmd)\n",
            "}\n",
        ),
    )]);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
    let rules: Vec<&str> = rep.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rep.findings.len(), 1, "только заражённый exec (Kotlin): {rules:?}");
    assert_eq!(rep.findings[0].rule, "sast/taint-command-exec");
}

// Внешний бенчмарк: OWASP Benchmark v1.2 (taint по CWE-78/89/22). Запуск вручную:
//   cargo test -p ailc-core --test core_tests _bench_owasp -- --nocapture --ignored
#[test]
#[ignore]
fn _bench_owasp() {
    use ailc_contracts::Ctx;
    use std::collections::{BTreeMap, HashSet};
    let base = "/tmp/BenchmarkJava";
    let testcode = format!("{base}/src/main/java/org/owasp/benchmark/testcode");
    if !std::path::Path::new(&testcode).exists() {
        eprintln!("SKIP: нет OWASP Benchmark в {testcode}");
        return;
    }
    let ctx = Ctx::new(&testcode);
    let rep = ailc_core::engines::sast::scan_taint(&ctx, &RunInput::default()).unwrap();
    let mut flagged: HashSet<String> = HashSet::new();
    for f in &rep.findings {
        if let Some(loc) = &f.location {
            let n = loc
                .file
                .rsplit('/')
                .next()
                .unwrap_or(&loc.file)
                .trim_end_matches(".java");
            flagged.insert(n.to_string());
        }
    }
    eprintln!(
        "\ntaint: разобрано {} java-файлов, {} находок, {} уникальных помеченных файлов",
        rep.files,
        rep.findings.len(),
        flagged.len()
    );
    let mut sorted: Vec<&String> = flagged.iter().collect();
    sorted.sort();
    let _ = std::fs::write(
        "/tmp/flagged.txt",
        sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n"),
    );
    let csv = std::fs::read_to_string(format!("{base}/expectedresults-1.2.csv")).unwrap();
    let mut stats: BTreeMap<&str, [u64; 4]> = BTreeMap::new(); // [TP,FP,FN,TN]
    for line in csv.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let p: Vec<&str> = line.split(',').collect();
        if p.len() < 4 {
            continue;
        }
        let key = match p[3].trim() {
            "78" => "cmdi(78)",
            "89" => "sqli(89)",
            "22" => "path(22)",
            _ => continue,
        };
        let vuln = p[2].trim() == "true";
        let hit = flagged.contains(p[0].trim());
        let e = stats.entry(key).or_insert([0; 4]);
        match (vuln, hit) {
            (true, true) => e[0] += 1,
            (false, true) => e[1] += 1,
            (true, false) => e[2] += 1,
            (false, false) => e[3] += 1,
        }
    }
    let row = |k: &str, e: &[u64; 4]| {
        let (tp, fp, fn_, tn) = (e[0] as f64, e[1] as f64, e[2] as f64, e[3] as f64);
        let rec = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
        let fpr = if fp + tn > 0.0 { fp / (fp + tn) } else { 0.0 };
        let prec = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        eprintln!(
            "{k:<10} TP={:<4} FP={:<4} FN={:<4} TN={:<4} | recall={:>5.1}% FPR={:>5.1}% prec={:>5.1}% Youden={:>+.3}",
            e[0], e[1], e[2], e[3], rec * 100.0, fpr * 100.0, prec * 100.0, rec - fpr
        );
    };
    eprintln!("\n=== OWASP Benchmark v1.2 — ailc taint (внутрипроцедурный) ===");
    let mut tot = [0u64; 4];
    for (k, e) in &stats {
        for i in 0..4 {
            tot[i] += e[i];
        }
        row(k, e);
    }
    row("ИТОГО", &tot);
}

// ───────── Tier-1 #2: confidence + сигнальный профиль + inline-ignore ─────────

fn mkf(rule: &str, sev: Severity, src: &str) -> Finding {
    Finding {
        rule: rule.into(),
        severity: sev,
        message: "m".into(),
        location: None,
        evidence: None,
        verified: true,
        source: src.into(),
    }
}

#[test]
fn confidence_separates_signal_from_noise() {
    use ailc_contracts::Confidence;
    // HIGH — точные токены / структурный AST / taint-путь.
    assert_eq!(
        mkf("private-key", Severity::Critical, "security.scan/secret").confidence(),
        Confidence::High
    );
    assert_eq!(
        mkf("sast/taint-command-exec", Severity::High, "security.scan/taint").confidence(),
        Confidence::High
    );
    // LOW — стиль/метрики/инфо-PII/дрейф доков/эвристики комплаенса = шум.
    for r in [
        "long-file",
        "deep-nesting",
        "debt-marker",
        "email-literal",
        "doc-drift",
        "foreign-tracker",
    ] {
        let f = mkf(r, Severity::Low, "quality.check/x");
        assert_eq!(f.confidence(), Confidence::Low, "{r} → low");
        assert!(!f.is_signal(), "{r} не сигнал");
    }
    // MEDIUM по умолчанию (неизвестное правило) → остаётся сигналом (ничего не теряем молча).
    let m = mkf("sql-injection", Severity::High, "security.scan/owasp");
    assert_eq!(m.confidence(), Confidence::Medium);
    assert!(m.is_signal());
}

#[test]
fn gate_routes_low_confidence_to_advisories_not_score() {
    use ailc_contracts::Thresholds;
    let policy = GatePolicy {
        block_at: Severity::High,
        families: vec![],
    };
    let t = Thresholds::default();
    let findings = vec![
        mkf("sql-injection", Severity::Medium, "security.scan/owasp"), // сигнал → warning
        mkf("long-file", Severity::Low, "quality.check/complexity"),   // шум → advisory
        mkf("deep-nesting", Severity::Low, "quality.check/antipattern"), // шум → advisory
    ];
    let r = GateRunner::classify(findings, vec![], vec![], &policy, &t);
    assert_eq!(r.warning.len(), 1, "в вердикт идёт только сигнал");
    assert_eq!(r.advisories.len(), 2, "низкоуверенный шум — в советы");
    // Советы НЕ снижают балл: тот же набор без шумовых находок даёт тот же score.
    let r2 = GateRunner::classify(
        vec![mkf("sql-injection", Severity::Medium, "security.scan/owasp")],
        vec![],
        vec![],
        &policy,
        &t,
    );
    assert_eq!(r.score, r2.score, "advisories не влияют на балл качества");
}

#[test]
fn inline_ignore_is_language_agnostic() {
    // Реальный (не-плейсхолдер) AWS-ключ + маркер подавления в комментарии РАЗНЫХ языков.
    const KEY: &str = "AKIAZ7QH4D2KLMNP9RS3";
    let cases = [
        ("c.rs", format!("let s = \"{KEY}\"; // ailc:ignore")),
        ("c.py", format!("s = \"{KEY}\"  # ailc:ignore")),
        ("c.lua", format!("s = \"{KEY}\" -- ailc:ignore")),
        ("c.html", format!("{KEY} <!-- ailc:ignore -->")),
        ("c.sql", format!("-- {KEY} ailc:ignore")),
    ];
    for (file, line) in &cases {
        let ctx = tmp(&[(file, line.as_str())]);
        let f = Finding {
            rule: "aws-access-key".into(),
            severity: Severity::Critical,
            message: "m".into(),
            location: Some(Location {
                file: (*file).into(),
                line: 1,
            }),
            evidence: None,
            verified: true,
            source: "security.scan/secret".into(),
        };
        let (conf, refd) = Verifier::verify(&ctx, vec![f]);
        assert!(conf.is_empty() && refd.len() == 1, "{file}: должно подавиться");
        assert!(
            refd[0].1.contains("ailc:ignore"),
            "{file}: причина именно inline-ignore, а не другое опровержение"
        );
    }
    // Маркер на СТРОКЕ ВЫШЕ тоже подавляет.
    let ctx = tmp(&[("p.go", &format!("// ailc:ignore\nkey := \"{KEY}\""))]);
    let f = Finding {
        rule: "aws-access-key".into(),
        severity: Severity::Critical,
        message: "m".into(),
        location: Some(Location {
            file: "p.go".into(),
            line: 2,
        }),
        evidence: None,
        verified: true,
        source: "security.scan/secret".into(),
    };
    assert_eq!(Verifier::verify(&ctx, vec![f]).1.len(), 1, "ignore на строке выше");
    // Скоуп `[rule]` подавляет ТОЛЬКО названное правило — чужое проходит.
    let ctx = tmp(&[("s.go", &format!("key := \"{KEY}\" // ailc:ignore[some-other-rule]"))]);
    let f = Finding {
        rule: "aws-access-key".into(),
        severity: Severity::Critical,
        message: "m".into(),
        location: Some(Location {
            file: "s.go".into(),
            line: 1,
        }),
        evidence: None,
        verified: true,
        source: "security.scan/secret".into(),
    };
    let (conf, _refd) = Verifier::verify(&ctx, vec![f]);
    assert_eq!(conf.len(), 1, "scoped ignore не подавляет чужое правило");
}
