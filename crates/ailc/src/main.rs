//! ailc — точка входа.
//!
//! Два режима:
//!   `ailc serve`               — MCP-сервер поверх stdio (для подключения в IDE).
//!                                 Наружу только front door `plan`, не плоские тулы.
//!   `ailc <путь> ["намерение"]` — CLI-демонстратор того же front door.
//!
//! Человек везде работает НАМЕРЕНИЕМ и получает QualityLedger; имён инструментов
//! и движков он не видит.

mod compliance_wizard;
mod custodian;
mod mcp;

use ailc_contracts::{Ctx, RunInput};
use ailc_core::fixer::Fixer;
use ailc_core::orchestrator::Orchestrator;
use ailc_core::registry::Registry;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.get(1).map(String::as_str) == Some("serve") {
        mcp::serve();
        return;
    }

    // Сопровождение: `ailc custodian <путь> [сек] [--fix] [--once]`.
    //   `install`/`uninstall` — автозапуск через launchd (macOS), переживает ребут.
    if args.get(1).map(String::as_str) == Some("custodian") {
        let sub = args.get(2).map(String::as_str);
        if sub == Some("install") || sub == Some("uninstall") {
            let mut root = ".".to_string();
            let mut interval = 900u64; // по умолчанию каждые 15 минут
            for a in args.iter().skip(3) {
                match a.parse::<u64>() {
                    Ok(n) => interval = n,
                    Err(_) => root = a.clone(),
                }
            }
            if sub == Some("install") {
                custodian::install(&root, interval);
            } else {
                custodian::uninstall(&root);
            }
            return;
        }
        let fix = args.iter().any(|a| a == "--fix");
        let once = args.iter().any(|a| a == "--once");
        let mut root = ".".to_string();
        let mut interval = 3u64;
        for a in args.iter().skip(2) {
            if a == "--fix" || a == "--once" {
                continue;
            }
            match a.parse::<u64>() {
                Ok(n) => interval = n,
                Err(_) => root = a.clone(),
            }
        }
        if once {
            custodian::run_once(&root, fix);
        } else {
            custodian::run(&root, interval, fix);
        }
        return;
    }

    // Definition of Done — многоосевой вердикт: `ailc dod <путь>`
    if args.get(1).map(String::as_str) == Some("dod") {
        run_dod(&args);
        return;
    }

    // Лёгкий однострочный статус (без тестов/линта) — для хука/частого вызова:
    // `ailc pulse <путь>`. Дешёвый детерминированный сигнал «всё ли ок».
    if args.get(1).map(String::as_str) == Some("pulse") {
        run_pulse(&args);
        return;
    }

    // Проектирование новой фичи: `ailc design "<что хочу>" [путь]`
    if args.get(1).map(String::as_str) == Some("design") {
        run_design(&args);
        return;
    }

    // Безопасная починка (формат/линт) с циклом проверка→фикс→проверка: `ailc fix <путь>`
    if args.get(1).map(String::as_str) == Some("fix") {
        run_fix(&args);
        return;
    }

    // Dev: прогнать одну capability. `ailc cap <id> [путь] [query]`
    if args.get(1).map(String::as_str) == Some("cap") {
        run_single_cap(&args);
        return;
    }

    // SARIF-отчёт для CI: `ailc sarif <путь> > results.sarif`
    if args.get(1).map(String::as_str) == Some("sarif") {
        run_sarif(&args);
        return;
    }

    // Экспорт возможностей как agentskills-пак: `ailc skills [папка]`
    if args.get(1).map(String::as_str) == Some("skills") {
        run_skills(&args);
        return;
    }

    // Интерактивный мастер комплаенса РФ: `ailc compliance-ru [путь-для-вывода]`
    if args.get(1).map(String::as_str) == Some("compliance-ru") {
        compliance_wizard::run(&args);
        return;
    }

    cli_demo(&args);
}

fn run_fix(args: &[String]) {
    let root = args.get(2).cloned().unwrap_or_else(|| ".".to_string());
    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);
    let ctx = Ctx::new(&root);

    let lint = |reg: &Registry, ctx: &Ctx| -> String {
        reg.get("verify/lint")
            .and_then(|c| c.run(ctx, &RunInput::default()).ok())
            .map(|o| o.summary)
            .unwrap_or_else(|| "—".to_string())
    };

    println!("ailc fix — безопасная починка ({root})\n");
    println!("Линт ДО:    {}", lint(&reg, &ctx));

    println!("\nПрименяю авто-фиксеры (формат/линт):");
    let steps = Fixer::run(&ctx);
    if steps.is_empty() {
        println!("  (тип проекта не распознан — нечего чинить)");
    }
    for s in &steps {
        let mark = if !s.ran {
            "⊘"
        } else if s.ok {
            "✓"
        } else {
            "✗"
        };
        println!("  {mark} {} — {}", s.tool, s.note);
    }

    println!("\nЛинт ПОСЛЕ:  {}", lint(&reg, &ctx));
    println!(
        "\nФормат/линт починены автоматически. Находки безопасности/логики НЕ трогаю —\n\
         их решает человек: `ailc {root} \"проверь безопасность\"`."
    );
}

fn run_dod(args: &[String]) {
    let root = args.get(2).cloned().unwrap_or_else(|| ".".to_string());
    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);
    let ctx = Ctx::new(&root);
    let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());

    println!("DOD CHECK — Definition of Done ({root})\n");
    for a in &report.axes {
        let mark = if !a.ran {
            "⊘"
        } else if a.ok {
            "✓"
        } else {
            "✗"
        };
        let kind = if a.hard { "hard" } else { "soft" };
        let detail = if !a.ran {
            "не выполнялась".to_string()
        } else if a.name == "OWASP HIGH" {
            format!("HIGH-находок: {}", a.high)
        } else {
            format!("находок: {}", a.findings)
        };
        println!("  {mark} {:<20} [{kind}] — {detail}", a.name);
    }
    println!(
        "\nВЕРДИКТ: {}",
        if report.passed {
            "✓ DoD выполнен — можно сдавать"
        } else {
            "✗ DoD НЕ выполнен — почини hard-оси (✗) выше"
        }
    );
}

/// Лёгкий однострочный статус качества (быстрые детерминированные проверки —
/// security+quality, БЕЗ тестов/линта). Для хука «на каждый промпт» и частого вызова.
fn run_pulse(args: &[String]) {
    let root = args.get(2).cloned().unwrap_or_else(|| ".".to_string());
    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);
    let ctx = Ctx::new(&root);
    let ledger = Orchestrator::deterministic_gate(
        &reg,
        &ctx,
        &RunInput::default(),
        "pulse",
        &[
            ailc_contracts::Family::Security,
            ailc_contracts::Family::Quality,
        ],
        false,
    );
    let mark = if ledger.passed { "✅" } else { "❌" };
    println!(
        "{mark} качество {:.0}/100 · блокеров {} · предупреждений {} · проверок {}",
        ledger.score, ledger.blocking, ledger.warning, ledger.checks_run
    );
}

/// Проектирование новой фичи «как в ИТ принято»: заготовка спеки + ADR.
fn run_design(args: &[String]) {
    let feature = match args.get(2) {
        Some(f) if !f.trim().is_empty() => f.clone(),
        _ => {
            println!(
                "ailc design — проектирование новой фичи\n\n\
                 Использование: ailc design \"<что хочу сделать>\" [путь]"
            );
            return;
        }
    };
    let path = args.get(3).cloned().unwrap_or_else(|| ".".to_string());
    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);
    let ctx = Ctx::new(&path);
    let input = RunInput {
        target: None,
        query: Some(feature.clone()),
    };

    println!("ailc design — «{feature}»\n");
    match reg.get("spec/feature").map(|c| c.run(&ctx, &input)) {
        Some(Ok(out)) => {
            println!("{}", out.summary);
            if let Some(s) = &out.skipped {
                println!("⚠ {s}");
            }
            for a in &out.artifacts {
                println!("  📄 {a}");
            }
            if !out.artifacts.is_empty() {
                println!(
                    "\nДальше: заполни разделы заготовки (зачем · что · критерии приёмки · риски)\n\
                     и решение в ADR. Готовность проверишь: `ailc {path} \"проверь перед сдачей\"`."
                );
            }
        }
        Some(Err(e)) => println!("ОШИБКА: {e}"),
        None => println!("инструмент проектирования недоступен"),
    }
}

fn run_single_cap(args: &[String]) {
    let id = args.get(2).map(String::as_str).unwrap_or("");
    let path = args.get(3).cloned().unwrap_or_else(|| ".".to_string());
    let query = args.get(4).cloned();

    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);

    let ctx = Ctx::new(&path);
    let input = RunInput {
        target: None,
        query,
    };
    match reg.get(id) {
        Some(cap) => match cap.run(&ctx, &input) {
            Ok(out) => {
                println!("{}", out.summary);
                if let Some(s) = &out.skipped {
                    println!("SKIPPED: {s}");
                }
                for f in out.findings.iter().take(25) {
                    let loc = f
                        .location
                        .as_ref()
                        .map(|l| format!(" ({}:{})", l.file, l.line))
                        .unwrap_or_default();
                    println!("  [{}] {} — {}{loc}", f.severity, f.rule, f.message);
                }
                for r in out.records.iter().take(25) {
                    println!("  {r}");
                }
            }
            Err(e) => println!("ОШИБКА: {e}"),
        },
        None => println!("нет такого capability: {id}"),
    }
}

/// SARIF 2.1.0-отчёт в stdout — для CI (GitHub/GitLab security-tab).
/// `ailc sarif <путь> > results.sarif`. В отчёт идут только подтверждённые находки
/// (ложные опровергнуты Verifier'ом); число опровергнутых и пропуски — в properties.
fn run_sarif(args: &[String]) {
    let root = args.get(2).cloned().unwrap_or_else(|| ".".to_string());
    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);
    let ctx = Ctx::new(&root);
    let report = Orchestrator::scan_all(&reg, &ctx, &RunInput::default());
    let sarif = ailc_core::sarif::to_sarif(
        &report.findings,
        env!("CARGO_PKG_VERSION"),
        report.refuted,
        &report.checks_run,
        &report.checks_skipped,
    );
    println!("{sarif}");
}

/// Экспорт всех capability как agentskills.io-совместимого пака.
/// `ailc skills [папка]` (по умолчанию `ailc-skills`). Любой agentskills-агент
/// (Claude Code, Cursor, …) обнаружит навыки и вызовет их через MCP-сервер ailc.
fn run_skills(args: &[String]) {
    let outdir = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "ailc-skills".to_string());
    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);
    let manifests = reg.manifests();
    let files = ailc_core::skills::generate(&manifests, env!("CARGO_PKG_VERSION"));

    let base = std::path::Path::new(&outdir);
    let mut written = 0usize;
    for f in &files {
        let p = base.join(&f.path);
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(&p, &f.content).is_ok() {
            written += 1;
        }
    }
    println!(
        "ailc skills → {outdir}/ : {written} файлов ({} навыков + plugin.json)",
        files.len().saturating_sub(1)
    );
    println!(
        "Подключение: папку можно установить как Claude Code plugin или использовать\n\
         любым agentskills.io-совместимым агентом — навыки вызывают ailc через MCP."
    );
}

/// CLI-витрина каталога + честное направление. Свободное намерение маршрутизирует
/// НЕЙРОСЕТЬ IDE (адаптивная петля `agent`), а из терминала LLM недоступен — поэтому
/// здесь не «тихий keyword-фолбэк», а указание на путь с моделью и на детерминированные
/// команды (инвариант «без молчаливых пропусков»).
fn cli_demo(args: &[String]) {
    let root = args.get(1).cloned().unwrap_or_else(|| ".".to_string());
    let intent = args.get(2).cloned();

    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);

    println!("ailc · capability в каталоге: {}", reg.all().len());
    if let Some(intent) = &intent {
        println!("Намерение: «{intent}»  ·  Проект: {root}");
    }

    println!(
        "\n⚠ Свободное намерение маршрутизирует НЕЙРОСЕТЬ IDE (адаптивная петля: план →\n\
         выполни → мало? довызови → почини → перепроверь). Из терминала LLM недоступен.\n\n\
         • Полный адаптивный режим: подключи ailc в IDE (`ailc serve`) и спроси там —\n\
         \u{20}\u{20}план/довызов/починку ведёт модель клиента.\n\
         • Детерминированно, без LLM:\n\
         \u{20}\u{20}ailc dod {root}        — многоосевой вердикт «готово?»\n\
         \u{20}\u{20}ailc sarif {root}      — полный скан (отчёт SARIF для CI)\n\
         \u{20}\u{20}ailc custodian {root}  — непрерывный фоновый гейт\n\
         \u{20}\u{20}ailc fix {root}        — безопасная починка формата/линта"
    );
}
