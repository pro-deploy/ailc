//! ailc — точка входа.
//!
//! Два режима:
//!   `ailc serve`               — MCP-сервер поверх stdio (для подключения в IDE).
//!                                 Наружу только front door `plan`, не плоские тулы.
//!   `ailc <путь> ["намерение"]` — CLI-демонстратор того же front door.
//!
//! Человек везде работает НАМЕРЕНИЕМ и получает QualityLedger; имён инструментов
//! и движков он не видит.
//!
//! КОД ВОЗВРАТА ПРОЦЕССА. Инструмент, продающий детерминированный гейт качества,
//! обязан уметь остановить сборку, а единственный способ сообщить об этом системе
//! непрерывной интеграции: код завершения процесса. Печать вердикта в стандартный вывод
//! таким способом не является, потому что `run:` в задании сборки смотрит именно на код.
//! Поэтому гейт-команды (`dod`, `pulse`, `custodian --once`, `sarif`) возвращают код по
//! вердикту, а не безусловный ноль (см. `EXIT_*` ниже): у `sarif` находки high/critical
//! дают код 1, несуществующий путь — код 3. Команды-действия (`fix`, `baseline`, `skills`,
//! `design`) возвращают ноль при успешном выполнении и ненулевой код при собственном сбое.

mod compliance_wizard;
mod custodian;
mod doctor;
mod mcp;

use ailc_contracts::{Ctx, RunInput};
use ailc_core::fixer::Fixer;
use ailc_core::orchestrator::Orchestrator;
use ailc_core::registry::Registry;
use std::process::ExitCode;

/// Вердикт подтверждён: сдавать можно.
const EXIT_OK: u8 = 0;
/// Вердикт провален: есть блокирующие находки. Сборку следует остановить.
const EXIT_FAILED: u8 = 1;
/// Вердикт НЕ подтверждён: ключевые (hard) проверки не выполнялись либо охват нулевой.
/// Отдельный код, а не слияние с провалом, потому что причина принципиально иная: не
/// «нашли дефект», а «не смогли проверить», и реакция на неё в сборке другая (починить
/// окружение и тулчейн, а не код). Для системы сборки оба кода одинаково не равны нулю,
/// поэтому зелёной сборки при непроверенном коде не будет.
const EXIT_NOT_CONFIRMED: u8 = 2;
/// Сбой самого инструмента (нет capability, ошибка записи, нераспознанные аргументы).
const EXIT_ERROR: u8 = 3;

/// Команды, известные точке входа. Всё прочее в первой позиции трактуется как путь
/// проекта для CLI-витрины, но только если такой каталог существует: опечатка вида
/// `ailc dodd` не должна молча превращаться в успешный прогон по несуществующему пути.
const KNOWN_COMMANDS: &[&str] = &[
    "serve",
    "custodian",
    "dod",
    "pulse",
    "design",
    "fix",
    "cap",
    "sarif",
    "skills",
    "compliance-ru",
    "doctor",
    "baseline",
];

/// Справка. Один разбор на все подкоманды: прежде `--help` трактовался как позиционный
/// путь, из-за чего `ailc baseline --help` реально замораживал долг, а
/// `ailc custodian --help` уходил в вечный цикл и создавал каталог `./--help/`.
fn print_help(cmd: Option<&str>) {
    let v = env!("CARGO_PKG_VERSION");
    match cmd {
        Some("dod") => println!(
            "ailc dod [путь]\n\nМногоосевой детерминированный вердикт «готово к сдаче?».\n\
             Коды возврата: 0 — подтверждено, 1 — есть блокеры, 2 — не подтверждено, 3 — сбой."
        ),
        Some("sarif") => println!(
            "ailc sarif [путь] > results.sarif\n\nПолный скан с отчётом SARIF 2.1.0 для CI.\n\
             Коды возврата: 0 — находок high/critical нет, 1 — есть, 3 — сбой (путь не существует)."
        ),
        Some("fix") => println!(
            "ailc fix [путь]\n\nБезопасная автопочинка формата и линта (формат/линт-фиксеры стека).\n\
             Находки безопасности и логики не трогает."
        ),
        Some("custodian") => println!(
            "ailc custodian [путь] [интервал-сек] [--fix] [--once]\n\
             ailc custodian install|uninstall [путь] [интервал-сек]\n\n\
             Непрерывный фоновый статический гейт (без сборки и тестов).\n\
             --once: один цикл с вердиктом кодом возврата. Остановка: файл .ailc/custodian/STOP."
        ),
        Some("doctor") => println!(
            "ailc doctor [путь]\n\nДиагностика подключения: бинарь, npx, конфигурации редакторов, сниппеты."
        ),
        Some("baseline") => println!(
            "ailc baseline [путь]\n\nЗаморозить текущие находки как базовую линию долга.\n\
             Уязвимости high и выше в линию не заносятся."
        ),
        Some("compliance-ru") => println!(
            "ailc compliance-ru [путь-для-вывода]\n\nИнтерактивный мастер комплаенса РФ: вопросы,\n\
             профиль норм, constitution.md и чек-лист."
        ),
        Some("pulse") => println!(
            "ailc pulse [путь]\n\nЛёгкий однострочный статус без тестов и линта (для хука)."
        ),
        Some("design") => println!("ailc design \"<что хочу>\" [путь]\n\nЗаготовка спецификации фичи и ADR."),
        Some("cap") => println!("ailc cap <id> [путь] [query]\n\nПрогнать одну capability по идентификатору."),
        Some("skills") => println!("ailc skills [папка]\n\nЭкспорт возможностей как agentskills-пака."),
        Some("serve") => println!("ailc serve\n\nMCP-сервер поверх stdio для подключения в IDE."),
        _ => println!(
            "ailc {v} — автономная проверка качества\n\n\
             Команды: serve · dod · sarif · fix · custodian · doctor · baseline ·\n\
             compliance-ru · pulse · design · cap · skills\n\
             Справка по команде: ailc <команда> --help\n\
             Свободное намерение: ailc <путь> \"<запрос>\" (адаптивная петля доступна в IDE через serve)"
        ),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    // Справка перехватывается ДО любых действий: флаг не должен доходить до подкоманд
    // как позиционный путь.
    if args.iter().skip(1).any(|a| a == "--help" || a == "-h")
        || args.get(1).map(String::as_str) == Some("help")
    {
        let cmd = args
            .get(1)
            .map(String::as_str)
            .filter(|c| KNOWN_COMMANDS.contains(c));
        print_help(cmd);
        return ExitCode::from(EXIT_OK);
    }

    if args.get(1).map(String::as_str) == Some("serve") {
        mcp::serve();
        return ExitCode::from(EXIT_OK);
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
            return ExitCode::from(EXIT_OK);
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
        // Гейт-режим: `--once` отдаёт вердикт кодом возврата (для хука и задания сборки).
        // Непрерывный режим не завершается штатно, поэтому у него кода вердикта нет.
        if once {
            let passed = custodian::run_once(&root, fix);
            return ExitCode::from(if passed { EXIT_OK } else { EXIT_FAILED });
        }
        custodian::run(&root, interval, fix);
        return ExitCode::from(EXIT_OK);
    }

    // Definition of Done — многоосевой вердикт: `ailc dod <путь>`
    if args.get(1).map(String::as_str) == Some("dod") {
        return run_dod(&args);
    }

    // Лёгкий однострочный статус (без тестов/линта) — для хука/частого вызова:
    // `ailc pulse <путь>`. Дешёвый детерминированный сигнал «всё ли ок».
    if args.get(1).map(String::as_str) == Some("pulse") {
        return run_pulse(&args);
    }

    // Проектирование новой фичи: `ailc design "<что хочу>" [путь]`
    if args.get(1).map(String::as_str) == Some("design") {
        return run_design(&args);
    }

    // Безопасная починка (формат/линт) с циклом проверка→фикс→проверка: `ailc fix <путь>`
    if args.get(1).map(String::as_str) == Some("fix") {
        run_fix(&args);
        return ExitCode::from(EXIT_OK);
    }

    // Dev: прогнать одну capability. `ailc cap <id> [путь] [query]`
    if args.get(1).map(String::as_str) == Some("cap") {
        return run_single_cap(&args);
    }

    // SARIF-отчёт для CI: `ailc sarif <путь> > results.sarif`
    if args.get(1).map(String::as_str) == Some("sarif") {
        return run_sarif(&args);
    }

    // Экспорт возможностей как agentskills-пак: `ailc skills [папка]`
    if args.get(1).map(String::as_str) == Some("skills") {
        run_skills(&args);
        return ExitCode::from(EXIT_OK);
    }

    // Интерактивный мастер комплаенса РФ: `ailc compliance-ru [путь-для-вывода]`
    if args.get(1).map(String::as_str) == Some("compliance-ru") {
        compliance_wizard::run(&args);
        return ExitCode::from(EXIT_OK);
    }

    // Диагностика подключения: `ailc doctor [путь]` — где бинарь, виден ли npx,
    // подключён ли ailc в редакторах, готовые сниппеты. Без LLM и без сети.
    if args.get(1).map(String::as_str) == Some("doctor") {
        doctor::run(&args);
        return ExitCode::from(EXIT_OK);
    }

    // Базовая линия долга: `ailc baseline <путь>` — заморозить текущие находки как
    // исторический долг (перемирие с легаси). Дальше DoD блокируют только новые.
    if args.get(1).map(String::as_str) == Some("baseline") {
        return run_baseline(&args);
    }

    // Первый аргумент не является известной командой: это путь проекта для витрины.
    // Несуществующий каталог — почти наверняка опечатка в имени команды; молчаливый
    // успех здесь маскировал бы её в скриптах.
    if let Some(first) = args.get(1) {
        if !std::path::Path::new(first).is_dir() {
            eprintln!(
                "ОШИБКА: «{first}» не является ни командой, ни существующим каталогом.\n\
                 Команды: {}. Справка: ailc --help",
                KNOWN_COMMANDS.join(", ")
            );
            return ExitCode::from(EXIT_ERROR);
        }
    }
    cli_demo(&args);
    ExitCode::from(EXIT_OK)
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
    // Итог честный: «починены» печатается только если хоть один фиксер реально отработал.
    if steps.iter().any(|s| s.ran && s.ok) {
        println!(
            "\nФормат/линт починены автоматически. Находки безопасности/логики НЕ трогаю —\n\
             их решает человек: `ailc {root} \"проверь безопасность\"`."
        );
    } else {
        println!("\nНичего не применено: фиксеры не отработали (см. строки выше).");
    }
}

/// Заморозить текущие находки как базовую линию долга (см. ailc_core::baseline).
fn run_baseline(args: &[String]) -> ExitCode {
    let root = args.get(2).cloned().unwrap_or_else(|| ".".to_string());
    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);
    let ctx = Ctx::new(&root);
    println!("ailc baseline — фиксирую базовую линию долга ({root})…");
    let report = Orchestrator::scan_all(&reg, &ctx, &RunInput::default());
    match ailc_core::baseline::record(&ctx, &report.findings) {
        Ok(rec) => {
            println!(
                "Заморожено находок: {} в .ailc/baseline/findings.txt\n\
                 С этого момента сдачу блокируют только НОВЫЕ находки; долг гасится порциями\n\
                 и виден в `ailc dod` отдельной строкой. Пересборка линии — эта же команда.",
                rec.frozen
            );
            if rec.refused > 0 {
                println!(
                    "ВНИМАНИЕ: {} уязвимостей (семейство security, важность high и выше) в линию\n\
                     НЕ занесены и продолжают блокировать сдачу. Долг это отсрочка по качеству,\n\
                     а не амнистия по безопасности: перечень смотрите в `ailc sarif {root}`.",
                    rec.refused
                );
            }
            ExitCode::from(EXIT_OK)
        }
        Err(e) => {
            println!("ОШИБКА: {e}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run_dod(args: &[String]) -> ExitCode {
    let root = args.get(2).cloned().unwrap_or_else(|| ".".to_string());
    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);
    let ctx = Ctx::new(&root);
    let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());

    println!("DOD CHECK — Definition of Done ({root})");
    println!(
        "Паспорт проекта: {}",
        ailc_core::profile::detect(std::path::Path::new(&root)).summary()
    );
    // Правила, по которым выносится вердикт, называются ЯВНО. Прежде заметка о политике
    // отбрасывалась именно здесь, поэтому подменённый или ослабленный файл политики
    // применялся молча и объяснить полученный вердикт было нечем.
    if let Some(note) = &report.policy_note {
        println!("Политика: {note}");
    }
    println!();
    for a in &report.axes {
        let mark = if !a.ran {
            "⊘"
        } else if a.ok {
            "✓"
        } else {
            "✗"
        };
        let kind = if a.hard { "hard" } else { "soft" };
        // Причина непрохождения печатается ИЗ ОСИ, а не зашитой строкой: осознанный
        // пропуск (нет подходящего стека) и сбой инструмента требуют разной реакции
        // человека, и различать их обязан вывод, а не только внутренняя структура.
        let detail = if !a.ran {
            a.not_run_reason
                .clone()
                .unwrap_or_else(|| "не выполнялась".to_string())
        } else if a.name == "OWASP HIGH" {
            format!("HIGH-находок: {}", a.high)
        } else {
            format!("находок: {}", a.findings)
        };
        // Чистый результат при неполном охвате или при отброшенных находках не является
        // доказательством отсутствия проблемы, поэтому оговорка идёт в ту же строку.
        let mut caveat = String::new();
        if a.ran && a.refuted > 0 {
            caveat.push_str(&format!(" · отброшено как ложные: {}", a.refuted));
        }
        if a.ran && a.out_of_scope > 0 {
            caveat.push_str(&format!(" · вне охвата файлов: {}", a.out_of_scope));
        }
        println!("  {mark} {:<20} [{kind}] — {detail}{caveat}", a.name);
    }
    if report.baseline_frozen {
        println!(
            "\nДолг (заморожен базовой линией): {} — не блокирует, гасите порциями",
            report.debt
        );
    }

    let (code, verdict) = dod_verdict(&report);
    println!("\n{verdict}");
    ExitCode::from(code)
}

/// Решение о вердикте и КОДЕ ВОЗВРАТА по отчёту DoD: чистая функция, чтобы инвариант
/// «проваленный вердикт даёт ненулевой код» проверялся тестом, а не только глазами.
/// Возвращает пару (код возврата, человекочитаемый вердикт).
///
/// ПОРЯДОК ВЕТВЕЙ СУЩЕСТВЕНЕН. Реально проваленная hard-ось важнее невыполненной:
/// найденный дефект это факт, требующий правки кода, тогда как невыполненная проверка это
/// неизвестность, требующая починки окружения. Если сообщить только о второй, человек
/// уйдёт налаживать тулчейн и не увидит, что дефект уже найден. Поэтому провал проверяется
/// раньше, а перечень невыполненных осей добавляется к нему справкой.
fn dod_verdict(report: &ailc_core::orchestrator::DodReport) -> (u8, String) {
    if report.confirmed {
        return (
            EXIT_OK,
            "ВЕРДИКТ: ✓ DoD выполнен — можно сдавать".to_string(),
        );
    }

    let hard_failed: Vec<&str> = report
        .axes
        .iter()
        .filter(|a| a.hard && a.ran && !a.ok)
        .map(|a| a.name)
        .collect();
    if !hard_failed.is_empty() {
        let mut s = format!(
            "ВЕРДИКТ: ✗ DoD НЕ выполнен — провалены hard-оси: {}",
            hard_failed.join(", ")
        );
        if !report.hard_not_run.is_empty() {
            s.push_str(&format!(
                "\nДополнительно НЕ выполнялись (вердикт по ним не подтверждён): {}",
                report.hard_not_run.join(", ")
            ));
        }
        return (EXIT_FAILED, s);
    }

    if report.zero_coverage {
        return (
            EXIT_NOT_CONFIRMED,
            "ВЕРДИКТ: ⊘ НЕ подтверждено — охват нулевой: ни одна проверка не выполнилась.\n\
             Пустой или нераспознанный по стеку каталог не даёт права на вердикт «можно сдавать»."
                .to_string(),
        );
    }
    (
        EXIT_NOT_CONFIRMED,
        format!(
            "ВЕРДИКТ: ⊘ НЕ подтверждено — ключевые проверки не выполнялись: {}.\n\
             Это не «дефектов нет», а «проверить не удалось»: почини окружение и тулчейн\n\
             (см. причину в строках с ⊘ выше), затем повтори.",
            report.hard_not_run.join(", ")
        ),
    )
}

/// Лёгкий однострочный статус качества (быстрые детерминированные проверки —
/// security+quality, БЕЗ тестов/линта). Для хука «на каждый промпт» и частого вызова.
fn run_pulse(args: &[String]) -> ExitCode {
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
    // Нулевой охват отделяем от чистого результата: «проверок 0» это не «всё хорошо».
    if ledger.checks_run == 0 {
        println!("⊘ НЕ подтверждено: ни одна проверка не выполнилась (нулевой охват)");
        return ExitCode::from(EXIT_NOT_CONFIRMED);
    }
    ExitCode::from(if ledger.passed { EXIT_OK } else { EXIT_FAILED })
}

/// Проектирование новой фичи «как в ИТ принято»: заготовка спеки + ADR.
fn run_design(args: &[String]) -> ExitCode {
    let feature = match args.get(2) {
        Some(f) if !f.trim().is_empty() => f.clone(),
        _ => {
            println!(
                "ailc design — проектирование новой фичи\n\n\
                 Использование: ailc design \"<что хочу сделать>\" [путь]"
            );
            return ExitCode::from(EXIT_ERROR);
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
            ExitCode::from(EXIT_OK)
        }
        Some(Err(e)) => {
            println!("ОШИБКА: {e}");
            ExitCode::from(EXIT_ERROR)
        }
        None => {
            println!("инструмент проектирования недоступен");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run_single_cap(args: &[String]) -> ExitCode {
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
                ExitCode::from(EXIT_OK)
            }
            Err(e) => {
                println!("ОШИБКА: {e}");
                ExitCode::from(EXIT_ERROR)
            }
        },
        None => {
            println!("нет такого capability: {id}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

/// SARIF 2.1.0-отчёт в stdout — для CI (GitHub/GitLab security-tab).
/// `ailc sarif <путь> > results.sarif`. В отчёт идут только подтверждённые находки
/// (ложные опровергнуты Verifier'ом); число опровергнутых и пропуски — в properties.
fn run_sarif(args: &[String]) -> ExitCode {
    let root = args.get(2).cloned().unwrap_or_else(|| ".".to_string());
    // Несуществующий путь — сбой инструмента, а не «пустой успешный отчёт»: прежде CI
    // с опечаткой в пути получал зелёную сборку с нулём находок.
    if !std::path::Path::new(&root).is_dir() {
        eprintln!("ОШИБКА: путь «{root}» не существует или не каталог");
        return ExitCode::from(EXIT_ERROR);
    }
    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);
    let ctx = Ctx::new(&root);
    let report = Orchestrator::scan_all(&reg, &ctx, &RunInput::default());
    let sarif = ailc_core::sarif::to_sarif(
        &report.findings,
        env!("CARGO_PKG_VERSION"),
        report.refuted,
        report.suppressed,
        &report.checks_run,
        &report.checks_skipped,
    );
    println!("{sarif}");
    // Гейт кодом возврата: находки high/critical дают ненулевой код, чтобы задание
    // сборки могло остановиться без разбора JSON. Отчёт при этом печатается всегда.
    let has_blocking = report.findings.iter().any(|f| {
        matches!(
            f.severity,
            ailc_contracts::Severity::High | ailc_contracts::Severity::Critical
        )
    });
    ExitCode::from(if has_blocking { EXIT_FAILED } else { EXIT_OK })
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
        "\n⚠ Свободное намерение маршрутизирует НЕЙРОСЕТЬ IDE (адаптивная петля: сначала\n\
         план, затем выполнение, при нехватке довызов, потом починка и перепроверка).\n\
         Из терминала большая языковая модель недоступна.\n\n\
         • Полный адаптивный режим: подключи ailc в IDE (`ailc serve`) и спроси там;\n\
         \u{20}\u{20}план, довызов и починку ведёт модель клиента.\n\
         • Детерминированно, без LLM:\n\
         \u{20}\u{20}ailc dod {root}        — многоосевой вердикт «готово?» (код возврата 0/1/2)\n\
         \u{20}\u{20}ailc sarif {root}      — полный скан (отчёт SARIF для CI)\n\
         \u{20}\u{20}ailc custodian {root}  — непрерывный фоновый гейт\n\
         \u{20}\u{20}ailc fix {root}        — безопасная починка формата/линта\n\
         \u{20}\u{20}ailc doctor {root}     — диагностика подключения и готовые сниппеты"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_core::orchestrator::{DodAxis, DodReport};

    fn axis(name: &'static str, hard: bool, ran: bool, ok: bool) -> DodAxis {
        DodAxis {
            name,
            hard,
            ran,
            findings: usize::from(!ok),
            high: 0,
            ok,
            refuted: 0,
            out_of_scope: 0,
            not_run_reason: if ran {
                None
            } else {
                Some("нет тулчейна".to_string())
            },
        }
    }

    fn report(axes: Vec<DodAxis>) -> DodReport {
        let hard_failed = axes.iter().any(|a| a.hard && a.ran && !a.ok);
        let hard_not_run: Vec<&'static str> = axes
            .iter()
            .filter(|a| a.hard && !a.ran)
            .map(|a| a.name)
            .collect();
        let zero_coverage = !axes.iter().any(|a| a.ran);
        let confirmed = !hard_failed && hard_not_run.is_empty() && !zero_coverage;
        DodReport {
            axes,
            passed: confirmed,
            confirmed,
            hard_not_run,
            zero_coverage,
            debt: 0,
            baseline_frozen: false,
            policy_note: None,
        }
    }

    /// Главный инвариант продукта: подтверждённый вердикт и ТОЛЬКО он даёт код ноль.
    /// Без этого шаг `run: ailc dod .` в задании сборки не способен её остановить.
    #[test]
    fn подтверждённый_вердикт_даёт_ноль() {
        let r = report(vec![axis("Секреты", true, true, true)]);
        assert_eq!(dod_verdict(&r).0, EXIT_OK);
    }

    #[test]
    fn проваленная_hard_ось_даёт_код_провала() {
        let r = report(vec![
            axis("Секреты", true, true, false),
            axis("Тесты", true, true, true),
        ]);
        let (code, text) = dod_verdict(&r);
        assert_eq!(code, EXIT_FAILED, "провал обязан быть ненулевым: {text}");
        assert!(text.contains("Секреты"), "провал назван по имени: {text}");
    }

    #[test]
    fn невыполненная_hard_ось_даёт_код_не_подтверждено() {
        let r = report(vec![
            axis("Секреты", true, true, true),
            axis("Тесты", true, false, true),
        ]);
        let (code, text) = dod_verdict(&r);
        assert_eq!(code, EXIT_NOT_CONFIRMED, "{text}");
        assert!(text.contains("Тесты"), "названа невыполненная ось: {text}");
    }

    /// Провал важнее неподтверждённости: иначе человек уходит починять тулчейн и не видит
    /// уже найденный дефект. Регрессия на порядок ветвей в `dod_verdict`.
    #[test]
    fn провал_важнее_невыполненной_оси() {
        let r = report(vec![
            axis("OWASP HIGH", true, true, false),
            axis("Тесты", true, false, true),
        ]);
        let (code, text) = dod_verdict(&r);
        assert_eq!(code, EXIT_FAILED, "{text}");
        assert!(
            text.contains("OWASP HIGH") && text.contains("Тесты"),
            "сообщены и провал, и невыполненная ось: {text}"
        );
    }

    #[test]
    fn нулевой_охват_не_даёт_зелёного() {
        let r = report(vec![axis("Секреты", true, false, true)]);
        let (code, _) = dod_verdict(&r);
        assert_ne!(code, EXIT_OK, "нулевой охват не равен «можно сдавать»");
    }

    /// Мягкая (soft) ось не имеет права ронять сборку: иначе стилистические замечания
    /// становятся блокерами и гейт перестают включать.
    #[test]
    fn провал_soft_оси_не_роняет_вердикт() {
        let r = report(vec![
            axis("Секреты", true, true, true),
            axis("Запахи кода", false, true, false),
        ]);
        assert_eq!(dod_verdict(&r).0, EXIT_OK);
    }
}
