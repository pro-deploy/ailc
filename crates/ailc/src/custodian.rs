//! Custodian — режим сопровождения: непрерывный (foreground watch) ИЛИ периодический
//! одноразовый прогон (`--once`, под launchd/cron).
//!
//! Цикл: наблюдай → прогони быстрый статический гейт → авто-обнови документацию
//! (идемпотентно — «починка» дрейфа) → уведоми (консоль · macOS · ALERT.md · чат-фид) →
//! запиши статус в .co/custodian/. Код сам НЕ правит. Kill-switch: файл .co/custodian/STOP.
//!
//! `ailc custodian install <путь> [сек]` ставит launchd-агент (по умолчанию каждые 900с),
//! который переживает перезапуск машины и сам зовёт `custodian <путь> --once`.

use ailc_contracts::{Ctx, Family, QualityLedger, RunInput};
use ailc_core::engines::store::Store;
use ailc_core::fixer::Fixer;
use ailc_core::orchestrator::Orchestrator;
use ailc_core::registry::Registry;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

/// Одноразовый прогон (один цикл) и выход — для периодического запуска launchd/cron.
pub fn run_once(root: &str, fix: bool) {
    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);
    let ctx = Ctx::new(root);
    run_cycle(&reg, &ctx, 1, fix);
}

pub fn run(root: &str, interval_secs: u64, fix: bool) {
    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);
    let ctx = Ctx::new(root);
    let stop = Path::new(root).join(".co/custodian/STOP");

    println!(
        "ailc · custodian: слежу за «{root}» (опрос каждые {interval_secs}с){}.\n  Остановить: создайте файл {}",
        if fix { ", автофикс ВКЛ" } else { "" },
        stop.display()
    );

    let mut last_fp: u64 = 0;
    let mut first = true;
    let mut cycle: u64 = 0;

    loop {
        if stop.exists() {
            println!("custodian: обнаружен STOP — останавливаюсь.");
            break;
        }
        let fp = fingerprint(Path::new(root));
        if first || fp != last_fp {
            first = false;
            last_fp = fp;
            cycle += 1;
            run_cycle(&reg, &ctx, cycle, fix);
        }
        std::thread::sleep(Duration::from_secs(interval_secs.max(1)));
    }
}

fn run_cycle(reg: &Registry, ctx: &Ctx, cycle: u64, fix: bool) {
    let input = RunInput::default();

    // 0. Безопасная починка (если включена): свои авто-фиксеры формата/линта.
    //    Делаем ДО проверки, чтобы вердикт отражал уже причёсанный код.
    let mut fixed: Vec<String> = Vec::new();
    if fix {
        for s in Fixer::run(ctx) {
            if s.ran && s.ok {
                fixed.push(s.tool);
            }
        }
    }

    // 1. Проверка — быстрый ДЕТЕРМИНИРОВАННЫЙ статический гейт (Security+Quality, без
    //    тестов/линта: на каждое сохранение их гонять дорого; тяжёлый прогон — по явному
    //    намерению «релиз»). RecipePlanner с keyword-маршрутом «качество и безопасность».
    let ledger = Orchestrator::deterministic_gate(
        reg,
        ctx,
        &input,
        "качество и безопасность",
        &[Family::Security, Family::Quality],
        false,
    );

    // 2. Починка дрейфа доков — идемпотентная регенерация (меняет файл только при отличии).
    //    Держим в синхроне обзор, диаграмму, спеку, C4, архитектуру, модель данных, глоссарий —
    //    «актуализировать всё из кода». При отсутствии — первый прогон их и спроектирует.
    let mut docs: Vec<String> = Vec::new();
    for id in [
        "generate/docs",
        "generate/diagram",
        "generate/spec",
        "generate/c4",
        "generate/architecture",
        "generate/data-model",
        "generate/glossary",
    ] {
        if let Some(cap) = reg.get(id) {
            if let Ok(out) = cap.run(ctx, &input) {
                docs.extend(out.artifacts);
            }
        }
    }

    // 3. Человеку — сжатая сводка + эскалация блокеров.
    println!("\n── цикл {cycle} ─────────────────────────────");
    println!("{}", ledger.headline);
    println!(
        "   проверок {} · блокеров {} · предупреждений {} · качество {:.0}/100",
        ledger.checks_run, ledger.blocking, ledger.warning, ledger.score
    );
    if !fixed.is_empty() {
        println!("   🔧 автофикс применён: {}", fixed.join(", "));
    }
    if !docs.is_empty() {
        println!("   📄 доки в синхроне: {}", docs.join(", "));
    }
    for d in ledger.open_decisions.iter().take(5) {
        println!("   ⚠ нужно решение: {d}");
    }

    // 4. Статус на диск (.co/custodian/status.md) + журнал (events.jsonl).
    let status = format!(
        "# Статус сопровождения ailc\n\nЦикл: {cycle}\n\n{}\n\nПроверок: {} · блокеров: {} · предупреждений: {} · качество: {:.0}/100\n\nПравила вынесенных решений:\n{}\n",
        ledger.headline,
        ledger.checks_run,
        ledger.blocking,
        ledger.warning,
        ledger.score,
        if ledger.open_decisions.is_empty() {
            "— нет —".to_string()
        } else {
            ledger
                .open_decisions
                .iter()
                .map(|d| format!("- {d}"))
                .collect::<Vec<_>>()
                .join("\n")
        }
    );
    let _ = Store::write(ctx, "custodian", "status.md", &status);
    let _ = Store::append(
        ctx,
        "custodian",
        "events.jsonl",
        &format!(
            "{{\"cycle\":{cycle},\"score\":{:.0},\"blocking\":{},\"warning\":{}}}",
            ledger.score, ledger.blocking, ledger.warning
        ),
    );

    // 5. Уведомления: ALERT.md (флаг для IDE/git/чата) · macOS-нотификация · чат-фид.
    notify(ctx, &ledger);
}

/// Уведомить о состоянии. Есть что эскалировать (блокеры/решения/советы по дрейфу) →
/// поднимаем ALERT.md + системную нотификацию macOS + строку в чат-фид; чисто → снимаем флаг.
fn notify(ctx: &Ctx, ledger: &QualityLedger) {
    let alert = ledger.blocking > 0
        || !ledger.open_decisions.is_empty()
        || !ledger.advisories.is_empty();
    let alert_path = ctx.root.join(".co/custodian/ALERT.md");

    if !alert {
        let _ = std::fs::remove_file(&alert_path); // чисто — снимаем флаг
        return;
    }

    // ALERT.md — машино/человеко-читаемый флаг (его же сёрфит `ailc serve` в чат).
    let mut body = format!("# 🔔 ailc custodian — нужно внимание\n\n{}\n\n", ledger.headline);
    if ledger.blocking > 0 {
        body.push_str(&format!("Блокеров: {}\n", ledger.blocking));
    }
    for d in ledger.open_decisions.iter().take(8) {
        body.push_str(&format!("- ⚠ {d}\n"));
    }
    for a in ledger.advisories.iter().take(8) {
        body.push_str(&format!("- 📋 {a}\n"));
    }
    let _ = Store::write(ctx, "custodian", "ALERT.md", &body);

    // Чат-фид: одна строка на событие (читается ИИ/интеграцией).
    let _ = Store::append(
        ctx,
        "custodian",
        "chat.md",
        &format!("- {} (блокеров {})", ledger.headline, ledger.blocking),
    );

    // Системное уведомление macOS (без зависимостей, через osascript).
    notify_macos(&ledger.headline);
}

/// Всплывающее уведомление macOS через osascript. На прочих ОС — no-op.
fn notify_macos(text: &str) {
    if !cfg!(target_os = "macos") {
        return;
    }
    let safe: String = text.replace(['"', '\\'], "'").chars().take(180).collect();
    let _ = Command::new("osascript")
        .arg("-e")
        .arg(format!(
            "display notification \"{safe}\" with title \"ailc custodian\""
        ))
        .status();
}

/// Стабильное имя launchd-агента: читаемое имя папки + короткий хеш пути (уникальность).
fn agent_label(abs_root: &Path) -> String {
    let name: String = abs_root
        .file_name()
        .map(|n| n.to_string_lossy().chars().filter(|c| c.is_ascii_alphanumeric()).collect())
        .unwrap_or_default();
    let mut h = DefaultHasher::new();
    abs_root.to_string_lossy().hash(&mut h);
    let name = if name.is_empty() { "proj".to_string() } else { name };
    format!("com.ailc.custodian.{name}-{:x}", h.finish() & 0xffffff)
}

/// Поставить launchd-агент: периодический `custodian <путь> --once`, переживает ребут.
pub fn install(root: &str, interval_secs: u64) {
    if !cfg!(target_os = "macos") {
        println!(
            "custodian install: автозагрузка через launchd — только macOS.\n  \
             Linux: systemd --user timer или cron на `ailc custodian {root} {interval_secs}`."
        );
        return;
    }
    let abs_root = std::fs::canonicalize(root).unwrap_or_else(|_| PathBuf::from(root));
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("ailc"));
    let home = match std::env::var("HOME") {
        Ok(h) => PathBuf::from(h),
        Err(_) => {
            println!("custodian install: не найден $HOME");
            return;
        }
    };
    let label = agent_label(&abs_root);
    let agents_dir = home.join("Library/LaunchAgents");
    let _ = std::fs::create_dir_all(&agents_dir);
    let _ = std::fs::create_dir_all(abs_root.join(".co/custodian"));
    let plist_path = agents_dir.join(format!("{label}.plist"));
    let log = abs_root.join(".co/custodian/launchd.log");
    let interval = interval_secs.max(60);

    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\"><dict>\n\
  <key>Label</key><string>{label}</string>\n\
  <key>ProgramArguments</key><array>\n\
    <string>{exe}</string><string>custodian</string><string>{root}</string><string>--once</string>\n\
  </array>\n\
  <key>StartInterval</key><integer>{interval}</integer>\n\
  <key>RunAtLoad</key><true/>\n\
  <key>StandardOutPath</key><string>{log}</string>\n\
  <key>StandardErrorPath</key><string>{log}</string>\n\
</dict></plist>\n",
        exe = exe.display(),
        root = abs_root.display(),
        log = log.display(),
    );
    // ailc:ignore — путь plist из $HOME (env оператора), запись своего launchd-плиста
    if std::fs::write(&plist_path, &plist).is_err() {
        println!("custodian install: не удалось записать {}", plist_path.display());
        return;
    }
    // ailc:ignore — launchctl с путём из $HOME (env оператора), управление своим демоном
    let _ = Command::new("launchctl").arg("unload").arg(&plist_path).status();
    // ailc:ignore — launchctl с путём из $HOME (env оператора), управление своим демоном
    let loaded = Command::new("launchctl")
        .arg("load")
        .arg(&plist_path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    println!("ailc · custodian установлен как launchd-агент:");
    println!("  plist:   {}", plist_path.display());
    println!("  запуск:  каждые {interval}с → проверка + актуализация доков (--once), переживает ребут.");
    println!(
        "  статус:  {}",
        if loaded { "✓ загружен (первый прогон — сейчас)" } else { "⚠ launchctl load не прошёл — загрузите вручную" }
    );
    println!("\nУправлять самому:");
    println!("  разовый прогон:   ailc custodian {} --once", abs_root.display());
    println!("  непрерывно (fg):  ailc custodian {} 900", abs_root.display());
    println!("  снять автозапуск: ailc custodian uninstall {}", abs_root.display());
    println!("  лог:    {}", log.display());
    println!("  алерты: {}/.co/custodian/ALERT.md", abs_root.display());
}

/// Снять launchd-агент.
pub fn uninstall(root: &str) {
    let abs_root = std::fs::canonicalize(root).unwrap_or_else(|_| PathBuf::from(root));
    let home = std::env::var("HOME").map(PathBuf::from).unwrap_or_default();
    let plist_path = home
        .join("Library/LaunchAgents")
        .join(format!("{}.plist", agent_label(&abs_root)));
    // ailc:ignore — launchctl с путём из $HOME (env оператора), управление своим демоном
    let _ = Command::new("launchctl").arg("unload").arg(&plist_path).status();
    let removed = std::fs::remove_file(&plist_path).is_ok();
    println!(
        "custodian uninstall: {} {}",
        plist_path.display(),
        if removed { "✓ снят" } else { "(агент не найден)" }
    );
}

/// Отпечаток дерева: сумма хешей (путь+mtime) по файлам. Порядконезависим; меняется
/// при любом изменении/добавлении/удалении. `.co` и служебные папки пропускаются
/// (иначе запись статуса сама бы запускала новый цикл).
fn fingerprint(root: &Path) -> u64 {
    let mut sum: u64 = 0;
    walk_fp(root, root, &mut sum);
    sum
}

fn walk_fp(dir: &Path, root: &Path, sum: &mut u64) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        // Пропускаем служебное И «docs» — иначе наша же генерация доков запускала бы
        // новый цикл (самозапуск). Хидден-папки (.co, .git) отсеяны выше.
        if matches!(
            name.as_ref(),
            "target" | "node_modules" | "vendor" | "dist" | "build" | "__pycache__" | "docs"
        ) {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            walk_fp(&path, root, sum);
        } else if let Ok(meta) = entry.metadata() {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let mut h = DefaultHasher::new();
            rel.to_string_lossy().hash(&mut h);
            mtime.hash(&mut h);
            *sum = sum.wrapping_add(h.finish());
        }
    }
}
