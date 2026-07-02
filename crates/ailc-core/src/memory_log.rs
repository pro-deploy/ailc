//! Серверное ведение памяти проекта: след оставляет САМ сервер, а не агент по памятке.
//!
//! Каждый вызов инструмента (plan / run / dod / autofix / design) дописывает строку в
//! журнал `.ailc/memory-bank/journal.md` и обновляет авто-блок «Журнал AILC» в
//! `.ailc/memory-bank/active-context.md` (последние события и следующий шаг). Ручные
//! разделы активного контекста не трогаются: авто-блок живёт в управляемых маркерах
//! генератора. Так память проекта актуальна, даже если агент среды о ней не вспоминал.

use crate::engines::generator::Generator;
use crate::engines::store::Store;
use ailc_contracts::Ctx;

const NS: &str = "memory-bank";
const JOURNAL: &str = "journal.md";
/// Сколько последних событий журнала показываем в активном контексте.
const RECENT: usize = 10;

/// Зафиксировать событие: инструмент, деталь (намерение/фича/идентификатор) и краткий
/// итог. Не паникует и не возвращает ошибок: память — побочный эффект, она не имеет
/// права ломать основной вызов.
pub fn note(ctx: &Ctx, tool: &str, detail: &str, digest: &str) {
    // Память ведём только внутри уже инициализированного проекта: наличие .ailc
    // подтверждает, что путь валиден и это корень проекта, а не случайный каталог.
    if !ctx.root.join(".ailc").is_dir() {
        return;
    }
    let detail = clip(detail, 120);
    let digest = clip(digest, 200);
    let line = if detail.is_empty() {
        format!("- [{}] {tool}: {digest}", today())
    } else {
        format!("- [{}] {tool} «{detail}»: {digest}", today())
    };
    let _ = Store::append(ctx, NS, JOURNAL, &line);
    refresh_active_context(ctx);
}

/// Перестроить авто-блок активного контекста из хвоста журнала.
fn refresh_active_context(ctx: &Ctx) {
    let journal = std::fs::read_to_string(ctx.root.join(".ailc").join(NS).join(JOURNAL))
        .unwrap_or_default();
    let recent: Vec<&str> = journal
        .lines()
        .filter(|l| l.starts_with("- "))
        .rev()
        .take(RECENT)
        .collect();
    let mut body = String::from("## Журнал AILC (ведётся сервером)\n\n");
    if recent.is_empty() {
        body.push_str("_Событий пока нет: журнал заполнится при первом вызове инструмента._\n");
    } else {
        // В хронологическом порядке: старые выше, свежие ниже.
        for l in recent.iter().rev() {
            body.push_str(l);
            body.push('\n');
        }
    }
    let _ = Generator::write_block(ctx, ".ailc/memory-bank/active-context.md", "ailc-journal", &body);
}

/// Первичный бутстрап активного контекста: паспорт проекта вместо пустой заглушки.
/// Идемпотентно (управляемый авто-блок); зовётся при инициализации MCP.
pub fn bootstrap(ctx: &Ctx, profile_summary: &str) {
    if !ctx.root.join(".ailc").is_dir() {
        return;
    }
    let body = format!(
        "## Паспорт (определён AILC)\n\n{profile_summary}\n\nПодробности в `.ailc/profile.md`.\n"
    );
    let _ = Generator::write_block(ctx, ".ailc/memory-bank/active-context.md", "ailc-passport", &body);
    refresh_active_context(ctx);
}

/// Дата в виде ГГГГ-ММ-ДД без внешних зависимостей (алгоритм civil_from_days).
fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Перевод «дней от эпохи» в календарную дату (Howard Hinnant, chrono-совместимо).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Обрезать строку до лимита по символам, без паники на кириллице.
fn clip(s: &str, max: usize) -> String {
    let s = s.trim().replace('\n', " · ");
    if s.chars().count() <= max {
        return s;
    }
    let cut: String = s.chars().take(max).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_ctx(tag: &str) -> Ctx {
        let root = std::env::temp_dir().join(format!(
            "ailc-memlog-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join(".ailc/memory-bank")).unwrap();
        Ctx::new(root.to_str().unwrap())
    }

    #[test]
    fn note_appends_journal_and_updates_context() {
        let ctx = temp_ctx("note");
        note(&ctx, "dod", "", "вердикт: не готов, 1 блокер");
        note(&ctx, "plan", "проверь перед сдачей", "балл 92, блокеров 0");
        let journal =
            std::fs::read_to_string(ctx.root.join(".ailc/memory-bank/journal.md")).unwrap();
        assert!(journal.contains("dod"));
        assert!(journal.contains("проверь перед сдачей"));
        let acx =
            std::fs::read_to_string(ctx.root.join(".ailc/memory-bank/active-context.md")).unwrap();
        assert!(acx.contains("Журнал AILC"));
        assert!(acx.contains("балл 92"));
        std::fs::remove_dir_all(&ctx.root).ok();
    }

    #[test]
    fn note_outside_project_is_silent_noop() {
        let root = std::env::temp_dir().join(format!(
            "ailc-memlog-noop-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let ctx = Ctx::new(root.to_str().unwrap());
        note(&ctx, "dod", "", "что-то"); // .ailc нет — тихо ничего
        assert!(!root.join(".ailc").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn civil_date_known_values() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
    }

    #[test]
    fn bootstrap_writes_passport_block_idempotently() {
        let ctx = temp_ctx("boot");
        bootstrap(&ctx, "стек: Rust · признаки: нет");
        let first =
            std::fs::read_to_string(ctx.root.join(".ailc/memory-bank/active-context.md")).unwrap();
        bootstrap(&ctx, "стек: Rust · признаки: нет");
        let second =
            std::fs::read_to_string(ctx.root.join(".ailc/memory-bank/active-context.md")).unwrap();
        assert!(first.contains("Паспорт"));
        assert_eq!(first, second);
        std::fs::remove_dir_all(&ctx.root).ok();
    }
}
