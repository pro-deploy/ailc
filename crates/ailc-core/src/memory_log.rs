//! Серверный след работы: каждый вызов инструмента (plan / run / dod / autofix / design)
//! оставляет строку в ЕДИНОМ журнале событий проекта `.ailc/process/journal.md`, а не по
//! памятке агента.
//!
//! Прежде сервер вёл собственный журнал `.ailc/memory-bank/journal.md` и писал свои
//! авто-блоки («Журнал AILC», «Состояние работ», «Паспорт») в активный контекст, который
//! одновременно принадлежал модели. Журналов событий было два (второй вёл процесс
//! поставки), а запись модели через memory/update стирала блоки сервера. Теперь
//! разделение такое: события пишутся в журнал процесса, состояние работ и паспорт входят в
//! пакет возобновления (`process::resume`), а `.ailc/memory-bank/` целиком принадлежит
//! заметкам модели. Данные прежнего размещения переносятся при подключении сервера
//! ([`bootstrap`]).

use crate::engines::store::Store;
use ailc_contracts::Ctx;

const NS: &str = "memory-bank";
/// Прежний журнал сервера, переносится в журнал процесса.
const LEGACY_JOURNAL: &str = "journal.md";
/// Ключи прежних серверных авто-блоков в активном контексте.
const LEGACY_BLOCKS: &[&str] = &["ailc-journal", "ailc-tasks", "ailc-passport"];

/// Зафиксировать событие: инструмент, деталь (намерение/фича/идентификатор) и краткий
/// итог. Не паникует и не возвращает ошибок: журнал — побочный эффект, он не имеет
/// права ломать основной вызов.
pub fn note(ctx: &Ctx, tool: &str, detail: &str, digest: &str) {
    // Журнал ведём только внутри уже инициализированного проекта: наличие .ailc
    // подтверждает, что путь валиден и это корень проекта, а не случайный каталог.
    if !ctx.root.join(".ailc").is_dir() {
        return;
    }
    let detail = clip(detail, 120);
    let digest = clip(digest, 200);
    let line = if detail.is_empty() {
        format!("{tool}: {digest}")
    } else {
        format!("{tool} «{detail}»: {digest}")
    };
    crate::process::plan::journal(ctx, &line);
}

/// Подготовка памяти при подключении сервера. Идемпотентно. Переносит прежний журнал
/// сервера в журнал процесса и убирает из активного контекста прежние серверные
/// авто-блоки, оставляя заметки модели нетронутыми. Паспорт проекта в активный контекст
/// больше не пишется: он лежит в `.ailc/profile.md`.
pub fn bootstrap(ctx: &Ctx, _profile_summary: &str) {
    if !ctx.root.join(".ailc").is_dir() {
        return;
    }
    let mem = ctx.root.join(".ailc").join(NS);
    let legacy = mem.join(LEGACY_JOURNAL);
    if let Ok(text) = std::fs::read_to_string(&legacy) {
        let lines: Vec<&str> = text.lines().filter(|l| l.starts_with("- ")).collect();
        if !lines.is_empty() {
            let mut block = format!(
                "- перенесено из .ailc/memory-bank/journal.md ({} событий):",
                lines.len()
            );
            for l in &lines {
                block.push_str("\n  ");
                block.push_str(l.trim_start_matches("- "));
            }
            let _ = Store::append(
                ctx,
                crate::process::plan::NS,
                crate::process::plan::JOURNAL,
                &block,
            );
        }
        let _ = std::fs::remove_file(&legacy);
    }
    let acx = mem.join("active-context.md");
    if let Ok(text) = std::fs::read_to_string(&acx) {
        let cleaned = strip_blocks(&text, LEGACY_BLOCKS);
        if cleaned != text {
            let _ = std::fs::write(&acx, cleaned);
        }
    }
}

/// Убрать из текста управляемые блоки с перечисленными ключами вместе с метками.
fn strip_blocks(text: &str, keys: &[&str]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut skipping = false;
    for line in text.lines() {
        if !skipping {
            let starts = keys.iter().any(|k| {
                line.contains(&format!("ailc:auto:start {k} "))
                    || line
                        .trim_end()
                        .ends_with(&format!("ailc:auto:start {k} -->"))
                    || line.contains(&format!("co:auto:start {k} "))
            });
            if starts {
                skipping = true;
                continue;
            }
            out.push_str(line);
            out.push('\n');
        } else if line.contains("ailc:auto:end") || line.contains("co:auto:end") {
            skipping = false;
        }
    }
    out
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
    fn note_пишет_в_единый_журнал_процесса() {
        let ctx = temp_ctx("note");
        note(&ctx, "dod", "", "вердикт: не готов, 1 блокер");
        note(&ctx, "plan", "проверь перед сдачей", "балл 92, блокеров 0");
        let journal = std::fs::read_to_string(ctx.root.join(".ailc/process/journal.md")).unwrap();
        assert!(journal.contains("dod: вердикт"));
        assert!(journal.contains("проверь перед сдачей"));
        assert!(!ctx.root.join(".ailc/memory-bank/journal.md").exists());
        std::fs::remove_dir_all(&ctx.root).ok();
    }

    #[test]
    fn note_outside_project_is_silent_noop() {
        let root = std::env::temp_dir().join(format!("ailc-memlog-noop-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let ctx = Ctx::new(root.to_str().unwrap());
        note(&ctx, "dod", "", "что-то"); // .ailc нет — тихо ничего
        assert!(!root.join(".ailc").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn bootstrap_переносит_прежний_журнал_и_убирает_серверные_блоки() {
        let ctx = temp_ctx("boot");
        let mem = ctx.root.join(".ailc/memory-bank");
        std::fs::write(
            mem.join("journal.md"),
            "- [2026-07-01] dod: старое событие\n",
        )
        .unwrap();
        std::fs::write(
            mem.join("active-context.md"),
            "<!-- ailc:auto:start ailc-journal -->\nжурнал\n<!-- ailc:auto:end -->\n\
             <!-- ailc:auto:start model-context -->\nзаметка модели\n<!-- ailc:auto:end -->\n",
        )
        .unwrap();
        bootstrap(&ctx, "стек: Rust");
        bootstrap(&ctx, "стек: Rust");
        let j = std::fs::read_to_string(ctx.root.join(".ailc/process/journal.md")).unwrap();
        assert_eq!(j.matches("старое событие").count(), 1, "{j}");
        assert!(!mem.join("journal.md").exists());
        let acx = std::fs::read_to_string(mem.join("active-context.md")).unwrap();
        assert!(
            acx.contains("заметка модели") && !acx.contains("журнал\n"),
            "{acx}"
        );
        std::fs::remove_dir_all(&ctx.root).ok();
    }
}
