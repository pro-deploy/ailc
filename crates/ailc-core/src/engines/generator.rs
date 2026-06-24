//! E5 Generator — идемпотентная запись файлов с авто-блоками («Всё как код»).
//!
//! Сгенерированное содержимое живёт между метками `co:auto:start КЛЮЧ` … `co:auto:end`.
//! При повторной генерации обновляется только блок — всё, что человек дописал СНАРУЖИ
//! меток, сохраняется. Нет изменений → файл не трогается (чтобы не плодить пустые правки).
//! Один движок на все писатели (доки/скаффолд/ADR) — логика записи не дублируется.

use ailc_contracts::{CapError, Ctx, Result};
use std::fmt;
use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAction {
    Created,
    Updated,
    Unchanged,
}

impl fmt::Display for WriteAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            WriteAction::Created => "создан",
            WriteAction::Updated => "обновлён",
            WriteAction::Unchanged => "без изменений",
        })
    }
}

pub struct Generator;

impl Generator {
    /// Идемпотентно вписать `content` в файл между метками `key`.
    /// Возвращает (относительный путь, что произошло).
    pub fn write_block(
        ctx: &Ctx,
        rel: &str,
        key: &str,
        content: &str,
    ) -> Result<(String, WriteAction)> {
        let path = ctx.root.join(rel);
        let existed = path.exists();
        // Файл есть, но нечитаем (бинарный/нет прав) → НЕ перезаписываем (потеря данных).
        let existing = if existed {
            match fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    return Err(CapError(format!(
                        "файл существует, но нечитаем ({rel}): {e} — не перезаписываю"
                    )))
                }
            }
        } else {
            String::new()
        };

        let start = format!("<!-- co:auto:start {key} -->");
        let end = "<!-- co:auto:end -->";
        let block = format!("{start}\n{content}\n{end}");

        // Конец блока ищем СТРОГО после своего начала (иначе при нескольких авто-блоках
        // схватим чужой `end` и порушим файл).
        let new_content = if let Some(si) = existing.find(&start) {
            match existing[si..].find(end) {
                Some(rel_ei) => {
                    let ei = si + rel_ei;
                    format!("{}{block}{}", &existing[..si], &existing[ei + end.len()..])
                }
                // Старт есть, конца нет (файл повреждён) — добавляем блок в конец.
                None => format!("{existing}\n\n{block}\n"),
            }
        } else if existing.trim().is_empty() {
            format!("{block}\n")
        } else {
            format!("{existing}\n\n{block}\n")
        };

        let action = if !existed {
            WriteAction::Created
        } else if new_content != existing {
            WriteAction::Updated
        } else {
            WriteAction::Unchanged
        };

        if action != WriteAction::Unchanged {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, new_content)?;
        }
        Ok((rel.to_string(), action))
    }
}
