//! E5 Generator — идемпотентная запись файлов с авто-блоками («Всё как код»).
//!
//! Сгенерированное содержимое живёт между метками `ailc:auto:start КЛЮЧ` … `ailc:auto:end`
//! (прежнее написание `co:auto` читается ради совместимости и мигрирует при первой записи).
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

/// Метка конца авто-блока в действующем написании.
pub const END_MARKER: &str = "<!-- ailc:auto:end -->";
/// Метка конца авто-блока в прежнем написании (по прежнему имени продукта). Читается
/// ради совместимости с документами, созданными до переименования; при первой же
/// перезаписи блок получает действующие метки.
pub const LEGACY_END_MARKER: &str = "<!-- co:auto:end -->";

/// Метка начала авто-блока с ключом в действующем написании.
pub fn start_marker(key: &str) -> String {
    format!("<!-- ailc:auto:start {key} -->")
}

/// Метка начала авто-блока с ключом в прежнем написании (только для чтения).
pub fn legacy_start_marker(key: &str) -> String {
    format!("<!-- co:auto:start {key} -->")
}

pub struct Generator;

impl Generator {
    /// Идемпотентно записать файл ЦЕЛИКОМ.
    ///
    /// Применяется к документам, собираемым по декларации стандарта: такой документ
    /// принадлежит машине целиком, а человеческий текст в нём живёт в размеченных зонах
    /// свободной прозы, которые сборщик переносит из прежней редакции сам. Совпадение
    /// содержимого означает, что файл не трогается: иначе каждая регенерация объявляла бы
    /// документ обновлённым и засоряла историю изменений пустыми правками.
    pub fn write_file(ctx: &Ctx, rel: &str, content: &str) -> Result<(String, WriteAction)> {
        let path = ctx.root.join(rel);
        let existed = path.exists();
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

        let action = if !existed {
            WriteAction::Created
        } else if existing != content {
            WriteAction::Updated
        } else {
            WriteAction::Unchanged
        };

        if action != WriteAction::Unchanged {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, content)?;
        }
        Ok((rel.to_string(), action))
    }

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

        let start = start_marker(key);
        let end = END_MARKER;
        let block = format!("{start}\n{content}\n{end}");

        // Конец блока ищем СТРОГО после своего начала (иначе при нескольких авто-блоках
        // схватим чужой `end` и порушим файл). Начало ищется в действующем написании, а
        // при его отсутствии в прежнем: документы, созданные до переименования продукта,
        // подхватываются и при первой же перезаписи получают действующие метки.
        let found = existing.find(&start).map(|i| (i, end)).or_else(|| {
            existing
                .find(&legacy_start_marker(key))
                .map(|i| (i, LEGACY_END_MARKER))
        });
        let new_content = if let Some((si, end_marker)) = found {
            match existing[si..].find(end_marker) {
                Some(rel_ei) => {
                    let ei = si + rel_ei;
                    format!(
                        "{}{block}{}",
                        &existing[..si],
                        &existing[ei + end_marker.len()..]
                    )
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
            let parent = path
                .parent()
                .ok_or_else(|| CapError(format!("у пути {rel} нет родительского каталога")))?;
            fs::create_dir_all(parent)?;
            // ЗАПИСЬ АТОМАРНА: временный файл рядом с целью, синхронизация на носитель,
            // затем переименование. Прежде здесь стоял прямой `fs::write`, который сперва
            // УСЕКАЕТ файл и лишь потом дописывает содержимое. Речь при этом идёт о файлах
            // ПОЛЬЗОВАТЕЛЯ (`CLAUDE.md`, `AGENTS.md`, документы проекта), поэтому аварийное
            // завершение или отказ записи в этом окне оставляли человека с обрезанным
            // собственным файлом, а конкурентного читателя с наполовину записанным. Тот же
            // приём уже применялся для служебного состояния, но не для чужих файлов.
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| CapError(format!("недопустимое имя файла в пути {rel}")))?;
            crate::engines::store::Store::atomic_write(parent, name, new_content.as_bytes())?;
        }
        Ok((rel.to_string(), action))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(tag: &str) -> Ctx {
        let root = std::env::temp_dir().join(format!(
            "ailc-gen-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Ctx::new(root.to_str().unwrap())
    }

    /// T-17: документ с метками прежнего написания подхватывается, обновляется на месте
    /// и получает действующие метки, а приписки человека снаружи блока сохраняются.
    #[test]
    fn прежние_метки_подхватываются_и_мигрируют() {
        let c = ctx("legacy");
        let path = c.root.join("ОБЗОР.md");
        std::fs::write(
            &path,
            "Моя приписка сверху.\n\n<!-- co:auto:start overview -->\nстарое содержимое\n<!-- co:auto:end -->\n\nПриписка снизу.\n",
        )
        .unwrap();

        let (_, action) =
            Generator::write_block(&c, "ОБЗОР.md", "overview", "новое содержимое").unwrap();
        assert_eq!(action, WriteAction::Updated);

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("новое содержимое"));
        assert!(
            !text.contains("старое содержимое"),
            "блок заменён, а не продублирован"
        );
        assert!(
            text.contains("<!-- ailc:auto:start overview -->"),
            "метки приведены к действующим"
        );
        assert!(!text.contains("co:auto"), "прежних меток не осталось");
        assert!(
            text.contains("Моя приписка сверху."),
            "текст человека сохранён"
        );
        assert!(text.contains("Приписка снизу."), "текст человека сохранён");
        std::fs::remove_dir_all(&c.root).ok();
    }

    /// Повторная запись того же содержимого файл не трогает.
    #[test]
    fn повторная_запись_идемпотентна() {
        let c = ctx("idem");
        Generator::write_block(&c, "a.md", "k", "тело").unwrap();
        let (_, action) = Generator::write_block(&c, "a.md", "k", "тело").unwrap();
        assert_eq!(action, WriteAction::Unchanged);
        std::fs::remove_dir_all(&c.root).ok();
    }
}
