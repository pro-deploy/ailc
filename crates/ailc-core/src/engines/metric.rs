//! E8 MetricEngine — числовые метрики по дереву исходников.
//!
//! Один проход по файлам считает «физику» кода: число строк и приближённую
//! цикломатическую сложность. Capability поверх этого движка лишь по-разному
//! агрегируют выход (порог-нарушители для гейта, топ для отчёта) — ноль
//! дублирования логики обхода и подсчёта. Чистый std, без внешних зависимостей.

use super::walk::{ext_of, walk};
use ailc_contracts::{Ctx, Result, RunInput};
use std::fs;

/// Метрика одного файла: путь относительно корня, число строк, сложность.
pub struct FileMetric {
    pub path: String,
    pub lines: u32,
    pub complexity: u32,
}

/// Исходные расширения, которые умеем считать (см. codeintel.rs как ориентир).
/// Текстовые файлы прочих типов пропускаем — метрика только по коду.
const SOURCE_EXTS: &[&str] = &[
    "go", "rs", "ts", "tsx", "js", "jsx", "py", "java", "kt", "swift", "cs", "c", "cpp", "h",
];

/// Ветвящие конструкции для приближённой цикломатической сложности.
/// Считаем грубо: число вхождений этих подстрок по всему файлу + 1 (базовый путь).
/// Пробелы вокруг ключевых слов отсекают совпадения внутри идентификаторов
/// (`ifaceFor`, `format` и т.п.).
const BRANCH_TOKENS: &[&str] = &[
    " if ", " elif ", " for ", " while ", " case ", " match ", " when ", "catch", " and ", " or ",
    "&&", "||",
];

pub struct MetricEngine;

impl MetricEngine {
    /// Метрика по каждому исходному файлу дерева (или из `input.target`).
    pub fn per_file(ctx: &Ctx, input: &RunInput) -> Result<Vec<FileMetric>> {
        let base = match &input.target {
            Some(t) => ctx.root.join(t),
            None => ctx.root.clone(),
        };
        let root = ctx.root.clone();
        let mut metrics: Vec<FileMetric> = Vec::new();

        walk(&base, &mut |path| {
            // Считаем только известные исходные расширения.
            if !SOURCE_EXTS.contains(&ext_of(path)) {
                return;
            }
            // Бинарь/нечитаемое → пропуск конкретного файла (не всего capability).
            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => return,
            };
            // Пустой файл нечего считать — пропускаем.
            if content.trim().is_empty() {
                return;
            }

            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            let lines = content.lines().count() as u32;
            let complexity = complexity_of(&content);

            metrics.push(FileMetric {
                path: rel,
                lines,
                complexity,
            });
        })?;

        Ok(metrics)
    }
}

/// Приближённая цикломатическая сложность файла:
/// 1 (базовый путь) + число вхождений ветвящих токенов по строкам.
fn complexity_of(content: &str) -> u32 {
    let mut branches: u32 = 0;
    for line in content.lines() {
        for token in BRANCH_TOKENS {
            branches = branches.saturating_add(count_occurrences(line, token));
        }
    }
    branches.saturating_add(1)
}

/// Число непересекающихся вхождений `needle` в `haystack` (чистый std).
fn count_occurrences(haystack: &str, needle: &str) -> u32 {
    if needle.is_empty() {
        return 0;
    }
    haystack.matches(needle).count() as u32
}
