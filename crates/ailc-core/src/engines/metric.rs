//! E8 MetricEngine — числовые метрики по дереву исходников.
//!
//! Один проход по файлам считает «физику» кода: число строк и приближённую
//! цикломатическую сложность. Capability поверх этого движка лишь по-разному
//! агрегируют выход (порог-нарушители для гейта, топ для отчёта) — ноль
//! дублирования логики обхода и подсчёта. Чистый std, без внешних зависимостей.

use super::codeintel::read_source;
use super::walk::{ext_of, walk};
use ailc_contracts::{Ctx, Result, RunInput};

/// Метрика одного файла: путь относительно корня, число строк, сложности и глубина.
pub struct FileMetric {
    pub path: String,
    pub lines: u32,
    /// Приближённая цикломатическая сложность по ветвящим лексемам.
    ///
    /// Семантика этой величины намеренно НЕ меняется: на неё настроены пороги в политике
    /// и базовые линии долга проектов, и её пересчёт по другому правилу превратил бы уже
    /// принятые решения о качестве в неверные без всякого изменения кода.
    pub complexity: u32,
    /// Когнитивная сложность: ветвление, взвешенное глубиной вложенности.
    ///
    /// Считается по дереву разбора, а не по лексемам. Отличие от цикломатической
    /// существенно: три последовательных ветвления читаются легко, а три вложенных друг в
    /// друга читаются тяжело, и одинаковая оценка для этих случаев вводит в заблуждение.
    /// Ноль означает, что грамматики для языка нет и величина не вычислялась.
    pub cognitive: u32,
    /// Наибольшая глубина вложенности управляющих конструкций. Ноль означает, что
    /// величина не вычислялась.
    pub nesting: u32,
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
        let base = ctx.base(input)?;
        let root = ctx.root.clone();
        let mut metrics: Vec<FileMetric> = Vec::new();

        walk(&base, &mut |path| {
            // Считаем только известные исходные расширения.
            if !SOURCE_EXTS.contains(&ext_of(path)) {
                return;
            }
            // Бинарь/нечитаемое: пропуск конкретного файла (не всего capability). Чтение
            // устойчивым read_source (как в codeintel), а не прямым fs::read_to_string:
            // файл в не-UTF-8 кодировке читается с заменой байтов, а не роняет метрику.
            let content = match read_source(path) {
                Some(c) => c,
                None => return,
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
            let (cognitive, nesting) = cognitive_of(ext_of(path), &content);

            metrics.push(FileMetric {
                path: rel,
                lines,
                complexity,
                cognitive,
                nesting,
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

/// Узлы дерева разбора, считающиеся ветвлением при подсчёте когнитивной сложности.
///
/// Перечень задан ТОЧНЫМИ именами узлов, а не подстроками. Прежнее сравнение по
/// вхождению подстроки (`match_`, `case_` и подобные) считало ветвлением служебные
/// узлы вроде `match_arm` и `match_block`: каждая ветка match завышала сложность,
/// хотя ветвлением является само выражение match, а не его рукава. Имена перечислены
/// по действующим грамматикам поддерживаемых языков; новое имя узла в обновлённой
/// грамматике добавляется сюда явно.
const BRANCH_NODES: &[&str] = &[
    // условные конструкции
    "if_statement",
    "if_expression",
    "if_let_expression",
    "elif_clause",
    "conditional_expression",
    "ternary_expression",
    // циклы
    "while_statement",
    "while_expression",
    "while_let_expression",
    "for_statement",
    "for_expression",
    "for_in_statement",
    "foreach_statement",
    "enhanced_for_statement",
    "loop_expression",
    "do_statement",
    // выбор по значению
    "match_expression",
    "match_statement",
    "switch_statement",
    "switch_expression",
    "when_expression",
    // обработка исключений
    "try_statement",
    "try_expression",
    "catch_clause",
    "except_clause",
];

/// Узлы, повышающие глубину вложенности. Совпадают с ветвящими, а также с телами функций
/// не считаются: вложенность внутри функции отсчитывается от самой функции.
fn is_branch_node(kind: &str) -> bool {
    BRANCH_NODES.contains(&kind)
}

/// Когнитивная сложность и наибольшая глубина вложенности по дереву разбора.
///
/// Правило подсчёта общепринятое: каждое ветвление добавляет единицу плюс текущую глубину
/// вложенности, поэтому вложенные конструкции стоят дороже последовательных. Возвращает
/// нули, если грамматики для языка нет: выдумывать величину, которую не удалось измерить,
/// недопустимо, поскольку на неё смотрит человек при решении о качестве.
fn cognitive_of(ext: &str, content: &str) -> (u32, u32) {
    use tree_sitter::Parser;

    let lang = super::codeintel::lang_for_ext(ext);
    let Some(language) = super::codeintel::ts_language(lang) else {
        return (0, 0);
    };
    let mut parser = Parser::new();
    if parser.set_language(&language).is_err() {
        return (0, 0);
    }
    let Some(tree) = parser.parse(content, None) else {
        return (0, 0);
    };

    // Обход в глубину с явным стеком: рекурсия по чужому дереву неизвестной глубины
    // рискует переполнить стек, а изоляция сбоев в конвейере рассчитана на панику, а не
    // на аварийное завершение процесса.
    let mut cognitive: u32 = 0;
    let mut max_depth: u32 = 0;
    let mut stack: Vec<(tree_sitter::Node, u32)> = vec![(tree.root_node(), 0)];
    while let Some((node, depth)) = stack.pop() {
        let branch = is_branch_node(node.kind());
        let next_depth = if branch {
            cognitive = cognitive.saturating_add(1 + depth);
            max_depth = max_depth.max(depth + 1);
            depth + 1
        } else {
            depth
        };
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push((child, next_depth));
        }
    }
    (cognitive, max_depth)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Вложенные ветвления стоят дороже последовательных: именно в этом смысл
    /// когнитивной сложности и её отличие от цикломатической, которая для обоих случаев
    /// даёт одно и то же число.
    #[test]
    fn вложенность_дороже_последовательности() {
        let последовательно = "fn f(a: i32) { if a > 0 {} if a > 1 {} if a > 2 {} }\n";
        let вложенно = "fn f(a: i32) { if a > 0 { if a > 1 { if a > 2 {} } } }\n";
        let (посл, гл_посл) = cognitive_of("rs", последовательно);
        let (влож, гл_влож) = cognitive_of("rs", вложенно);
        assert!(
            посл > 0 && влож > 0,
            "величина обязана вычисляться для Rust"
        );
        assert!(
            влож > посл,
            "вложенные ветвления обязаны стоить дороже последовательных: {влож} против {посл}"
        );
        assert!(гл_влож > гл_посл, "глубина вложенности обязана различаться");
        assert_eq!(
            complexity_of(последовательно),
            complexity_of(вложенно),
            "цикломатическая сложность в этих случаях совпадает, поэтому одной её мало"
        );
    }

    /// Регрессия: рукав match (узел match_arm) не является ветвлением. Прежнее сравнение
    /// по подстроке `match_` считало каждый рукав отдельным ветвлением и завышало
    /// когнитивную сложность пропорционально числу рукавов.
    #[test]
    fn рукава_match_не_считаются_ветвлением() {
        let код = "fn f(a: i32) -> i32 { match a { 1 => 1, 2 => 2, _ => 0 } }\n";
        let (сложн, глуб) = cognitive_of("rs", код);
        assert_eq!(
            сложн, 1,
            "ветвлением является само выражение match, а не его рукава"
        );
        assert_eq!(глуб, 1);
    }

    /// Язык без грамматики честно даёт нули, а не выдуманное число.
    #[test]
    fn язык_без_грамматики_даёт_нули() {
        assert_eq!(cognitive_of("txt", "если то иначе\n"), (0, 0));
    }
}
