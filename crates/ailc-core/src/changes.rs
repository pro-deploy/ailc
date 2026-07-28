//! Журнал изменений: запись на каждое, даже мелкое изменение.
//!
//! Требование «документируется всё» распадается на два разных обязательства, и смешивать
//! их нельзя. Журнальное обязательство исполняется для ста процентов изменений и
//! исполняется сервером: запись формируется детерминированно из самого различия, без
//! единого вопроса к человеку. Проектное обязательство (спека, архитектурное решение,
//! обновление технического задания) возникает только там, где есть решение, которое стоит
//! записать, и определяется классом изменения. Так требование выполняется буквально и при
//! этом не превращается в бюрократию, от которой откажутся на второй день.
//!
//! КЛАСС ИЗМЕНЕНИЯ ВЫВОДИТСЯ ИЗ РАЗЛИЧИЯ, А НЕ СО СЛОВ АГЕНТА. Иначе любая правка
//! объявлялась бы косметической, и дисциплина держалась бы на добросовестности того, кого
//! она ограничивает.

use crate::engines::store::Store;
use ailc_contracts::{Ctx, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Пространство журнала в служебном каталоге проекта.
const NS: &str = "changes";

/// Класс изменения. Определяет, какие документы обязаны сопровождать правку.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeClass {
    /// Изменение не меняет наблюдаемого поведения: комментарии, форматирование,
    /// переименования внутри модуля. Достаточно журнальной записи.
    Cosmetic,
    /// Исправление дефекта. Требуется связь с задачей или спекой, техническое задание
    /// не требуется.
    Defect,
    /// Новая функциональность. Требуется спека до написания кода, а на сдаче обновление
    /// технического задания и диаграмм.
    Feature,
    /// Слом публичного контракта либо смена архитектурного решения. Требуется
    /// архитектурное решение и обновление архитектурных документов.
    ContractBreak,
}

impl ChangeClass {
    pub fn label(&self) -> &'static str {
        match self {
            ChangeClass::Cosmetic => "косметическое",
            ChangeClass::Defect => "исправление дефекта",
            ChangeClass::Feature => "новая функциональность",
            ChangeClass::ContractBreak => "слом публичного контракта",
        }
    }

    /// Что обязано сопровождать изменение этого класса.
    pub fn requires(&self) -> &'static str {
        match self {
            ChangeClass::Cosmetic => "только запись в журнале изменений",
            ChangeClass::Defect => "связь с задачей или спекой",
            ChangeClass::Feature => "спека до написания кода и обновление документов на сдаче",
            ChangeClass::ContractBreak => {
                "архитектурное решение (ADR) и обновление архитектурных документов"
            }
        }
    }

    /// Требуется ли для этого класса проектный документ, а не только журнальная запись.
    pub fn needs_design_document(&self) -> bool {
        !matches!(self, ChangeClass::Cosmetic)
    }
}

/// Запись журнала изменений.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRecord {
    /// Порядковый номер записи.
    pub number: u32,
    pub date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    pub class: ChangeClass,
    /// Намерение, с которым изменение выполнялось, в формулировке человека или агента.
    pub intent: String,
    /// Затронутые файлы.
    pub files: Vec<String>,
    /// Публичные символы, появившиеся в изменении.
    pub added_symbols: Vec<String>,
    /// Публичные символы, исчезнувшие в изменении.
    pub removed_symbols: Vec<String>,
    /// Связанные документы: спеки, архитектурные решения, задачи.
    pub links: Vec<String>,
}

/// Отпечаток различия: по нему повторный вызов не плодит одинаковые записи.
fn digest(files: &[String], added: &[String], removed: &[String]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for s in files.iter().chain(added).chain(removed) {
        for b in s.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{h:016x}")
}

/// Вывод команды git, либо None, если git недоступен или это не репозиторий.
fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).to_string())
}

/// Изменённые файлы рабочего дерева.
pub fn changed_files(root: &Path) -> Option<Vec<String>> {
    let text = git(root, &["status", "--porcelain=v1", "-uall"])?;
    let mut files = Vec::new();
    for line in text.lines() {
        if line.len() < 4 {
            continue;
        }
        let path = line[3..].split(" -> ").last().unwrap_or("").trim();
        let path = path.trim_matches('"');
        // Собственное состояние ailc изменением проекта не является. Без этого отсева
        // запись журнала сама меняла бы различие и порождала бы следующую запись, то есть
        // журнал рос бы от самого факта своего ведения.
        if path.is_empty() || path.starts_with(".ailc/") || path.starts_with(".ailc\\") {
            continue;
        }
        files.push(path.to_string());
    }
    files.sort();
    Some(files)
}

/// Является ли строка содержательной, то есть не пустой и не комментарием.
///
/// Различение приблизительное и намеренно консервативное: сомнительная строка считается
/// содержательной, поэтому ошибка может лишь завысить класс изменения, но не занизить
/// его. Занижение было бы опасным: оно превратило бы правку поведения в косметическую и
/// сняло бы требование к сопровождающим документам.
fn is_meaningful(line: &str) -> bool {
    let t = line.trim();
    if t.is_empty() {
        return false;
    }
    let markers = ["//", "#", "--", "/*", "*", "*/", "<!--", "\"\"\"", "'''"];
    !markers.iter().any(|m| t.starts_with(m))
}

/// Признак объявления, доступного извне. Приблизительный, по ключевым словам языков.
fn public_declaration(line: &str) -> Option<String> {
    let t = line.trim();
    let patterns = [
        ("pub fn ", "функция"),
        ("pub struct ", "тип"),
        ("pub enum ", "тип"),
        ("pub trait ", "интерфейс"),
        ("export function ", "функция"),
        ("export class ", "тип"),
        ("export const ", "константа"),
        ("public class ", "тип"),
        ("public interface ", "интерфейс"),
        ("func ", "функция"),
        ("def ", "функция"),
    ];
    for (p, kind) in patterns {
        if let Some(rest) = t.strip_prefix(p) {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            // Приватное по соглашению языка публичным контрактом не является.
            if p == "def " && name.starts_with('_') {
                continue;
            }
            if p == "func " && !name.chars().next().is_some_and(|c| c.is_uppercase()) {
                continue;
            }
            return Some(format!("{kind} {name}"));
        }
    }
    None
}

/// Итог разбора различия рабочего дерева.
pub struct Diff {
    pub files: Vec<String>,
    pub added_symbols: Vec<String>,
    pub removed_symbols: Vec<String>,
    /// Есть ли содержательные (не комментарии и не пустые строки) изменения.
    pub meaningful: bool,
}

/// Разобрать различие рабочего дерева относительно последнего состояния истории.
pub fn diff(root: &Path) -> Option<Diff> {
    let files = changed_files(root)?;
    // Различие берётся и по отслеживаемым файлам, и по индексу: правка, добавленная в
    // индекс, изменением быть не перестаёт.
    let text = git(root, &["diff", "HEAD", "-U0"]).unwrap_or_default();

    let mut added_symbols: Vec<String> = Vec::new();
    let mut removed_symbols: Vec<String> = Vec::new();
    let mut meaningful = false;

    for line in text.lines() {
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if let Some(body) = line.strip_prefix('+') {
            if is_meaningful(body) {
                meaningful = true;
            }
            if let Some(s) = public_declaration(body) {
                added_symbols.push(s);
            }
        } else if let Some(body) = line.strip_prefix('-') {
            if is_meaningful(body) {
                meaningful = true;
            }
            if let Some(s) = public_declaration(body) {
                removed_symbols.push(s);
            }
        }
    }

    // Новый файл в различии не виден (он не отслеживается), но его появление это
    // содержательное изменение само по себе.
    if !files.is_empty() && text.trim().is_empty() {
        meaningful = true;
    }

    added_symbols.sort();
    added_symbols.dedup();
    removed_symbols.sort();
    removed_symbols.dedup();
    Some(Diff {
        files,
        added_symbols,
        removed_symbols,
        meaningful,
    })
}

/// Классифицировать изменение по различию.
pub fn classify(d: &Diff) -> ChangeClass {
    if !d.removed_symbols.is_empty() {
        // Исчезнувшее объявление, доступное извне, ломает публичный контракт независимо
        // от того, что об этом думает автор правки.
        return ChangeClass::ContractBreak;
    }
    if !d.meaningful {
        return ChangeClass::Cosmetic;
    }
    if !d.added_symbols.is_empty() {
        return ChangeClass::Feature;
    }
    ChangeClass::Defect
}

/// Записать изменение в журнал.
///
/// Повторный вызов на том же различии новой записи не создаёт: журнал фиксирует
/// изменения, а не число обращений к инструменту.
pub fn record(ctx: &Ctx, intent: &str) -> Result<Option<ChangeRecord>> {
    let Some(d) = diff(&ctx.root) else {
        return Ok(None); // вне репозитория различие неопределимо, и это честный пропуск
    };
    if d.files.is_empty() {
        return Ok(None);
    }

    let dg = digest(&d.files, &d.added_symbols, &d.removed_symbols);
    let existing = all(ctx);
    if existing
        .iter()
        .any(|r| digest(&r.files, &r.added_symbols, &r.removed_symbols) == dg)
    {
        return Ok(None);
    }

    let rec = ChangeRecord {
        number: existing.iter().map(|r| r.number).max().unwrap_or(0) + 1,
        date: crate::answers::today(),
        commit: git(&ctx.root, &["rev-parse", "--short", "HEAD"]).map(|s| s.trim().to_string()),
        class: classify(&d),
        intent: intent.trim().to_string(),
        files: d.files,
        added_symbols: d.added_symbols,
        removed_symbols: d.removed_symbols,
        links: Vec::new(),
    };

    let body = toml::to_string_pretty(&rec)
        .map_err(|e| ailc_contracts::CapError(format!("запись журнала не сериализуется: {e}")))?;
    Store::write(ctx, NS, &format!("{:04}.toml", rec.number), &body)?;
    Ok(Some(rec))
}

/// Все записи журнала, упорядоченные по номеру.
pub fn all(ctx: &Ctx) -> Vec<ChangeRecord> {
    let mut out: Vec<ChangeRecord> = Store::read_all(ctx, NS)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(_, body)| toml::from_str::<ChangeRecord>(&body).ok())
        .collect();
    out.sort_by_key(|r| r.number);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(tag: &str) -> Option<Ctx> {
        let root = std::env::temp_dir().join(format!(
            "ailc-changes-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("src")).ok()?;
        let ok = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return None;
        }
        for (k, v) in [("user.email", "т@т"), ("user.name", "тест")] {
            let _ = std::process::Command::new("git")
                .args(["config", k, v])
                .current_dir(&root)
                .status();
        }
        std::fs::write(root.join("src/lib.rs"), "pub fn начальная() {}\n").ok()?;
        let _ = std::process::Command::new("git")
            .args(["add", "-A"])
            .current_dir(&root)
            .status();
        let _ = std::process::Command::new("git")
            .args(["commit", "-qm", "начало"])
            .current_dir(&root)
            .status();
        Some(Ctx::new(root.to_str().unwrap()))
    }

    /// Правка одних комментариев поведения не меняет и требует только журнальной записи.
    #[test]
    fn правка_комментариев_косметическая() {
        let Some(ctx) = repo("косметика") else {
            return;
        };
        std::fs::write(
            ctx.root.join("src/lib.rs"),
            "// пояснение к функции\npub fn начальная() {}\n",
        )
        .unwrap();
        let d = diff(&ctx.root).expect("различие определимо в репозитории");
        assert!(!d.meaningful, "изменены только комментарии");
        assert_eq!(classify(&d), ChangeClass::Cosmetic);
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Появление объявления, доступного извне, это новая функциональность.
    #[test]
    fn новое_публичное_объявление_это_функциональность() {
        let Some(ctx) = repo("функция") else {
            return;
        };
        std::fs::write(
            ctx.root.join("src/lib.rs"),
            "pub fn начальная() {}\npub fn добавленная() {}\n",
        )
        .unwrap();
        let d = diff(&ctx.root).unwrap();
        assert_eq!(classify(&d), ChangeClass::Feature);
        assert!(d.added_symbols.iter().any(|s| s.contains("добавленная")));
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Исчезновение объявления, доступного извне, ломает публичный контракт независимо
    /// от того, что об этом думает автор правки.
    #[test]
    fn исчезнувшее_публичное_объявление_ломает_контракт() {
        let Some(ctx) = repo("слом") else { return };
        std::fs::write(ctx.root.join("src/lib.rs"), "fn внутренняя() {}\n").unwrap();
        let d = diff(&ctx.root).unwrap();
        assert_eq!(classify(&d), ChangeClass::ContractBreak);
        assert!(d.removed_symbols.iter().any(|s| s.contains("начальная")));
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Журнал фиксирует изменения, а не число обращений: повторный вызов на том же
    /// различии новой записи не создаёт.
    #[test]
    fn повторная_запись_не_плодит_дубли() {
        let Some(ctx) = repo("дубли") else {
            return;
        };
        std::fs::write(
            ctx.root.join("src/lib.rs"),
            "pub fn начальная() {}\npub fn вторая() {}\n",
        )
        .unwrap();
        let первая = record(&ctx, "добавил вторую функцию").unwrap();
        assert!(
            первая.is_some(),
            "первое изменение обязано попасть в журнал"
        );
        let вторая = record(&ctx, "тот же прогон").unwrap();
        assert!(вторая.is_none(), "то же различие второй записи не даёт");
        assert_eq!(all(&ctx).len(), 1);
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Вне репозитория различие неопределимо, и это честный пропуск, а не ошибка.
    #[test]
    fn вне_репозитория_журнал_молчит() {
        let root = std::env::temp_dir().join(format!("ailc-changes-негит-{}", std::process::id()));
        std::fs::create_dir_all(&root).ok();
        let ctx = Ctx::new(root.to_str().unwrap());
        // Каталог может случайно оказаться внутри чужого репозитория; тогда проверка не о том.
        if diff(&ctx.root).is_some() {
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        assert!(record(&ctx, "что-то").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&root);
    }
}
