//! Переменные окружения продукта с совместимостью по прежнему имени.
//!
//! Продукт называется `ailc`, поэтому его публичный контракт обязан использовать префикс
//! `AILC_`. Исторически переменные назывались с префиксом `CO_MCP_` по прежнему имени
//! проекта, и после переименования в поставке соседствовали два префикса: установщики
//! читали `AILC_VERSION` и `AILC_BINDIR`, а сервер и политика читали `CO_MCP_POLICY`,
//! `CO_MCP_NO_RULES` и подобные. Разнобой в именах публичного контракта дезориентирует
//! пользователя и выглядит следом незавершённого переименования.
//!
//! Переход выполняется без слома существующих установок: сначала читается новое имя, а
//! при его отсутствии прежнее. Поддержка прежнего имени сохраняется на один выпуск и
//! после этого снимается.

use std::ffi::OsString;

/// Прежний префикс имён переменных окружения (по прежнему имени продукта).
const LEGACY_PREFIX: &str = "CO_MCP_";
/// Действующий префикс имён переменных окружения.
const PREFIX: &str = "AILC_";

/// Имя переменной в прежнем написании, если новое имя начинается с действующего префикса.
fn legacy_name(name: &str) -> Option<String> {
    name.strip_prefix(PREFIX)
        .map(|tail| format!("{LEGACY_PREFIX}{tail}"))
}

/// Значение переменной окружения как строка: сначала новое имя, затем прежнее.
pub fn var(name: &str) -> Option<String> {
    if let Ok(v) = std::env::var(name) {
        return Some(v);
    }
    legacy_name(name).and_then(|old| std::env::var(old).ok())
}

/// Значение переменной окружения как строка операционной системы (для путей).
pub fn var_os(name: &str) -> Option<OsString> {
    if let Some(v) = std::env::var_os(name) {
        return Some(v);
    }
    legacy_name(name).and_then(std::env::var_os)
}

/// Задана ли переменная (в новом либо прежнем написании).
pub fn is_set(name: &str) -> bool {
    var_os(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn прежнее_имя_выводится_из_нового() {
        assert_eq!(legacy_name("AILC_POLICY").as_deref(), Some("CO_MCP_POLICY"));
        assert_eq!(
            legacy_name("AILC_NO_RULES").as_deref(),
            Some("CO_MCP_NO_RULES")
        );
        assert_eq!(legacy_name("PATH"), None);
    }

    #[test]
    fn новое_имя_имеет_приоритет_над_прежним() {
        // Переменные с уникальным суффиксом, чтобы не мешать другим тестам.
        let new = "AILC_TEST_PRIORITY_CASE";
        let old = "CO_MCP_TEST_PRIORITY_CASE";
        // SAFETY: тест однопоточно владеет уникальными именами переменных.
        unsafe {
            std::env::set_var(old, "старое");
        }
        assert_eq!(var(new).as_deref(), Some("старое"), "прежнее имя читается");
        unsafe {
            std::env::set_var(new, "новое");
        }
        assert_eq!(var(new).as_deref(), Some("новое"), "новое имя важнее");
        unsafe {
            std::env::remove_var(new);
            std::env::remove_var(old);
        }
    }
}
