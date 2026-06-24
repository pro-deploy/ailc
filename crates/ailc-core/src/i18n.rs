//! Локализация UI (ru/en). Язык — из переменной окружения `CO_MCP_LANG`
//! (`en`/`english` → English, иначе русский по умолчанию).
//!
//! Здесь — ЛИЦО продукта (вердикт, QualityLedger), что видит человек. Технический слой
//! (сообщения находок, шаблоны доков) пока на русском — это отдельный, больший пласт.

use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    Ru,
    En,
}

/// Выбранный язык — один раз из `CO_MCP_LANG` (по умолчанию русский).
pub fn lang() -> Lang {
    static L: OnceLock<Lang> = OnceLock::new();
    *L.get_or_init(|| match std::env::var("CO_MCP_LANG").map(|s| s.to_lowercase()) {
        Ok(s) if s == "en" || s == "english" => Lang::En,
        _ => Lang::Ru,
    })
}

/// Строка по выбранному языку: `t("по-русски", "in English")`.
pub fn t(ru: &'static str, en: &'static str) -> &'static str {
    match lang() {
        Lang::Ru => ru,
        Lang::En => en,
    }
}
