//! Девять переиспользуемых движков. Реализованы:
//!   E1 Scan      — обход + правила → findings (референс модели «инструмент = конфиг»)
//!   E3 CodeIntel — извлечение символов; тир regex (полиглот), tree-sitter за feature-флагом
//! Остальные добавляются по очереди: runner (E2), llmjudge (E4), generator (E5),
//! gate (E6), store (E7), metric (E8), diagram (E9), index (E0).

pub mod codeintel;
pub mod diagram;
pub mod gate;
pub mod generator;
pub mod index;
pub mod metric;
pub mod osv;
pub mod runner;
pub mod sast;
pub mod scan;
pub mod store;
pub mod surface;
pub mod walk;
