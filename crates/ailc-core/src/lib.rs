//! Ядро ailc: трейт Capability, реестр и переиспользуемые движки.
//!
//! Здесь же позже поселится оркестратор (planner / router / executor /
//! verify_supervisor / rigor_scorer / escalation). Пока — фундамент инструментов.

pub mod agent;
pub mod autofix;
pub mod engines;
pub mod fixer;
pub mod i18n;
pub mod orchestrator;
pub mod pipeline;
pub mod policy;
pub mod registry;
pub mod sarif;
pub mod skills;
pub mod stack;
pub mod verify;

use ailc_contracts::{CapabilityManifest, CapabilityOutput, Ctx, Result, RunInput};

/// Инструмент = тонкая обёртка над движком + конфиг.
///
/// Трейт намеренно узкий: вся общая логика живёт в движках (`engines::*`),
/// а конкретный capability лишь отдаёт движку свою таблицу правил/шаблон.
pub trait Capability: Send + Sync {
    fn manifest(&self) -> &CapabilityManifest;
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput>;
}
