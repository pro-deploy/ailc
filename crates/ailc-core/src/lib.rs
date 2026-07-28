//! Ядро ailc: трейт Capability, реестр, переиспользуемые движки и оркестратор
//! (planner / router / executor / verify_supervisor / rigor_scorer / escalation),
//! который живёт в модуле [`orchestrator`].

pub mod agent;
pub mod answers;
pub mod autofix;
pub mod baseline;
pub mod cache;
pub mod calibrate;
pub mod changes;
pub mod engines;
pub mod env;
pub mod fixer;
pub mod i18n;
pub mod memory_log;
pub mod model;
pub mod orchestrator;
pub mod pipeline;
pub mod policy;
pub mod profile;
pub mod re;
pub mod registry;
pub mod sarif;
pub mod skills;
pub mod stack;
pub mod standards;
pub mod tasks;
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
