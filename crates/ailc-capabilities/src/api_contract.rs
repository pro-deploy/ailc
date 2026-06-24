//! Контракт публичного API: снимок (`generate/api-baseline`) и проверка слома
//! (`verify/api-break`). Из ailc — но по-честному, детерминированно и офлайн.
//!
//! Снимок = отсортированный набор публичных символов (язык·вид·имя) в `.co/api/baseline.txt`.
//! Проверка сравнивает текущее публичное API со снимком: символ был в снимке и пропал →
//! слом контракта (удалён/переименован). Перемещение между файлами сломом НЕ считается
//! (ключ — без файла). Параметры/типы не сравниваются (символы их не несут) — честное
//! ограничение v1: ловим удаление/переименование, самый частый слом.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Finding, Result, RunInput,
    Severity, Symbol, SymbolKind, Tier,
};
use ailc_core::engines::codeintel::CodeIntelEngine;
use ailc_core::engines::store::Store;
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::collections::BTreeSet;

const TARGET_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;
const NS: &str = "api";
const BASELINE: &str = "baseline.txt";

/// Публичный, описываемый символ (контрактный): функция/метод/тип/класс/интерфейс/трейт/enum.
fn is_contract(s: &Symbol) -> bool {
    s.exported
        && matches!(
            s.kind,
            SymbolKind::Function
                | SymbolKind::Method
                | SymbolKind::Type
                | SymbolKind::Class
                | SymbolKind::Interface
                | SymbolKind::Trait
                | SymbolKind::Enum
        )
}

/// Ключ символа в контракте: язык·вид·имя (без файла — переезд не слом).
fn key(s: &Symbol) -> String {
    format!("{} {} {}", s.lang, s.kind, s.name)
}

/// Текущее публичное API проекта как отсортированный набор ключей.
fn current_api(ctx: &Ctx, input: &RunInput) -> Result<BTreeSet<String>> {
    Ok(CodeIntelEngine::symbols(ctx, input)?
        .iter()
        .filter(|s| is_contract(s))
        .map(key)
        .collect())
}

// ───────────────────────── generate/api-baseline ─────────────────────────

pub struct ApiBaseline {
    manifest: CapabilityManifest,
}
impl Default for ApiBaseline {
    fn default() -> Self {
        Self::new()
    }
}
impl ApiBaseline {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "generate/api-baseline",
                family: Family::Generate,
                engine: EngineKind::Generator,
                when_to_use: "Зафиксировать снимок публичного API в .co/api/baseline.txt — эталон, против которого verify/api-break ловит слом контракта.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: true,
            },
        }
    }
}
impl Capability for ApiBaseline {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let api = current_api(ctx, input)?;
        let mut out = CapabilityOutput::default();
        if api.is_empty() {
            out.skipped = Some("публичных символов не найдено — снимок не нужен".into());
            out.summary = "generate/api-baseline: нет публичного API".into();
            return Ok(out);
        }
        let body = api.iter().cloned().collect::<Vec<_>>().join("\n");
        Store::write(ctx, NS, BASELINE, &body)?;
        out.artifacts.push(format!(".co/{NS}/{BASELINE}"));
        out.metrics.push(("public_symbols".into(), api.len() as f64));
        out.summary = format!("generate/api-baseline: снимок {} публичных символов", api.len());
        Ok(out)
    }
}

// ───────────────────────── verify/api-break ─────────────────────────

pub struct ApiBreak {
    manifest: CapabilityManifest,
}
impl Default for ApiBreak {
    fn default() -> Self {
        Self::new()
    }
}
impl ApiBreak {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "verify/api-break",
                family: Family::Verify,
                engine: EngineKind::CodeIntel,
                when_to_use: "Проверить, не сломан ли публичный контракт: удалённые/переименованные публичные символы относительно снимка .co/api/baseline.txt.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}
impl Capability for ApiBreak {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        // Снимок: один файл baseline.txt в .co/api/.
        let baseline: Option<String> = Store::read_all(ctx, NS)?
            .into_iter()
            .find(|(name, _)| name == BASELINE)
            .map(|(_, c)| c);
        let baseline = match baseline {
            Some(b) => b,
            None => {
                out.skipped = Some(
                    "нет снимка API (.co/api/baseline.txt) — сделай: ailc cap generate/api-baseline".into(),
                );
                out.summary = "verify/api-break: снимок не сделан".into();
                return Ok(out);
            }
        };

        let old: BTreeSet<String> = baseline.lines().map(str::to_string).filter(|l| !l.trim().is_empty()).collect();
        let new = current_api(ctx, input)?;

        let removed: Vec<&String> = old.difference(&new).collect();
        for k in &removed {
            out.findings.push(Finding {
                rule: "api-break".into(),
                severity: Severity::Medium,
                message: format!(
                    "Публичный символ `{k}` исчез относительно снимка — слом контракта (удаление/переименование)"
                ),
                location: None,
                evidence: None,
                verified: true,
                source: "verify/api-break".into(),
            });
        }
        out.metrics.push(("api_removed".into(), removed.len() as f64));
        out.metrics.push(("api_added".into(), new.difference(&old).count() as f64));
        out.summary = format!(
            "verify/api-break: удалено/переименовано {} публичных символов, добавлено {}",
            removed.len(),
            new.difference(&old).count()
        );
        Ok(out)
    }
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(ApiBaseline::new()));
    reg.register(Box::new(ApiBreak::new()));
}
