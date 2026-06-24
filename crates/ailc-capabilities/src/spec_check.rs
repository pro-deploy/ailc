//! `spec.check/drift` — дрейф документации (Фаза 4): держит ли документация шаг за
//! кодом. Сверяет авто-блок каждого документа (`docs/*`) с СВЕЖИМ результатом тех же
//! build-функций, что и генераторы (единый источник истины — `spec_gen::doc_specs`).
//!
//! Семейство Spec → гоняется в гейте РЯДОМ С БЕЗОПАСНОСТЬЮ. Делает «актуальность доков»
//! проверяемой, а не только авто-обновляемой: устаревший документ врёт о коде — это
//! находка-предупреждение. Отсутствие доков на существенном проекте — мягкий нудж
//! «собрать из кода?». Не мутирует (генерацию решает человек/намерение/custodian).

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Finding, Location, Result,
    RunInput, Severity, Tier,
};
use ailc_core::engines::codeintel::CodeIntelEngine;
use ailc_core::engines::surface;
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::fs;

use crate::spec_gen::doc_specs;

const TARGET_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;

/// Содержимое авто-блока документа (между метками `co:auto`), обрезанное. None — нет
/// файла или блока (документ ещё не сгенерирован).
fn read_auto_block(ctx: &Ctx, rel: &str, key: &str) -> Option<String> {
    let text = fs::read_to_string(ctx.root.join(rel)).ok()?;
    let start = format!("<!-- co:auto:start {key} -->");
    let si = text.find(&start)?;
    let after = &text[si + start.len()..];
    let ei = after.find("<!-- co:auto:end -->")?;
    Some(after[..ei].trim().to_string())
}

/// Проект «существенный» — есть что документировать (публичных символов ≥ 5 или есть
/// эндпоинты). На тривиальном скрипте не пилим за отсутствие доков.
fn is_substantial(ctx: &Ctx, input: &RunInput) -> Result<bool> {
    let public = CodeIntelEngine::symbols(ctx, input)?
        .iter()
        .filter(|s| s.exported)
        .count();
    if public >= 5 {
        return Ok(true);
    }
    Ok(!surface::extract(ctx, input)?.routes.is_empty())
}

pub struct DriftCheck {
    manifest: CapabilityManifest,
}

impl Default for DriftCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl DriftCheck {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "spec.check/drift",
                family: Family::Spec,
                engine: EngineKind::CodeIntel,
                when_to_use: "Проверить, не устарела ли документация (спека/архитектура/C4/модель/глоссарий) относительно кода — и есть ли она вообще.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for DriftCheck {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let mut in_sync = 0usize;
        let mut stale = 0usize;
        let mut missing: Vec<&'static str> = Vec::new();

        for d in doc_specs() {
            match read_auto_block(ctx, d.rel, d.key) {
                None => {
                    missing.push(d.title);
                    out.records.push(format!("{}: отсутствует", d.rel));
                }
                Some(cur) => {
                    // Свежий авто-контент тем же билдером, что и генератор → дрейф = разница.
                    let fresh = (d.build)(ctx, input)?.trim().to_string();
                    if cur == fresh {
                        in_sync += 1;
                        out.records.push(format!("{}: актуально", d.rel));
                    } else {
                        stale += 1;
                        out.records.push(format!("{}: УСТАРЕЛО", d.rel));
                        out.findings.push(Finding {
                            rule: "doc-drift".into(),
                            severity: Severity::Low,
                            message: format!(
                                "Документ «{}» устарел — код изменился. Обнови: `ailc <путь> \"обнови документацию\"`",
                                d.rel
                            ),
                            location: Some(Location {
                                file: d.rel.to_string(),
                                line: 1,
                            }),
                            evidence: None,
                            verified: true,
                            source: "spec.check/drift".into(),
                        });
                    }
                }
            }
        }

        // Отсутствие доков — мягкий нудж, и только на существенном проекте (агрегатно).
        if !missing.is_empty() && is_substantial(ctx, input)? {
            out.findings.push(Finding {
                rule: "doc-missing".into(),
                severity: Severity::Info,
                message: format!(
                    "Нет документации из кода: {}. Собрать: `ailc <путь> \"обнови документацию\"`",
                    missing.join(", ")
                ),
                location: None,
                evidence: None,
                verified: true,
                source: "spec.check/drift".into(),
            });
        }

        out.metrics.push(("docs_in_sync".into(), in_sync as f64));
        out.metrics.push(("docs_stale".into(), stale as f64));
        out.metrics.push(("docs_missing".into(), missing.len() as f64));
        out.summary = format!(
            "spec.check/drift: актуальны {in_sync}, устарели {stale}, отсутствуют {}",
            missing.len()
        );
        Ok(out)
    }
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(DriftCheck::new()));
}
