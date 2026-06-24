//! E9 Diagram как CORE-capability поверх `DiagramEngine`.
//!
//! Два инструмента — одна модель: оба берут граф зависимостей у E3 CodeIntel и
//! рендерят его в Mermaid через `DiagramEngine::mermaid_deps`. Разница только в
//! назначении вывода: `code.intel/diagram` отдаёт текст в ответ (без записи на диск),
//! `generate/diagram` идемпотентно пишет его в документацию через E5 Generator.
//! Логика анализа и рендеринга не дублируется — capability лишь тонкий конфиг.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Tier,
};
use ailc_core::engines::codeintel::CodeIntelEngine;
use ailc_core::engines::diagram::DiagramEngine;
use ailc_core::engines::generator::Generator;
use ailc_core::registry::Registry;
use ailc_core::Capability;

/// Схема входа — как у прочих проверок «по проекту».
const TARGET_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;

// ───────────────────────── code.intel/diagram ─────────────────────────

pub struct DiagramView {
    manifest: CapabilityManifest,
}

impl Default for DiagramView {
    fn default() -> Self {
        Self::new()
    }
}

impl DiagramView {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "code.intel/diagram",
                family: Family::CodeIntel,
                engine: EngineKind::Diagram,
                when_to_use: "Показать связи частей проекта диаграммой Mermaid — наглядная карта зависимостей без записи на диск.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for DiagramView {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let graph = CodeIntelEngine::dependency_graph(ctx, input)?;
        let mut out = CapabilityOutput::default();

        let modules = graph.modules.len();
        let edges = graph.edges.len();
        out.metrics.push(("modules".into(), modules as f64));
        out.metrics.push(("edges".into(), edges as f64));

        // Инвариант «нет молчаливых пропусков»: пустая модель → честная причина.
        if modules == 0 {
            out.skipped = Some("нет модулей для диаграммы (не найдено исходников)".into());
            out.summary = "code.intel/diagram: нет модулей для диаграммы".into();
            return Ok(out);
        }

        let mermaid = DiagramEngine::mermaid_deps(ctx, input)?;
        for line in mermaid.lines() {
            out.records.push(line.to_string());
        }
        out.summary = format!(
            "code.intel/diagram: {modules} модулей, {edges} рёбер"
        );
        Ok(out)
    }
}

// ───────────────────────── generate/diagram ─────────────────────────

pub struct DiagramDoc {
    manifest: CapabilityManifest,
}

impl Default for DiagramDoc {
    fn default() -> Self {
        Self::new()
    }
}

impl DiagramDoc {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "generate/diagram",
                family: Family::Generate,
                engine: EngineKind::Diagram,
                when_to_use: "Записать диаграмму связей частей проекта (Mermaid) в документацию docs/ДИАГРАММА.md.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: true, // пишет файл документации
            },
        }
    }
}

impl Capability for DiagramDoc {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let graph = CodeIntelEngine::dependency_graph(ctx, input)?;
        let mut out = CapabilityOutput::default();

        let modules = graph.modules.len();
        let edges = graph.edges.len();
        out.metrics.push(("modules".into(), modules as f64));
        out.metrics.push(("edges".into(), edges as f64));

        // Инвариант «нет молчаливых пропусков»: пустую диаграмму не пишем.
        if modules == 0 {
            out.skipped = Some("нет модулей для диаграммы (не найдено исходников)".into());
            out.summary = "generate/diagram: нет модулей для диаграммы".into();
            return Ok(out);
        }

        let mermaid = DiagramEngine::mermaid_deps(ctx, input)?;
        // Оборачиваем граф в блок Mermaid, чтобы просмотрщик документации его отрисовал.
        let content = format!("```mermaid\n{}\n```", mermaid.trim_end());

        let (path, action) =
            Generator::write_block(ctx, "docs/ДИАГРАММА.md", "deps", &content)?;
        out.artifacts.push(path.clone());
        out.summary = format!(
            "generate/diagram: {path} ({action}) — {modules} модулей, {edges} рёбер"
        );
        Ok(out)
    }
}

/// Регистрирует capability движка E9 Diagram.
pub fn register(reg: &mut Registry) {
    reg.register(Box::new(DiagramView::new())); // CodeIntel: текст в ответ
    reg.register(Box::new(DiagramDoc::new())); // Generate: запись в документацию
}
