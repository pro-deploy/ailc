//! `code.intel/diff-scope` — радиус влияния правки: какие функции затронуты изменением
//! (транзитивно, через граф вызовов). Из ailc, но офлайн и детерминированно.
//!
//! git diff (vs HEAD) → изменённые файлы → их функции → обратный обход графа вызовов
//! (кто их зовёт, транзитивно) → затронутая поверхность. Для вайбкодера: «что я задел».
//! Это информация (records), не находки.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Tier,
};
use ailc_core::engines::codeintel::CodeIntelEngine;
use ailc_core::engines::runner::Runner;
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::collections::{BTreeSet, HashMap, HashSet};

const TARGET_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;

pub struct DiffScope {
    manifest: CapabilityManifest,
}
impl Default for DiffScope {
    fn default() -> Self {
        Self::new()
    }
}
impl DiffScope {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "code.intel/diff-scope",
                family: Family::CodeIntel,
                engine: EngineKind::CodeIntel,
                when_to_use: "Радиус влияния текущей правки: какие функции затронуты изменением через граф вызовов (что задело это изменение перед сдачей).",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: false, // зависит от состояния git working tree
                mutates: false,
            },
        }
    }
}

impl Capability for DiffScope {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        // Изменённые файлы — git diff vs HEAD (staged + unstaged).
        let res = Runner::run(ctx, "git", &["diff", "--name-only", "HEAD"]);
        if !res.ran {
            out.skipped = Some(res.skipped_reason.unwrap_or_else(|| "git недоступен".into()));
            out.summary = "code.intel/diff-scope: пропущено (нет git)".into();
            return Ok(out);
        }
        if !res.exit_ok {
            out.skipped = Some("не git-репозиторий или нет коммита HEAD".into());
            out.summary = "code.intel/diff-scope: пропущено (нет HEAD)".into();
            return Ok(out);
        }
        let changed: HashSet<String> = res
            .stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if changed.is_empty() {
            out.summary = "code.intel/diff-scope: изменений относительно HEAD нет".into();
            out.records.push("рабочее дерево чисто — радиус влияния пуст".into());
            return Ok(out);
        }

        // Функции в изменённых файлах = «эпицентр».
        let syms = CodeIntelEngine::symbols(ctx, input)?;
        let epicenter: BTreeSet<String> = syms
            .iter()
            .filter(|s| changed.contains(&s.file))
            .map(|s| s.name.clone())
            .collect();

        // Обратный граф вызовов: callee → кто его зовёт.
        let cg = CodeIntelEngine::call_graph(ctx, input)?;
        let mut callers: HashMap<&str, Vec<&str>> = HashMap::new();
        for (caller, callee) in &cg.edges {
            callers.entry(callee.as_str()).or_default().push(caller.as_str());
        }

        // Транзитивно: кого затрагивает изменение эпицентра.
        let mut affected: BTreeSet<String> = BTreeSet::new();
        let mut queue: Vec<String> = epicenter.iter().cloned().collect();
        while let Some(n) = queue.pop() {
            if let Some(cs) = callers.get(n.as_str()) {
                for c in cs {
                    if affected.insert((*c).to_string()) {
                        queue.push((*c).to_string());
                    }
                }
            }
        }
        // Сам эпицентр не считаем «затронутым извне».
        for e in &epicenter {
            affected.remove(e);
        }

        out.metrics.push(("changed_files".into(), changed.len() as f64));
        out.metrics.push(("epicenter".into(), epicenter.len() as f64));
        out.metrics.push(("affected".into(), affected.len() as f64));

        let mut files: Vec<&String> = changed.iter().collect();
        files.sort();
        out.records.push(format!("изменено файлов: {}", changed.len()));
        for f in files.iter().take(20) {
            out.records.push(format!("  ~ {f}"));
        }
        if !epicenter.is_empty() {
            out.records.push(format!(
                "правленые функции: {}",
                epicenter.iter().take(15).cloned().collect::<Vec<_>>().join(", ")
            ));
        }
        out.records.push(format!("затронуто (зовут изменённое) функций: {}", affected.len()));
        for a in affected.iter().take(25) {
            out.records.push(format!("  → {a}()"));
        }
        if affected.len() > 25 {
            out.records.push(format!("  … ещё {}", affected.len() - 25));
        }

        out.summary = format!(
            "code.intel/diff-scope: {} изменённых файлов, {} правленых функций, радиус {} функций",
            changed.len(),
            epicenter.len(),
            affected.len()
        );
        Ok(out)
    }
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(DiffScope::new()));
}
