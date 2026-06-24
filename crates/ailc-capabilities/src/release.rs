//! Из ailc, офлайн: `generate/release-notes` (changelog из conventional-commits) и
//! `setup/cicd` (CI-конфиг, гоняющий ailc). Переиспользуют Runner(git) + Generator.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Tier,
};
use ailc_core::engines::generator::Generator;
use ailc_core::engines::runner::Runner;
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::collections::BTreeMap;
use std::fs;

const TARGET_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;

// ───────────────────────── generate/release-notes ─────────────────────────

/// Тип conventional-commit → человеко-заголовок раздела.
fn section(kind: &str) -> Option<&'static str> {
    match kind {
        "feat" => Some("✨ Новое"),
        "fix" => Some("🐛 Исправления"),
        "perf" => Some("⚡ Производительность"),
        "refactor" => Some("♻ Рефакторинг"),
        "docs" => Some("📝 Документация"),
        "test" => Some("✅ Тесты"),
        "build" | "ci" => Some("🔧 Сборка/CI"),
        _ => None, // chore/style и прочее — в changelog не выносим
    }
}

pub struct ReleaseNotes {
    manifest: CapabilityManifest,
}
impl Default for ReleaseNotes {
    fn default() -> Self {
        Self::new()
    }
}
impl ReleaseNotes {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "generate/release-notes",
                family: Family::Generate,
                engine: EngineKind::Generator,
                when_to_use: "Собрать changelog из conventional-commits (feat/fix/...) с последнего тега — заметки к релизу в docs/RELEASE-NOTES.md.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: false, // зависит от истории git
                mutates: true,
            },
        }
    }
}
impl Capability for ReleaseNotes {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        // Диапазон: с последнего тега до HEAD (если тегов нет — вся история).
        let last_tag = {
            let r = Runner::run(ctx, "git", &["describe", "--tags", "--abbrev=0"]);
            if r.ran && r.exit_ok {
                r.stdout.trim().to_string()
            } else {
                String::new()
            }
        };
        let range = if last_tag.is_empty() {
            "HEAD".to_string()
        } else {
            format!("{last_tag}..HEAD")
        };
        let log = Runner::run(ctx, "git", &["log", &range, "--no-merges", "--pretty=format:%s"]);
        if !log.ran {
            out.skipped = Some(log.skipped_reason.unwrap_or_else(|| "git недоступен".into()));
            out.summary = "generate/release-notes: пропущено (нет git)".into();
            return Ok(out);
        }
        if !log.exit_ok {
            out.skipped = Some("не git-репозиторий или нет коммитов".into());
            out.summary = "generate/release-notes: пропущено (нет истории)".into();
            return Ok(out);
        }

        // Группируем conventional-commits по типу.
        let mut groups: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
        let mut counted = 0usize;
        for subj in log.stdout.lines() {
            let subj = subj.trim();
            if subj.is_empty() {
                continue;
            }
            // type(scope)?: subject
            if let Some(colon) = subj.find(':') {
                let head = &subj[..colon];
                let kind = head.split('(').next().unwrap_or(head).trim();
                if let Some(sec) = section(kind) {
                    let text = subj[colon + 1..].trim().to_string();
                    groups.entry(sec).or_default().push(text);
                    counted += 1;
                }
            }
        }

        let mut doc = String::from("# Заметки к релизу\n\n");
        if last_tag.is_empty() {
            doc.push_str("_С начала истории._\n\n");
        } else {
            doc.push_str(&format!("_Изменения с тега {last_tag}._\n\n"));
        }
        if groups.is_empty() {
            doc.push_str("— значимых изменений (feat/fix/…) не найдено —\n");
        } else {
            for (sec, items) in &groups {
                doc.push_str(&format!("## {sec}\n"));
                for it in items {
                    doc.push_str(&format!("- {it}\n"));
                }
                doc.push('\n');
            }
        }

        let (path, action) =
            Generator::write_block(ctx, "docs/RELEASE-NOTES.md", "release-notes", doc.trim_end())?;
        out.artifacts.push(path.clone());
        out.metrics.push(("commits".into(), counted as f64));
        out.summary = format!("generate/release-notes: {path} ({action}), {counted} изменений");
        Ok(out)
    }
}

// ───────────────────────── setup/cicd ─────────────────────────

const WORKFLOW: &str = r#"# Сгенерировано ailc. Гейт качества/безопасности в CI.
# ailc должен быть доступен (соберите из исходников или установите бинарь).
name: ailc quality gate
on: [push, pull_request]
jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Definition of Done
        run: ailc dod .
      - name: SARIF → security tab
        run: ailc sarif . > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
"#;

pub struct CicdScaffold {
    manifest: CapabilityManifest,
}
impl Default for CicdScaffold {
    fn default() -> Self {
        Self::new()
    }
}
impl CicdScaffold {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "setup/cicd",
                family: Family::Setup,
                engine: EngineKind::Generator,
                when_to_use: "Сгенерировать GitHub Actions workflow, который гоняет ailc dod + sarif в CI — внедрить гейт в один шаг.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: true,
            },
        }
    }
}
impl Capability for CicdScaffold {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let rel = ".github/workflows/ailc.yml";
        let path = ctx.root.join(rel);
        if path.exists() {
            out.skipped = Some(format!("{rel} уже существует — не перезаписываю"));
            out.summary = format!("setup/cicd: {rel} на месте");
            return Ok(out);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, WORKFLOW)?;
        out.artifacts.push(rel.into());
        out.summary = format!("setup/cicd: создан {rel} (гоняет ailc dod + sarif)");
        Ok(out)
    }
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(ReleaseNotes::new()));
    reg.register(Box::new(CicdScaffold::new()));
}
