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
use ailc_core::changes::ChangeClass;

const TARGET_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;

/// Содержимое авто-блока документа (между метками `ailc:auto`), обрезанное. None — нет
/// файла или блока (документ ещё не сгенерирован). Прежнее написание меток `co:auto`
/// читается ради совместимости с документами, созданными до переименования продукта.
fn read_auto_block(ctx: &Ctx, rel: &str, key: &str) -> Option<String> {
    use ailc_core::engines::generator::{
        legacy_start_marker, start_marker, END_MARKER, LEGACY_END_MARKER,
    };
    let text = fs::read_to_string(ctx.root.join(rel)).ok()?;
    let (start, end) = match text.find(&start_marker(key)) {
        Some(_) => (start_marker(key), END_MARKER),
        None => (legacy_start_marker(key), LEGACY_END_MARKER),
    };
    let si = text.find(&start)?;
    let after = &text[si + start.len()..];
    let ei = after.find(end)?;
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

impl DriftCheck {
    /// Сверить документы, объявленные декларациями стандартов, со свежей сборкой.
    ///
    /// Возвращает число актуальных, устаревших и ещё не выпущенных документов. Сборка
    /// идемпотентна и не зависит ни от даты, ни от состояния истории изменений, поэтому
    /// расхождение означает именно изменение кода или ответов, а не течение времени.
    fn check_declared(
        &self,
        ctx: &Ctx,
        input: &RunInput,
        out: &mut CapabilityOutput,
    ) -> Result<(usize, usize, usize)> {
        use ailc_core::engines::docgen;

        let m = ailc_core::model::build(ctx, input)?;
        let answers = ailc_core::answers::Answers::load(ctx);
        let profile = ailc_core::profile::detect(&ctx.root);
        let changes = ailc_core::changes::all(ctx);
        let head = std::process::Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .current_dir(&ctx.root)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();

        let (mut fresh, mut stale, mut absent) = (0usize, 0usize, 0usize);
        for doc in ailc_core::standards::documents() {
            let on_disk = fs::read_to_string(ctx.root.join(doc.path)).ok();
            let r = docgen::render(
                doc,
                &m,
                &answers,
                &profile,
                on_disk.as_deref(),
                &head,
                &changes,
            );
            out.metrics.push((
                format!("полнота:{}", doc.id),
                f64::from(r.completeness.percent()),
            ));
            match on_disk {
                None => {
                    absent += 1;
                    out.records.push(format!("{}: не выпущен", doc.path));
                }
                Some(текст) if текст == r.text => {
                    fresh += 1;
                    out.records.push(format!("{}: актуален", doc.path));
                }
                Some(_) => {
                    stale += 1;
                    out.records.push(format!("{}: РАЗОШЁЛСЯ С КОДОМ", doc.path));
                    out.findings.push(Finding {
                        rule: "doc-drift".into(),
                        severity: Severity::High,
                        message: format!(
                            "Документ «{}» ({}) разошёлся с кодом и врёт о системе. Пересобери: `ailc cap generate/doc <путь> \"{}\"`",
                            doc.title, doc.path, doc.id
                        ),
                        location: Some(Location {
                            file: doc.path.to_string(),
                            line: 1,
                        }),
                        evidence: None,
                        verified: true,
                        source: "spec.check/drift".into(),
                    });
                }
            }
        }
        Ok((fresh, stale, absent))
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
                            severity: Severity::High,
                            message: format!(
                                "Документ «{}» разошёлся с кодом и врёт о нём. Пересобери: `ailc cap generate/doc <путь>`",
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

        // Документы, объявленные декларациями стандартов, сверяются иначе: они
        // принадлежат машине целиком, поэтому дрейф это расхождение файла со свежей
        // сборкой. Собранный документ сравнивается с тем, что лежит на диске, и
        // расхождение блокирует: устаревший документ по стандарту врёт о системе, а
        // именно на такой документ ссылаются при сдаче.
        let (декл_свежих, декл_устаревших, декл_нет) = self.check_declared(ctx, input, &mut out)?;
        in_sync += декл_свежих;
        stale += декл_устаревших;
        if декл_нет > 0 {
            out.records
                .push(format!("документов по стандартам не выпущено: {декл_нет}"));
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
        out.metrics
            .push(("docs_missing".into(), missing.len() as f64));
        out.summary = format!(
            "spec.check/drift: актуальны {in_sync}, устарели {stale}, отсутствуют {}",
            missing.len()
        );
        Ok(out)
    }
}

// ───────────────────────── spec.check/trace ─────────────────────────

/// `spec.check/trace` — прослеживаемость изменения: у текущей правки есть чертёж.
///
/// Детерминированно: git называет изменённые файлы, а спеки (`docs/specs/*`) и бэклог
/// (`.ailc/backlog/*`) должны упоминать хотя бы часть затронутых исходников. Изменение
/// исходников, которое не прослеживается ни к одной спеке или задаче, — сигнал
/// «код без чертежа» (мягкий: нудж к spec-first, не блокер; жёсткость решает политика).
/// Вне git-репозитория проверка честно пропускается.
pub struct TraceCheck {
    manifest: CapabilityManifest,
}

impl Default for TraceCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceCheck {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "spec.check/trace",
                family: Family::Spec,
                engine: EngineKind::CodeIntel,
                when_to_use: "Проверить, что текущее изменение (git) прослеживается к спеке или задаче бэклога.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

/// Изменённые файлы рабочего дерева по git (модифицированные и новые), либо None,
/// когда git недоступен или это не репозиторий.
fn changed_files(root: &std::path::Path) -> Option<Vec<String>> {
    let out = std::process::Command::new("git")
        .args(["status", "--porcelain=v1", "-uall"])
        .current_dir(root)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut files = Vec::new();
    for line in text.lines() {
        if line.len() < 4 {
            continue;
        }
        // Формат: XY <path> либо XY <old> -> <new> (переименование).
        let path = line[3..].split(" -> ").last().unwrap_or("").trim();
        if !path.is_empty() {
            files.push(path.trim_matches('"').to_string());
        }
    }
    Some(files)
}

/// Исходник ли это (по расширению) — конфиги и доки чертежа не требуют.
fn is_source(path: &str) -> bool {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "rs" | "py"
            | "js"
            | "ts"
            | "tsx"
            | "jsx"
            | "go"
            | "java"
            | "kt"
            | "rb"
            | "php"
            | "cs"
            | "swift"
            | "dart"
            | "scala"
            | "c"
            | "cpp"
            | "h"
            | "hpp"
            | "vue"
            | "svelte"
    )
}

/// Собрать текст всех спек и задач бэклога (ограниченно по числу файлов).
fn specs_text(ctx: &Ctx) -> String {
    let mut text = String::new();
    let mut push_dir = |dir: std::path::PathBuf| {
        if let Ok(rd) = fs::read_dir(dir) {
            for e in rd.flatten().take(200) {
                if e.path().extension().and_then(|x| x.to_str()) == Some("md") {
                    if let Ok(t) = fs::read_to_string(e.path()) {
                        text.push_str(&t);
                        text.push('\n');
                    }
                }
            }
        }
    };
    push_dir(ctx.root.join("docs/specs"));
    push_dir(ctx.root.join(".ailc/backlog"));
    text
}

impl Capability for TraceCheck {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let Some(files) = changed_files(&ctx.root) else {
            out.skipped = Some(
                "git недоступен или это не репозиторий — прослеживаемость не проверить".into(),
            );
            out.summary = "spec.check/trace: пропущено (нет git)".into();
            return Ok(out);
        };
        let sources: Vec<String> = files.into_iter().filter(|f| is_source(f)).collect();
        if sources.is_empty() {
            out.summary = "spec.check/trace: изменённых исходников нет".into();
            return Ok(out);
        }
        // Класс изменения выводится из самого различия, а не со слов агента: иначе любая
        // правка объявлялась бы косметической, и дисциплина держалась бы на
        // добросовестности того, кого она ограничивает.
        let class = match ailc_core::changes::diff(&ctx.root) {
            Some(d) => ailc_core::changes::classify(&d),
            None => ChangeClass::Defect,
        };

        // Косметическая правка поведения не меняет: достаточно записи в журнале
        // изменений, которую сервер делает сам. Требовать под неё техническое задание
        // значило бы убить дисциплину на второй день.
        if class == ChangeClass::Cosmetic {
            out.metrics.push(("change_needs_design".into(), 0.0));
            out.summary = format!(
                "spec.check/trace: изменение косметическое ({} исходников), достаточно записи в журнале",
                sources.len()
            );
            return Ok(out);
        }

        let specs = specs_text(ctx);
        // Файл прослеживается, если спека/бэклог упоминает его имя или путь.
        let uncovered: Vec<&String> = sources
            .iter()
            .filter(|f| {
                let name = std::path::Path::new(f.as_str())
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(f.as_str());
                !(specs.contains(f.as_str()) || specs.contains(name))
            })
            .collect();
        out.metrics.push(("change_needs_design".into(), 1.0));
        if uncovered.is_empty() {
            out.summary = format!(
                "spec.check/trace: изменение прослеживается ({}, исходников: {})",
                class.label(),
                sources.len()
            );
            return Ok(out);
        }

        // Соразмерность классу. Слом публичного контракта и новая функциональность без
        // чертежа блокируют сдачу; исправление дефекта остаётся предупреждением, поскольку
        // дефект чаще всего уже описан в задаче, а его срочность законна.
        let severity = match class {
            ChangeClass::ContractBreak | ChangeClass::Feature => Severity::High,
            _ => Severity::Medium,
        };
        let listed: Vec<String> = uncovered.iter().take(8).map(|s| s.to_string()).collect();
        out.findings.push(Finding {
            rule: "change-without-spec".into(),
            severity,
            message: format!(
                "{}: изменение не прослеживается к спеке, решению или задаче ({} из {} файлов): {}. Требуется {}",
                class.label(),
                uncovered.len(),
                sources.len(),
                listed.join(", "),
                class.requires()
            ),
            location: Some(Location {
                file: uncovered[0].to_string(),
                line: 1,
            }),
            evidence: None,
            verified: true,
            source: "spec.check/trace".into(),
        });
        out.summary = format!(
            "spec.check/trace: {} без чертежа ({} из {} изменённых исходников)",
            class.label(),
            uncovered.len(),
            sources.len()
        );
        Ok(out)
    }
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(DriftCheck::new()));
    reg.register(Box::new(TraceCheck::new()));
}

#[cfg(test)]
mod trace_tests {
    use super::*;

    /// Временный git-репозиторий с одним незакоммиченным исходником.
    fn git_repo(tag: &str) -> Option<std::path::PathBuf> {
        let root = std::env::temp_dir().join(format!(
            "ailc-trace-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let ok = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return None; // git недоступен — тесты честно пропускаются
        }
        fs::write(root.join("billing.py"), "def charge(): pass\n").unwrap();
        Some(root)
    }

    #[test]
    fn uncovered_change_is_flagged() {
        let Some(root) = git_repo("flag") else { return };
        let ctx = Ctx::new(root.to_str().unwrap());
        let out = TraceCheck::new().run(&ctx, &RunInput::default()).unwrap();
        assert_eq!(out.findings.len(), 1, "исходник без спеки должен ловиться");
        assert_eq!(out.findings[0].rule, "change-without-spec");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn spec_mention_covers_change() {
        let Some(root) = git_repo("covered") else {
            return;
        };
        fs::create_dir_all(root.join("docs/specs")).unwrap();
        fs::write(
            root.join("docs/specs/billing.md"),
            "# Спека оплаты\n\nЗатрагивает billing.py: функция charge.\n",
        )
        .unwrap();
        let ctx = Ctx::new(root.to_str().unwrap());
        let out = TraceCheck::new().run(&ctx, &RunInput::default()).unwrap();
        assert!(
            out.findings.is_empty(),
            "упомянутый в спеке файл прослеживается: {}",
            out.summary
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn outside_git_is_honest_skip() {
        let root = std::env::temp_dir().join(format!("ailc-trace-nogit-{}", std::process::id()));
        // Каталог вне git: создаём пустым и без init.
        fs::create_dir_all(&root).ok();
        let probe = std::process::Command::new("git")
            .args(["rev-parse", "--is-inside-work-tree"])
            .current_dir(&root)
            .output();
        // Если каталог внезапно внутри чьего-то репозитория (напр. /tmp под git), тест
        // не о том — пропускаем.
        if probe.map(|o| o.status.success()).unwrap_or(false) {
            return;
        }
        let ctx = Ctx::new(root.to_str().unwrap());
        let out = TraceCheck::new().run(&ctx, &RunInput::default()).unwrap();
        assert!(out.skipped.is_some(), "вне git — осознанный пропуск");
        fs::remove_dir_all(&root).ok();
    }
}
