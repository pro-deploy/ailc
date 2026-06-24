//! Capability поверх E8 MetricEngine — тонкие конфиги, без новой логики.
//!
//! Один движок (`MetricEngine::per_file`) питает обе проверки: одна кормит гейт
//! (Quality, findings по порогам), другая даёт информационный отчёт (CodeIntel,
//! топ файлов по сложности). Агрегаты считаются здесь, а не дублируются в движке.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Finding, Location, Result,
    RunInput, Severity, Tier,
};
use ailc_core::engines::metric::{FileMetric, MetricEngine};
use ailc_core::registry::Registry;
use ailc_core::Capability;

/// Единая JSON-схема входа для проверок «по проекту».
const TARGET_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;


/// Агрегаты по списку файловых метрик. Считаем один раз, переиспользуем в обоих
/// capability — без дублирования.
fn aggregates(files: &[FileMetric]) -> (f64, f64, f64) {
    let total_files = files.len() as f64;
    let total_lines: u64 = files.iter().map(|f| f.lines as u64).sum();
    let max_complexity = files.iter().map(|f| f.complexity).max().unwrap_or(0);
    (total_files, total_lines as f64, max_complexity as f64)
}

// ───────────────────────── quality.check/complexity ─────────────────────────

pub struct ComplexityCheck {
    manifest: CapabilityManifest,
}

impl Default for ComplexityCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl ComplexityCheck {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "quality.check/complexity",
                family: Family::Quality,
                engine: EngineKind::Metric,
                when_to_use: "Найти слишком длинные и слишком сложные файлы — кандидаты на разбиение перед изменением.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for ComplexityCheck {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        // Валидация подпути прогона до обхода: абсолютный target (например «/etc»)
        // и компоненты «..» не должны уводить сканирование за корень проекта.
        // Ctx::base отвергает такие цели единообразно со scan/codeintel/sast, поэтому
        // проверяем здесь до вызова движка (T42: устранение асимметрии валидации).
        let _base = ctx.base(input)?;
        let files = MetricEngine::per_file(ctx, input)?;
        let mut out = CapabilityOutput::default();
        // Пороги длины/сложности — из PolicyPack (governance как данные).
        let t = ailc_core::policy::load(&ctx.root).0.thresholds;

        // Нет файлов для подсчёта — честный пустой результат (не молчаливый пропуск).
        if files.is_empty() {
            out.metrics.push(("total_files".into(), 0.0));
            out.metrics.push(("total_lines".into(), 0.0));
            out.metrics.push(("max_complexity".into(), 0.0));
            out.summary = "quality.check/complexity: исходных файлов не найдено".into();
            return Ok(out);
        }

        for f in &files {
            if f.lines > t.max_lines {
                out.findings.push(Finding {
                    rule: "long-file".into(),
                    severity: Severity::Low,
                    message: format!("Слишком длинный файл: {} строк", f.lines),
                    location: Some(Location {
                        file: f.path.clone(),
                        line: 1,
                    }),
                    evidence: None,
                    verified: true,
                    source: "quality.check/complexity".into(),
                });
            }
            if f.complexity > t.max_complexity {
                out.findings.push(Finding {
                    rule: "high-complexity".into(),
                    severity: Severity::Medium,
                    message: format!("Слишком высокая сложность: {}", f.complexity),
                    location: Some(Location {
                        file: f.path.clone(),
                        line: 1,
                    }),
                    evidence: None,
                    verified: true,
                    source: "quality.check/complexity".into(),
                });
            }
        }

        let (total_files, total_lines, max_complexity) = aggregates(&files);
        out.metrics.push(("total_files".into(), total_files));
        out.metrics.push(("total_lines".into(), total_lines));
        out.metrics.push(("max_complexity".into(), max_complexity));
        out.summary = format!(
            "quality.check/complexity: {} файлов, {} нарушителей порога",
            files.len(),
            out.findings.len()
        );
        Ok(out)
    }
}

// ───────────────────────── code.intel/metrics ─────────────────────────

pub struct CodeMetrics {
    manifest: CapabilityManifest,
}

impl Default for CodeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeMetrics {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "code.intel/metrics",
                family: Family::CodeIntel,
                engine: EngineKind::Metric,
                when_to_use: "Числовая карта кода: размеры и сложность файлов, топ самых сложных — где сосредоточен риск.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for CodeMetrics {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        // Та же защита, что и в ComplexityCheck: подпуть прогона валидируется через
        // Ctx::base до обхода, чтобы абсолютный или родительский target не уводил
        // отчёт за корень проекта (T42).
        let _base = ctx.base(input)?;
        let mut files = MetricEngine::per_file(ctx, input)?;
        let mut out = CapabilityOutput::default();

        let (total_files, total_lines, max_complexity) = aggregates(&files);
        out.metrics.push(("total_files".into(), total_files));
        out.metrics.push(("total_lines".into(), total_lines));
        out.metrics.push(("max_complexity".into(), max_complexity));

        if files.is_empty() {
            out.summary = "code.intel/metrics: исходных файлов не найдено".into();
            return Ok(out);
        }

        // Топ-10 файлов по убыванию сложности (стабильно: при равенстве — по пути).
        files.sort_by(|a, b| {
            b.complexity
                .cmp(&a.complexity)
                .then_with(|| a.path.cmp(&b.path))
        });
        for f in files.iter().take(10) {
            out.records.push(format!(
                "{} — {} строк, сложность {}",
                f.path, f.lines, f.complexity
            ));
        }

        out.summary = format!(
            "code.intel/metrics: {} файлов, {} строк, макс. сложность {}",
            total_files as u64, total_lines as u64, max_complexity as u64
        );
        Ok(out)
    }
}

/// Регистрирует capability на движке E8 Metric.
pub fn register(reg: &mut Registry) {
    reg.register(Box::new(ComplexityCheck::new())); // Quality, кормит гейт
    reg.register(Box::new(CodeMetrics::new())); // CodeIntel, информационный отчёт
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Уникальная пустая временная папка для файловых фикстур.
    fn tmp() -> PathBuf {
        let n = CNT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ailc-metric-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Записывает файл по относительному пути внутри папки, создавая родителей.
    fn write(dir: &std::path::Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }

    // ───────────────────────── T42: валидация target через ctx.base ─────────────────────────

    #[test]
    fn complexity_target_абсолютный_путь_отвергается() {
        // Абсолютный target вида «/etc» при Path::join заменил бы всю базу и увёл бы
        // сканирование за корень проекта. Ctx::base обязан вернуть Err до обхода.
        let dir = tmp();
        let input = RunInput {
            target: Some("/etc".to_string()),
            ..Default::default()
        };
        let res = ComplexityCheck::new().run(&Ctx::new(&dir), &input);
        assert!(
            res.is_err(),
            "абсолютный target должен отвергаться через ctx.base"
        );
    }

    #[test]
    fn complexity_target_с_двумя_точками_отвергается() {
        // Компоненты «..» уводят вверх по дереву файлов мимо корня проекта.
        let dir = tmp();
        let input = RunInput {
            target: Some("../../etc".to_string()),
            ..Default::default()
        };
        let res = ComplexityCheck::new().run(&Ctx::new(&dir), &input);
        assert!(
            res.is_err(),
            "target с .. должен отвергаться через ctx.base"
        );
    }

    #[test]
    fn complexity_target_одна_точка_внутри_тоже_отвергается() {
        // Даже если родительский компонент стоит не в начале, проверка на ParentDir
        // в Ctx::base обязана его поймать (защита от обхода вида sub/../../etc).
        let dir = tmp();
        let input = RunInput {
            target: Some("sub/../../etc".to_string()),
            ..Default::default()
        };
        let res = ComplexityCheck::new().run(&Ctx::new(&dir), &input);
        assert!(
            res.is_err(),
            "вложенный .. должен отвергаться через ctx.base"
        );
    }

    #[test]
    fn codemetrics_target_абсолютный_путь_отвергается() {
        let dir = tmp();
        let input = RunInput {
            target: Some("/etc".to_string()),
            ..Default::default()
        };
        let res = CodeMetrics::new().run(&Ctx::new(&dir), &input);
        assert!(
            res.is_err(),
            "абсолютный target должен отвергаться через ctx.base"
        );
    }

    #[test]
    fn codemetrics_target_с_двумя_точками_отвергается() {
        let dir = tmp();
        let input = RunInput {
            target: Some("..".to_string()),
            ..Default::default()
        };
        let res = CodeMetrics::new().run(&Ctx::new(&dir), &input);
        assert!(
            res.is_err(),
            "target «..» должен отвергаться через ctx.base"
        );
    }

    // ───────────────────────── Позитив: легитимные цели проходят ─────────────────────────

    #[test]
    fn complexity_без_target_сканирует_корень() {
        // Отсутствие target означает весь проект и должно проходить валидацию.
        let dir = tmp();
        write(&dir, "src/main.rs", "fn main() {\n    if true {}\n}\n");
        let input = RunInput::default();
        let res = ComplexityCheck::new().run(&Ctx::new(&dir), &input);
        assert!(res.is_ok(), "пустой target (весь проект) должен проходить");
        let out = res.unwrap();
        // Файл найден и посчитан: метрика total_files больше нуля.
        let total = out
            .metrics
            .iter()
            .find(|(k, _)| k.as_str() == "total_files")
            .map(|(_, v)| *v)
            .unwrap_or(0.0);
        assert!(total >= 1.0, "должен быть посчитан хотя бы один файл");
    }

    #[test]
    fn complexity_относительный_подпуть_проходит() {
        // Легитимный относительный подпуть без «..» и без ведущего слэша допустим.
        let dir = tmp();
        write(&dir, "src/lib.rs", "pub fn f() {}\n");
        let input = RunInput {
            target: Some("src".to_string()),
            ..Default::default()
        };
        let res = ComplexityCheck::new().run(&Ctx::new(&dir), &input);
        assert!(res.is_ok(), "относительный подпуть src должен проходить");
    }

    #[test]
    fn codemetrics_относительный_подпуть_проходит() {
        let dir = tmp();
        write(&dir, "src/lib.rs", "pub fn f() {\n    for _ in 0..3 {}\n}\n");
        let input = RunInput {
            target: Some("src".to_string()),
            ..Default::default()
        };
        let res = CodeMetrics::new().run(&Ctx::new(&dir), &input);
        assert!(res.is_ok(), "относительный подпуть src должен проходить");
    }
}
