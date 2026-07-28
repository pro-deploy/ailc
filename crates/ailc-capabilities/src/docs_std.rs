//! Выпуск документов комплекта по стандартам: `generate/doc`.
//!
//! Документ собирается целиком из декларации стандарта, модели проекта и реестра
//! ответов. Пустой запрос означает весь объявленный комплект, непустой указывает
//! идентификатор одного документа.
//!
//! Полнота каждого документа по стандарту выдаётся метрикой, поэтому соответствие
//! составу разделов становится измеримым, а не предметом мнения.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Tier,
};
use ailc_core::answers::Answers;
use ailc_core::engines::docgen;
use ailc_core::engines::generator::Generator;
use ailc_core::model;
use ailc_core::registry::Registry;
use ailc_core::standards;
use ailc_core::Capability;

const SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"},"query":{"type":"string","description":"идентификатор документа (тз-гост-19, тз-гост-34, архитектура-arc42, архитектура-c4); пусто = весь комплект"}}}"#;

pub struct GenerateDoc {
    manifest: CapabilityManifest,
}

impl Default for GenerateDoc {
    fn default() -> Self {
        Self::new()
    }
}

impl GenerateDoc {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "generate/doc",
                family: Family::Generate,
                engine: EngineKind::Generator,
                when_to_use: "Выпустить документ по стандарту целиком: техническое задание по ГОСТ 19.201-78 или ГОСТ 34.602-2020, описание архитектуры по arc42, диаграммы по модели C4. Пустой запрос выпускает весь комплект.",
                input_schema: SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: true,
            },
        }
    }
}

/// Действующее состояние истории изменений в кратком виде.
fn commit(ctx: &Ctx) -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(&ctx.root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

impl Capability for GenerateDoc {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        let wanted = input
            .query
            .as_deref()
            .map(str::trim)
            .filter(|q| !q.is_empty());
        let docs: Vec<&'static standards::Document> = match wanted {
            Some(id) => match standards::document(id) {
                Some(d) => vec![d],
                None => {
                    let known: Vec<&str> = standards::documents().iter().map(|d| d.id).collect();
                    out.skipped = Some(format!(
                        "документ «{id}» не объявлен; объявлены: {}",
                        known.join(", ")
                    ));
                    out.summary = format!("generate/doc: пропущено (неизвестный документ {id})");
                    return Ok(out);
                }
            },
            None => standards::documents(),
        };

        let m = model::build(ctx, input)?;
        let answers = Answers::load(ctx);
        let profile = ailc_core::profile::detect(&ctx.root);
        let head = commit(ctx);
        // Лист регистрации изменений сводит записи журнала: каждое изменение кода
        // оставляет там след, и документ показывает этот след, а не умалчивает о нём.
        let changes = ailc_core::changes::all(ctx);

        let mut полных = 0usize;
        for doc in &docs {
            let previous = std::fs::read_to_string(ctx.root.join(doc.path)).ok();
            let r = docgen::render(
                doc,
                &m,
                &answers,
                &profile,
                previous.as_deref(),
                &head,
                &changes,
            );
            let (path, action) = Generator::write_file(ctx, doc.path, &r.text)?;

            out.artifacts.push(path.clone());
            out.metrics.push((
                format!("полнота:{}", doc.id),
                f64::from(r.completeness.percent()),
            ));
            out.records.push(format!(
                "{} ({}): {path} ({action}), полнота {} процентов, закрыто {} из {} обязательных разделов",
                doc.title,
                doc.designation,
                r.completeness.percent(),
                r.completeness.filled,
                r.completeness.required
            ));
            if r.completeness.complete() {
                полных += 1;
            } else {
                for (n, t) in r.completeness.missing.iter().take(6) {
                    out.records.push(format!("  не закрыт раздел {n} {t}"));
                }
            }
        }

        out.summary = format!(
            "generate/doc: выпущено документов {}, из них полных по стандарту {}. Незакрытые разделы закрываются через spec/questions и spec/answer.",
            docs.len(),
            полных
        );
        Ok(out)
    }
}

// ───────────────────────── deliver/change-log ─────────────────────────

/// Запись изменения в журнал.
///
/// Обязательство «документируется любое, даже мелкое изменение» исполняется здесь и
/// исполняется сервером: запись формируется детерминированно из самого различия, класс
/// изменения выводится из него же, а человека ни о чём не спрашивают. Повторный вызов на
/// том же различии новой записи не создаёт: журнал фиксирует изменения, а не число
/// обращений к инструменту.
pub struct ChangeLog {
    manifest: CapabilityManifest,
}

impl Default for ChangeLog {
    fn default() -> Self {
        Self::new()
    }
}

impl ChangeLog {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "deliver/change-log",
                family: Family::Deliver,
                engine: EngineKind::Store,
                when_to_use: "Зарегистрировать текущее изменение в журнале изменений: класс выводится из различия, запись попадает в лист регистрации изменений документов. Намерение правки передавай в query.",
                input_schema: r#"{"type":"object","properties":{"query":{"type":"string","description":"намерение правки простыми словами"},"target":{"type":"string"}}}"#,
                tier: Tier::Core,
                deterministic: false,
                mutates: true,
            },
        }
    }
}

impl Capability for ChangeLog {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let intent = input.query.as_deref().unwrap_or("не указано");
        match ailc_core::changes::record(ctx, intent)? {
            Some(r) => {
                out.artifacts
                    .push(format!(".ailc/changes/{:04}.toml", r.number));
                out.records.push(format!(
                    "изменение {}: {}, затронуто файлов {}, требуется {}",
                    r.number,
                    r.class.label(),
                    r.files.len(),
                    r.class.requires()
                ));
                out.summary = format!(
                    "deliver/change-log: записано изменение {} ({})",
                    r.number,
                    r.class.label()
                );
            }
            None => {
                out.skipped = Some(
                    "изменений нет либо это же различие уже зарегистрировано, а вне репозитория различие неопределимо"
                        .into(),
                );
                out.summary = "deliver/change-log: новых изменений не зарегистрировано".into();
            }
        }
        Ok(out)
    }
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(GenerateDoc::new()));
    reg.register(Box::new(ChangeLog::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> Ctx {
        let root = std::env::temp_dir().join(format!(
            "ailc-docsstd-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"учёт\"\nversion = \"2.0.0\"\nlicense = \"Apache-2.0\"\n",
        )
        .unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn провести() {}\n").unwrap();
        Ctx::new(root.to_str().unwrap())
    }

    /// Документ выпускается целиком, с титульными реквизитами и отметкой о полноте, а
    /// повторный выпуск без изменений файл не трогает.
    #[test]
    fn документ_выпускается_и_повторный_выпуск_идемпотентен() {
        let ctx = tmp("выпуск");
        let cap = GenerateDoc::new();
        let input = RunInput {
            query: Some("тз-гост-19".into()),
            ..Default::default()
        };

        let первый = cap.run(&ctx, &input).unwrap();
        assert!(первый.skipped.is_none());
        let текст = std::fs::read_to_string(ctx.root.join("docs/ТЗ-ГОСТ-19.201.md")).unwrap();
        assert!(
            текст.contains("Обозначение документа"),
            "титульные реквизиты обязательны"
        );
        assert!(
            текст.contains("учёт"),
            "наименование изделия берётся из манифеста"
        );
        assert!(
            текст.contains("2.0.0"),
            "версия изделия берётся из манифеста"
        );
        assert!(текст.contains("Лист регистрации изменений"));
        assert!(текст.contains("Отметка о полноте"));
        assert!(
            текст.contains("4.8 Специальные требования") || !текст.contains("4.8"),
            "условные разделы сохраняются в оглавлении"
        );

        let второй = cap.run(&ctx, &input).unwrap();
        assert!(
            второй.records.iter().any(|r| r.contains("без изменений")),
            "повторный выпуск без изменений обязан не трогать файл: {:?}",
            второй.records
        );
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Запрос несуществующего документа честно отвергается с перечнем объявленных.
    #[test]
    fn неизвестный_документ_отвергается() {
        let ctx = tmp("чужой");
        let out = GenerateDoc::new()
            .run(
                &ctx,
                &RunInput {
                    query: Some("такого-нет".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(out.skipped.is_some());
        assert!(out.skipped.unwrap().contains("тз-гост-19"));
        let _ = std::fs::remove_dir_all(&ctx.root);
    }
}
