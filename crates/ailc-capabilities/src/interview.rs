//! Механика опроса: `spec/questions` выдаёт очередь вопросов, `spec/answer` принимает
//! ответ.
//!
//! Заполнять документы руками не требуется. Сервер детерминированно знает по декларациям
//! стандартов, какие обязательные разделы не закрыты, какой вопрос по каждому задать и
//! какой черновик выведен из кода. Агент задаёт вопрос человеку обычным языком и
//! возвращает ответ обратно. Разделение ответственности неизменно: модель отвечает за
//! формулировку и за перевод реплики в значение поля, а решение о том, что раздел закрыт
//! и что документ полон, принимает проверка.
//!
//! Опрос идёт порциями и по большей части на подтверждение, а не с чистого листа: там,
//! где модель проекта даёт черновик, он прикладывается к вопросу. Уже полученные ответы
//! повторно не запрашиваются.
//!
//! Механика намеренно не обращается к модели агента сама. Это переиспользует инверсию
//! адаптивной петли, введённую для `plan`: сервер возвращает вопросы как инструкцию, и
//! работает одинаково у клиентов с обратным вызовом модели и без него.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Tier,
};
use ailc_core::answers::{Answer, AnswerSource, Answers};
use ailc_core::model;
use ailc_core::registry::Registry;
use ailc_core::standards::{self, Section, Source};
use ailc_core::Capability;

/// Сколько вопросов отдавать за один раз. Анкета на сто пунктов не будет заполнена
/// никогда, а короткая порция закрывается в диалоге за одну реплику.
const BATCH: usize = 8;

const QUESTIONS_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"},"query":{"type":"string","description":"идентификатор документа; пусто = все документы комплекта"}}}"#;
const ANSWER_SCHEMA: &str = r#"{"type":"object","properties":{"query":{"type":"string","description":"JSON вида {\"id\":\"тз.назначение\",\"value\":\"...\",\"source\":\"human|confirmed|derived\"} либо строка «идентификатор=значение»"},"target":{"type":"string"}},"required":["query"]}"#;

// ───────────────────────────── spec/questions ─────────────────────────────

pub struct Questions {
    manifest: CapabilityManifest,
}

impl Default for Questions {
    fn default() -> Self {
        Self::new()
    }
}

impl Questions {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "spec/questions",
                family: Family::Spec,
                engine: EngineKind::Generator,
                when_to_use: "Узнать, каких сведений не хватает документам по стандартам, и получить очередь вопросов человеку с черновиками из кода. Задай эти вопросы пользователю, ответы верни через spec/answer.",
                input_schema: QUESTIONS_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for Questions {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let m = model::build(ctx, input)?;
        let profile = ailc_core::profile::detect(&ctx.root);
        let registry = Answers::load(ctx);

        // Ограничение по документу, если он назван в запросе.
        let wanted = input
            .query
            .as_deref()
            .map(str::trim)
            .filter(|q| !q.is_empty());
        let docs: Vec<&'static standards::Document> = match wanted {
            Some(id) => match standards::document(id) {
                Some(d) => vec![d],
                None => {
                    out.skipped = Some(format!("документ «{id}» не объявлен"));
                    out.summary = format!("spec/questions: пропущено (неизвестный документ {id})");
                    return Ok(out);
                }
            },
            None => standards::documents(),
        };

        let mut asked = 0usize;
        let mut total_required = 0usize;
        let mut total_filled = 0usize;

        for doc in &docs {
            let c = standards::completeness(doc, &m, &profile, &|id| registry.is_filled(id));
            total_required += c.required;
            total_filled += c.filled;
            out.metrics
                .push((format!("полнота:{}", doc.id), f64::from(c.percent())));

            for s in doc.sections {
                if asked >= BATCH {
                    break;
                }
                if !needs_answer(s, &m, &profile, &registry) {
                    continue;
                }
                let Some(question) = s.question else { continue };
                let mut rec = format!(
                    "ВОПРОС [{}] раздел {} «{}» документа «{}»: {}",
                    s.id, s.number, s.title, doc.title, question
                );
                if let Some(draft) = standards::draft_text(s.draft, &m) {
                    // Черновик обращает вопрос в подтверждение: человеку остаётся
                    // согласиться или поправить, а не сочинять раздел заново.
                    rec.push_str(&format!(
                        "\nЧЕРНОВИК ИЗ КОДА (предложи подтвердить или поправить):\n{draft}"
                    ));
                }
                out.records.push(rec);
                asked += 1;
            }
        }

        if asked == 0 {
            out.summary = format!(
                "spec/questions: обязательные разделы закрыты ({total_filled} из {total_required})"
            );
            return Ok(out);
        }

        out.records.push(format!(
            "КАК ОТВЕЧАТЬ: задай эти вопросы пользователю обычным языком, затем на каждый ответ вызови spec/answer с query вида {{\"id\":\"<идентификатор>\",\"value\":\"<ответ>\",\"source\":\"human\"}}. Если пользователь подтвердил черновик, укажи source \"confirmed\"."
        ));
        out.summary = format!(
            "spec/questions: закрыто {total_filled} из {total_required} обязательных разделов, задать вопросов сейчас: {asked}"
        );
        Ok(out)
    }
}

/// Требует ли раздел ответа: обязателен для этого проекта, наполняется человеком и
/// ответа на него ещё нет.
fn needs_answer(
    s: &Section,
    m: &model::ProjectModel,
    p: &ailc_core::profile::ProjectProfile,
    registry: &Answers,
) -> bool {
    if !matches!(s.source, Source::FromInterview | Source::Mixed) {
        return false;
    }
    if !standards::is_required(s, m, p) {
        return false;
    }
    !registry.is_filled(s.id)
}

// ───────────────────────────── spec/answer ─────────────────────────────

pub struct AcceptAnswer {
    manifest: CapabilityManifest,
}

impl Default for AcceptAnswer {
    fn default() -> Self {
        Self::new()
    }
}

impl AcceptAnswer {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "spec/answer",
                family: Family::Spec,
                engine: EngineKind::Store,
                when_to_use: "Записать ответ пользователя на вопрос по разделу стандарта в реестр требований. Идентификатор раздела берётся из вопроса, выданного spec/questions.",
                input_schema: ANSWER_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: true,
            },
        }
    }
}

/// Разобранный ответ агента.
struct Parsed {
    id: String,
    value: String,
    source: AnswerSource,
}

/// Разобрать запрос агента. Принимается объект JSON, а при его отсутствии простая
/// форма «идентификатор=значение»: у клиентов бывает и то, и другое.
fn parse(query: &str) -> std::result::Result<Parsed, String> {
    let q = query.trim();
    if q.starts_with('{') {
        let v: serde_json::Value =
            serde_json::from_str(q).map_err(|e| format!("запрос не разбирается как JSON: {e}"))?;
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .ok_or("в запросе нет поля id")?
            .trim()
            .to_string();
        let value = v
            .get("value")
            .and_then(|x| x.as_str())
            .ok_or("в запросе нет поля value")?
            .trim()
            .to_string();
        let source = match v.get("source").and_then(|x| x.as_str()).unwrap_or("human") {
            "confirmed" => AnswerSource::Confirmed,
            "derived" => AnswerSource::Derived,
            _ => AnswerSource::Human,
        };
        return Ok(Parsed { id, value, source });
    }
    let (id, value) = q
        .split_once('=')
        .ok_or("ожидается объект JSON либо строка вида «идентификатор=значение»")?;
    Ok(Parsed {
        id: id.trim().to_string(),
        value: value.trim().to_string(),
        source: AnswerSource::Human,
    })
}

/// Найти объявленный раздел по идентификатору ответа.
fn find_section(id: &str) -> Option<(&'static standards::Document, &'static Section)> {
    for d in standards::documents() {
        for s in d.sections {
            if s.id == id {
                return Some((d, s));
            }
        }
    }
    None
}

impl Capability for AcceptAnswer {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let Some(query) = input.query.as_deref().filter(|q| !q.trim().is_empty()) else {
            out.skipped = Some("нужен ответ в query".into());
            out.summary = "spec/answer: пропущено (пустой запрос)".into();
            return Ok(out);
        };

        let parsed = match parse(query) {
            Ok(p) => p,
            Err(e) => {
                out.skipped = Some(e.clone());
                out.summary = format!("spec/answer: пропущено ({e})");
                return Ok(out);
            }
        };

        // Идентификатор обязан принадлежать объявленному разделу: иначе ответ осел бы в
        // реестре мёртвым грузом и ни один документ его бы не подхватил.
        let Some((doc, section)) = find_section(&parsed.id) else {
            out.skipped = Some(format!(
                "раздел «{}» не объявлен ни в одном документе",
                parsed.id
            ));
            out.summary = format!("spec/answer: пропущено (неизвестный раздел {})", parsed.id);
            return Ok(out);
        };

        if parsed.value.trim().is_empty() {
            out.skipped = Some("пустой ответ раздела не закрывает".into());
            out.summary = "spec/answer: пропущено (пустой ответ)".into();
            return Ok(out);
        }

        let mut registry = Answers::load(ctx);
        registry.set(
            &parsed.id,
            Answer {
                value: parsed.value.clone(),
                source: parsed.source,
                date: ailc_core::answers::today(),
                commit: current_commit(ctx),
                question: section.question.unwrap_or(section.title).to_string(),
            },
        );
        let rel = registry.save(ctx)?;

        out.artifacts.push(rel);
        out.records.push(format!(
            "раздел {} «{}» документа «{}» закрыт ({})",
            section.number,
            section.title,
            doc.title,
            parsed.source.label()
        ));
        out.summary = format!(
            "spec/answer: записан ответ на раздел {} «{}»",
            section.number, section.title
        );
        Ok(out)
    }
}

/// Состояние истории изменений на момент ответа. Нужно, чтобы позже отличить ответ,
/// данный по действующему коду, от ответа, данного до значительных правок.
fn current_commit(ctx: &Ctx) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(&ctx.root)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(Questions::new()));
    reg.register(Box::new(AcceptAnswer::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> Ctx {
        let root = std::env::temp_dir().join(format!(
            "ailc-interview-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn работа() {}\n").unwrap();
        Ctx::new(root.to_str().unwrap())
    }

    /// Очередь вопросов не пуста на проекте без ответов и выдаётся порциями, а не
    /// анкетой на сотню пунктов, которую никто не заполнит.
    #[test]
    fn очередь_вопросов_выдаётся_порциями() {
        let ctx = tmp("очередь");
        let out = Questions::new().run(&ctx, &RunInput::default()).unwrap();
        let вопросы = out
            .records
            .iter()
            .filter(|r| r.starts_with("ВОПРОС"))
            .count();
        assert!(вопросы > 0, "на проекте без ответов вопросы обязаны быть");
        assert!(
            вопросы <= BATCH,
            "очередь обязана выдаваться порциями, а не целиком: {вопросы}"
        );
        assert!(
            out.metrics.iter().any(|(k, _)| k.starts_with("полнота:")),
            "полнота по стандарту обязана быть измерена"
        );
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Записанный ответ закрывает раздел и больше не запрашивается: интервью не должно
    /// спрашивать одно и то же дважды.
    #[test]
    fn отвеченный_раздел_повторно_не_спрашивается() {
        let ctx = tmp("повтор");
        let первый = Questions::new().run(&ctx, &RunInput::default()).unwrap();
        let id = первый
            .records
            .iter()
            .find(|r| r.starts_with("ВОПРОС ["))
            .and_then(|r| r.split(['[', ']']).nth(1))
            .expect("в очереди есть хотя бы один вопрос")
            .to_string();

        let ответ = AcceptAnswer::new()
            .run(
                &ctx,
                &RunInput {
                    query: Some(format!(
                        "{{\"id\":\"{id}\",\"value\":\"Разработка ведётся инициативно.\",\"source\":\"human\"}}"
                    )),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(
            ответ.skipped.is_none(),
            "ответ обязан приниматься: {:?}",
            ответ.skipped
        );

        let второй = Questions::new().run(&ctx, &RunInput::default()).unwrap();
        assert!(
            !второй
                .records
                .iter()
                .any(|r| r.contains(&format!("[{id}]"))),
            "закрытый раздел не должен спрашиваться повторно"
        );
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Ответ на необъявленный раздел отвергается: иначе он осел бы в реестре мёртвым
    /// грузом, а человек считал бы, что раздел закрыт.
    #[test]
    fn ответ_на_необъявленный_раздел_отвергается() {
        let ctx = tmp("чужой");
        let out = AcceptAnswer::new()
            .run(
                &ctx,
                &RunInput {
                    query: Some("{\"id\":\"такого.нет\",\"value\":\"что-то\"}".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(
            out.skipped.is_some(),
            "неизвестный раздел обязан отвергаться"
        );
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Простая форма ответа принимается наравне с объектом: у клиентов бывает и то, и другое.
    #[test]
    fn простая_форма_ответа_принимается() {
        let p = parse("тз.назначение=Учёт заявок").expect("простая форма разбирается");
        assert_eq!(p.id, "тз.назначение");
        assert_eq!(p.value, "Учёт заявок");
        assert_eq!(p.source, AnswerSource::Human);
    }
}
