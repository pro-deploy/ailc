//! Журнал работ как инструменты: `task/plan`, `task/update`, `task/list`.
//!
//! Закрывает вопрос человека, вернувшегося к проекту после обрыва: что из задуманного
//! сделано, что брошено на середине, что отложено и почему, а от чего решено отказаться.
//! Список задач агента живёт в его сеансе и исчезает вместе с ним, поэтому состояние
//! работ переносится в проект, где переживает и перезапуск среды разработки, и потерю
//! связи, и отключение электричества.
//!
//! Раздел «Состояние работ» в активном контексте перестраивается сервером при КАЖДОМ
//! вызове любого инструмента, а не только этих трёх: память проекта не должна зависеть
//! от того, вспомнил ли о ней агент.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Tier,
};
use ailc_core::registry::Registry;
use ailc_core::tasks::{self, TaskStatus};
use ailc_core::Capability;

const PLAN_SCHEMA: &str = r#"{"type":"object","properties":{"query":{"type":"string","description":"план работ: по одной задаче на строку; первая строка может быть намерением, если начинается со слова «намерение:»"},"target":{"type":"string"}},"required":["query"]}"#;
const UPDATE_SCHEMA: &str = r#"{"type":"object","properties":{"query":{"type":"string","description":"JSON вида {\"number\":3,\"status\":\"done|in-progress|deferred|rejected|planned\",\"reason\":\"...\"} либо строка «3 = в работе» или «3 = отложено: ждём ответа заказчика»"},"target":{"type":"string"}},"required":["query"]}"#;
const LIST_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;

fn manifest(
    id: &'static str,
    engine: EngineKind,
    when: &'static str,
    schema: &'static str,
    mutates: bool,
) -> CapabilityManifest {
    CapabilityManifest {
        id,
        family: Family::Backlog,
        engine,
        when_to_use: when,
        input_schema: schema,
        tier: Tier::Core,
        deterministic: true,
        mutates,
    }
}

// ───────────────────────────── task/plan ─────────────────────────────

pub struct TaskPlan {
    manifest: CapabilityManifest,
}

impl Default for TaskPlan {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskPlan {
    pub fn new() -> Self {
        Self {
            manifest: manifest(
                "task/plan",
                EngineKind::Store,
                "Записать план работ в журнал проекта: по одной задаче на строку. Вызывай СРАЗУ после того, как составил план, до того как приступил к работе: иначе при обрыве сеанса план потеряется вместе с ним.",
                PLAN_SCHEMA,
                true,
            ),
        }
    }
}

impl Capability for TaskPlan {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let Some(text) = input.query.as_deref().filter(|q| !q.trim().is_empty()) else {
            out.skipped = Some("нужен план работ в query: по одной задаче на строку".into());
            out.summary = "task/plan: пропущено (пустой план)".into();
            return Ok(out);
        };

        // Первая строка вида «намерение: …» задаёт общее намерение всех задач порции.
        // Без него задача через месяц читается как «непонятно зачем это делали».
        let mut intent = String::new();
        let mut lines: Vec<&str> = Vec::new();
        for line in text.lines() {
            let t = line.trim().trim_start_matches(['-', '*', '•']).trim();
            if t.is_empty() {
                continue;
            }
            if let Some(rest) = t.strip_prefix("намерение:") {
                intent = rest.trim().to_string();
                continue;
            }
            lines.push(t);
        }

        let mut создано = 0usize;
        let mut повторов = 0usize;
        for title in lines {
            match tasks::add(ctx, title, &intent)? {
                Some(t) => {
                    создано += 1;
                    out.records
                        .push(format!("[{}] {} ({})", t.number, t.title, t.status.label()));
                }
                None => повторов += 1,
            }
        }

        let all = tasks::all(ctx);
        let s = tasks::summary(&all);
        out.artifacts.push(".ailc/tasks/".into());
        out.metrics.push(("tasks_total".into(), s.total() as f64));
        out.metrics.push(("tasks_done".into(), s.done as f64));
        if повторов > 0 {
            out.records.push(format!(
                "уже были в журнале и повторно не заводились: {повторов}"
            ));
        }
        out.summary = format!(
            "task/plan: заведено задач {создано}, всего в журнале {} (сделано {}, в работе {}, отложено {}, решено не делать {})",
            s.total(),
            s.done,
            s.in_progress,
            s.deferred,
            s.rejected
        );
        Ok(out)
    }
}

// ───────────────────────────── task/update ─────────────────────────────

pub struct TaskUpdate {
    manifest: CapabilityManifest,
}

impl Default for TaskUpdate {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskUpdate {
    pub fn new() -> Self {
        Self {
            manifest: manifest(
                "task/update",
                EngineKind::Store,
                "Отметить состояние задачи журнала работ: взял в работу, сделал, отложил, решил не делать. Отсрочка и отказ принимаются только с причиной. Вызывай в момент смены состояния, а не в конце сеанса.",
                UPDATE_SCHEMA,
                true,
            ),
        }
    }
}

/// Разобрать запрос: объект JSON либо простая форма «3 = отложено: причина».
fn parse(query: &str) -> std::result::Result<(u32, TaskStatus, Option<String>), String> {
    let q = query.trim();
    if q.starts_with('{') {
        let v: serde_json::Value =
            serde_json::from_str(q).map_err(|e| format!("запрос не разбирается как JSON: {e}"))?;
        let number = v
            .get("number")
            .and_then(serde_json::Value::as_u64)
            .ok_or("в запросе нет поля number")? as u32;
        let status = v
            .get("status")
            .and_then(|x| x.as_str())
            .and_then(TaskStatus::parse)
            .ok_or("в запросе нет распознаваемого поля status")?;
        let reason = v.get("reason").and_then(|x| x.as_str()).map(str::to_string);
        return Ok((number, status, reason));
    }
    let (num, rest) = q
        .split_once('=')
        .ok_or("ожидается объект JSON либо строка вида «3 = отложено: причина»")?;
    let number: u32 = num
        .trim()
        .parse()
        .map_err(|_| format!("«{}» не похоже на номер задачи", num.trim()))?;
    let (statustext, reason) = match rest.split_once(':') {
        Some((s, r)) => (s, Some(r.trim().to_string())),
        None => (rest, None),
    };
    let status = TaskStatus::parse(statustext)
        .ok_or_else(|| format!("состояние «{}» не распознано", statustext.trim()))?;
    Ok((number, status, reason))
}

impl Capability for TaskUpdate {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let Some(query) = input.query.as_deref().filter(|q| !q.trim().is_empty()) else {
            out.skipped = Some("нужен запрос в query".into());
            out.summary = "task/update: пропущено (пустой запрос)".into();
            return Ok(out);
        };

        let (number, status, reason) = match parse(query) {
            Ok(v) => v,
            Err(e) => {
                out.skipped = Some(e.clone());
                out.summary = format!("task/update: пропущено ({e})");
                return Ok(out);
            }
        };

        match tasks::update(ctx, number, status, reason.as_deref())? {
            Ok(t) => {
                out.artifacts
                    .push(format!(".ailc/tasks/{:04}.toml", t.number));
                out.records.push(format!(
                    "[{}] {}: {}{}",
                    t.number,
                    t.title,
                    t.status.label(),
                    t.reason
                        .as_deref()
                        .map(|r| format!(". Причина: {r}"))
                        .unwrap_or_default()
                ));
                out.summary = format!(
                    "task/update: задача {} переведена в состояние «{}»",
                    t.number,
                    t.status.label()
                );
            }
            Err(причина) => {
                out.skipped = Some(причина.clone());
                out.summary = format!("task/update: пропущено ({причина})");
            }
        }
        Ok(out)
    }
}

// ───────────────────────────── task/list ─────────────────────────────

pub struct TaskList {
    manifest: CapabilityManifest,
}

impl Default for TaskList {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskList {
    pub fn new() -> Self {
        Self {
            manifest: manifest(
                "task/list",
                EngineKind::Store,
                "Показать состояние работ по проекту: что сделано, что в работе, что в очереди, что отложено и что решено не делать, с причинами. Вызывай в начале сеанса, чтобы восстановить контекст после перерыва.",
                LIST_SCHEMA,
                false,
            ),
        }
    }
}

impl Capability for TaskList {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let all = tasks::all(ctx);

        // Пустой журнал это осознанное сообщение, а не молчание: человек должен понять,
        // что работ не заводили, а не решить, что инструмент не сработал.
        if all.is_empty() {
            out.skipped = Some("журнал работ пуст: задачи заводятся вызовом task/plan".into());
            out.summary = "task/list: журнал работ пуст".into();
            return Ok(out);
        }

        for t in &all {
            let mut rec = format!("[{}] {} · {}", t.number, t.title, t.status.label());
            if let Some(r) = &t.reason {
                rec.push_str(&format!(" · причина: {r}"));
            }
            if !t.intent.is_empty() {
                rec.push_str(&format!(" · намерение: {}", t.intent));
            }
            if !t.links.is_empty() {
                rec.push_str(&format!(" · см.: {}", t.links.join(", ")));
            }
            out.records.push(rec);
        }

        let s = tasks::summary(&all);
        out.metrics.push(("tasks_total".into(), s.total() as f64));
        out.metrics.push(("tasks_done".into(), s.done as f64));
        out.metrics
            .push(("tasks_in_progress".into(), s.in_progress as f64));
        out.metrics
            .push(("tasks_deferred".into(), s.deferred as f64));
        out.summary = format!(
            "task/list: всего {} (сделано {}, в работе {}, в очереди {}, отложено {}, решено не делать {})",
            s.total(),
            s.done,
            s.in_progress,
            s.planned,
            s.deferred,
            s.rejected
        );
        Ok(out)
    }
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(TaskPlan::new()));
    reg.register(Box::new(TaskUpdate::new()));
    reg.register(Box::new(TaskList::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> Ctx {
        let root = std::env::temp_dir().join(format!(
            "ailc-captasks-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join(".ailc")).unwrap();
        Ctx::new(root.to_str().unwrap())
    }

    fn q(s: &str) -> RunInput {
        RunInput {
            query: Some(s.to_string()),
            ..Default::default()
        }
    }

    /// Полный оборот: план записан, состояние менялось, и после «потери сеанса» всё
    /// восстанавливается чтением журнала, а не памятью агента.
    #[test]
    fn план_и_состояние_восстанавливаются_после_обрыва() {
        let ctx = tmp("оборот");
        let out = TaskPlan::new()
            .run(
                &ctx,
                &q("намерение: внедрить выгрузку отчётов\n- спроектировать формат\n- реализовать выгрузку\n- написать руководство"),
            )
            .unwrap();
        assert!(out.summary.contains("заведено задач 3"), "{}", out.summary);

        TaskUpdate::new().run(&ctx, &q("1 = сделано")).unwrap();
        TaskUpdate::new().run(&ctx, &q("2 = в работе")).unwrap();
        TaskUpdate::new()
            .run(&ctx, &q("3 = отложено: ждём макеты от дизайнера"))
            .unwrap();

        let список = TaskList::new().run(&ctx, &RunInput::default()).unwrap();
        assert!(
            список.summary.contains("сделано 1")
                && список.summary.contains("в работе 1")
                && список.summary.contains("отложено 1"),
            "сводка обязана показывать состояние: {}",
            список.summary
        );
        assert!(
            список
                .records
                .iter()
                .any(|r| r.contains("ждём макеты от дизайнера")),
            "причина отсрочки обязана быть видна: {:?}",
            список.records
        );
        assert!(
            список
                .records
                .iter()
                .any(|r| r.contains("внедрить выгрузку отчётов")),
            "намерение обязано сохраняться: {:?}",
            список.records
        );
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Отсрочка без причины отвергается на уровне инструмента, а не только внутри ядра.
    #[test]
    fn отсрочка_без_причины_не_принимается_инструментом() {
        let ctx = tmp("причина");
        TaskPlan::new().run(&ctx, &q("сделать нечто")).unwrap();
        let out = TaskUpdate::new().run(&ctx, &q("1 = отложено")).unwrap();
        assert!(
            out.skipped.is_some(),
            "отсрочка без причины принята быть не должна"
        );
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Пустой журнал сообщается явно: молчание человек прочитал бы как поломку.
    #[test]
    fn пустой_журнал_сообщается_явно() {
        let ctx = tmp("пусто");
        let out = TaskList::new().run(&ctx, &RunInput::default()).unwrap();
        assert!(out.skipped.is_some());
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Обе формы запроса принимаются: агент передаёт объект, человек говорит строкой.
    #[test]
    fn обе_формы_запроса_разбираются() {
        let (n, s, r) =
            parse("{\"number\":2,\"status\":\"rejected\",\"reason\":\"дорого\"}").unwrap();
        assert_eq!(
            (n, s, r.as_deref()),
            (2, TaskStatus::Rejected, Some("дорого"))
        );
        let (n, s, r) = parse("7 = отложено: ждём ответа").unwrap();
        assert_eq!(
            (n, s, r.as_deref()),
            (7, TaskStatus::Deferred, Some("ждём ответа"))
        );
        assert!(parse("нечто").is_err());
    }
}
