//! План работ из мелких шагов и журнал «начат / завершён».
//!
//! ЗАЧЕМ. Сессия модели может оборваться в любой момент: кончился контекст, упала среда
//! разработки, пропала сеть. Чтобы новая сессия продолжила с точного места, состояние
//! работ живёт в проекте, а не в памяти модели. Каждый шаг перед началом получает
//! запись «начат», после проверки запись «завершён» или «проверка не прошла». Шаг,
//! оставшийся «в работе», после обрыва виден сразу.
//!
//! ГОТОВНОСТЬ РЕШАЕТ ailc. У шага обязательно поле `check`: команда оболочки или
//! проверка ailc с префиксом `cap:`. Шаг закрывается только при успешном `check`, поэтому
//! слабой модели не нужно помнить и не нужно оценивать, закончила ли она.

use crate::engines::runner::Runner;
use crate::engines::store::Store;
use crate::registry::Registry;
use ailc_contracts::{CapError, Ctx, Result, RunInput};
use serde::{Deserialize, Serialize};

/// Пространство хранения процесса (`.ailc/process/`).
pub const NS: &str = "process";
/// Журнал шагов.
pub const JOURNAL: &str = "journal.md";
const CHECK_TIMEOUT_SECS: u64 = 600;
/// Больше файлов в одном шаге слабая модель удерживает плохо: такой шаг надо дробить.
pub const MAX_FILES_PER_STEP: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepStatus {
    Planned,
    InProgress,
    Done,
}

impl StepStatus {
    pub fn label(&self) -> &'static str {
        match self {
            StepStatus::Planned => "запланирован",
            StepStatus::InProgress => "в работе",
            StepStatus::Done => "сделан",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub number: u32,
    pub title: String,
    #[serde(default)]
    pub task: String,
    /// Этап процесса, к которому относится шаг.
    pub stage: u8,
    #[serde(default)]
    pub iteration: u32,
    #[serde(default)]
    pub files: Vec<String>,
    /// Что прочитать перед началом шага: так модель не тащит в контекст лишнее.
    #[serde(default)]
    pub read_first: Vec<String>,
    pub check: String,
    pub status: StepStatus,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

fn file_name(n: u32) -> String {
    format!("step-{n:04}.toml")
}

/// Все шаги по порядку.
pub fn all(ctx: &Ctx) -> Vec<Step> {
    let mut v: Vec<Step> = Store::read_all(ctx, NS)
        .unwrap_or_default()
        .into_iter()
        .filter(|(name, _)| name.starts_with("step-") && name.ends_with(".toml"))
        .filter_map(|(_, body)| toml::from_str::<Step>(&body).ok())
        .collect();
    v.sort_by_key(|s| s.number);
    v
}

fn save(ctx: &Ctx, s: &Step) -> Result<()> {
    let body =
        toml::to_string_pretty(s).map_err(|e| CapError(format!("шаг не сериализуется: {e}")))?;
    Store::write(ctx, NS, &file_name(s.number), &body)
}

/// Отметка времени для журнала: дата и время UTC.
pub fn stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let hms = secs % 86_400;
    format!(
        "{} {:02}:{:02} UTC",
        crate::answers::today(),
        hms / 3600,
        (hms % 3600) / 60
    )
}

/// Дописать строку журнала процесса. Ошибки журнала основной вызов не ломают.
pub fn journal(ctx: &Ctx, line: &str) {
    let _ = Store::append(ctx, NS, JOURNAL, &format!("- [{}] {line}", stamp()));
}

/// Последние `n` строк журнала.
pub fn journal_tail(ctx: &Ctx, n: usize) -> Vec<String> {
    let text =
        std::fs::read_to_string(ctx.root.join(".ailc").join(NS).join(JOURNAL)).unwrap_or_default();
    let lines: Vec<String> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    lines[lines.len().saturating_sub(n)..].to_vec()
}

/// Новые данные шага.
pub struct NewStep<'a> {
    pub title: &'a str,
    pub task: &'a str,
    pub files: Vec<String>,
    pub read_first: Vec<String>,
    pub check: &'a str,
}

/// Добавить шаг. `Err` в правой части содержит причину отказа для модели.
pub fn add(
    ctx: &Ctx,
    stage: u8,
    iteration: u32,
    n: NewStep,
) -> Result<std::result::Result<Step, String>> {
    let title = n.title.trim();
    if title.is_empty() {
        return Ok(Err("у шага нет title".into()));
    }
    if n.check.trim().is_empty() {
        return Ok(Err(
            "у шага нет check: укажите команду или cap:<id>, по которой ailc решит, что шаг сделан"
                .into(),
        ));
    }
    if n.files.len() > MAX_FILES_PER_STEP {
        return Ok(Err(format!(
            "шаг затрагивает {} файлов, допустимо не больше {MAX_FILES_PER_STEP}: разбейте его",
            n.files.len()
        )));
    }
    let existing = all(ctx);
    if existing
        .iter()
        .any(|s| s.title == title && s.iteration == iteration && s.status != StepStatus::Done)
    {
        return Ok(Err(format!("незакрытый шаг «{title}» уже есть в плане")));
    }
    let s = Step {
        number: existing.iter().map(|s| s.number).max().unwrap_or(0) + 1,
        title: title.to_string(),
        task: n.task.trim().to_string(),
        stage,
        iteration,
        files: n.files,
        read_first: n.read_first,
        check: n.check.trim().to_string(),
        status: StepStatus::Planned,
        attempts: 0,
        last_result: None,
        note: None,
        started: None,
        finished: None,
        commit: None,
    };
    save(ctx, &s)?;
    journal(ctx, &format!("ЗАПЛАНИРОВАН шаг {}: {}", s.number, s.title));
    Ok(Ok(s))
}

fn find(ctx: &Ctx, number: u32) -> std::result::Result<Step, String> {
    all(ctx)
        .into_iter()
        .find(|s| s.number == number)
        .ok_or_else(|| format!("шага {number} в плане нет"))
}

/// Отметить начало шага (запись «начат» делается ДО правок).
pub fn begin(ctx: &Ctx, number: u32) -> Result<std::result::Result<Step, String>> {
    let mut s = match find(ctx, number) {
        Ok(s) => s,
        Err(e) => return Ok(Err(e)),
    };
    if s.status == StepStatus::Done {
        return Ok(Err(format!("шаг {number} уже сделан")));
    }
    if let Some(other) = all(ctx)
        .into_iter()
        .find(|o| o.status == StepStatus::InProgress && o.number != number)
    {
        return Ok(Err(format!(
            "сначала закройте шаг {} «{}»: он в работе (step_done)",
            other.number, other.title
        )));
    }
    s.status = StepStatus::InProgress;
    s.started = Some(stamp());
    save(ctx, &s)?;
    journal(
        ctx,
        &format!(
            "НАЧАТ шаг {}: {} (файлы: {})",
            s.number,
            s.title,
            if s.files.is_empty() {
                "не указаны".into()
            } else {
                s.files.join(", ")
            }
        ),
    );
    Ok(Ok(s))
}

/// Результат проверки шага.
pub struct CheckResult {
    pub passed: bool,
    pub detail: String,
}

/// Выполнить `check` шага.
pub fn run_check(ctx: &Ctx, reg: Option<&Registry>, check: &str) -> CheckResult {
    if let Some(id) = check.trim().strip_prefix("cap:") {
        let Some(cap) = reg.and_then(|r| r.get(id.trim())) else {
            return CheckResult {
                passed: false,
                detail: format!("нет проверки {id}"),
            };
        };
        return match cap.run(ctx, &RunInput::default()) {
            Ok(out) if out.skipped.is_some() => CheckResult {
                passed: false,
                detail: format!("проверка пропущена: {}", out.skipped.unwrap_or_default()),
            },
            Ok(out) => {
                let mut lines: Vec<String> = out
                    .findings
                    .iter()
                    .take(5)
                    .map(|f| match &f.location {
                        Some(l) => format!("{}:{} {}", l.file, l.line, f.message),
                        None => f.message.clone(),
                    })
                    .collect();
                if lines.is_empty() {
                    lines.push(out.summary.clone());
                }
                CheckResult {
                    passed: out.findings.is_empty(),
                    detail: lines.join("\n"),
                }
            }
            Err(e) => CheckResult {
                passed: false,
                detail: format!("сбой проверки: {e}"),
            },
        };
    }
    let r = Runner::run_timeout(ctx, "sh", &["-c", check], CHECK_TIMEOUT_SECS);
    if !r.ran {
        return CheckResult {
            passed: false,
            detail: r
                .skipped_reason
                .unwrap_or_else(|| "команда не запустилась".into()),
        };
    }
    CheckResult {
        passed: r.exit_ok,
        detail: r.tail(15).join("\n"),
    }
}

fn git_head(ctx: &Ctx) -> Option<String> {
    let r = Runner::run_timeout(ctx, "git", &["rev-parse", "--short", "HEAD"], 10);
    (r.ran && r.exit_ok)
        .then(|| r.stdout.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Завершить шаг: ailc сам выполняет `check`. Шаг закрывается только при успехе.
pub fn done(
    ctx: &Ctx,
    reg: Option<&Registry>,
    number: u32,
    note: Option<&str>,
) -> Result<std::result::Result<(Step, CheckResult), String>> {
    let mut s = match find(ctx, number) {
        Ok(s) => s,
        Err(e) => return Ok(Err(e)),
    };
    if s.status == StepStatus::Done {
        return Ok(Err(format!("шаг {number} уже сделан")));
    }
    let res = run_check(ctx, reg, &s.check);
    s.attempts += 1;
    s.last_result = Some(clip(&res.detail, 1500));
    if let Some(n) = note.map(str::trim).filter(|n| !n.is_empty()) {
        s.note = Some(n.to_string());
    }
    if res.passed {
        s.status = StepStatus::Done;
        s.finished = Some(stamp());
        s.commit = git_head(ctx);
        journal(ctx, &format!("ЗАВЕРШЁН шаг {}: {}", s.number, s.title));
    } else {
        // Шаг остаётся «в работе»: даже если начало не отмечали, проверка уже была.
        s.status = StepStatus::InProgress;
        if s.started.is_none() {
            s.started = Some(stamp());
        }
        journal(
            ctx,
            &format!(
                "ПРОВЕРКА НЕ ПРОШЛА шаг {} (попытка {}): {}",
                s.number,
                s.attempts,
                first_line(&res.detail)
            ),
        );
    }
    save(ctx, &s)?;
    Ok(Ok((s, res)))
}

pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let tail: String = s
        .chars()
        .rev()
        .take(max)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("…{tail}")
}

fn first_line(s: &str) -> String {
    clip(s.lines().find(|l| !l.trim().is_empty()).unwrap_or(""), 160)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> Ctx {
        let dir = std::env::temp_dir().join(format!("ailc-plan-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".ailc")).unwrap();
        Ctx::new(dir)
    }

    fn step<'a>(title: &'a str, check: &'a str) -> NewStep<'a> {
        NewStep {
            title,
            task: "",
            files: vec![],
            read_first: vec![],
            check,
        }
    }

    #[test]
    fn шаг_закрывается_только_при_успешной_проверке() {
        let ctx = tmp("check");
        let s = add(&ctx, 6, 1, step("первый", "false")).unwrap().unwrap();
        begin(&ctx, s.number).unwrap().unwrap();
        let (s1, r1) = done(&ctx, None, s.number, None).unwrap().unwrap();
        assert!(!r1.passed);
        assert_eq!(s1.status, StepStatus::InProgress);

        let t = add(&ctx, 6, 1, step("второй", "true")).unwrap().unwrap();
        // Нельзя начать второй, пока первый в работе.
        assert!(begin(&ctx, t.number).unwrap().is_err());
        let (t1, r2) = done(&ctx, None, t.number, None).unwrap().unwrap();
        assert!(r2.passed);
        assert_eq!(t1.status, StepStatus::Done);
        let j = journal_tail(&ctx, 10).join("\n");
        assert!(j.contains("НАЧАТ шаг 1") && j.contains("ЗАВЕРШЁН шаг 2"));
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    #[test]
    fn шаг_без_проверки_и_слишком_крупный_отклоняются() {
        let ctx = tmp("reject");
        assert!(add(&ctx, 6, 1, step("x", "")).unwrap().is_err());
        let big = NewStep {
            title: "y",
            task: "",
            files: vec!["a".into(), "b".into(), "c".into(), "d".into()],
            read_first: vec![],
            check: "true",
        };
        assert!(add(&ctx, 6, 1, big).unwrap().is_err());
        let _ = std::fs::remove_dir_all(&ctx.root);
    }
}
