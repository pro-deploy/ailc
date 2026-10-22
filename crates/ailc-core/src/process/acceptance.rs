//! Критерии приёмки как данные и приёмка измерением.
//!
//! Каждый критерий в `.ailc/process/acceptance.toml` обязан иметь порог, оператор,
//! единицу и команду замера. Это превращает спор о вкусах в измерение: на этапе 9 ailc
//! сам выполняет команды, извлекает число и сравнивает его с порогом, а человек видит
//! таблицу «критерий, порог, факт».
//!
//! Команда бывает трёх видов: обычная команда оболочки (число берётся регулярным
//! выражением `extract`), проверка ailc с префиксом `cap:` (число равно количеству
//! находок) и `manual` (критерий подтверждает человек, автоматически он не засчитывается).

use crate::engines::runner::Runner;
use crate::registry::Registry;
use ailc_contracts::{Ctx, RunInput};
use serde::{Deserialize, Serialize};

/// Путь к файлу критериев проекта.
pub const FILE: &str = ".ailc/process/acceptance.toml";
/// Отчёт последней приёмки.
pub const REPORT: &str = ".ailc/process/acceptance-report.md";
/// Таймаут одной команды замера.
const MEASURE_TIMEOUT_SECS: u64 = 600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Criterion {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub title: String,
    pub threshold: Option<f64>,
    #[serde(default)]
    pub op: String,
    #[serde(default)]
    pub unit: String,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub extract: String,
    #[serde(default)]
    pub confirmed_by: String,
}

#[derive(Debug, Default, Deserialize)]
struct File {
    #[serde(default)]
    criterion: Vec<Criterion>,
}

/// Прочитать критерии. `Err` содержит человекочитаемую причину.
pub fn load(ctx: &Ctx) -> Result<Vec<Criterion>, String> {
    let path = ctx.root.join(FILE);
    let text = std::fs::read_to_string(&path).map_err(|_| {
        format!("нет файла {FILE}: скопируйте шаблон .ailc/templates/acceptance.toml")
    })?;
    parse(&text)
}

pub fn parse(text: &str) -> Result<Vec<Criterion>, String> {
    toml::from_str::<File>(text)
        .map(|f| f.criterion)
        .map_err(|e| format!("{FILE} не разбирается: {e}"))
}

fn op_ok(op: &str) -> bool {
    matches!(op, "<=" | ">=" | "==" | "<" | ">")
}

/// Проблемы критериев: строка без порога, оператора, единицы или команды не принимается.
pub fn validate(list: &[Criterion]) -> Vec<String> {
    let mut out = Vec::new();
    if list.is_empty() {
        out.push("нет ни одного критерия [[criterion]]".to_string());
    }
    for (i, c) in list.iter().enumerate() {
        let name = if c.id.is_empty() {
            format!("критерий №{}", i + 1)
        } else {
            c.id.clone()
        };
        if c.title.trim().is_empty() {
            out.push(format!("{name}: нет title"));
        }
        if c.threshold.is_none() {
            out.push(format!(
                "{name}: нет порога threshold (слова без числа не принимаются)"
            ));
        }
        if !op_ok(c.op.trim()) {
            out.push(format!(
                "{name}: оператор op должен быть одним из <=, >=, ==, <, >"
            ));
        }
        if c.unit.trim().is_empty() {
            out.push(format!("{name}: нет единицы unit"));
        }
        let cmd = c.command.trim();
        if cmd.is_empty() {
            out.push(format!("{name}: нет команды замера command"));
        } else if cmd != "manual" && !cmd.starts_with("cap:") {
            match regex::Regex::new(&c.extract) {
                Ok(re) if re.captures_len() >= 2 => {}
                Ok(_) => out.push(format!("{name}: в extract нужна одна группа захвата числа")),
                Err(e) => out.push(format!(
                    "{name}: extract не является регулярным выражением: {e}"
                )),
            }
        }
    }
    out
}

/// Исход одного критерия.
#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub id: String,
    pub title: String,
    pub threshold: f64,
    pub op: String,
    pub unit: String,
    pub actual: Option<f64>,
    /// `Some(true)` выполнен, `Some(false)` не выполнен, `None` нужно решение человека
    /// (ручной критерий или замер не удался).
    pub passed: Option<bool>,
    pub note: String,
}

/// Итог приёмки.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub outcomes: Vec<Outcome>,
    /// Все автоматические критерии выполнены и ни один замер не сорвался.
    pub passed: bool,
    pub manual: usize,
}

fn compare(actual: f64, op: &str, threshold: f64) -> bool {
    match op {
        "<=" => actual <= threshold,
        ">=" => actual >= threshold,
        "<" => actual < threshold,
        ">" => actual > threshold,
        _ => (actual - threshold).abs() < 1e-9,
    }
}

fn measure(ctx: &Ctx, reg: Option<&Registry>, c: &Criterion) -> Result<f64, String> {
    let cmd = c.command.trim();
    if let Some(id) = cmd.strip_prefix("cap:") {
        let reg = reg.ok_or("реестр проверок недоступен")?;
        let cap = reg.get(id.trim()).ok_or(format!("нет проверки {id}"))?;
        let out = cap
            .run(ctx, &RunInput::default())
            .map_err(|e| e.to_string())?;
        if let Some(why) = out.skipped {
            return Err(format!("проверка {id} пропущена: {why}"));
        }
        return Ok(out.findings.len() as f64);
    }
    let r = Runner::run_timeout(ctx, "sh", &["-c", cmd], MEASURE_TIMEOUT_SECS);
    if !r.ran {
        return Err(r
            .skipped_reason
            .unwrap_or_else(|| "команда не запустилась".into()));
    }
    let re = regex::Regex::new(&c.extract).map_err(|e| e.to_string())?;
    let all = format!("{}\n{}", r.stdout, r.stderr);
    let caps = re
        .captures(&all)
        .ok_or_else(|| format!("в выводе нет совпадения с {}", c.extract))?;
    caps.get(1)
        .and_then(|m| m.as_str().replace(',', ".").parse::<f64>().ok())
        .ok_or_else(|| "захваченное значение не число".to_string())
}

/// Выполнить замеры и сравнить с порогами.
pub fn run(ctx: &Ctx, reg: Option<&Registry>, list: &[Criterion]) -> Report {
    let mut outcomes = Vec::new();
    let mut manual = 0;
    for c in list {
        let threshold = c.threshold.unwrap_or(0.0);
        let mut o = Outcome {
            id: c.id.clone(),
            title: c.title.clone(),
            threshold,
            op: c.op.clone(),
            unit: c.unit.clone(),
            actual: None,
            passed: None,
            note: String::new(),
        };
        if c.command.trim() == "manual" {
            manual += 1;
            o.note = format!("подтверждает {}", c.confirmed_by);
        } else {
            match measure(ctx, reg, c) {
                Ok(v) => {
                    o.actual = Some(v);
                    o.passed = Some(compare(v, c.op.trim(), threshold));
                }
                Err(e) => o.note = format!("замер не удался: {e}"),
            }
        }
        outcomes.push(o);
    }
    // Ручные критерии в автоматический итог не входят: их подтверждает человек. Сорванный
    // замер приравнивается к невыполненному критерию, а не к выполненному.
    let automated = |o: &&Outcome| !o.note.starts_with("подтверждает");
    let passed = outcomes.iter().any(|o| automated(&o))
        && outcomes
            .iter()
            .filter(automated)
            .all(|o| o.passed == Some(true));
    Report {
        outcomes,
        passed,
        manual,
    }
}

fn fmt_num(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{}", v as i64)
    } else {
        format!("{v:.2}")
    }
}

/// Таблица для человека в формате Markdown.
pub fn render(r: &Report, version: Option<&str>) -> String {
    let mut s = String::from("# Отчёт приёмки\n\n");
    s.push_str(&format!("- Дата: {}\n", crate::answers::today()));
    if let Some(v) = version {
        s.push_str(&format!("- Версия: {v}\n"));
    }
    s.push_str(&format!(
        "- Итог: {}\n\n",
        if r.passed {
            "все автоматические критерии выполнены"
        } else {
            "есть невыполненные или неизмеренные критерии"
        }
    ));
    s.push_str("| Критерий | Порог | Факт | Итог |\n|---|---|---|---|\n");
    for o in &r.outcomes {
        let fact = o.actual.map(fmt_num).unwrap_or_else(|| "нет".into());
        let res = match o.passed {
            Some(true) => "выполнен".to_string(),
            Some(false) => "не выполнен".to_string(),
            None => o.note.clone(),
        };
        s.push_str(&format!(
            "| {} | {} {} {} | {} | {} |\n",
            o.title,
            o.op,
            fmt_num(o.threshold),
            o.unit,
            fact,
            res
        ));
    }
    if r.manual > 0 {
        s.push_str(&format!(
            "\nРучных критериев: {}. Их подтверждает человек при подписи приёмки.\n",
            r.manual
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn встроенный_шаблон_валиден() {
        let list = parse(crate::process::templates::builtin("acceptance.toml").unwrap()).unwrap();
        assert!(validate(&list).is_empty(), "{:?}", validate(&list));
    }

    #[test]
    fn критерий_без_порога_отклоняется() {
        let list = parse("[[criterion]]\nid='x'\ntitle='быстро'\nop='<='\nunit='мс'\ncommand='echo 1'\nextract='([0-9]+)'\n").unwrap();
        assert!(validate(&list).iter().any(|e| e.contains("порога")));
    }

    #[test]
    fn замер_из_вывода_команды() {
        let dir = std::env::temp_dir().join(format!("ailc-acc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ctx = Ctx::new(&dir);
        let list = parse(crate::process::templates::builtin("acceptance.toml").unwrap()).unwrap();
        let r = run(&ctx, None, &list);
        assert!(r.passed, "{:?}", r.outcomes);
        assert_eq!(r.outcomes[0].actual, Some(210.0));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
