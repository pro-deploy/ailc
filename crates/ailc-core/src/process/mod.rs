//! Процесс поставки из девяти этапов: от идеи заказчика до приёмки по критериям.
//!
//! ЗАЧЕМ. Проверки ailc отвечают на вопрос «хорош ли код», но не на вопрос «что делать
//! дальше». Слабая модель без внешней опоры теряет нить: пишет код до согласования,
//! меняет требования на ходу, после обрыва сессии не помнит, где остановилась. Модуль
//! ведёт состояние процесса в проекте и отвечает модели готовым заданием, а переходы
//! между этапами разрешает детерминированный гейт, а не модель.
//!
//! Этапы: 1 идея, 2 ландшафт, 3 ADR, 4 критерии, 5 согласование (контрольная точка),
//! 6 разработка, 7 проверка качества, 8 развёртывание, 9 приёмка (контрольная точка).
//! Циклы возврата: А (не согласовано, 5 в 2), Б (запрос на изменение, в 5), В (гейт не
//! пройден, 7 в 6), Г (критерий не выполнен, 9 в 6), Д (приёмка пройдена, новая
//! итерация с этапа 1).
//!
//! ЗАМОРОЗКА. При согласовании сохраняются sha256 брифа, карты ландшафта, критериев и
//! всех ADR. На этапах 6–9 любое расхождение с этим снимком считается нарушением: менять
//! требования можно только запросом на изменение, который возвращает процесс на этап 5.

pub mod acceptance;
pub mod plan;
pub mod resume;
pub mod templates;

use crate::engines::runner::Runner;
use crate::engines::store::Store;
use crate::registry::Registry;
use ailc_contracts::{CapError, Ctx, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub use plan::NS;

/// Файл состояния процесса.
const STATE: &str = "state.toml";
/// Одна строка о том, чего процесс ждёт от человека.
pub const NEXT: &str = ".ailc/process/NEXT.md";
pub const BRIEF: &str = "docs/brief.md";
pub const LANDSCAPE: &str = "docs/landscape.md";
/// Начиная с этого числа файлов репозиторий считается большой кодовой базой.
const LARGE_REPO_FILES: usize = 400;

/// Описание этапа.
pub struct StageInfo {
    pub number: u8,
    pub title: &'static str,
    pub card: &'static str,
    /// Чего ждут от человека на этом этапе. `None`: модель работает сама.
    pub human: Option<&'static str>,
}

pub const STAGES: [StageInfo; 9] = [
    StageInfo {
        number: 1,
        title: "Идея заказчика",
        card: "stages/01-idea.md",
        human: Some("ответить на вопросы модели о проблеме, пользователях и цели"),
    },
    StageInfo {
        number: 2,
        title: "Исследование ландшафта",
        card: "stages/02-landscape.md",
        human: None,
    },
    StageInfo {
        number: 3,
        title: "ADR",
        card: "stages/03-adr.md",
        human: None,
    },
    StageInfo {
        number: 4,
        title: "Критерии приёмки и метрики",
        card: "stages/04-criteria.md",
        human: None,
    },
    StageInfo {
        number: 5,
        title: "Согласование требований",
        card: "stages/05-approval.md",
        human: Some("подтвердить объём, ADR и критерии приёмки (или сказать, что не устраивает)"),
    },
    StageInfo {
        number: 6,
        title: "Разработка",
        card: "stages/06-dev.md",
        human: None,
    },
    StageInfo {
        number: 7,
        title: "Проверка качества",
        card: "stages/07-quality.md",
        human: None,
    },
    StageInfo {
        number: 8,
        title: "Развёртывание",
        card: "stages/08-deploy.md",
        human: Some("выкатить новую версию и создать git-тег vX.Y.Z (модель подскажет номер)"),
    },
    StageInfo {
        number: 9,
        title: "Приёмка по критериям",
        card: "stages/09-acceptance.md",
        human: Some("посмотреть таблицу «критерий, порог, факт» и подписать приёмку"),
    },
];

pub fn stage_info(n: u8) -> &'static StageInfo {
    &STAGES[(n.clamp(1, 9) - 1) as usize]
}

/// Переход между этапами.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    pub date: String,
    pub from: u8,
    pub to: u8,
    /// advance, approve, return, change, scenario.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cycle: Option<String>,
    #[serde(default)]
    pub reason: String,
}

/// Состояние процесса.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub stage: u8,
    pub iteration: u32,
    /// `mvp` или `feature` (фича в большой кодовой базе).
    pub scenario: String,
    pub frozen: bool,
    #[serde(default)]
    pub frozen_hashes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frozen_commit: Option<String>,
    /// Выпущенные версии: повторно использовать номер нельзя.
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance_passed: Option<bool>,
    #[serde(default)]
    pub change_requests: u32,
    #[serde(default)]
    pub history: Vec<Transition>,
}

/// Определить сценарий: базовая линия долга или крупный репозиторий означают доработку
/// существующей системы.
pub fn detect_scenario(ctx: &Ctx) -> &'static str {
    if crate::baseline::exists(ctx) || crate::calibrate::observe(ctx).files > LARGE_REPO_FILES {
        "feature"
    } else {
        "mvp"
    }
}

pub fn scenario_label(s: &str) -> &'static str {
    if s == "feature" {
        "новая фича в существующей кодовой базе"
    } else {
        "MVP с нуля"
    }
}

/// Прочитать состояние, если процесс уже начат.
pub fn load(ctx: &Ctx) -> Option<State> {
    let text = std::fs::read_to_string(ctx.root.join(".ailc").join(NS).join(STATE)).ok()?;
    toml::from_str(&text).ok()
}

fn save(ctx: &Ctx, st: &State) -> Result<()> {
    let body = toml::to_string_pretty(st)
        .map_err(|e| CapError(format!("состояние процесса не сериализуется: {e}")))?;
    Store::write(ctx, NS, STATE, &body)?;
    write_next(ctx, st);
    Ok(())
}

/// Прочитать состояние или создать новое на этапе 1.
pub fn load_or_init(ctx: &Ctx) -> Result<State> {
    if let Some(st) = load(ctx) {
        return Ok(st);
    }
    let st = State {
        stage: 1,
        iteration: 1,
        scenario: detect_scenario(ctx).to_string(),
        frozen: false,
        frozen_hashes: BTreeMap::new(),
        frozen_commit: None,
        versions: Vec::new(),
        acceptance_passed: None,
        change_requests: 0,
        history: Vec::new(),
    };
    save(ctx, &st)?;
    plan::journal(
        ctx,
        &format!(
            "ПРОЦЕСС НАЧАТ: этап 1, сценарий «{}»",
            scenario_label(&st.scenario)
        ),
    );
    Ok(st)
}

/// Инициализация при первом обращении к серверу: шаблоны и состояние. Идемпотентно.
pub fn init(ctx: &Ctx, profile: &crate::profile::ProjectProfile) -> templates::ScaffoldReport {
    let large = detect_scenario(ctx) == "feature";
    let rep = templates::scaffold(ctx, profile, large).unwrap_or_default();
    let _ = load_or_init(ctx);
    rep
}

/// Записать NEXT.md: файл передачи работы агенту ИИ в следующей сессии.
///
/// Новая сессия агента не помнит предыдущих, поэтому всё нужное для продолжения обязано
/// лежать на диске. Прежде NEXT.md содержал лишь номер этапа и строку о том, что нужно от
/// человека, а сведения для продолжения (прерванный шаг, память модели, принятые решения,
/// последние события, следующее действие) собирал только пакет возобновления на лету, и
/// агент без настроенного хука их не получал. Теперь в NEXT.md записывается сам пакет
/// возобновления; строка о том, что нужно от человека, стоит первой.
pub fn write_next(ctx: &Ctx, st: &State) {
    let info = stage_info(st.stage);
    let line = match info.human {
        Some(h) => format!("**От человека сейчас нужно:** {h}."),
        None => {
            "**От человека сейчас ничего не нужно:** агент работает по карточке этапа.".to_string()
        }
    };
    let packet = resume::packet(ctx, st, None);
    let body = packet
        .strip_prefix("# Пакет возобновления ailc\n")
        .unwrap_or(&packet);
    let text = format!(
        "# Что дальше\n\n> Файл передачи работы агенту ИИ в новой сессии. Ведётся ailc \
         автоматически при каждом событии процесса, вручную не править.\n\n{line}\n{body}"
    );
    let _ = Store::write(ctx, NS, "NEXT.md", &text);
}

/// Обновить NEXT.md, если процесс в проекте начат. Зовётся после событий, которые не
/// меняют состояние процесса, но меняют то, что должен знать следующий агент: запись в
/// журнал, заметка в памяти, закрытие шага.
pub fn refresh_next(ctx: &Ctx) {
    if let Some(st) = load(ctx) {
        write_next(ctx, &st);
    }
}

fn read(ctx: &Ctx, rel: &str) -> Option<String> {
    std::fs::read_to_string(ctx.root.join(rel)).ok()
}

/// ADR проекта: путь относительно корня и текст.
pub fn decisions(ctx: &Ctx) -> Vec<(String, String)> {
    // Оба каталога журнала решений (см. `crate::adr`): новые записи в docs/adr/, прежние в
    // .ailc/decisions/. Прежние остаются на своём месте и под своим путём, поэтому снимок
    // заморозки у уже согласованных проектов не меняется.
    crate::adr::list(ctx)
        .into_iter()
        .filter_map(|r| Some((r.rel, std::fs::read_to_string(&r.path).ok()?)))
        .collect()
}

pub fn adr_status(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("- Статус:"))
        .map(|s| s.trim().to_string())
}

pub fn adr_title(text: &str) -> String {
    text.lines()
        .find(|l| l.starts_with("# "))
        .map(|l| l.trim_start_matches("# ").trim().to_string())
        .unwrap_or_default()
}

/// Готов ли ADR: статус «предложено» или «принято», обязательные разделы и раздел
/// «Решение» заполнены (старые записи без пометок тоже проходят по «Решению»).
fn adr_ready(text: &str) -> bool {
    let st = adr_status(text).unwrap_or_default();
    if st != "предложено" && st != "принято" {
        return false;
    }
    // Обязательные разделы задаются списком (см. `templates::ADR_REQUIRED`): у записей,
    // созданных до снятия пометки «(обязательно)» с заголовков, она по-прежнему есть, у
    // новых её нет, и проверка одинакова для обоих. Записи старого формата без раздела
    // «Рассмотренные варианты» проходят по тем разделам, которые в них есть.
    let mut marked = String::with_capacity(text.len() + 64);
    for line in text.lines() {
        let required = line
            .strip_prefix("## ")
            .map(str::trim)
            .filter(|h| templates::ADR_REQUIRED.contains(h));
        match required {
            Some(h) => marked.push_str(&format!("## {h} (обязательно)")),
            None => marked.push_str(line),
        }
        marked.push('\n');
    }
    templates::missing_required(&marked).is_empty()
}

/// Файлы, которые замораживаются при согласовании.
fn frozen_files(ctx: &Ctx) -> Vec<String> {
    let mut v = vec![
        BRIEF.to_string(),
        LANDSCAPE.to_string(),
        acceptance::FILE.to_string(),
    ];
    v.extend(decisions(ctx).into_iter().map(|(p, _)| p));
    v
}

fn snapshot(ctx: &Ctx) -> BTreeMap<String, String> {
    frozen_files(ctx)
        .into_iter()
        .map(|rel| {
            let h = std::fs::read(ctx.root.join(&rel))
                .map(|b| crate::policy::sha256_hex(&b))
                .unwrap_or_else(|_| "отсутствует".to_string());
            (rel, h)
        })
        .collect()
}

/// Нарушения заморозки: какие файлы требований изменились после согласования.
pub fn frozen_violations(ctx: &Ctx, st: &State) -> Vec<String> {
    if !st.frozen {
        return Vec::new();
    }
    let now = snapshot(ctx);
    let mut out = Vec::new();
    for (rel, h) in &st.frozen_hashes {
        match now.get(rel) {
            Some(n) if n == h => {}
            Some(n) if n == "отсутствует" => {
                out.push(format!("{rel}: удалён после согласования"))
            }
            _ => out.push(format!("{rel}: изменён после согласования")),
        }
    }
    for rel in now.keys() {
        if !st.frozen_hashes.contains_key(rel) && now[rel] != "отсутствует" {
            out.push(format!("{rel}: добавлен после согласования"));
        }
    }
    out
}

fn git(ctx: &Ctx, args: &[&str]) -> Option<String> {
    let r = Runner::run_timeout(ctx, "git", args, 15);
    (r.ran && r.exit_ok).then(|| r.stdout.trim().to_string())
}

fn is_semver_tag(v: &str) -> bool {
    let Some(rest) = v.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<&str> = rest.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Проблемы, которые не дают уйти с текущего этапа вперёд.
pub fn gate_problems(
    ctx: &Ctx,
    reg: Option<&Registry>,
    st: &State,
    version: Option<&str>,
) -> Vec<String> {
    let mut p = Vec::new();
    match st.stage {
        1 | 2 => {
            let rel = if st.stage == 1 { BRIEF } else { LANDSCAPE };
            match read(ctx, rel) {
                None => p.push(format!(
                    "нет файла {rel}: создайте его из .ailc/templates/{}",
                    rel.trim_start_matches("docs/")
                )),
                Some(t) => {
                    for m in templates::missing_required(&t) {
                        p.push(format!("{rel}: не заполнен обязательный раздел «{m}»"));
                    }
                }
            }
        }
        3 => {
            let ds = decisions(ctx);
            if !ds.iter().any(|(_, t)| adr_ready(t)) {
                p.push("нет ни одного ADR со статусом «предложено» и заполненными обязательными разделами".into());
            }
            for (rel, t) in &ds {
                if adr_status(t).map(|s| s == "предложено").unwrap_or(false) {
                    for m in templates::missing_required(t) {
                        p.push(format!("{rel}: не заполнен раздел «{m}»"));
                    }
                }
            }
        }
        4 => match acceptance::load(ctx) {
            Err(e) => p.push(e),
            Ok(list) => p.extend(acceptance::validate(&list)),
        },
        5 => p.push(
            "с этапа 5 вперёд ведёт только action=approve после явного согласия человека".into(),
        ),
        6 => {
            let steps: Vec<_> = plan::all(ctx)
                .into_iter()
                .filter(|s| s.iteration == st.iteration)
                .collect();
            if steps.is_empty() {
                p.push("в плане нет шагов этой итерации: добавьте их через action=plan_add".into());
            }
            for s in steps.iter().filter(|s| s.status != plan::StepStatus::Done) {
                p.push(format!(
                    "шаг {} «{}» не сделан ({})",
                    s.number,
                    s.title,
                    s.status.label()
                ));
            }
            p.extend(frozen_violations(ctx, st));
        }
        7 => {
            p.extend(frozen_violations(ctx, st));
            match reg {
                None => p.push("реестр проверок недоступен: dod не выполнить".into()),
                Some(reg) => {
                    let rep = crate::orchestrator::Orchestrator::dod(
                        reg,
                        ctx,
                        &ailc_contracts::RunInput::default(),
                    );
                    if !rep.passed {
                        for a in rep.axes.iter().filter(|a| a.hard && (!a.ran || !a.ok)) {
                            p.push(format!(
                                "dod: ось «{}» {}",
                                a.name,
                                if a.ran {
                                    format!("провалена, находок {}", a.findings)
                                } else {
                                    "не выполнилась".into()
                                }
                            ));
                        }
                        if p.is_empty() {
                            p.push("dod не подтверждён".into());
                        }
                    }
                }
            }
        }
        8 => match version.map(str::trim) {
            None | Some("") => p.push("передайте version=vX.Y.Z развёрнутой версии".into()),
            Some(v) if !is_semver_tag(v) => p.push(format!("версия «{v}» не в формате vX.Y.Z")),
            Some(v) if st.versions.iter().any(|x| x == v) => p.push(format!(
                "версия {v} уже выпускалась: каждая выкатка получает новый номер"
            )),
            Some(v) => {
                if git(
                    ctx,
                    &["rev-parse", "-q", "--verify", &format!("refs/tags/{v}")],
                )
                .is_none()
                {
                    p.push(format!("git-тега {v} нет: создайте его на коммите выкатки"));
                }
            }
        },
        _ => {
            p.extend(frozen_violations(ctx, st));
            if st.acceptance_passed != Some(true) {
                p.push("приёмка не пройдена: вызовите action=accept, все автоматические критерии должны быть выполнены".into());
            }
        }
    }
    p
}

fn push(st: &mut State, from: u8, to: u8, kind: &str, cycle: Option<&str>, reason: &str) {
    st.history.push(Transition {
        date: plan::stamp(),
        from,
        to,
        kind: kind.to_string(),
        cycle: cycle.map(str::to_string),
        reason: reason.trim().to_string(),
    });
}

/// Нормализовать обозначение цикла к кириллице.
pub fn cycle_of(s: &str) -> Option<char> {
    match s.trim().to_uppercase().as_str() {
        "А" | "A" => Some('А'),
        "Б" | "B" => Some('Б'),
        "В" | "V" => Some('В'),
        "Г" | "G" => Some('Г'),
        "Д" | "D" => Some('Д'),
        _ => None,
    }
}

/// Ответ действия: текст для модели и структура.
pub struct Reply {
    pub text: String,
    pub data: Value,
    pub error: bool,
}

fn ok(text: String, data: Value) -> Reply {
    Reply {
        text,
        data,
        error: false,
    }
}

fn refuse(text: String) -> Reply {
    Reply {
        data: json!({ "error": text }),
        text,
        error: true,
    }
}

fn str_arg<'a>(args: &'a Value, k: &str) -> Option<&'a str> {
    args.get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn list_arg(args: &Value, k: &str) -> Vec<String> {
    match args.get(k) {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(s)) => s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn num_arg(args: &Value, k: &str) -> Option<u32> {
    match args.get(k) {
        Some(Value::Number(n)) => n.as_u64().map(|v| v as u32),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Единая точка входа для инструмента MCP `stage` и подкоманды `ailc stage`.
pub fn handle(ctx: &Ctx, reg: Option<&Registry>, args: &Value) -> Reply {
    let action = str_arg(args, "action").unwrap_or("status");
    let mut st = match load_or_init(ctx) {
        Ok(s) => s,
        Err(e) => return refuse(format!("состояние процесса недоступно: {e}")),
    };
    let reason = str_arg(args, "reason").unwrap_or("");
    let r = match action {
        "status" => Ok(status(ctx, &st)),
        "resume" => {
            let budget = num_arg(args, "budget_tokens").map(|v| v as usize);
            let packet = resume::packet(ctx, &st, budget);
            Ok(ok(packet.clone(), json!({ "stage": st.stage, "packet": packet })))
        }
        "advance" => advance(ctx, reg, &mut st, reason, str_arg(args, "version")),
        "approve" => approve(ctx, &mut st, reason),
        "return" => go_back(ctx, &mut st, str_arg(args, "cycle").unwrap_or(""), reason),
        "change" => change(ctx, &mut st, str_arg(args, "title").unwrap_or("изменение требований"), reason),
        "accept" => accept(ctx, reg, &mut st),
        "scenario" => {
            let s = match str_arg(args, "scenario") {
                Some("mvp") => "mvp",
                Some("feature") => "feature",
                _ => return refuse("scenario должен быть mvp или feature".into()),
            };
            let from = st.stage;
            st.scenario = s.to_string();
            push(&mut st, from, from, "scenario", None, reason);
            Ok(ok(format!("Сценарий: {}.", scenario_label(s)), json!({ "scenario": s })))
        }
        "plan_add" => {
            let n = plan::NewStep {
                title: str_arg(args, "title").unwrap_or(""),
                task: str_arg(args, "task").unwrap_or(""),
                files: list_arg(args, "files"),
                read_first: list_arg(args, "read_first"),
                check: str_arg(args, "check").unwrap_or(""),
            };
            match plan::add(ctx, st.stage, st.iteration, n) {
                Ok(Ok(s)) => Ok(ok(format!("Шаг {} добавлен: {}. Проверка готовности: {}", s.number, s.title, s.check), json!(s))),
                Ok(Err(e)) => return refuse(e),
                Err(e) => Err(e),
            }
        }
        "step_begin" => match num_arg(args, "step") {
            None => return refuse("укажите step: номер шага".into()),
            Some(n) => match plan::begin(ctx, n) {
                Ok(Ok(s)) => Ok(ok(step_brief("Начат", &s), json!(s))),
                Ok(Err(e)) => return refuse(e),
                Err(e) => Err(e),
            },
        },
        "step_done" => match num_arg(args, "step") {
            None => return refuse("укажите step: номер шага".into()),
            Some(n) => match plan::done(ctx, reg, n, str_arg(args, "note")) {
                Ok(Ok((s, res))) => {
                    let text = if res.passed {
                        format!("Шаг {} сделан: проверка «{}» прошла.\n\n{}", s.number, s.check, next_hint(ctx, &st))
                    } else {
                        format!(
                            "Шаг {} НЕ закрыт: проверка «{}» не прошла (попытка {}).\nВывод:\n{}\n\nИсправь и снова вызови step_done.",
                            s.number, s.check, s.attempts, res.detail
                        )
                    };
                    Ok(ok(text, json!({ "step": s, "passed": res.passed })))
                }
                Ok(Err(e)) => return refuse(e),
                Err(e) => Err(e),
            },
        },
        "plan" => Ok(plan_list(ctx, &st)),
        other => return refuse(format!(
            "неизвестное действие «{other}». Допустимо: status, resume, advance, approve, return, change, accept, scenario, plan, plan_add, step_begin, step_done"
        )),
    };
    match r {
        Ok(reply) => {
            if !reply.error {
                if let Err(e) = save(ctx, &st) {
                    return refuse(format!("не удалось сохранить состояние: {e}"));
                }
            }
            reply
        }
        Err(e) => refuse(e.to_string()),
    }
}

fn step_brief(verb: &str, s: &plan::Step) -> String {
    let mut t = format!("{verb} шаг {}: {}\n", s.number, s.title);
    if !s.read_first.is_empty() {
        t.push_str(&format!("Прочитай сначала: {}\n", s.read_first.join(", ")));
    }
    if !s.files.is_empty() {
        t.push_str(&format!("Меняй только: {}\n", s.files.join(", ")));
    }
    t.push_str(&format!("Готовность проверит ailc командой: {}\nПосле правок вызови stage action=step_done step={}.", s.check, s.number));
    t
}

fn next_hint(ctx: &Ctx, st: &State) -> String {
    match plan::all(ctx)
        .into_iter()
        .find(|s| s.iteration == st.iteration && s.status != plan::StepStatus::Done)
    {
        Some(s) => format!(
            "Следующий шаг {}: {}. Вызови step_begin step={}.",
            s.number, s.title, s.number
        ),
        None if st.stage == 6 => "Все шаги сделаны. Вызови stage action=advance.".into(),
        None => String::new(),
    }
}

fn status(ctx: &Ctx, st: &State) -> Reply {
    let info = stage_info(st.stage);
    let problems = if st.stage == 7 {
        // На этапе 7 гейт гоняет полный dod: в статусе его не запускаем, это дорого.
        vec!["условие перехода: подтверждённый dod (проверится при advance)".to_string()]
    } else {
        gate_problems(ctx, None, st, None)
    };
    let mut t = format!(
        "Этап {} из 9: {}. Итерация {}. Сценарий: {}. Требования {}.\n",
        info.number,
        info.title,
        st.iteration,
        scenario_label(&st.scenario),
        if st.frozen {
            "заморожены"
        } else {
            "открыты"
        }
    );
    if let Some(h) = info.human {
        t.push_str(&format!("Ждём от человека: {h}.\n"));
    }
    if problems.is_empty() {
        t.push_str("Условия перехода выполнены: можно вызвать action=advance.\n");
    } else {
        t.push_str("До перехода осталось:\n");
        for p in &problems {
            t.push_str(&format!("  - {p}\n"));
        }
    }
    t.push_str("\nДля полной инструкции и точки остановки вызови action=resume.");
    ok(
        t,
        json!({ "stage": st.stage, "title": info.title, "iteration": st.iteration, "scenario": st.scenario, "frozen": st.frozen, "problems": problems }),
    )
}

fn plan_list(ctx: &Ctx, st: &State) -> Reply {
    let steps: Vec<_> = plan::all(ctx)
        .into_iter()
        .filter(|s| s.iteration == st.iteration)
        .collect();
    let mut t = format!("План итерации {}:\n", st.iteration);
    if steps.is_empty() {
        t.push_str("  шагов нет\n");
    }
    for s in &steps {
        t.push_str(&format!(
            "  {} [{}] {} (check: {})\n",
            s.number,
            s.status.label(),
            s.title,
            s.check
        ));
    }
    ok(t, json!({ "steps": steps }))
}

fn advance(
    ctx: &Ctx,
    reg: Option<&Registry>,
    st: &mut State,
    reason: &str,
    version: Option<&str>,
) -> Result<Reply> {
    let from = st.stage;
    let problems = gate_problems(ctx, reg, st, version);
    if !problems.is_empty() {
        let mut t = format!("Переход с этапа {from} закрыт гейтом:\n");
        for p in &problems {
            t.push_str(&format!("  - {p}\n"));
        }
        if from == 7 {
            t.push_str("\nЕсли это блокеры качества, вызови action=return cycle=В с их перечнем.");
        }
        if from == 9 {
            t.push_str("\nЕсли критерий не выполнен, вызови action=return cycle=Г.");
        }
        return Ok(Reply {
            data: json!({ "advanced": false, "problems": problems }),
            text: t,
            error: true,
        });
    }
    if from == 9 {
        if reason.is_empty() {
            return Ok(refuse(
                "для завершения приёмки передайте reason: слова человека о подписи приёмки".into(),
            ));
        }
        // Цикл Д: новая итерация, требования снова открыты.
        st.iteration += 1;
        st.stage = 1;
        st.frozen = false;
        st.frozen_hashes.clear();
        st.frozen_commit = None;
        st.acceptance_passed = None;
        push(st, 9, 1, "advance", Some("Д"), reason);
        plan::journal(
            ctx,
            &format!("ПРИЁМКА ПОДПИСАНА: {reason}. Итерация {}", st.iteration),
        );
        return Ok(ok(
            format!("Приёмка подписана. Начата итерация {} с этапа 1. Новые пожелания заказчика оформляются как бриф новой итерации.", st.iteration),
            json!({ "advanced": true, "stage": 1, "iteration": st.iteration }),
        ));
    }
    if from == 8 {
        if let Some(v) = version {
            st.versions.push(v.trim().to_string());
        }
    }
    st.stage = from + 1;
    push(st, from, st.stage, "advance", None, reason);
    plan::journal(ctx, &format!("ПЕРЕХОД {from} в {}", st.stage));
    let card = templates::load(ctx, stage_info(st.stage).card).unwrap_or_default();
    Ok(ok(
        format!(
            "Переход выполнен: этап {} «{}».\n\n{card}",
            st.stage,
            stage_info(st.stage).title
        ),
        json!({ "advanced": true, "stage": st.stage }),
    ))
}

fn approve(ctx: &Ctx, st: &mut State, reason: &str) -> Result<Reply> {
    if st.stage != 5 {
        return Ok(refuse(format!(
            "согласование возможно только на этапе 5, сейчас этап {}",
            st.stage
        )));
    }
    if reason.is_empty() {
        return Ok(refuse(
            "передайте reason: дословно слова человека, которыми он согласовал объём".into(),
        ));
    }
    // Сначала убеждаемся, что этапы 1–4 действительно закрыты: согласовать можно только
    // то, что существует.
    let mut gaps = Vec::new();
    for s in 1..=4u8 {
        let probe = State {
            stage: s,
            ..st.clone()
        };
        gaps.extend(gate_problems(ctx, None, &probe, None));
    }
    if !gaps.is_empty() {
        let mut t = String::from("Согласовывать нечего, пока не закрыты предыдущие этапы:\n");
        for g in &gaps {
            t.push_str(&format!("  - {g}\n"));
        }
        return Ok(Reply {
            data: json!({ "approved": false, "problems": gaps }),
            text: t,
            error: true,
        });
    }
    let mut accepted = Vec::new();
    for (rel, text) in decisions(ctx) {
        if adr_status(&text).as_deref() == Some("предложено") {
            let new = text.replacen("- Статус: предложено", "- Статус: принято", 1);
            if std::fs::write(ctx.root.join(&rel), new).is_ok() {
                accepted.push(rel);
            }
        }
    }
    st.frozen_hashes = snapshot(ctx);
    st.frozen = true;
    st.frozen_commit = git(ctx, &["rev-parse", "--short", "HEAD"]);
    st.stage = 6;
    push(st, 5, 6, "approve", None, reason);
    plan::journal(
        ctx,
        &format!("СОГЛАСОВАНО: {reason}. Требования заморожены"),
    );
    let card = templates::load(ctx, stage_info(6).card).unwrap_or_default();
    Ok(ok(
        format!(
            "Согласовано. ADR приняты: {}. Требования заморожены ({} файлов). Этап 6.\n\n{card}",
            if accepted.is_empty() {
                "нет новых".into()
            } else {
                accepted.join(", ")
            },
            st.frozen_hashes.len()
        ),
        json!({ "approved": true, "accepted_adr": accepted, "frozen": st.frozen_hashes.keys().collect::<Vec<_>>() }),
    ))
}

fn go_back(ctx: &Ctx, st: &mut State, cycle: &str, reason: &str) -> Result<Reply> {
    if reason.is_empty() {
        return Ok(refuse(
            "передайте reason: что именно не так (без причины возврат неотличим от ошибки)".into(),
        ));
    }
    let from = st.stage;
    let (need, to) = match cycle_of(cycle) {
        Some('А') => (5, 2),
        Some('В') => (7, 6),
        Some('Г') => (9, 6),
        Some('Б') => return change(ctx, st, "изменение требований", reason),
        _ => return Ok(refuse("cycle должен быть А (не согласовано), В (гейт не пройден) или Г (критерий не выполнен); для изменения требований используйте action=change".into())),
    };
    if from != need {
        return Ok(refuse(format!(
            "цикл {cycle} возможен только с этапа {need}, сейчас этап {from}"
        )));
    }
    let c = cycle_of(cycle).map(|c| c.to_string());
    st.stage = to;
    if to == 6 {
        st.acceptance_passed = None;
    }
    push(st, from, to, "return", c.as_deref(), reason);
    plan::journal(
        ctx,
        &format!(
            "ВОЗВРАТ цикл {}: этап {from} в {to}. {reason}",
            c.clone().unwrap_or_default()
        ),
    );
    let note = if to == 6 {
        "Требования не меняются: исправляется код. Добавь шаги исправления через plan_add."
    } else {
        "Доработай карту ландшафта, ADR и критерии по замечаниям, затем снова пройди этапы до согласования."
    };
    Ok(ok(
        format!("Возврат на этап {to} «{}». {note}", stage_info(to).title),
        json!({ "stage": to, "cycle": c }),
    ))
}

fn change(ctx: &Ctx, st: &mut State, title: &str, reason: &str) -> Result<Reply> {
    if reason.is_empty() {
        return Ok(refuse(
            "передайте reason: что именно просит изменить заказчик".into(),
        ));
    }
    let from = st.stage;
    if from <= 4 {
        // До согласования изменение стоит дёшево: правится бриф или критерии на месте.
        push(st, from, from, "change", Some("Б"), reason);
        plan::journal(
            ctx,
            &format!("ИЗМЕНЕНИЕ до согласования (этап {from}): {reason}"),
        );
        return Ok(ok(
            format!("Требования ещё не заморожены: внеси изменение прямо в бриф, ADR или критерии. Этап остаётся {from}."),
            json!({ "stage": from, "change_request": null }),
        ));
    }
    st.change_requests += 1;
    let n = st.change_requests;
    let tpl = templates::load(ctx, "change-request.md").unwrap_or_default();
    let body = tpl
        .replace("{number}", &n.to_string())
        .replace("{title}", title)
        .replace("{date}", &crate::answers::today())
        .replace("{stage}", &from.to_string())
        .replace("{text}", reason);
    let name = format!("cr-{n:04}.md");
    Store::write(ctx, NS, &name, &body)?;
    st.stage = 5;
    st.frozen = false;
    st.acceptance_passed = None;
    push(st, from, 5, "change", Some("Б"), reason);
    plan::journal(
        ctx,
        &format!("ЗАПРОС НА ИЗМЕНЕНИЕ CR-{n} с этапа {from}: {reason}"),
    );
    Ok(ok(
        format!(
            "Оформлен запрос на изменение .ailc/{NS}/{name}. Процесс возвращён на этап 5: обнови бриф, ADR и критерии, оцени сдвиг сроков и снова согласуй с заказчиком. Код по новому требованию до согласования не пишется."
        ),
        json!({ "stage": 5, "change_request": format!(".ailc/{NS}/{name}") }),
    ))
}

fn accept(ctx: &Ctx, reg: Option<&Registry>, st: &mut State) -> Result<Reply> {
    if st.stage != 9 {
        return Ok(refuse(format!(
            "приёмка выполняется на этапе 9, сейчас этап {}",
            st.stage
        )));
    }
    let list = match acceptance::load(ctx) {
        Ok(l) => l,
        Err(e) => return Ok(refuse(e)),
    };
    let problems = acceptance::validate(&list);
    if !problems.is_empty() {
        return Ok(refuse(format!(
            "критерии невалидны: {}",
            problems.join("; ")
        )));
    }
    let rep = acceptance::run(ctx, reg, &list);
    let md = acceptance::render(&rep, st.versions.last().map(String::as_str));
    let _ = std::fs::write(ctx.root.join(acceptance::REPORT), &md);
    st.acceptance_passed = Some(rep.passed);
    plan::journal(
        ctx,
        &format!(
            "ПРИЁМКА: {}",
            if rep.passed {
                "критерии выполнены"
            } else {
                "есть невыполненные критерии"
            }
        ),
    );
    let tail = if rep.passed {
        "\nПокажи таблицу заказчику. После его подписи вызови action=advance с reason = его слова."
    } else {
        "\nНевыполненный критерий: вызови action=return cycle=Г с перечнем. Пороги менять нельзя."
    };
    Ok(ok(
        format!("{md}{tail}"),
        json!({ "passed": rep.passed, "report": rep }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn гейт_adr_проверяет_разделы_по_списку_без_пометок_в_заголовках() {
        let ctx = Ctx::new(std::env::temp_dir().join("ailc-proc-adr-ready-nonexistent"));
        let empty = templates::render_adr(&ctx, "1", "БД", "2026-01-01", "нет");
        assert!(!empty.contains("(обязательно)"));
        assert!(
            !adr_ready(&empty),
            "пустые разделы не должны проходить гейт"
        );
        let mut filled = String::new();
        for line in empty.lines() {
            filled.push_str(line);
            filled.push('\n');
            if line.starts_with("## ") {
                filled.push_str("Текст раздела.\n");
            }
        }
        assert!(adr_ready(&filled), "{filled}");
    }

    fn tmp(name: &str) -> Ctx {
        let dir = std::env::temp_dir().join(format!("ailc-proc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".ailc")).unwrap();
        Ctx::new(dir)
    }

    fn call(ctx: &Ctx, a: Value) -> Reply {
        handle(ctx, None, &a)
    }

    fn fill_brief(ctx: &Ctx) {
        std::fs::create_dir_all(ctx.root.join("docs")).unwrap();
        std::fs::write(
            ctx.root.join(BRIEF),
            "# Бриф\n## Проблема (обязательно)\nНет записи.\n## Для кого (обязательно)\nПациенты.\n## Цель и метрика успеха (обязательно)\n40%.\n## Что входит в объём (обязательно)\nЗапись.\n",
        )
        .unwrap();
    }

    #[test]
    fn полный_проход_с_заморозкой_и_изменением() {
        let ctx = tmp("flow");
        let r = call(&ctx, json!({"action":"advance"}));
        assert!(r.error, "пустой бриф не пускает дальше");
        fill_brief(&ctx);
        assert!(!call(&ctx, json!({"action":"advance"})).error);
        std::fs::write(ctx.root.join(LANDSCAPE), "# К\n## Системы и интеграции (обязательно)\nМИС.\n## Ограничения безопасности и инфраструктуры (обязательно)\nРФ.\n## Риски (обязательно)\nНет; принят.\n").unwrap();
        assert!(!call(&ctx, json!({"action":"advance"})).error);
        std::fs::create_dir_all(ctx.root.join(crate::adr::LEGACY_DIR)).unwrap();
        std::fs::write(
            ctx.root.join(".ailc/decisions/1.md"),
            "# ADR-1: БД\n\n- Статус: предложено\n\n## Контекст\nх\n## Решение\nPostgreSQL.\n",
        )
        .unwrap();
        assert!(!call(&ctx, json!({"action":"advance"})).error);
        std::fs::create_dir_all(ctx.root.join(".ailc/process")).unwrap();
        std::fs::write(
            ctx.root.join(acceptance::FILE),
            templates::builtin("acceptance.toml").unwrap(),
        )
        .unwrap();
        assert!(!call(&ctx, json!({"action":"advance"})).error);
        assert_eq!(load(&ctx).unwrap().stage, 5);
        assert!(
            call(&ctx, json!({"action":"approve"})).error,
            "без слов человека нельзя"
        );
        assert!(!call(&ctx, json!({"action":"approve","reason":"да, согласую"})).error);
        let st = load(&ctx).unwrap();
        assert!(st.frozen && st.stage == 6);
        assert!(
            std::fs::read_to_string(ctx.root.join(".ailc/decisions/1.md"))
                .unwrap()
                .contains("Статус: принято")
        );

        // Тихая правка брифа после согласования ловится.
        std::fs::write(ctx.root.join(BRIEF), "изменено").unwrap();
        assert!(!frozen_violations(&ctx, &load(&ctx).unwrap()).is_empty());

        // Запрос на изменение возвращает на этап 5 и снимает заморозку.
        assert!(!call(&ctx, json!({"action":"change","reason":"добавить оплату"})).error);
        let st = load(&ctx).unwrap();
        assert_eq!(st.stage, 5);
        assert!(!st.frozen);
        assert!(ctx.root.join(".ailc/process/cr-0001.md").is_file());
        assert!(ctx.root.join(NEXT).is_file());
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    #[test]
    fn возврат_только_с_правильного_этапа() {
        let ctx = tmp("back");
        assert!(call(&ctx, json!({"action":"return","cycle":"В","reason":"x"})).error);
        assert!(call(&ctx, json!({"action":"return","cycle":"А"})).error);
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    #[test]
    fn семвер() {
        assert!(is_semver_tag("v1.2.3"));
        assert!(!is_semver_tag("1.2.3"));
        assert!(!is_semver_tag("v1.2"));
    }
}
