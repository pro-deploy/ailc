//! Пакет возобновления: всё, что нужно новой сессии, чтобы продолжить с точного места.
//!
//! ЗАЧЕМ. Под капотом может работать слабая модель с контекстом около 256 тысяч токенов.
//! Читать историю целиком ей нельзя: история растёт без предела, а место нужно коду.
//! Поэтому сервер собирает короткий пакет с жёстким бюджетом. Разделы идут по важности,
//! и при нехватке места первыми сокращаются самые старые сведения, а не точка остановки.
//! Сжатие делает шаблон, а не нейросеть, поэтому факты не искажаются.

use super::{plan, stage_info, templates, State};
use ailc_contracts::Ctx;

/// Бюджет пакета по умолчанию, в токенах.
pub const DEFAULT_BUDGET_TOKENS: usize = 6000;
/// Грубая оценка: в русском тексте на токен приходится около трёх символов.
const CHARS_PER_TOKEN: usize = 3;

fn git_status(ctx: &Ctx) -> Vec<String> {
    let r = crate::engines::runner::Runner::run_timeout(ctx, "git", &["status", "--porcelain"], 15);
    if !(r.ran && r.exit_ok) {
        return vec!["(git недоступен: незакоммиченные изменения не определить)".into()];
    }
    r.stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// Раздел пакета: заголовок, строки и приоритет (меньше значит важнее).
struct Section {
    title: String,
    lines: Vec<String>,
    /// Можно ли сокращать раздел, отбрасывая строки с начала (старые сведения).
    trim_head: bool,
}

/// Собрать пакет возобновления.
pub fn packet(ctx: &Ctx, st: &State, budget_tokens: Option<usize>) -> String {
    let budget = budget_tokens.unwrap_or(DEFAULT_BUDGET_TOKENS).max(1000) * CHARS_PER_TOKEN;
    let info = stage_info(st.stage);
    let steps: Vec<_> = plan::all(ctx)
        .into_iter()
        .filter(|s| s.iteration == st.iteration)
        .collect();
    let current = steps
        .iter()
        .find(|s| s.status == plan::StepStatus::InProgress);
    let next_planned = steps.iter().find(|s| s.status == plan::StepStatus::Planned);

    let mut sections: Vec<Section> = Vec::new();

    // 1. Где мы.
    sections.push(Section {
        title: "Где мы".into(),
        lines: vec![
            format!("Этап {} из 9: {}. Итерация {}.", info.number, info.title, st.iteration),
            format!("Сценарий: {}.", super::scenario_label(&st.scenario)),
            format!(
                "Требования: {}.",
                if st.frozen {
                    "заморожены, менять бриф, ADR и критерии нельзя; новое оформляется через action=change"
                } else {
                    "открыты"
                }
            ),
        ],
        trim_head: false,
    });

    // 2. Точка остановки и единственное следующее действие.
    let mut stop = Vec::new();
    if let Some(s) = current {
        stop.push(format!(
            "Шаг {} «{}» был НАЧАТ и не закрыт (возможен обрыв сессии).",
            s.number, s.title
        ));
        if !s.files.is_empty() {
            stop.push(format!("Файлы шага: {}", s.files.join(", ")));
        }
        if !s.read_first.is_empty() {
            stop.push(format!(
                "Прочитать перед продолжением: {}",
                s.read_first.join(", ")
            ));
        }
        stop.push(format!("Проверка готовности: {}", s.check));
        if let Some(r) = &s.last_result {
            stop.push(format!(
                "Последний результат проверки (попытка {}):",
                s.attempts
            ));
            stop.extend(r.lines().take(10).map(|l| format!("    {l}")));
        }
        stop.push(format!(
            "СДЕЛАЙ СЕЙЧАС: посмотри файлы шага и вызови stage action=step_done step={}. ailc сам перепроверит: если шаг уже готов, он закроется, если нет, доделай по выводу проверки.",
            s.number
        ));
    } else if let (6, Some(s)) = (st.stage, next_planned) {
        stop.push(format!(
            "Незакрытых шагов в работе нет. Следующий шаг {}: {}.",
            s.number, s.title
        ));
        stop.push(format!(
            "СДЕЛАЙ СЕЙЧАС: вызови stage action=step_begin step={}.",
            s.number
        ));
    } else {
        let card = templates::load(ctx, info.card).unwrap_or_default();
        let now = card
            .split("## Сделай сейчас")
            .nth(1)
            .map(|t| t.trim().to_string())
            .unwrap_or_else(|| "выполни карточку этапа ниже".into());
        stop.push(format!("СДЕЛАЙ СЕЙЧАС: {now}"));
    }
    if let Some(h) = info.human {
        stop.push(format!("От человека на этом этапе нужно: {h}."));
    }
    sections.push(Section {
        title: "Точка остановки и следующее действие".into(),
        lines: stop,
        trim_head: false,
    });

    // 3. Незакоммиченные изменения.
    let mut gs = git_status(ctx);
    if gs.is_empty() {
        gs.push("нет".into());
    } else if gs.len() > 30 {
        let more = gs.len() - 30;
        gs.truncate(30);
        gs.push(format!("… и ещё {more}"));
    }
    sections.push(Section {
        title: "Незакоммиченные изменения (git status)".into(),
        lines: gs,
        trim_head: true,
    });

    // 4. Что нельзя нарушать.
    let mut rules = Vec::new();
    for (rel, text) in super::decisions(ctx) {
        if super::adr_status(&text).as_deref() == Some("принято") {
            rules.push(format!("{} ({rel})", super::adr_title(&text)));
        }
    }
    let violations = super::frozen_violations(ctx, st);
    for v in &violations {
        rules.push(format!("НАРУШЕНИЕ ЗАМОРОЗКИ: {v}"));
    }
    if rules.is_empty() {
        rules.push("принятых ADR пока нет".into());
    }
    sections.push(Section {
        title: "Принятые решения (не нарушать)".into(),
        lines: rules,
        trim_head: true,
    });

    // 5. Карточка этапа целиком.
    let card = templates::load(ctx, info.card).unwrap_or_default();
    sections.push(Section {
        title: "Карточка этапа".into(),
        lines: card
            .lines()
            .filter(|l| !l.contains("ailc-template:"))
            .map(str::to_string)
            .collect(),
        trim_head: false,
    });

    // 6. План: закрытые шаги свёрнуты, открытые полностью.
    let mut pl = Vec::new();
    let done: Vec<_> = steps
        .iter()
        .filter(|s| s.status == plan::StepStatus::Done)
        .collect();
    if !done.is_empty() {
        pl.push(format!("Сделано шагов: {}.", done.len()));
        for s in &done {
            pl.push(format!("  ✓ {} {}", s.number, s.title));
        }
    }
    for s in steps.iter().filter(|s| s.status != plan::StepStatus::Done) {
        pl.push(format!(
            "  [{}] {} {} (check: {})",
            s.status.label(),
            s.number,
            s.title,
            s.check
        ));
    }
    if pl.is_empty() {
        pl.push("шагов в плане этой итерации нет".into());
    }
    sections.push(Section {
        title: "План итерации".into(),
        lines: pl,
        trim_head: true,
    });

    // 7. Последние события и переходы.
    let mut ev = plan::journal_tail(ctx, 15);
    for t in st.history.iter().rev().take(5).rev() {
        ev.push(format!(
            "- переход {} в {} ({}{}): {}",
            t.from,
            t.to,
            t.kind,
            t.cycle
                .as_deref()
                .map(|c| format!(", цикл {c}"))
                .unwrap_or_default(),
            t.reason
        ));
    }
    sections.push(Section {
        title: "Последние события".into(),
        lines: ev,
        trim_head: true,
    });

    fit(sections, budget)
}

fn render(sections: &[Section]) -> String {
    let mut out = String::from("# Пакет возобновления ailc\n");
    for s in sections {
        if s.lines.is_empty() {
            continue;
        }
        out.push_str(&format!("\n## {}\n", s.title));
        for l in &s.lines {
            out.push_str(l);
            out.push('\n');
        }
    }
    out
}

/// Уложить разделы в бюджет: сокращаем с конца списка (наименее важные разделы),
/// отбрасывая самые старые строки. Разделы без права сокращения не трогаются.
fn fit(mut sections: Vec<Section>, budget: usize) -> String {
    loop {
        let text = render(&sections);
        if text.chars().count() <= budget {
            return text;
        }
        let Some(s) = sections
            .iter_mut()
            .rev()
            .find(|s| s.trim_head && s.lines.len() > 1)
        else {
            // Сокращать нечего: отдаём как есть, но с пометкой, а не молча обрезанным.
            return format!(
                "{text}\n(пакет превысил бюджет: обязательные разделы не сокращаются)\n"
            );
        };
        let drop = (s.lines.len() / 2).max(1);
        s.lines.drain(..drop);
        s.lines
            .insert(0, format!("(старые сведения сокращены: {drop} строк)"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn пакет_показывает_прерванный_шаг_и_укладывается_в_бюджет() {
        let dir = std::env::temp_dir().join(format!("ailc-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".ailc")).unwrap();
        let ctx = Ctx::new(&dir);
        let mut st = super::super::load_or_init(&ctx).unwrap();
        st.stage = 6;
        for i in 0..200 {
            plan::journal(
                &ctx,
                &format!("событие {i} с длинным описанием для проверки бюджета пакета"),
            );
        }
        let s = plan::add(
            &ctx,
            6,
            st.iteration,
            plan::NewStep {
                title: "модель записи",
                task: "",
                files: vec!["src/a.rs".into()],
                read_first: vec![],
                check: "true",
            },
        )
        .unwrap()
        .unwrap();
        plan::begin(&ctx, s.number).unwrap().unwrap();
        let p = packet(&ctx, &st, Some(1500));
        assert!(p.contains("был НАЧАТ и не закрыт"));
        assert!(p.contains("step_done step=1"));
        assert!(p.chars().count() <= 1500 * CHARS_PER_TOKEN + 200);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
