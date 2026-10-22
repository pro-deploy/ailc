//! Шаблоны процесса: бриф, карта ландшафта, ADR, критерии приёмки, запрос на изменение,
//! шаг плана и девять карточек этапов.
//!
//! ЗАЧЕМ. Слабая модель надёжно заполняет готовую структуру и плохо придумывает её сама.
//! Шаблон даёт ей разделы, подсказку к каждому и пример, а гейт перехода проверяет, что
//! обязательные разделы заполнены. Поэтому результат предсказуем независимо от модели.
//!
//! ПРОЕКТ ВАЖНЕЕ ВСТРОЕННОГО. При инициализации шаблоны раскладываются в
//! `.ailc/templates/`. Команда правит их под себя, и все чтения берут файл проекта, а
//! встроенную версию используют только при его отсутствии. Новая встроенная версия
//! правки команды не затирает: рядом кладётся файл `.new`, и человек сам решает, что
//! перенести.

use crate::profile::ProjectProfile;
use ailc_contracts::Ctx;
use std::path::PathBuf;

/// Каталог шаблонов в проекте.
pub const DIR: &str = ".ailc/templates";

/// Встроенные шаблоны: относительный путь внутри каталога шаблонов и содержимое.
pub const BUILTIN: &[(&str, &str)] = &[
    ("brief.md", include_str!("../../assets/templates/brief.md")),
    (
        "landscape.md",
        include_str!("../../assets/templates/landscape.md"),
    ),
    ("adr.md", include_str!("../../assets/templates/adr.md")),
    (
        "acceptance.toml",
        include_str!("../../assets/templates/acceptance.toml"),
    ),
    (
        "change-request.md",
        include_str!("../../assets/templates/change-request.md"),
    ),
    (
        "step.toml",
        include_str!("../../assets/templates/step.toml"),
    ),
    (
        "stages/01-idea.md",
        include_str!("../../assets/templates/stages/01-idea.md"),
    ),
    (
        "stages/02-landscape.md",
        include_str!("../../assets/templates/stages/02-landscape.md"),
    ),
    (
        "stages/03-adr.md",
        include_str!("../../assets/templates/stages/03-adr.md"),
    ),
    (
        "stages/04-criteria.md",
        include_str!("../../assets/templates/stages/04-criteria.md"),
    ),
    (
        "stages/05-approval.md",
        include_str!("../../assets/templates/stages/05-approval.md"),
    ),
    (
        "stages/06-dev.md",
        include_str!("../../assets/templates/stages/06-dev.md"),
    ),
    (
        "stages/07-quality.md",
        include_str!("../../assets/templates/stages/07-quality.md"),
    ),
    (
        "stages/08-deploy.md",
        include_str!("../../assets/templates/stages/08-deploy.md"),
    ),
    (
        "stages/09-acceptance.md",
        include_str!("../../assets/templates/stages/09-acceptance.md"),
    ),
];

/// Дополнительные критерии приёмки по паспорту проекта. Добавляются в шаблон
/// `acceptance.toml` при раскладке, чтобы требования закона и доступности не зависели от
/// того, вспомнит ли о них модель.
const PDN_CRITERIA: &str = r#"
[[criterion]]
id = "compliance-pdn-logs"
kind = "compliance"
title = "Персональные данные не попадают в журналы (152-ФЗ)"
threshold = 0
op = "=="
unit = "находок"
command = "cap:compliance.ru/pdn-logs"
extract = ""
confirmed_by = "команда"
"#;

const UI_CRITERIA: &str = r#"
[[criterion]]
id = "a11y-focus"
kind = "accessibility"
title = "У интерактивных элементов виден фокус клавиатуры"
threshold = 0
op = "=="
unit = "находок"
command = "cap:quality.ui/focus-visible"
extract = ""
confirmed_by = "команда"
"#;

const LLM_CRITERIA: &str = r#"
[[criterion]]
id = "ai-prompt-injection"
kind = "ai-safety"
title = "Нет путей промпт-инъекции в вызовах нейросети"
threshold = 0
op = "=="
unit = "находок"
command = "cap:security.ai/prompt-injection"
extract = ""
confirmed_by = "команда"
"#;

const REGRESSION_CRITERIA: &str = r#"
[[criterion]]
id = "regression-api"
kind = "regression"
title = "Нет ломающих изменений публичного API"
threshold = 0
op = "=="
unit = "находок"
command = "cap:verify/api-break"
extract = ""
confirmed_by = "команда"
"#;

/// Встроенное содержимое шаблона по относительному пути.
pub fn builtin(rel: &str) -> Option<&'static str> {
    BUILTIN.iter().find(|(p, _)| *p == rel).map(|(_, c)| *c)
}

/// Путь шаблона в проекте.
pub fn project_path(ctx: &Ctx, rel: &str) -> PathBuf {
    ctx.root.join(DIR).join(rel)
}

/// Шаблон для чтения: версия проекта, а при её отсутствии встроенная.
pub fn load(ctx: &Ctx, rel: &str) -> Option<String> {
    std::fs::read_to_string(project_path(ctx, rel))
        .ok()
        .or_else(|| builtin(rel).map(str::to_string))
}

/// Текст новой записи ADR по шаблону проекта (или встроенному). Строка-заголовок
/// версии шаблона в запись не попадает: это служебная пометка шаблона, а не решения.
pub fn render_adr(ctx: &Ctx, number: &str, title: &str, date: &str, replaces: &str) -> String {
    let tpl = load(ctx, "adr.md").unwrap_or_default();
    tpl.lines()
        .filter(|l| !l.contains("ailc-template:"))
        .collect::<Vec<_>>()
        .join("\n")
        .trim_start()
        .replace("{number}", number)
        .replace("{title}", title)
        .replace("{date}", date)
        .replace("{replaces}", replaces)
        + "\n"
}

/// Номер версии из заголовка `ailc-template: <имя> vN`.
pub fn version_of(text: &str) -> Option<u32> {
    let line = text.lines().find(|l| l.contains("ailc-template:"))?;
    let v = line.split_whitespace().find(|w| {
        w.starts_with('v') && w.len() > 1 && w[1..].chars().all(|c| c.is_ascii_digit())
    })?;
    v[1..].parse().ok()
}

/// Шаблон с поправками по паспорту проекта (сейчас это критерии приёмки).
pub fn render_builtin(rel: &str, profile: &ProjectProfile, large: bool) -> Option<String> {
    let base = builtin(rel)?;
    if rel != "acceptance.toml" {
        return Some(base.to_string());
    }
    let mut s = base.to_string();
    if profile.has_pdn {
        s.push_str(PDN_CRITERIA);
    }
    if profile.has_ui {
        s.push_str(UI_CRITERIA);
    }
    if profile.has_llm {
        s.push_str(LLM_CRITERIA);
    }
    if large {
        s.push_str(REGRESSION_CRITERIA);
    }
    Some(s)
}

/// Итог раскладки шаблонов.
#[derive(Debug, Default)]
pub struct ScaffoldReport {
    pub created: Vec<String>,
    /// Шаблоны, у которых встроенная версия новее проектной: рядом положен `.new`.
    pub outdated: Vec<String>,
}

/// Разложить шаблоны в `.ailc/templates/`. Идемпотентно: существующие файлы не
/// перезаписываются никогда.
pub fn scaffold(
    ctx: &Ctx,
    profile: &ProjectProfile,
    large: bool,
) -> std::io::Result<ScaffoldReport> {
    let mut rep = ScaffoldReport::default();
    for (rel, _) in BUILTIN {
        let Some(content) = render_builtin(rel, profile, large) else {
            continue;
        };
        let path = project_path(ctx, rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::read_to_string(&path) {
            Err(_) => {
                std::fs::write(&path, &content)?;
                rep.created.push(format!("{DIR}/{rel}"));
            }
            Ok(existing) => {
                let mine = version_of(&existing).unwrap_or(0);
                let theirs = version_of(&content).unwrap_or(0);
                if theirs > mine {
                    let new_path = path.with_extension(format!(
                        "{}.new",
                        path.extension().and_then(|e| e.to_str()).unwrap_or("txt")
                    ));
                    std::fs::write(&new_path, &content)?;
                    rep.outdated.push(format!("{DIR}/{rel}"));
                }
            }
        }
    }
    Ok(rep)
}

/// Обязательные разделы (`## Название (обязательно)`), в которых нет содержимого кроме
/// комментариев-подсказок и пустых строк.
pub fn missing_required(text: &str) -> Vec<String> {
    let mut missing = Vec::new();
    let mut current: Option<String> = None;
    let mut filled = false;
    let mut in_comment = false;
    let flush = |name: &Option<String>, filled: bool, out: &mut Vec<String>| {
        if let Some(n) = name {
            if !filled {
                out.push(n.clone());
            }
        }
    };
    for line in text.lines() {
        let t = line.trim();
        if let Some(h) = t.strip_prefix("## ") {
            flush(&current, filled, &mut missing);
            filled = false;
            current = h
                .strip_suffix("(обязательно)")
                .map(|n| n.trim().to_string());
            continue;
        }
        if t.starts_with("# ") {
            flush(&current, filled, &mut missing);
            current = None;
            continue;
        }
        // Комментарии-подсказки содержимым не считаются, в том числе многострочные.
        let mut rest = t.to_string();
        loop {
            if in_comment {
                match rest.find("-->") {
                    Some(i) => {
                        rest = rest[i + 3..].to_string();
                        in_comment = false;
                    }
                    None => {
                        rest.clear();
                        break;
                    }
                }
            } else {
                match rest.find("<!--") {
                    Some(i) => {
                        if !rest[..i].trim().is_empty() {
                            filled = true;
                        }
                        rest = rest[i + 4..].to_string();
                        in_comment = true;
                    }
                    None => break,
                }
            }
        }
        if !rest.trim().is_empty() {
            filled = true;
        }
    }
    flush(&current, filled, &mut missing);
    missing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn шаблон_с_подсказками_не_считается_заполненным() {
        let t = builtin("brief.md").unwrap();
        let m = missing_required(t);
        assert!(m.contains(&"Проблема".to_string()));
        assert!(m.contains(&"Цель и метрика успеха".to_string()));
    }

    #[test]
    fn текст_в_разделе_закрывает_требование() {
        let t = "# Б\n\n## Проблема (обязательно)\n<!-- подсказка -->\nНет записи онлайн.\n\n## Для кого (обязательно)\n<!-- многострочная\nподсказка -->\n";
        assert_eq!(missing_required(t), vec!["Для кого".to_string()]);
    }

    #[test]
    fn adr_по_шаблону_без_служебной_строки() {
        let ctx = Ctx::new(std::env::temp_dir().join("ailc-adr-nonexistent"));
        let t = render_adr(&ctx, "7", "БД", "2026-01-01", "нет");
        assert!(t.starts_with("# ADR-7: БД"));
        assert!(t.contains("- Статус: предложено") && t.contains("- Заменено: нет"));
        assert!(!t.contains("ailc-template"));
        assert!(missing_required(&t).contains(&"Решение".to_string()));
    }

    #[test]
    fn версия_читается_из_заголовка() {
        assert_eq!(version_of("<!-- ailc-template: brief v3 -->"), Some(3));
        assert_eq!(version_of("# ailc-template: acceptance v1"), Some(1));
        assert_eq!(version_of("без заголовка"), None);
    }

    #[test]
    fn все_встроенные_шаблоны_имеют_версию() {
        for (rel, c) in BUILTIN {
            assert!(version_of(c).is_some(), "нет версии у {rel}");
        }
    }
}
