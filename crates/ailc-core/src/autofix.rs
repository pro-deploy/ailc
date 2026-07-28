//! LLM-автофикс — семантическая починка находок через модель клиента (sampling).
//!
//! Цикл на каждую находку: LLM правит строку → АДВЕРСАРИАЛЬНАЯ ПЕРЕПРОВЕРКА тем же
//! детектором на этом файле (целевая находка должна уйти И новых появиться не должно)
//! → оставляем или ОТКАТЫВАЕМ. Это loop-until-dry с реальным fix и встроенным verify.
//! Безопасно: правка, не прошедшая проверку, откатывается; правит только по флагу.

use crate::engines::gate::GateRunner;
use crate::orchestrator::Sampler;
use crate::policy;
use crate::registry::Registry;
use ailc_contracts::{Ctx, Family, Finding, RunInput};
use std::collections::HashMap;
use std::fs;

const SYSTEM: &str = "Ты чинишь дефект кода МИНИМАЛЬНОЙ правкой. Верни ТОЛЬКО исправленную строку(и) кода — без markdown-ограждений, без комментариев и пояснений.";

pub struct FixOutcome {
    pub rule: String,
    pub file: String,
    pub line: u32,
    pub status: String,
}

pub struct AutofixReport {
    pub outcomes: Vec<FixOutcome>,
    pub applied: usize,
    pub reverted: usize,
}

pub fn run(
    reg: &Registry,
    ctx: &Ctx,
    sampler: &mut dyn Sampler,
    max_fixes: usize,
) -> AutofixReport {
    let (pack, _) = policy::load(&ctx.root);
    let mut policy = pack.gate;
    for fam in [Family::Security, Family::Quality] {
        if !policy.families.contains(&fam) {
            policy.families.push(fam);
        }
    }
    let report = GateRunner::run(reg, ctx, &RunInput::default(), &policy);
    let findings: Vec<Finding> = report.blocking.into_iter().chain(report.warning).collect();

    let mut out = AutofixReport {
        outcomes: Vec::new(),
        applied: 0,
        reverted: 0,
    };

    // Смещение номеров строк по каждому файлу: применённая ранее правка могла быть
    // многострочной и сдвинуть все последующие находки этого же файла. Без пересчёта
    // мы правили бы не ту строку по устаревшему номеру из первоначального отчёта.
    let mut line_shift: HashMap<String, i64> = HashMap::new();

    for f in findings {
        if out.applied >= max_fixes {
            break;
        }
        let loc = match f.location.clone() {
            Some(l) => l,
            None => continue, // нечего точечно править
        };
        let path = ctx.root.join(&loc.file);
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // Номер строки корректируется на накопленное смещение от уже применённых правок
        // этого файла; отрицательный результат означает, что строка исчезла из файла.
        let shift = *line_shift.get(&loc.file).unwrap_or(&0);
        let shifted = (loc.line as i64).saturating_sub(1) + shift;
        if shifted < 0 {
            continue;
        }
        let idx = shifted as usize;
        let lines: Vec<&str> = content.lines().collect();
        if idx >= lines.len() {
            continue;
        }
        let original = lines[idx].to_string();

        // Базовая линия по файлу тем же детектором. Счётчики ведутся по каждому правилу
        // отдельно: сравнение одних лишь сумм позволяло принять правку, которая убрала
        // одну находку и одновременно породила другую по соседнему правилу.
        let before = file_findings(reg, ctx, &f.source, &loc.file);
        let before_by_rule = count_by_rule(&before);
        let before_rule = before_by_rule.get(&f.rule).copied().unwrap_or(0);
        let before_total = before.len();
        if before_rule == 0 {
            continue; // находка уже не воспроизводится (правили выше) — пропуск
        }

        // Просим LLM.
        let prompt = format!(
            "Проблема [{}]: {}\nИсходная строка:\n{original}\nВерни исправленную строку.",
            f.rule, f.message
        );
        let resp = match sampler.sample(SYSTEM, &prompt) {
            Some(r) => r,
            None => {
                out.outcomes.push(FixOutcome {
                    rule: f.rule,
                    file: loc.file,
                    line: loc.line,
                    status: "⊘ LLM недоступен".into(),
                });
                continue;
            }
        };
        let fixed = clean(&resp);
        if fixed.is_empty() || fixed.trim() == original.trim() {
            out.outcomes.push(FixOutcome {
                rule: f.rule,
                file: loc.file,
                line: loc.line,
                status: "⊘ правка пустая/без изменений".into(),
            });
            continue;
        }

        // Применяем. Запись атомарная (tmp + rename): прямой fs::write сначала усекает
        // файл, и аварийное завершение процесса в этом окне оставляло бы пользователя
        // с обрезанным исходником.
        let new_content = replace_line(&content, idx, &fixed);
        if write_user_file(&path, &new_content).is_err() {
            continue;
        }

        // Адверсариальная проверка: целевое правило обязано убыть, и при этом либо общее
        // число находок строго уменьшилось, либо ни одно ДРУГОЕ правило не выросло
        // (сравнение по счётчикам каждого правила). Прежний критерий
        // `after_total <= before_total` пропускал правку, которая заменила одну находку
        // другой: сумма не менялась, а дефект фактически оставался.
        let after = file_findings(reg, ctx, &f.source, &loc.file);
        let after_by_rule = count_by_rule(&after);
        let after_rule = after_by_rule.get(&f.rule).copied().unwrap_or(0);
        let after_total = after.len();
        let no_other_rule_grew = after_by_rule.iter().all(|(rule, cnt)| {
            *rule == f.rule || *cnt <= before_by_rule.get(rule).copied().unwrap_or(0)
        });
        let accepted =
            after_rule < before_rule && (after_total < before_total || no_other_rule_grew);

        if accepted {
            // Многострочная замена сдвигает все последующие строки файла: дельта равна
            // числу строк замены минус одна (заменялась ровно одна строка).
            let delta = fixed.lines().count() as i64 - 1;
            if delta != 0 {
                *line_shift.entry(loc.file.clone()).or_insert(0) += delta;
            }
            out.applied += 1;
            out.outcomes.push(FixOutcome {
                rule: f.rule,
                file: loc.file,
                line: loc.line,
                status: "✓ исправлено и проверено".into(),
            });
        } else {
            let _ = write_user_file(&path, &content); // откат, тоже атомарно
            out.reverted += 1;
            out.outcomes.push(FixOutcome {
                rule: f.rule,
                file: loc.file,
                line: loc.line,
                status: "↩ откат (правка не прошла проверку)".into(),
            });
        }
    }
    out
}

fn file_findings(reg: &Registry, ctx: &Ctx, source: &str, file: &str) -> Vec<Finding> {
    reg.get(source)
        .and_then(|c| {
            c.run(
                ctx,
                &RunInput {
                    target: Some(file.to_string()),
                    query: None,
                },
            )
            .ok()
        })
        .map(|o| o.findings)
        .unwrap_or_default()
}

/// Счётчик находок по каждому правилу: нужен адверсариальной проверке, чтобы замечать
/// правку, которая убрала находку одного правила и породила находку другого.
fn count_by_rule(findings: &[Finding]) -> HashMap<String, usize> {
    let mut m: HashMap<String, usize> = HashMap::new();
    for f in findings {
        *m.entry(f.rule.clone()).or_insert(0) += 1;
    }
    m
}

/// Убрать markdown-ограждения из ответа LLM.
///
/// Вырезается ТОЛЬКО парная обёртка по краям ответа (первая и последняя строки,
/// начинающиеся с ```). Прежняя фильтрация всех строк с ограждениями портила правки
/// Markdown-файлов: если исправляемая строка сама была ограждением кодового блока,
/// она молча исчезала из ответа модели.
fn clean(s: &str) -> String {
    let trimmed = s.trim();
    let lines: Vec<&str> = trimmed.lines().collect();
    if lines.len() >= 2
        && lines
            .first()
            .is_some_and(|l| l.trim_start().starts_with("```"))
        && lines
            .last()
            .is_some_and(|l| l.trim_start().starts_with("```"))
    {
        return lines[1..lines.len() - 1].join("\n").trim().to_string();
    }
    trimmed.to_string()
}

/// Атомарная запись файла пользователя через хелпер Store (tmp + rename).
fn write_user_file(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
    else {
        return Err(std::io::Error::other("некорректный путь"));
    };
    crate::engines::store::Store::atomic_write(parent, name, content.as_bytes())
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// Заменить строку idx (replacement может быть многострочным).
/// Окончания строк сохраняются: `lines()` отбрасывает `\r`, и прежде одна точечная
/// правка молча перезаписывала CRLF-окончания всего файла.
fn replace_line(content: &str, idx: usize, repl: &str) -> String {
    let eol = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
    if idx < lines.len() {
        lines[idx] = repl.to_string();
    }
    let mut s = lines.join(eol);
    if content.ends_with('\n') {
        s.push_str(eol);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Парная обёртка из ограждений по краям ответа снимается, а содержимое сохраняется.
    #[test]
    fn clean_снимает_парную_обёртку() {
        assert_eq!(clean("```rust\nlet a = 1;\n```"), "let a = 1;");
        assert_eq!(clean("let a = 1;"), "let a = 1;");
    }

    /// Ограждение ВНУТРИ ответа (правка Markdown-файла) не вырезается: прежняя версия
    /// молча удаляла такие строки и портила исправление.
    #[test]
    fn clean_сохраняет_ограждение_внутри_markdown_правки() {
        let ответ = "```md\nтекст\n```python\n```";
        // Внешняя пара снимается, внутренняя строка-ограждение остаётся содержимым.
        assert_eq!(clean(ответ), "текст\n```python");
        // Ответ без обёртки, сам являющийся ограждением с текстом, не трогается.
        assert_eq!(
            clean("обычный текст с ```кодом``` внутри"),
            "обычный текст с ```кодом``` внутри"
        );
    }
}
