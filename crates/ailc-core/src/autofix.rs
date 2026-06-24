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
        let idx = (loc.line as usize).saturating_sub(1);
        let lines: Vec<&str> = content.lines().collect();
        if idx >= lines.len() {
            continue;
        }
        let original = lines[idx].to_string();

        // Базовая линия по файлу тем же детектором.
        let before = file_findings(reg, ctx, &f.source, &loc.file);
        let before_rule = before.iter().filter(|x| x.rule == f.rule).count();
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

        // Применяем.
        let new_content = replace_line(&content, idx, &fixed);
        if fs::write(&path, &new_content).is_err() {
            continue;
        }

        // Адверсариальная проверка: целевая ушла И новых не прибавилось.
        let after = file_findings(reg, ctx, &f.source, &loc.file);
        let after_rule = after.iter().filter(|x| x.rule == f.rule).count();
        let after_total = after.len();

        if after_rule < before_rule && after_total <= before_total {
            out.applied += 1;
            out.outcomes.push(FixOutcome {
                rule: f.rule,
                file: loc.file,
                line: loc.line,
                status: "✓ исправлено и проверено".into(),
            });
        } else {
            let _ = fs::write(&path, &content); // откат
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

/// Убрать markdown-ограждения из ответа LLM.
fn clean(s: &str) -> String {
    s.lines()
        .filter(|l| !l.trim_start().starts_with("```"))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

/// Заменить строку idx (replacement может быть многострочным).
fn replace_line(content: &str, idx: usize, repl: &str) -> String {
    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
    if idx < lines.len() {
        lines[idx] = repl.to_string();
    }
    let mut s = lines.join("\n");
    if content.ends_with('\n') {
        s.push('\n');
    }
    s
}
