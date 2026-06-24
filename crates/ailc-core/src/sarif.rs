//! SARIF 2.1.0 — индустриальный формат отчёта статического анализа для CI
//! (GitHub/GitLab security-tab, Azure DevOps, любой SARIF-ридер). Превращает
//! `Finding[]` в SARIF-документ.
//!
//! Отличие ailc: в отчёт идут ТОЛЬКО верифицированные находки — ложные
//! (комментарии/плейсхолдеры/строки определений правил) уже опровергнуты
//! состязательным Verifier'ом. Число опровергнутых и список пропущенных проверок
//! выносятся в `properties` прогона — честная картина охвата прямо в артефакте CI.

use ailc_contracts::{Finding, Severity};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Severity ailc → уровень SARIF (error/warning/note).
fn level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Порядок сортировки: критичное первым (0), информационное последним (4). Так отчёт
/// ВЕДЁТ безопасностью, а стилевые заметки уходят вниз: сигнал виден сразу и в CLI, и у
/// SARIF-ридера, без удаления каких-либо находок.
fn severity_order(sev: Severity) -> u8 {
    match sev {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

/// SARIF-ранг (0..100, выше значит разбирать раньше). Позволяет потребителю (GitHub
/// security-tab и др.) приоритизировать находки, не отбрасывая низкоприоритетные.
fn severity_rank(sev: Severity) -> u8 {
    match sev {
        Severity::Critical => 100,
        Severity::High => 85,
        Severity::Medium => 55,
        Severity::Low => 25,
        Severity::Info => 10,
    }
}

/// Сериализовать находки в SARIF 2.1.0 (pretty JSON).
///
/// `refuted` — сколько ложных отсеял Verifier; `checks_run`/`checks_skipped` —
/// какие проверки выполнены и какие пропущены (с причиной). Всё это попадает в
/// `runs[0].properties`, чтобы потребитель видел реальный охват, а не «0 = чисто».
pub fn to_sarif(
    findings: &[Finding],
    version: &str,
    refuted: usize,
    checks_run: &[String],
    checks_skipped: &[(String, String)],
) -> String {
    // Уникальные правила (id → описание). BTreeMap → стабильный порядок вывода.
    let mut rules_map: BTreeMap<&str, &str> = BTreeMap::new();
    for f in findings {
        rules_map.entry(&f.rule).or_insert(&f.message);
    }
    let rules: Vec<Value> = rules_map
        .iter()
        .map(|(id, desc)| {
            json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": desc },
            })
        })
        .collect();

    // Сортируем по серьёзности (критичное первым), сохраняя порядок внутри одного уровня
    // (sort_by_key стабилен). Отчёт начинается с самого важного, стиль уходит в хвост.
    let mut ordered: Vec<&Finding> = findings.iter().collect();
    ordered.sort_by_key(|f| severity_order(f.severity));

    let results: Vec<Value> = ordered
        .iter()
        .map(|f| {
            let mut result = json!({
                "ruleId": f.rule,
                "level": level(f.severity),
                "rank": severity_rank(f.severity),
                "message": { "text": f.message },
                "properties": { "severity": f.severity.to_string(), "source": f.source },
            });
            if let Some(loc) = &f.location {
                let mut region = json!({ "startLine": loc.line.max(1) });
                if let Some(ev) = &f.evidence {
                    region["snippet"] = json!({ "text": ev });
                }
                result["locations"] = json!([{
                    "physicalLocation": {
                        "artifactLocation": { "uri": loc.file },
                        "region": region,
                    }
                }]);
            }
            result
        })
        .collect();

    let skipped: Vec<Value> = checks_skipped
        .iter()
        .map(|(id, reason)| json!({ "check": id, "reason": reason }))
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "ailc",
                "version": version,
                "rules": rules,
            }},
            "results": results,
            "properties": {
                "refutedFalsePositives": refuted,
                "checksRun": checks_run,
                "checksSkipped": skipped,
            },
        }]
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_contracts::Location;

    fn f(rule: &str, sev: Severity) -> Finding {
        Finding {
            rule: rule.into(),
            severity: sev,
            message: "m".into(),
            location: Some(Location {
                file: "a.rs".into(),
                line: 1,
            }),
            evidence: None,
            verified: true,
            source: "test".into(),
        }
    }

    #[test]
    fn sarif_ведёт_критичным_и_проставляет_ранг() {
        // Подаём вперемешку: note первым, critical в середине — отчёт обязан вести critical,
        // а note уходить в хвост. Так сигнал виден сразу, ничего не отброшено.
        let findings = vec![
            f("style-note", Severity::Info),
            f("rce", Severity::Critical),
            f("warn", Severity::Medium),
        ];
        let out = to_sarif(&findings, "0.0.0", 0, &[], &[]);
        let d: Value = serde_json::from_str(&out).expect("валидный SARIF JSON");
        let res = d["runs"][0]["results"].as_array().expect("results массив");
        assert_eq!(res.len(), 3);
        assert_eq!(res[0]["ruleId"], "rce", "критичное первым");
        assert_eq!(res[0]["rank"], 100);
        assert_eq!(res[0]["level"], "error");
        assert_eq!(res.last().unwrap()["ruleId"], "style-note", "информационное в хвосте");
        assert_eq!(res.last().unwrap()["rank"], 10);
    }
}
