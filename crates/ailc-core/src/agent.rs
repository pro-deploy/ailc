//! Адаптивный агент — мозг = нейросеть IDE (через MCP sampling).
//!
//! Не один разовый вызов LLM, а ПЕТЛЯ: PLAN (ИИ строит план заранее) → EXECUTE
//! (DAG, параллельно) → VERIFY (адверсариальный отсев) → REFLECT (хватает ли? →
//! довызвать ещё / починить / готово) → … → детерминированный GATE → QualityLedger.
//!
//! Инвариант: ИИ решает ЧТО запускать и довызывать; вердикт PASS/FAIL выносит
//! детерминированный гейт, а не нейросеть. Петля ограничена бюджетом раундов и
//! «сухим» счётчиком (loop-until-dry), чтобы всегда сходиться. Многораундовый
//! sampling за один вызов уже опробован в `autofix` — здесь тот же механизм.

use crate::orchestrator::{
    collect_results, finalize_ledger, CollectedRun, LedgerInput, Orchestrator, Sampler,
};
use crate::pipeline::{Pipeline, PipelineEngine, Step};
use crate::policy;
use crate::registry::Registry;
use crate::verify::Verifier;
use ailc_contracts::{AgentPlan, Ctx, Family, Finding, QualityLedger, RunInput};
use serde::Deserialize;

const PLAN_SYSTEM: &str = "Ты — планировщик проверок качества и безопасности кода. По намерению пользователя и стеку проекта выбери, какие инструменты запустить. Отвечай ТОЛЬКО JSON-объектом плана, без пояснений и markdown-ограждений.";
const REFLECT_SYSTEM: &str = "Ты ведёшь адаптивный аудит кода. По результатам уже выполненных проверок реши, достаточно ли их, нужно ли довызвать ещё инструменты или безопасно починить найденное. Отвечай ТОЛЬКО JSON-объектом, без пояснений.";

/// Сколько раундов петли максимум (PLAN считается отдельно; это раунды EXECUTE).
const DEFAULT_BUDGET: usize = 4;
/// Максимум правок за fix-проход (как в autofix по умолчанию).
const MAX_FIX: usize = 8;
/// Сколько «пустых» рефлексий подряд (нет новых инструментов) обрывают петлю.
const DRY_LIMIT: usize = 2;

pub struct AgentOrchestrator;

impl AgentOrchestrator {
    /// Прогнать адаптивную петлю под намерение. `budget` — потолок раундов EXECUTE
    /// (0 → дефолт). Требует `sampler` (нейросеть IDE); при сбое плана откатывается на
    /// детерминированный безопасный набор (НЕ keyword-роутинг).
    pub fn run(
        reg: &Registry,
        ctx: &Ctx,
        input: &RunInput,
        intent: &str,
        sampler: &mut dyn Sampler,
        budget: usize,
    ) -> QualityLedger {
        let (pack, policy_note) = policy::load(&ctx.root);
        let budget = if budget == 0 { DEFAULT_BUDGET } else { budget };

        // ── PLAN ── нейросеть IDE решает, ЧТО запускать (и строгая ли это «сдача»).
        let prompt = plan_prompt(reg, ctx, intent);
        let plan = sampler
            .sample(PLAN_SYSTEM, &prompt)
            .map(|resp| parse_plan(&resp, reg))
            .unwrap_or_default();

        // Фолбэк: LLM не дал валидный план → детерминированный безопасный набор
        // (security+quality+доки), расширенный ПАСПОРТОМ проекта: у проекта с признаками
        // РФ и ПДн в набор входит комплаенс без каких-либо настроек. Это НЕ
        // keyword-роутинг — фиксированное безопасное умолчание, чтобы инструмент не
        // «молчал» при сбое модели.
        if plan.steps.is_empty() {
            let mut fams = vec![Family::Security, Family::Quality, Family::Spec];
            let prof = crate::profile::detect(&ctx.root);
            for f in prof.extra_families() {
                if !fams.contains(&f) {
                    fams.push(f);
                }
            }
            // Строгость фолбэка определяется ДЕТЕРМИНИРОВАННО по намерению, а не берётся
            // из пустого плана: при сбое sampling `plan` равен `AgentPlan::default()`, и
            // его `strict == false` терял бы строгий режим ровно на сдаче/релизе, то есть
            // там, где он важнее всего.
            let strict = plan.strict || strict_intent(intent);
            let mut ledger =
                Orchestrator::deterministic_gate(reg, ctx, input, intent, &fams, strict);
            ledger.rounds.push(format!(
                "⚠ LLM не дал план — детерминированный безопасный набор по паспорту ({})",
                prof.summary()
            ));
            return ledger;
        }

        // Активный набор инструментов; карта кода — всегда первой.
        let mut active: Vec<String> = vec!["code.intel/symbols".to_string()];
        for s in &plan.steps {
            if s.id != "code.intel/symbols" && !active.contains(&s.id) {
                active.push(s.id.clone());
            }
        }

        let mut rounds: Vec<String> = Vec::new();
        let mut extra_artifacts: Vec<String> = Vec::new();

        // ── ЧЕРТЕЖИ ДО КОДА ── для намерения-фичи сервер сам готовит комплект: спека с
        // критериями приёмки + ADR (spec/feature), запись в бэклоге, имя ветки. Агент
        // среды получает задание с чертежами, а не чистый лист. Мелкая доработка
        // (kind=change) и вопрос бюрократию не запускают.
        if plan.kind.trim().eq_ignore_ascii_case("feature") {
            let chain: &[(&str, &str)] = &[
                ("spec/feature", "спека и ADR"),
                ("backlog/add", "задача в бэклоге"),
                ("deliver/branch-name", "имя ветки"),
            ];
            let mut made: Vec<String> = Vec::new();
            let mut failed: Vec<String> = Vec::new();
            for (id, label) in chain {
                let Some(cap) = reg.get(id) else { continue };
                let di = RunInput {
                    target: None,
                    query: Some(intent.to_string()),
                };
                // Сбой capability НЕ глотается: он фиксируется в журнале раундов, чтобы
                // отсутствие спеки/задачи/ветки не выглядело так, будто их не заказывали
                // (инвариант «нет молчаливых пропусков»).
                match cap.run(ctx, &di) {
                    Ok(out) => {
                        extra_artifacts.extend(out.artifacts.iter().cloned());
                        let detail = out
                            .artifacts
                            .first()
                            .cloned()
                            .or_else(|| out.records.first().cloned())
                            .unwrap_or_else(|| out.summary.clone());
                        made.push(format!("{label}: {detail}"));
                    }
                    Err(e) => failed.push(format!("{label} ({id}): {e}")),
                }
            }
            if !made.is_empty() {
                rounds.push(format!("чертежи до кода — {}", made.join(" · ")));
            }
            if !failed.is_empty() {
                rounds.push(format!("⚠ чертежи до кода, сбои — {}", failed.join(" · ")));
            }
        }
        let mut dry = 0usize;
        // Последний прогон (collected, confirmed, refuted) — из него собираем вердикт.
        let mut last: Option<(CollectedRun, Vec<Finding>, usize)> = None;

        for round in 0..budget {
            // ── EXECUTE ── свежий полный прогон активного набора (находки замещаются,
            // не накапливаются — после fix файл меняется, состояние всегда актуально).
            let pipeline = build_pipeline(&active);
            let results = PipelineEngine::execute(reg, ctx, input, &pipeline);
            let collected = collect_results(results);
            // ── VERIFY ── состязательно отсеиваем ложные.
            let (confirmed, refuted) = Verifier::verify(ctx, collected.findings.clone());
            rounds.push(round_line(round, &collected, &confirmed));
            last = Some((collected, confirmed.clone(), refuted.len()));

            if round + 1 >= budget {
                break;
            }

            // ── REFLECT ── хватает ли? довызвать / починить / готово.
            let p = reflect_prompt(intent, &confirmed, plan.stop_when.as_deref(), round + 1);
            let decision = sampler
                .sample(REFLECT_SYSTEM, &p)
                .map(|r| parse_reflect(&r))
                .unwrap_or(Reflect::Done);

            match decision {
                Reflect::Done => break,
                Reflect::More(ids) => {
                    let new: Vec<String> = ids
                        .into_iter()
                        .filter(|i| reg.get(i).is_some() && !active.contains(i))
                        .collect();
                    if new.is_empty() {
                        dry += 1;
                        rounds.push("рефлексия: новых инструментов нет".into());
                        if dry >= DRY_LIMIT {
                            break;
                        }
                    } else {
                        rounds.push(format!("довызов: {}", new.join(", ")));
                        active.extend(new);
                        dry = 0;
                    }
                }
                Reflect::Fix => {
                    if plan.fix {
                        let rep = crate::autofix::run(reg, ctx, sampler, MAX_FIX);
                        rounds.push(format!(
                            "починка: исправлено {}, откатов {}",
                            rep.applied, rep.reverted
                        ));
                    } else {
                        rounds.push("рефлексия: запрошен fix, но он не разрешён планом".into());
                    }
                    dry = 0;
                }
            }
        }

        // Бюджет не меньше единицы, поэтому раунд всегда состоялся. Если по какой-то
        // причине его нет, честнее вернуть пустой вердикт, чем оборвать сеанс.
        let (collected, confirmed, refuted): (CollectedRun, Vec<Finding>, usize) =
            last.unwrap_or_default();

        // ── ФИНАЛЬНЫЙ ПРОХОД СДАЧИ ── на строгом намерении (сдача/релиз) сервер сам
        // приводит документы в порядок (идемпотентные авто-блоки из кода) и дописывает
        // ретро-ADR по детерминированному сигналу архитектурного изменения (сломан
        // публичный контракт). Черновик ADR формулирует нейросеть, если доступна;
        // иначе детерминированная формулировка. Вердикт гейта это не меняет.
        if plan.strict {
            let mut refreshed: Vec<&str> = Vec::new();
            let mut refresh_failed: Vec<String> = Vec::new();
            for id in ["generate/docs", "generate/spec", "generate/c4"] {
                if let Some(cap) = reg.get(id) {
                    // Сбой генератора фиксируется в журнале, а не глотается: на сдаче
                    // человек обязан видеть, что документы НЕ обновились и почему.
                    match cap.run(ctx, input) {
                        Ok(_) => refreshed.push(id),
                        Err(e) => refresh_failed.push(format!("{id}: {e}")),
                    }
                }
            }
            if !refreshed.is_empty() {
                rounds.push(format!(
                    "сдача: документы обновлены из кода ({})",
                    refreshed.join(", ")
                ));
            }
            if !refresh_failed.is_empty() {
                rounds.push(format!(
                    "⚠ сдача: документы НЕ обновились — {}",
                    refresh_failed.join(" · ")
                ));
            }
            let broke: Vec<&Finding> = confirmed
                .iter()
                .filter(|f| f.source == "verify/api-break")
                .collect();
            if !broke.is_empty() {
                let what: Vec<String> = broke.iter().take(5).map(|f| f.message.clone()).collect();
                let context = format!(
                    "Изменён публичный контракт: {}. Намерение: «{intent}».",
                    what.join("; ")
                );
                // Черновик решения: нейросеть формулирует, если доступна; иначе шаблон.
                let text = sampler
                    .sample(
                        "Сформулируй краткую запись архитектурного решения (ADR) по-русски: контекст, решение, последствия. Верни обычный текст без markdown-ограждений.",
                        &context,
                    )
                    .unwrap_or(context);
                if let Some(adr) = reg.get("generate/adr") {
                    let di = RunInput {
                        target: None,
                        query: Some(text),
                    };
                    match adr.run(ctx, &di) {
                        Ok(out) => {
                            extra_artifacts.extend(out.artifacts.iter().cloned());
                            rounds.push(format!("ретро-ADR: контракт изменился — {}", out.summary));
                        }
                        // Сбой фиксируется явно: слом контракта без записи решения не
                        // должен выглядеть так, будто ADR и не требовался.
                        Err(e) => rounds.push(format!("⚠ ретро-ADR не создан: {e}")),
                    }
                }
            }
        }

        let mut artifacts = collected.artifacts;
        artifacts.extend(extra_artifacts);

        // ── GATE ── детерминированный вердикт по подтверждённым находкам.
        finalize_ledger(
            ctx,
            &pack,
            policy_note,
            intent,
            LedgerInput {
                map_summary: collected.map_summary,
                confirmed,
                checks_run: collected.checks_run,
                checks_skipped: collected.checks_skipped,
                tools_failed: collected.tools_failed,
                artifacts,
                refuted,
                strict: plan.strict,
                rounds,
            },
        )
    }
}

fn build_pipeline(active: &[String]) -> Pipeline {
    Pipeline {
        name: "agent".into(),
        steps: active.iter().map(|id| Step::of(id)).collect(),
    }
}

fn round_line(round: usize, c: &CollectedRun, confirmed: &[Finding]) -> String {
    format!(
        "раунд {}: выполнено {} проверок, находок {} (подтверждено {}), пропущено {}",
        round + 1,
        c.checks_run.len(),
        c.findings.len(),
        confirmed.len(),
        c.checks_skipped.len()
    )
}

/// Промпт PLAN: каталог инструментов + стек проекта + намерение → JSON-план.
fn plan_prompt(reg: &Registry, ctx: &Ctx, intent: &str) -> String {
    let mut p = String::from("Доступные инструменты (id — когда применять):\n");
    for m in reg.manifests() {
        p.push_str(&format!("- {}: {}\n", m.id, m.when_to_use));
    }
    p.push_str(&format!(
        "\nКонтекст проекта: {}\n",
        project_context(&ctx.root)
    ));
    p.push_str("\nНамерение пользователя: «");
    p.push_str(intent);
    p.push_str(
        "»\n\nВерни ТОЛЬКО JSON-объект плана: \
        {\"steps\":[{\"id\":\"<id из списка>\",\"why\":\"<зачем, кратко>\"}],\
        \"kind\":\"feature|change|question\" (feature — просят НОВУЮ функциональность, \
        сервер сначала подготовит спеку и ADR; change — доработка/проверка существующего; \
        question — просто вопрос),\
        \"strict\":<true если это сдача/релиз/выкат/мерж в прод>,\
        \"fix\":<true если можно безопасно чинить формат/линт>,\
        \"stop_when\":\"<критерий, когда проверок достаточно>\"}. \
        Бери только id из списка, подходящие под стек проекта.",
    );
    p
}

/// Краткий детерминированный контекст: какой стек распознан (единый источник `stack`).
fn project_context(root: &std::path::Path) -> String {
    let found = crate::stack::detect(root);
    if found.is_empty() {
        "манифесты сборки не обнаружены (стек неизвестен)".to_string()
    } else {
        format!("стек: {}", found.join(", "))
    }
}

/// Разбор плана: достать JSON-объект из ответа, распарсить, оставить только
/// существующие id инструментов (защита от галлюцинаций модели).
fn parse_plan(resp: &str, reg: &Registry) -> AgentPlan {
    let Some(json) = extract_object(resp) else {
        return AgentPlan::default();
    };
    let mut plan: AgentPlan = serde_json::from_str(json).unwrap_or_default();
    plan.steps.retain(|s| reg.get(&s.id).is_some());
    plan
}

/// Промпт REFLECT: текущие подтверждённые находки + критерий достаточности → решение.
fn reflect_prompt(
    intent: &str,
    confirmed: &[Finding],
    stop_when: Option<&str>,
    round: usize,
) -> String {
    let mut p = format!(
        "Намерение: «{intent}». Раунд {round}.\nПодтверждённые находки ({}):\n",
        confirmed.len()
    );
    for f in confirmed.iter().take(20) {
        let loc = f
            .location
            .as_ref()
            .map(|l| format!(" {}:{}", l.file, l.line))
            .unwrap_or_default();
        p.push_str(&format!(
            "- [{}] {} — {}{}\n",
            f.severity, f.rule, f.message, loc
        ));
    }
    if confirmed.is_empty() {
        p.push_str("(находок нет)\n");
    }
    if let Some(sw) = stop_when {
        p.push_str(&format!("\nКритерий достаточности: {sw}\n"));
    }
    p.push_str(
        "\nРеши, что дальше. Верни ТОЛЬКО JSON: \
        {\"action\":\"done|more|fix\",\"more\":[\"<id инструмента, если action=more>\"]}. \
        done — проверок достаточно; more — нужно довызвать ещё инструменты; \
        fix — безопасно починить найденное и перепроверить.",
    );
    p
}

enum Reflect {
    Done,
    More(Vec<String>),
    Fix,
}

#[derive(Deserialize, Default)]
struct ReflectRaw {
    #[serde(default)]
    action: String,
    #[serde(default)]
    more: Vec<String>,
}

fn parse_reflect(resp: &str) -> Reflect {
    let Some(json) = extract_object(resp) else {
        return Reflect::Done;
    };
    let raw: ReflectRaw = serde_json::from_str(json).unwrap_or_default();
    match raw.action.trim().to_lowercase().as_str() {
        "more" => Reflect::More(raw.more),
        "fix" => Reflect::Fix,
        _ => Reflect::Done,
    }
}

/// Строгое ли намерение («сдача»): детерминированная эвристика по простым маркерам
/// сдачи/релиза/выката. Используется ТОЛЬКО фолбэком при сбое sampling или невалидном
/// ответе плана: штатно строгость решает нейросеть на фазе PLAN. Без этой эвристики
/// фолбэк терял строгий режим ровно на сдаче, где он важнее всего.
fn strict_intent(intent: &str) -> bool {
    let s = intent.to_lowercase();
    const MARKERS: &[&str] = &[
        "сдач",
        "сдать",
        "сдаю",
        "релиз",
        "выкат",
        "выклад",
        "прод",
        "мерж",
        "слить",
        "release",
        "ship",
        "deploy",
        "merge",
        "prod",
    ];
    MARKERS.iter().any(|m| s.contains(m))
}

/// Достать первый ПОЛНЫЙ JSON-объект `{ … }` из ответа модели (терпимо к обрамлению и
/// прозе ДО и ПОСЛЕ объекта). Поиск балансный: счётчик фигурных скобок с учётом строковых
/// литералов и экранирования. Прежний срез «от первого `{` до последнего `}`» ломался на
/// прозе после объекта, если в ней встречалась закрывающая скобка: в срез попадал мусор, и
/// валидный план не разбирался.
fn extract_object(s: &str) -> Option<&str> {
    let start = s.find('{')?;
    let bytes = s.as_bytes();
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    for (i, &c) in bytes.iter().enumerate().skip(start) {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[start..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_object_балансный_поиск_терпит_прозу_после_объекта() {
        // Проза после объекта содержит закрывающую скобку: прежний срез до ПОСЛЕДНЕЙ `}`
        // захватывал мусор, и план не разбирался.
        let resp = r#"Вот план: {"steps":[{"id":"a","why":"b"}],"strict":true} (см. блок {выше})"#;
        let json = extract_object(resp).expect("объект найден");
        assert_eq!(json, r#"{"steps":[{"id":"a","why":"b"}],"strict":true}"#);
        assert!(serde_json::from_str::<serde_json::Value>(json).is_ok());
    }

    #[test]
    fn extract_object_учитывает_скобки_в_строковых_литералах() {
        let resp = r#"{"note":"скобка } в строке","x":1} хвост"#;
        let json = extract_object(resp).expect("объект найден");
        assert_eq!(json, r#"{"note":"скобка } в строке","x":1}"#);
        // Экранированная кавычка внутри строки не сбивает разбор.
        let resp2 = r#"{"a":"\"}","b":2} и ещё"#;
        assert_eq!(extract_object(resp2), Some(r#"{"a":"\"}","b":2}"#));
    }

    #[test]
    fn extract_object_незакрытый_объект_не_извлекается() {
        assert_eq!(extract_object(r#"{"a": 1"#), None);
        assert_eq!(extract_object("проза без объекта"), None);
    }

    #[test]
    fn strict_intent_распознаёт_маркеры_сдачи() {
        assert!(strict_intent("проверь всё перед сдачей"));
        assert!(strict_intent("готовим релиз 1.2"));
        assert!(strict_intent("можно мержить в прод?"));
        assert!(strict_intent("ready to ship / deploy"));
        assert!(!strict_intent("посмотри качество кода"));
        assert!(!strict_intent("найди запахи в модуле"));
    }
}
