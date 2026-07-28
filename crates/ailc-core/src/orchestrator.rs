//! Оркестратор — детерминированные прогоны и сборка вердикта (QualityLedger).
//!
//! Адаптивная LLM-петля (PLAN→EXECUTE→REFLECT→FIX) живёт в `crate::agent`. Здесь:
//!   • `deterministic_gate` — прогон фиксированных семейств без LLM/keyword (custodian,
//!     бенчмарк, фолбэк агента);
//!   • `scan_all` — сплошной скан для отчётов (SARIF);
//!   • `dod` — многоосевой Definition of Done;
//!   • общие хелперы сборки вердикта (`collect_results`, `finalize_ledger`), которые
//!     переиспользует агент.
//!
//! Маршрутизация по ключевым словам УДАЛЕНА: ЧТО запускать под намерение решает
//! нейросеть IDE (`crate::agent`), а не хардкод. Гарантию по-прежнему даёт гейт.

use crate::engines::gate::{GateRunner, SECURITY_FLOOR_IDS, SECURITY_FLOOR_TIMEOUT};
use crate::pipeline::{Pipeline, PipelineEngine, Step, StepResult};
use crate::policy;
use crate::registry::Registry;
use ailc_contracts::{
    CapabilityOutput, CheckOutcome, Ctx, Family, Finding, GateReport, PolicyPack, QualityLedger,
    RunInput, Severity, Tier,
};
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;

// Бюджет времени и состав детерминированного пола безопасности (глубокий SAST/taint)
// определены в ОДНОМ месте, в `engines::gate` (`SECURITY_FLOOR_IDS` и
// `SECURITY_FLOOR_TIMEOUT`), и импортируются сюда. Прежде здесь жили копии с другим
// таймаутом (180 против 120 секунд в гейте), и один и тот же анализатор получал разный
// бюджет в зависимости от пути вызова.

/// Доступ к LLM (модель клиента через MCP sampling). Реализуется транспортом
/// (бинарём), ядро от транспорта не зависит. Используется агентом и автофиксом.
pub trait Sampler {
    /// Запросить у LLM ответ. None = sampling недоступен/ошибка.
    fn sample(&mut self, system: &str, user: &str) -> Option<String>;
}

// ───────────────────── Общие хелперы (агент + детерминированные прогоны) ─────────────────────

/// Свёртка результатов шагов пайплайна: находки (до verify), что выполнено, что
/// пропущено (с причиной), артефакты генераторов и сводка-карта кода.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct CollectedRun {
    pub findings: Vec<Finding>,
    pub checks_run: Vec<String>,
    pub checks_skipped: Vec<(String, String)>,
    /// Сбои инструмента (шаг не смог выполниться: ошибка, паника, таймаут). Отдельно от
    /// осознанных пропусков, потому что различие меняет вердикт (см. `GateReport`).
    pub tools_failed: Vec<(String, String)>,
    pub artifacts: Vec<String>,
    pub map_summary: String,
}

/// Свернуть результаты шагов в `CollectedRun`. Инвариант «нет молчаливых пропусков»:
/// ошибка/skip → причина; генератор-артефакт без находок проверкой НЕ считается.
pub(crate) fn collect_results(results: Vec<StepResult>) -> CollectedRun {
    let mut c = CollectedRun::default();
    for r in results {
        let cap = r.capability;
        let out = r.output;
        let produced_artifact = !out.artifacts.is_empty();

        if cap == "code.intel/symbols" {
            if r.error.is_none() {
                c.map_summary = out.summary;
            }
            continue;
        }
        c.artifacts.extend(out.artifacts);

        if let Some(e) = r.error {
            // Шаг не выполнился (ошибка capability, паника, превышение лимита времени). Это
            // СБОЙ ИНСТРУМЕНТА, а не осознанный пропуск: результата нет, и вердикт «чисто»
            // на таком шаге неправомерен. Пишем в оба списка: в первый для перечня
            // непройденного человеку, во второй для вычисления вердикта.
            c.checks_skipped.push((cap.clone(), format!("ошибка: {e}")));
            c.tools_failed.push((cap, e));
        } else if let Some(reason) = out.skipped {
            c.checks_skipped.push((cap, reason));
        } else if produced_artifact && out.findings.is_empty() {
            // Генератор: создал файл, не проверка — не считаем «проверкой».
        } else {
            c.checks_run.push(cap);
            c.findings.extend(out.findings);
        }
    }
    c
}

/// Вход сборки вердикта: уже верифицированные находки + контекст прогона.
pub(crate) struct LedgerInput {
    pub map_summary: String,
    pub confirmed: Vec<Finding>,
    pub checks_run: Vec<String>,
    pub checks_skipped: Vec<(String, String)>,
    /// Сбои инструмента: снимают вердикт, в отличие от осознанных пропусков.
    pub tools_failed: Vec<(String, String)>,
    pub artifacts: Vec<String>,
    pub refuted: usize,
    /// «Сдача» (строгий режим): недоделанное/дрейф доков БЛОКИРУЮТ, а не предупреждают.
    /// Решает агент (нейросеть IDE) на фазе PLAN — больше не keyword.
    pub strict: bool,
    pub rounds: Vec<String>,
}

/// Финализация вердикта: rigor → гейт (классификация по политике) → строгость
/// (`escalate_unfinished` при strict) → `QualityLedger`. ЕДИНСТВЕННОЕ место сборки —
/// общее для агента и детерминированных прогонов.
pub(crate) fn finalize_ledger(
    ctx: &Ctx,
    pack: &PolicyPack,
    policy_note: Option<String>,
    intent: &str,
    inp: LedgerInput,
) -> QualityLedger {
    let mut ledger = QualityLedger {
        project: ctx.root.display().to_string(),
        intent: intent.to_string(),
        policy_name: pack.name.clone(),
        map_summary: inp.map_summary,
        artifacts: inp.artifacts,
        rounds: inp.rounds,
        refuted: inp.refuted,
        ..Default::default()
    };

    // Rigor Score — тщательность: доля реально выполненных проверок из попытанных.
    let attempted = inp.checks_run.len() + inp.checks_skipped.len();
    ledger.rigor = if inp.checks_run.is_empty() {
        0.0
    } else {
        100.0 * inp.checks_run.len() as f64 / attempted as f64
    };

    // Базовая линия долга применяется ЗДЕСЬ, то есть в единственном месте сборки вердикта,
    // а не только в пути Definition of Done. Прежде адаптивный прогон `plan` её не учитывал,
    // и один и тот же набор находок давал два разных ответа: `dod` сообщал, что сдавать
    // можно, а `plan` в тот же момент насчитывал блокеры. Для продукта, ценность которого
    // состоит в детерминированном вердикте, такое расхождение подрывает доверие сильнее
    // любого отдельного правила. Уязвимости в долг не уходят никогда (см. `baseline`).
    let base = crate::baseline::load(ctx);
    let (confirmed, debt) = crate::baseline::split(&base, inp.confirmed);
    ledger.debt = debt.len();

    // Гейт: классификация подтверждённых находок по политике (порог из governance).
    let mut report = GateRunner::classify(
        confirmed,
        inp.checks_run,
        inp.checks_skipped,
        inp.tools_failed,
        &pack.gate,
        &pack.thresholds,
    );
    // «Сдача» строже: недоделанное блокирует, а не просто предупреждает.
    if inp.strict {
        GateRunner::escalate_unfinished(&mut report);
    }
    ledger.checks_run = report.checks_run.len();
    ledger.checks = report.checks_run.clone();
    ledger.blocking = report.blocking.len();
    ledger.warning = report.warning.len();
    ledger.findings_total = ledger.blocking + ledger.warning;
    ledger.score = report.score;
    ledger.passed = report.passed;
    ledger.checks_skipped = report.checks_skipped.clone();
    // Инвариант «нет молчаливых пропусков»: битая policy не молча подменяется дефолтом.
    if let Some(n) = policy_note {
        if n.starts_with('⚠') {
            ledger.checks_skipped.push(("governance".to_string(), n));
        }
    }

    for f in report.blocking.iter().take(8) {
        let loc = f
            .location
            .as_ref()
            .map(|l| format!(" ({}:{})", l.file, l.line))
            .unwrap_or_default();
        ledger.open_decisions.push(format!(
            "{}{loc} — поправь это или подтверди, что не проблема",
            f.message
        ));
    }
    for f in report.advisories.iter() {
        ledger.advisories.push(f.message.clone());
    }
    ledger.advisories.truncate(6);

    ledger.tests = test_status(&report, inp.strict);
    ledger.headline = headline(&ledger);
    ledger
}

pub(crate) fn test_status(report: &GateReport, serious: bool) -> Option<String> {
    use crate::i18n::t;
    if report.checks_run.iter().any(|id| id == "verify/test") {
        let failed = report
            .blocking
            .iter()
            .chain(report.warning.iter())
            .any(|f| f.source == "verify/test");
        Some(if failed {
            t("❌ падают", "❌ failing").into()
        } else {
            t("✅ прошли", "✅ passing").into()
        })
    } else if let Some((_, reason)) = report
        .checks_skipped
        .iter()
        .find(|(id, _)| id == "verify/test")
    {
        Some(format!("⚠ {reason}"))
    } else if serious {
        Some(t("⚠ не запускались", "⚠ not run").into())
    } else {
        None
    }
}

pub(crate) fn headline(l: &QualityLedger) -> String {
    use crate::i18n::{t, Lang};
    let ru = crate::i18n::lang() == Lang::Ru;
    let tests = l
        .tests
        .as_ref()
        .map(|tt| format!(" {}: {tt}.", t("Тесты", "Tests")))
        .unwrap_or_default();
    if l.passed {
        // Честность: ноль выполненных проверок — это НЕ подтверждённое качество.
        if l.checks_run == 0 {
            if !l.checks_skipped.is_empty() {
                let n = l.checks_skipped.len();
                return if ru {
                    format!("⚠ Качество НЕ подтверждено: ни одна проверка не выполнилась ({n} пропущено).{tests}")
                } else {
                    format!("⚠ Quality NOT confirmed: no check ran ({n} skipped).{tests}")
                };
            }
            if !l.artifacts.is_empty() {
                let n = l.artifacts.len();
                return if ru {
                    format!("✅ Артефакты созданы ({n}). Проверки качества не выполнялись — балл не присваивается.{tests}")
                } else {
                    format!("✅ Artifacts created ({n}). No quality checks ran — no score assigned.{tests}")
                };
            }
            return if ru {
                format!("⚠ Качество НЕ подтверждено: проверки не выполнялись.{tests}")
            } else {
                format!("⚠ Quality NOT confirmed: no checks ran.{tests}")
            };
        }
        if ru {
            format!(
                "✅ Готово к сдаче. Качество {:.0}/100, прошло {} проверок, блокеров нет.{tests}",
                l.score, l.checks_run
            )
        } else {
            format!(
                "✅ Ready to ship. Quality {:.0}/100, {} checks passed, no blockers.{tests}",
                l.score, l.checks_run
            )
        }
    } else if ru {
        format!("❌ Пока отдавать нельзя. Качество {:.0}/100, {} блокер(ов) требуют твоего решения.{tests}", l.score, l.blocking)
    } else {
        format!(
            "❌ Not ready to ship. Quality {:.0}/100, {} blocker(s) need your decision.{tests}",
            l.score, l.blocking
        )
    }
}

pub struct Orchestrator;

impl Orchestrator {
    /// Детерминированный прогон фиксированных семейств (БЕЗ LLM/keyword): обойти все
    /// не-мутирующие Core-capability нужных семейств → выполнить (DAG, параллельно) →
    /// состязательно опровергнуть ложные → вердикт. Замена прежнего RecipePlanner для
    /// custodian/бенчмарка и ФОЛБЭК агента, когда LLM не дал план. Маршрут не из
    /// намерения, а из явного списка семейств — поэтому работает офлайн.
    pub fn deterministic_gate(
        reg: &Registry,
        ctx: &Ctx,
        input: &RunInput,
        intent: &str,
        families: &[Family],
        strict: bool,
    ) -> QualityLedger {
        let (pack, policy_note) = policy::load(&ctx.root);
        let mut ids: Vec<String> = vec!["code.intel/symbols".to_string()];
        for m in reg.manifests() {
            if !m.mutates && m.tier == Tier::Core && families.contains(&m.family) {
                ids.push(m.id.to_string());
            }
        }
        ids.dedup();
        let pipeline = Pipeline {
            name: "deterministic".into(),
            steps: ids.iter().map(|id| Step::of(id)).collect(),
        };
        let collected = Self::cached_run(ctx, input, &ids, || {
            collect_results(PipelineEngine::execute(reg, ctx, input, &pipeline))
        });
        let (confirmed, refuted) = crate::verify::Verifier::verify(ctx, collected.findings);
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
                artifacts: collected.artifacts,
                refuted: refuted.len(),
                strict,
                rounds: Vec::new(),
            },
        )
    }

    /// Прогон набора проверок с кэшем по отпечатку дерева.
    ///
    /// Кэшируется только СТАТИЧЕСКАЯ часть: набор идентификаторов входит в ключ, а
    /// проверки семейства verify (тесты, линт, покрытие) в гейтовый прогон не попадают и
    /// выполняются отдельно, поэтому закэшировать «зелёные тесты» невозможно по устройству.
    /// При любом расхождении отпечатка выполняется полный прогон.
    fn cached_run(
        ctx: &Ctx,
        input: &RunInput,
        ids: &[String],
        run: impl FnOnce() -> CollectedRun,
    ) -> CollectedRun {
        let key = input
            .target
            .is_none()
            .then(|| crate::cache::fingerprint(ctx))
            .flatten()
            .map(|f| format!("{f}|{}", ids.join(",")));
        if let Some(k) = &key {
            if let Some(hit) = crate::cache::load_run(ctx, k) {
                return hit;
            }
        }
        let fresh = run();
        if let Some(k) = &key {
            let _ = crate::cache::save_run(ctx, k, &fresh);
        }
        fresh
    }

    /// Прогон ЗАЯВЛЕННОГО плана (инверсия адаптивной петли для клиентов без sampling):
    /// роль планировщика играет сама модель агента среды, она выбирает инструменты
    /// (через find_capability или список tools) и передаёт их id, а сервер выполняет
    /// EXECUTE, VERIFY и GATE. Инвариант сохраняется: ЧТО запускать решает нейросеть
    /// (пусть и клиентская), вердикт PASS/FAIL выносит детерминированный гейт.
    /// Неизвестные id не глотаются молча, а попадают в пропущенные с причиной.
    pub fn declared_gate(
        reg: &Registry,
        ctx: &Ctx,
        input: &RunInput,
        intent: &str,
        step_ids: &[String],
        strict: bool,
    ) -> QualityLedger {
        let (pack, policy_note) = policy::load(&ctx.root);
        let mut ids: Vec<String> = vec!["code.intel/symbols".to_string()];
        let mut unknown: Vec<(String, String)> = Vec::new();
        for id in step_ids {
            if reg.get(id).is_none() {
                unknown.push((
                    id.clone(),
                    "нет такого инструмента (актуальный id возьми из find_capability)".to_string(),
                ));
            } else if !ids.contains(id) {
                ids.push(id.clone());
            }
        }
        let pipeline = Pipeline {
            name: "declared".into(),
            steps: ids.iter().map(|id| Step::of(id)).collect(),
        };
        let results = PipelineEngine::execute(reg, ctx, input, &pipeline);
        let mut collected = collect_results(results);
        collected.checks_skipped.extend(unknown);
        let (confirmed, refuted) = crate::verify::Verifier::verify(ctx, collected.findings);
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
                artifacts: collected.artifacts,
                refuted: refuted.len(),
                strict,
                rounds: vec![format!(
                    "план агента среды: заявлено шагов {} (петлю ведёт клиентская модель, sampling не нужен)",
                    step_ids.len()
                )],
            },
        )
    }
}

// ───────────────────────── Сплошной скан для отчётов (SARIF) ─────────────────────────

/// Результат сплошного статического скана: подтверждённые находки (ложные отсеяны),
/// сколько опровергнуто Verifier'ом, и какие проверки выполнены/пропущены.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    /// Сколько находок ОПРОВЕРГНУТО как ложные (комментарий, плейсхолдер, определение
    /// шаблона поиска). Это вывод инструмента о ложности находки.
    pub refuted: usize,
    /// Сколько находок ПОДАВЛЕНО решением человека (маркер `ailc:ignore`). Считается
    /// отдельно от `refuted` намеренно: подавление это сокрытие НАСТОЯЩЕЙ находки, и
    /// складывать его в счётчик «ложные срабатывания, опровергнутые верификатором» значит
    /// выдавать одно за другое. Читатель отчёта обязан видеть, что часть находок не
    /// исчезла, а была скрыта, и в каком объёме.
    pub suppressed: usize,
    pub checks_run: Vec<String>,
    pub checks_skipped: Vec<(String, String)>,
    /// Служебные заметки о прогоне (например, «результат взят из кэша»). Отдельное поле,
    /// а не элемент `checks_run`: тот является чистым списком идентификаторов capability,
    /// и потребители (SARIF, счётчики) не обязаны фильтровать из него прозу.
    #[serde(default)]
    pub notes: Vec<String>,
}

impl Orchestrator {
    /// Сплошной статический скан Security/Quality/Compliance/Spec (Core): гонит все
    /// не-мутирующие проверки этих семейств, состязательно опровергает ложные находки
    /// Verifier'ом и возвращает только подтверждённые. Без intent-роутинга —
    /// исчерпывающее покрытие для отчётов (SARIF) и CI.
    pub fn scan_all(reg: &Registry, ctx: &Ctx, input: &RunInput) -> ScanReport {
        // Инкрементальность: если дерево, политика и версия бинаря не изменились с
        // прошлого прогона, результат берётся из кэша. Кэш применяется только при
        // ПОЛНОМ совпадении отпечатка, поэтому ускоряет повторный вызов и не способен
        // подменить вердикт (см. модуль `cache`). Прогон по подпути не кэшируется:
        // отпечаток снимается со всего дерева и для частичного скана несопоставим.
        let cache_key = input
            .target
            .is_none()
            .then(|| crate::cache::fingerprint(ctx))
            .flatten();
        if let Some(key) = &cache_key {
            // Восстанавливается ОТЧЁТ ЦЕЛИКОМ, включая реальный состав выполненных проверок,
            // пропуски, число опровергнутых и подавленных. Прежде здесь достраивались
            // константы («выполнена одна проверка кэш прогона», «пропусков нет»), из-за чего
            // отчёт SARIF в системе сборки утверждал отсутствие пропусков, стирая пропуски
            // того прогона, результат которого и переиспользуется.
            if let Some(mut report) = crate::cache::load::<ScanReport>(ctx, key) {
                // Пометка о переиспользовании идёт в СЛУЖЕБНЫЕ ЗАМЕТКИ, а не в `checks_run`:
                // тот остаётся чистым списком идентификаторов выполненных проверок, и
                // счётчики/SARIF не получают в нём элемент-прозу. Человек при этом видит и
                // то, что прогон взят из кэша, и его реальный состав.
                report
                    .notes
                    .push("результат взят из кэша: дерево не изменилось".to_string());
                return report;
            }
        }

        // СЕМЕЙСТВО `Verify` ВКЛЮЧЕНО В ОХВАТ. Его отсутствие было дырой в отчёте: проверки
        // `verify/desktop` и `verify/mobile` эмитят находки важности Critical (оболочка
        // Electron с включённой интеграцией Node, разрешённый незашифрованный трафик), а
        // `verify/api-break` сообщает о сломанном публичном контракте, и ничего из этого не
        // попадало в отчёт SARIF для системы сборки. Мутирующие capability по-прежнему
        // исключены проверкой `m.mutates` ниже, поэтому сплошной скан остаётся безопасным
        // для рабочего дерева и ничего в нём не меняет.
        let families = [
            Family::Security,
            Family::Quality,
            Family::Compliance,
            Family::Spec,
            Family::Verify,
        ];
        let mut findings = Vec::new();
        let mut checks_run = Vec::new();
        let mut checks_skipped = Vec::new();
        for cap in reg.all() {
            let m = cap.manifest();
            // Защитный минимум (sast/taint) включается ПО ИДЕНТИФИКАТОРУ, даже будучи
            // Tier::Enterprise: иначе полный скан и SARIF недосчитывают потоковые
            // уязвимости, которые гейт и dod уже учитывают (см. SECURITY_FLOOR_IDS).
            let is_floor = SECURITY_FLOOR_IDS.contains(&m.id);
            if m.mutates || (m.tier != Tier::Core && !is_floor) || !families.contains(&m.family) {
                continue;
            }
            match cap.run(ctx, input) {
                Ok(out) => {
                    // НАХОДКИ ЗАБИРАЮТСЯ ВСЕГДА, даже когда capability одновременно сообщила
                    // о пропуске. Прежде ветки были взаимоисключающими, и признак пропуска
                    // отбрасывал ВСЕ находки этой capability. Так теряются реальные данные:
                    // проверка настольных оболочек и мобильной конфигурации выставляют
                    // признак пропуска при отказе движка на ОДНОЙ из своих осей, уже собрав
                    // находки по остальным. Пропуск и находки не исключают друг друга:
                    // первое говорит о неполноте охвата, второе о том, что успели найти.
                    let skipped = out.skipped;
                    if !out.findings.is_empty() {
                        findings.extend(out.findings);
                    }
                    match skipped {
                        Some(reason) => checks_skipped.push((m.id.to_string(), reason)),
                        None => checks_run.push(m.id.to_string()),
                    }
                }
                Err(e) => checks_skipped.push((m.id.to_string(), format!("ошибка: {e}"))),
            }
        }
        // Verify-максимализм: те же гарантии, что и в гейте — в отчёт идут только выжившие.
        let (confirmed, refuted) = crate::verify::Verifier::verify(ctx, findings);
        // Дедуп по (правило, файл, строка): одно место, найденное правилами-дублями из
        // разных capability (ssrf-internal-host/ssti/cors-* определены и в owasp, и в
        // web_security), это ОДНА находка. Системно убирает двойной счёт без потери данных.
        let confirmed = Self::dedup_findings(confirmed);
        // Подавленное решением человека отделяем от опровергнутого как ложного: см.
        // документацию полей `refuted` и `suppressed` у `ScanReport`.
        let suppressed = refuted
            .iter()
            .filter(|(_, r)| crate::verify::is_inline_suppression(r))
            .count();
        let report = ScanReport {
            findings: confirmed,
            refuted: refuted.len() - suppressed,
            suppressed,
            checks_run,
            checks_skipped,
            notes: Vec::new(),
        };
        // Запись кэша: сбой (нет прав, том только для чтения) намеренно игнорируется —
        // кэш является ускорением, и его недоступность не должна мешать проверке.
        if let Some(key) = &cache_key {
            let _ = crate::cache::save(ctx, key, &report);
        }
        report
    }

    /// Дедупликация находок по (правило, файл, строка). Находки без локации сохраняются все
    /// (их нельзя надёжно сопоставить). Порядок сохраняется, остаётся первое вхождение.
    fn dedup_findings(findings: Vec<Finding>) -> Vec<Finding> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::with_capacity(findings.len());
        for f in findings {
            match f.location.as_ref() {
                Some(l) if !seen.insert((f.rule.clone(), l.file.clone(), l.line)) => continue,
                _ => out.push(f),
            }
        }
        out
    }
}

// ───────────────────────── DoD: многоосевой вердикт «готово?» ─────────────────────────

pub struct DodAxis {
    pub name: &'static str,
    pub hard: bool,
    pub ran: bool,
    pub findings: usize,
    pub high: usize,
    pub ok: bool,
    /// Сколько находок по этой оси опровергнуто верификатором как ложные
    /// (комментарии/плейсхолдеры/шаблоны). Для оси «Секреты» ненулевое значение
    /// означает: токены были, но отброшены эвристикой, поэтому «находок: 0» не равно
    /// «секретов нет», требуется ручная проверка (см. T03). Заполняется там, где
    /// верификатор доступен; иначе остаётся 0.
    pub refuted: usize,
    /// Сколько файлов осталось вне охвата проверки (скрытые/непросканированные). Для
    /// оси «Секреты» ненулевое значение понижает уверенность вердикта: чистый результат
    /// при неполном охвате не является доказательством отсутствия секретов (см. T03).
    pub out_of_scope: u64,
    /// Причина, по которой ось не выполнилась (осознанный пропуск или сбой инструмента).
    /// `None`, когда ось реально выполнена. Делает различимыми «не запускалось» и
    /// «выполнено, находок нет» в человекочитаемом вердикте (см. T85/T86).
    pub not_run_reason: Option<String>,
}

pub struct DodReport {
    pub axes: Vec<DodAxis>,
    /// Сдача разрешена. ВНИМАНИЕ: это итоговый строгий вердикт, а не просто «нет
    /// проваленных hard-осей». Он равен `false`, если хотя бы одна hard-ось не
    /// выполнялась (пропуск/сбой инструмента) или охват нулевой, даже когда ни одна
    /// выполненная hard-ось не провалена (см. T85). Так печать вердикта, читающая
    /// `passed`, не выдаёт «можно сдавать» при незапущенных ключевых проверках без
    /// правок на стороне вызывающего кода.
    pub passed: bool,
    /// Подтверждённый вердикт: третье состояние помимо «прошло»/«провалено». Истинно
    /// только когда все hard-оси РЕАЛЬНО выполнились и ни одна не провалена при
    /// ненулевом охвате. Семантически совпадает с `passed`, но назван явно для нового
    /// кода, чтобы отличать «подтверждённое качество» от «проблем не найдено, но
    /// ключевые проверки не запускались» (см. T03/T85).
    pub confirmed: bool,
    /// Список hard-осей, которые НЕ выполнились (пропуск тулчейна, сбой инструмента,
    /// нулевой охват). Непустой список означает «НЕ подтверждено: ключевые проверки не
    /// запускались» и перечисляет, какие именно (см. T85). Пуст при подтверждённом
    /// вердикте.
    pub hard_not_run: Vec<&'static str>,
    /// Охват нулевой: ни одна проверка не выполнилась (пустой/несорсовый репозиторий).
    /// Такой репозиторий не имеет права давать вердикт «можно сдавать» (см. T85).
    pub zero_coverage: bool,
    /// Замороженный долг: сколько находок отфильтровано базовой линией (`.ailc/baseline`).
    /// Ноль и при отсутствии линии, и при полностью погашенном долге; наличие линии
    /// различается через `baseline_frozen`.
    pub debt: usize,
    /// Базовая линия зафиксирована (перемирие с легаси действует).
    pub baseline_frozen: bool,
    /// Заметка о загруженной политике: какая политика применена и, что важнее, чем она
    /// подозрительна (не разобралась, не прошла проверку контрольной суммы, ослаблена
    /// относительно организационного дефолта).
    ///
    /// Поле существует потому, что прежде заметка выбрасывалась ИМЕННО на путях вердикта
    /// (`let (pack, _note) = ...` в `dod` и в гейте), то есть ровно там, где её обязан
    /// увидеть человек и система сборки. В результате подменённая или ослабленная политика
    /// применялась молча, и вердикт выглядел обычным.
    pub policy_note: Option<String>,
}

impl Orchestrator {
    /// Исполняемый Definition of Done: гонит набор проверок и даёт вердикт по КАЖДОЙ
    /// оси (✓/✗/не выполнялась). Hard-оси блокируют общий вердикт. Композиция готовых
    /// детекторов — «готово» становится проверяемым, а не мнением.
    ///
    /// Вердикт имеет ТРИ состояния (см. T85/T03): «подтверждено, можно сдавать»
    /// (`confirmed == true`), «провалено, есть блокеры» (выполненная hard-ось дала
    /// находки) и «НЕ подтверждено» (хотя бы одна hard-ось не выполнялась либо охват
    /// нулевой). Третье состояние не даёт пустому/несорсовому репозиторию или
    /// прогону без тулчейна выдать ложно-зелёный вердикт.
    pub fn dod(reg: &Registry, ctx: &Ctx, input: &RunInput) -> DodReport {
        let (pack, policy_note) = policy::load(&ctx.root);
        // Паспорт проекта: от него зависит, какие профильные оси считать жёсткими
        // (доступность у UI-проекта, комплаенс у проекта с признаками РФ и ПДн,
        // безопасность ИИ у проекта с LLM). Дёшев, вычисляется на каждый прогон.
        let prof = crate::profile::detect(&ctx.root);
        // Базовая линия долга: находки из неё НЕ блокируют сдачу (перемирие с легаси),
        // а считаются отдельно. Долг применяется только к статическим находкам; оси
        // verify (тесты/линт) под долг не попадают — тесты обязаны проходить всегда.
        let base = crate::baseline::load(ctx);
        let mut debt = 0usize;
        let mut policy = pack.gate;
        // Семейства, которые гейт собирает САМ: Security/Quality (находки осей),
        // Spec (дрейф доков) и Compliance (РФ). Семейство Verify СОЗНАТЕЛЬНО исключаем
        // из гейтового прогона: verify-оси (test/lint/coverage/api-break) исполняются
        // НАПРЯМУЮ ниже ради корректной классификации исхода и позитивного доказательства
        // тестов (см. T86), а двойной прогон дорогого внешнего раннера недопустим.
        // Verify, если он попал в загруженную политику, для этого внутреннего прогона
        // убираем (пользовательскую политику на диске это не меняет).
        policy.families.retain(|f| *f != Family::Verify);
        for fam in [Family::Security, Family::Quality, Family::Compliance] {
            if !policy.families.contains(&fam) {
                policy.families.push(fam);
            }
        }
        // Spec нужен для оси дрейфа доков: в дефолтной политике он есть, но кастомная
        // могла его убрать. Добавляем явно, чтобы hard-ось доков имела источник.
        if !policy.families.contains(&Family::Spec) {
            policy.families.push(Family::Spec);
        }
        // Эскалация недоделанного/дрейфа доков ОБЯЗАТЕЛЬНА в пути DoD: жёсткие оси
        // «Недоделанное» и «Доки/Спека актуальны» опираются на правила низкой
        // уверенности (doc-drift/doc-missing), которые classify уводит в advisories, а
        // обычный GateRunner::run эскалацию не вызывает. Без этого hard-ось доков
        // никогда не валит вердикт (см. T86). Поэтому переносим такие находки в
        // блокеры до агрегации осей.
        //
        // Оси пола безопасности (secret/sast/taint) из гейтового прогона ИСКЛЮЧЕНЫ явно:
        // ниже они исполняются напрямую (`run_axis_direct`), и без исключения тот же
        // тяжёлый анализ гонялся бы дважды за один вердикт. Verify-оси исключать не нужно:
        // семейство Verify уже убрано из families выше. Дедупликация не страдает: находки
        // исключённых источников подмешивает прямой прогон, а фильтр по `direct_caps` в
        // цикле агрегации остаётся страховкой.
        const DIRECT_SECURITY_CAPS: &[&str] = &[
            "security.scan/secret",
            "security.scan/sast",
            "security.scan/taint",
        ];
        let mut report = GateRunner::run_excluding(reg, ctx, input, &policy, DIRECT_SECURITY_CAPS);
        GateRunner::escalate_unfinished(&mut report);

        // Оси, исход которых считаем НАПРЯМУЮ из выхода capability, а не из агрегата
        // гейта: пол безопасности (SAST/taint, см. T36), оси secret (ради числа
        // опровергнутых секретов, см. T03) и verify-оси (см. T86). Гейт теряет сводку
        // прогона и список опровергнутых, не различает «инструмент упал» от «нашёл
        // замечания», а для verify/test нужна сводка ради позитивного доказательства
        // прогона. Поэтому исключаем эти источники из гейтового by_src, чтобы не задвоить
        // их находки при прямом прогоне ниже.
        let direct_caps: &[&str] = &[
            "security.scan/secret",
            "security.scan/sast",
            "security.scan/taint",
            "verify/test",
            "verify/lint",
            "verify/coverage",
            "verify/api-break",
        ];

        // Находки по источнику (capability id) → (всего, HIGH+). Источник истины по
        // достоверности — единая карта `ailc_contracts::rule_confidence` через
        // `Finding::is_signal`/`Finding::confidence`; локальных списков правил здесь
        // НЕТ (см. T88). После эскалации в blocking/warning попадают и доковые правила.
        let mut by_src: HashMap<&str, (usize, usize)> = HashMap::new();
        // Отдельно учитываем ТОЛЬКО блокирующие находки. Это нужно оси-страховке ниже:
        // она обязана поймать блокеры, не покрытые ни одной именованной осью, и при этом
        // не имеет права валить вердикт из-за предупреждений, которые по определению не
        // блокируют. Именованные оси продолжают считать по `by_src` (всего и HIGH+), их
        // поведение не меняется.
        let mut blocking_by_src: HashMap<&str, (usize, usize)> = HashMap::new();
        for (f, blocks) in report
            .blocking
            .iter()
            .map(|f| (f, true))
            .chain(report.warning.iter().map(|f| (f, false)))
        {
            if direct_caps.contains(&f.source.as_str()) {
                continue; // прямой прогон считает их сам
            }
            // Замороженный долг не блокирует: находка из базовой линии уходит в метрику
            // долга (verify-источники сюда не попадают: семейство исключено из гейта).
            if crate::baseline::is_debt(&base, f) {
                debt += 1;
                continue;
            }
            let high = f.severity >= Severity::High;
            let e = by_src.entry(f.source.as_str()).or_default();
            e.0 += 1;
            if high {
                e.1 += 1;
            }
            if blocks {
                let b = blocking_by_src.entry(f.source.as_str()).or_default();
                b.0 += 1;
                if high {
                    b.1 += 1;
                }
            }
        }

        // Прямой прогон осей: пол безопасности (см. T36) и verify-оси (см. T86).
        // Исполняем capability напрямую, классифицируем исход через
        // `CapabilityOutput::outcome` (Ran/Skipped/Failed), подмешиваем верифицированные
        // находки в by_src. Тяжёлый SAST/taint защищён таймаутом.
        let mut direct_outcomes: HashMap<&str, CheckOutcome> = HashMap::new();
        // Число опровергнутых верификатором находок по оси (см. T03 для secret).
        let mut direct_refuted: HashMap<&str, usize> = HashMap::new();
        for id in [
            "security.scan/secret",
            "security.scan/sast",
            "security.scan/taint",
            "verify/test",
            "verify/lint",
            "verify/coverage",
            "verify/api-break",
        ] {
            let heavy = SECURITY_FLOOR_IDS.contains(&id);
            // Долг применим только к статическим сканерам; verify-оси (тесты, линт,
            // покрытие, контракт API) обязаны проходить всегда, их долг не спасает.
            let base_for_axis = if id.starts_with("verify/") {
                None
            } else {
                Some(&base)
            };
            let (outcome, refuted) = Self::run_axis_direct(
                reg,
                ctx,
                input,
                id,
                heavy,
                &mut by_src,
                base_for_axis,
                &mut debt,
            );
            direct_outcomes.insert(id, outcome);
            direct_refuted.insert(id, refuted);
        }

        let ran = |id: &str| report.checks_run.iter().any(|x| x == id);

        // (имя оси, capability-источник, hard?)
        let defs: &[(&'static str, &'static str, bool)] = &[
            ("Конституция", "quality.check/constitution", true),
            ("Тесты", "verify/test", true),
            ("Секреты", "security.scan/secret", true),
            ("OWASP HIGH", "security.scan/owasp", true),
            // Глубокий SAST/taint: единственный источник High-уверенности, поэтому
            // hard. Раньше недостижим из DoD из-за Tier::Enterprise (см. T36).
            ("SAST (AST)", "security.scan/sast", true),
            ("Taint-поток", "security.scan/taint", true),
            ("Запахи кода", "quality.check/smell", false),
            // Hard: «Definition of Done» = сдача. Незавершённое (заглушки/пустые блоки)
            // не даёт пройти DoD — это и есть «не даём сдать недоделанное».
            ("Недоделанное", "quality.check/completeness", true),
            ("Анти-паттерны", "quality.check/antipattern", false),
            ("Циклы зависимостей", "quality.check/cycles", false),
            ("Мёртвый код", "quality.check/dead-code", false),
            ("Доки/Спека актуальны", "spec.check/drift", true),
            // Мягкая ось spec-first: изменение прослеживается к спеке или задаче
            // бэклога. Нудж к «чертежам до кода», не блокер (вне git пропускается).
            ("Изменение со спекой", "spec.check/trace", false),
            ("Контракт API не сломан", "verify/api-break", true),
        ];

        let mut axes = Vec::new();
        let mut hard_failed = false;
        let mut hard_not_run: Vec<&'static str> = Vec::new();
        // Сколько проверок реально выполнилось (для определения нулевого охвата):
        // считаем оси гейта (за вычетом прямых) и прямой прогон.
        let mut any_ran = report
            .checks_run
            .iter()
            .any(|id| !direct_caps.contains(&id.as_str()));
        for (name, src, hard) in defs {
            // Исход оси: прямой прогон (verify/пол) даёт явный Ran/Skipped/Failed;
            // остальные оси берут did_run из checks_run гейта.
            let outcome: CheckOutcome = if let Some(o) = direct_outcomes.remove(src) {
                o
            } else if ran(src) {
                CheckOutcome::Ran
            } else {
                CheckOutcome::Skipped("не выполнялась".into())
            };
            let did_run = outcome.did_run();
            if did_run {
                any_ran = true;
            }
            let not_run_reason = outcome.reason().map(|r| r.to_string());
            let (cnt, high) = by_src.get(src).copied().unwrap_or((0, 0));
            // OWASP-ось проходит, если нет HIGH (MEDIUM допустимы); прочие — если 0 находок.
            let ok = if *src == "security.scan/owasp" {
                high == 0
            } else {
                cnt == 0
            };
            // Hard-ось валит вердикт, если выполнилась и не прошла. Hard-ось, которая
            // НЕ выполнилась (пропуск/сбой), не валит «проблемами», но снимает
            // подтверждение: итог становится «НЕ подтверждено» (см. T85).
            if *hard && did_run && !ok {
                hard_failed = true;
            }
            if *hard && !did_run {
                hard_not_run.push(name);
            }
            // Опровергнутые верификатором находки по оси (заполнено для прямых прогонов:
            // секрет/SAST/taint/verify). Для оси «Секреты» ненулевое значение сигналит,
            // что токены были, но отброшены эвристикой (см. T03).
            let refuted = direct_refuted.get(src).copied().unwrap_or(0);
            axes.push(DodAxis {
                name,
                hard: *hard,
                ran: did_run,
                findings: cnt,
                high,
                ok,
                refuted,
                out_of_scope: 0,
                not_run_reason,
            });
        }

        // Агрегатная ось «Комплаенс РФ» — сумма по всем compliance.ru/*. По умолчанию
        // soft (регуляторные риски эвристичны, окончательно решает юрист), но паспорт
        // делает её ЖЁСТКОЙ, когда проект русскоязычный и работает с ПДн: у такого
        // проекта сдача с комплаенс-находками недопустима без явного решения человека.
        let comp_hard = prof.ru_locale && prof.has_pdn;
        let comp_ran = report
            .checks_run
            .iter()
            .any(|x| x.starts_with("compliance.ru/"));
        let (mut c_cnt, mut c_high) = (0usize, 0usize);
        for (src, (cnt, high)) in &by_src {
            if src.starts_with("compliance.ru/") {
                c_cnt += cnt;
                c_high += high;
            }
        }
        if comp_hard && comp_ran && c_cnt > 0 {
            hard_failed = true;
        }
        if comp_hard && !comp_ran {
            hard_not_run.push("Комплаенс РФ");
        }
        axes.push(DodAxis {
            name: "Комплаенс РФ",
            hard: comp_hard,
            ran: comp_ran,
            findings: c_cnt,
            high: c_high,
            ok: c_cnt == 0,
            refuted: 0,
            out_of_scope: 0,
            not_run_reason: if comp_ran {
                None
            } else {
                Some("не выполнялась".into())
            },
        });

        // Профильная ось «Доступность UI» — сумма по quality.ui/*; появляется только у
        // проекта с интерфейсом.
        //
        // ОСЬ МЯГКАЯ, И ЭТО ИСПРАВЛЕНИЕ ПРЕЖНЕГО ПРОТИВОРЕЧИЯ. Она была объявлена жёсткой,
        // печаталась в вердикте с пометкой «hard», но провалиться не могла НИ ПРИ КАКОМ
        // наборе находок: условие провала требует важности High и выше, а среди тринадцати
        // правил `quality.ui/*` нет ни одного такого (девять Medium и четыре Low), и поднять
        // важность нечему, поскольку эскалация недоделанного работает только по трём
        // источникам, куда `quality.ui/*` не входит. Итог был хуже безвредного мёртвого кода:
        // человек видел строку с отметкой «✓ [hard]» и ненулевым числом замечаний рядом, то
        // есть создавалась видимость работающей защиты.
        //
        // Из двух способов устранить противоречие (сделать ось мягкой либо опустить порог до
        // Medium) выбран первый, потому что он соответствует уже написанному замыслу «советы
        // по улучшению видны, но сдачу не валят» и не ломает сборку ни одному действующему
        // пользователю с интерфейсом. Порог High сохранён: если когда-нибудь появится правило
        // доступности такой важности, решение о жёсткости нужно принять заново и осознанно.
        if prof.has_ui {
            let ui_ran = report
                .checks_run
                .iter()
                .any(|x| x.starts_with("quality.ui/"));
            let (mut u_cnt, mut u_high) = (0usize, 0usize);
            for (src, (cnt, high)) in &by_src {
                if src.starts_with("quality.ui/") {
                    u_cnt += cnt;
                    u_high += high;
                }
            }
            // Мягкая ось вердикт не валит и в перечень невыполненных жёстких осей не идёт:
            // иначе проект с интерфейсом получал бы «НЕ подтверждено» из-за отсутствия
            // разметки, что не является ни дефектом, ни поводом задержать сдачу.
            axes.push(DodAxis {
                name: "Доступность UI",
                hard: false,
                ran: ui_ran,
                findings: u_cnt,
                high: u_high,
                ok: u_high == 0,
                refuted: 0,
                out_of_scope: 0,
                not_run_reason: if ui_ran {
                    None
                } else {
                    Some("не выполнялась".into())
                },
            });
        }

        // Профильная ось «Безопасность ИИ» — сумма по security.ai/* (OWASP LLM01/LLM02);
        // появляется только у проекта с обращениями к нейросетям и сразу жёсткая: любая
        // подтверждённая находка (инъекция в подсказку, исполнение вывода модели) блокирует.
        if prof.has_llm {
            let ai_ran = report
                .checks_run
                .iter()
                .any(|x| x.starts_with("security.ai/"));
            let (mut a_cnt, mut a_high) = (0usize, 0usize);
            for (src, (cnt, high)) in &by_src {
                if src.starts_with("security.ai/") {
                    a_cnt += cnt;
                    a_high += high;
                }
            }
            if ai_ran && a_cnt > 0 {
                hard_failed = true;
            }
            if !ai_ran {
                hard_not_run.push("Безопасность ИИ");
            }
            axes.push(DodAxis {
                name: "Безопасность ИИ",
                hard: true,
                ran: ai_ran,
                findings: a_cnt,
                high: a_high,
                ok: a_cnt == 0,
                refuted: 0,
                out_of_scope: 0,
                not_run_reason: if ai_ran {
                    None
                } else {
                    Some("не выполнялась".into())
                },
            });
        }

        // ── ОСЬ-СТРАХОВКА: ни один блокер не имеет права остаться вне вердикта ──────
        //
        // Гейт (`GateRunner`) классифицирует находки ВСЕХ зарегистрированных capability и
        // складывает блокеры в `report.blocking`. Вердикт же до этого считался
        // исключительно по таблице `defs` плюс три профильные агрегатные оси, то есть по
        // РУЧНОМУ перечню источников. Любая capability, не попавшая в этот перечень,
        // молча выпадала из вердикта: её находки ложились в `by_src` под ключ, который ни
        // одна ось не читает. Практический масштаб разрыва: в реестре пятнадцать
        // capability семейства безопасности, а осей на них четыре, поэтому известные
        // уязвимости в зависимостях (`security.scan/deps`), инъекции, SSRF, небезопасная
        // инфраструктура как код и критичные находки Electron/Tauri (`verify/desktop`)
        // видны в отчёте SARIF и НЕ влияли на ответ «можно ли сдавать».
        //
        // Дописать в `defs` ещё десять строк было бы починкой симптома: перечень снова
        // разойдётся с реестром при следующей новой capability, причём молча. Поэтому
        // разрыв закрывается ПО ОСТАТКУ: всё, что не покрыто явными осями, попадает в
        // агрегатную ось, а жёсткость определяется СЕМЕЙСТВОМ capability из реестра, а не
        // строковым префиксом идентификатора. Инвариант «нет молчаливых пропусков»
        // становится структурным: чтобы находка не влияла на вердикт, её capability надо
        // удалить из реестра, а не забыть дописать в список.
        let mut covered: HashSet<&str> = defs.iter().map(|(_, src, _)| *src).collect();
        covered.extend(direct_caps.iter().copied());
        // Агрегатные оси покрывают источники по префиксу, но только если сама ось была
        // добавлена: профильные оси появляются лишь у подходящего проекта.
        let mut covered_prefixes: Vec<&str> = vec!["compliance.ru/"];
        if prof.has_ui {
            covered_prefixes.push("quality.ui/");
        }
        if prof.has_llm {
            covered_prefixes.push("security.ai/");
        }

        let (mut sec_cnt, mut sec_high) = (0usize, 0usize);
        let (mut oth_cnt, mut oth_high) = (0usize, 0usize);
        let mut sec_srcs: Vec<&str> = Vec::new();
        let mut oth_srcs: Vec<&str> = Vec::new();
        for (src, (cnt, high)) in &blocking_by_src {
            if covered.contains(src) || covered_prefixes.iter().any(|p| src.starts_with(p)) {
                continue;
            }
            // Жёсткость по семейству из реестра. Если capability в реестре почему-то нет,
            // консервативно считаем источник безопасностью по префиксу идентификатора:
            // ошибиться в сторону лишней строгости здесь безопаснее, чем пропустить блокер.
            let is_security = reg.get(src).map_or_else(
                || src.starts_with("security."),
                |c| c.manifest().family == Family::Security,
            );
            if is_security {
                sec_cnt += cnt;
                sec_high += high;
                sec_srcs.push(src);
            } else {
                oth_cnt += cnt;
                oth_high += high;
                oth_srcs.push(src);
            }
        }
        // Порядок источников в имени оси стабилен: карта источников это HashMap, а вердикт
        // и его печать обязаны быть воспроизводимыми от прогона к прогону.
        sec_srcs.sort_unstable();
        oth_srcs.sort_unstable();

        if sec_cnt > 0 {
            hard_failed = true;
            axes.push(DodAxis {
                name: "Безопасность (прочее)",
                hard: true,
                ran: true,
                findings: sec_cnt,
                high: sec_high,
                ok: false,
                refuted: 0,
                out_of_scope: 0,
                not_run_reason: None,
            });
        }
        if oth_cnt > 0 {
            axes.push(DodAxis {
                name: "Качество (прочее)",
                hard: false,
                ran: true,
                findings: oth_cnt,
                high: oth_high,
                ok: false,
                refuted: 0,
                out_of_scope: 0,
                not_run_reason: None,
            });
        }

        // Третье состояние вердикта (см. T85/T03): «можно сдавать» только когда ни одна
        // выполненная hard-ось не провалена, все hard-оси РЕАЛЬНО выполнились и охват
        // ненулевой. Иначе это либо «провалено» (hard_failed), либо «НЕ подтверждено»
        // (hard_not_run непуст или охват нулевой). passed делаем равным confirmed, чтобы
        // печать вердикта, читающая report.passed, не выдавала зелёное при незапущенных
        // проверках без правок вызывающего кода.
        let zero_coverage = !any_ran;
        let confirmed = !hard_failed && hard_not_run.is_empty() && !zero_coverage;
        DodReport {
            axes,
            passed: confirmed,
            confirmed,
            hard_not_run,
            zero_coverage,
            debt,
            baseline_frozen: crate::baseline::exists(ctx),
            policy_note,
        }
    }

    /// Исполнить capability оси НАПРЯМУЮ по идентификатору и классифицировать её исход
    /// единообразно через `CapabilityOutput::outcome` (Ran/Skipped/Failed), подмешав
    /// верифицированные находки в `by_src`. Решает две задачи Волны 2 сразу:
    ///   • T36: пол безопасности (глубокий SAST/taint) помечен `Tier::Enterprise` и
    ///     обычным авто-гейтом отсекается, поэтому DoD исполняет его здесь напрямую;
    ///   • T86: verify-оси (test/lint/coverage/api-break) не должны путать «инструмент
    ///     упал» (сборка/конфиг/импорт/паника) с находкой; для `verify/test` требуется
    ///     ПОЗИТИВНОЕ доказательство прогона прежде «тесты прошли».
    ///
    /// `heavy` включает защиту по таймауту: тяжёлый AST/taint-разбор исполняется в
    /// ОТСОЕДИНЁННОМ потоке (его нельзя безопасно join'ить при зависании), результат
    /// ждём через канал с таймаутом, как делает пайплайн (`pipeline::STEP_TIMEOUT`).
    /// Лёгкие verify-оси исполняем синхронно (они сами ограничены раннером).
    #[allow(clippy::too_many_arguments)]
    fn run_axis_direct(
        reg: &Registry,
        ctx: &Ctx,
        input: &RunInput,
        id: &'static str,
        heavy: bool,
        by_src: &mut HashMap<&str, (usize, usize)>,
        base: Option<&std::collections::HashSet<String>>,
        debt: &mut usize,
    ) -> (CheckOutcome, usize) {
        let Some(cap) = reg.get_arc(id) else {
            // Capability не зарегистрирована: это осознанный пропуск с явной причиной,
            // а не молчаливое «чисто» (инвариант «нет молчаливых пропусков»).
            return (
                CheckOutcome::Skipped(format!("{id}: capability не зарегистрирована в реестре")),
                0,
            );
        };

        let result = if heavy {
            let cap = cap.clone();
            let ctx_owned = ctx.clone();
            let input_owned = input.clone();
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let res = cap.run(&ctx_owned, &input_owned);
                // Получатель мог уйти по таймауту — ошибку отправки игнорируем.
                let _ = tx.send(res);
            });
            match rx.recv_timeout(SECURITY_FLOOR_TIMEOUT) {
                Ok(r) => r,
                // Зависание сверх бюджета: фиксируем как сбой инструмента, не выполнение.
                Err(_) => {
                    return (
                        CheckOutcome::Failed(format!(
                            "{id}: превышен таймаут {} c (глубокий анализ не завершился)",
                            SECURITY_FLOOR_TIMEOUT.as_secs()
                        )),
                        0,
                    );
                }
            }
        } else {
            cap.run(ctx, input)
        };

        let out = match result {
            Ok(out) => out,
            // Capability вернула ошибку: сбой инструмента (разбор/IO), не находка.
            Err(e) => {
                return (
                    CheckOutcome::Failed(format!("{id}: ошибка анализа: {e}")),
                    0,
                );
            }
        };

        // Классификация исхода: Skipped/Failed по маркерам, иначе Ran. Для verify/test
        // ужесточаем: «выполнено» только при позитивном доказательстве прогона тестов.
        let outcome = Self::axis_outcome(id, &out);
        let mut refuted_n = 0usize;
        if outcome.did_run() {
            // В подсчёт оси идут находки, пережившие состязательный проход верификатора
            // (ложные отсеяны тем же образом, что и в гейте). Число опровергнутых сохраняем:
            // для оси секретов оно отличает «0 находок при полном охвате» от «токены были, но
            // отброшены эвристикой» (см. T03).
            let (confirmed, refuted) = crate::verify::Verifier::verify(ctx, out.findings);
            refuted_n = refuted.len();
            let e = by_src.entry(id).or_default();
            for f in confirmed {
                // Для глубоких анализаторов floor (sast/taint) находка, пережившая
                // верификатор, засчитывается, даже если её первичный флаг verified=false
                // (эвристический taint, T14): сам состязательный проход и есть фактическая
                // верификация, поэтому ось «Taint-поток» становится живой и валит сдачу на
                // реальном необезвреженном потоке. Для прочих осей сохраняем анти-гейминг:
                // неверифицированные находки в подсчёт не идут (см. gate_counts_only_verified).
                if !f.verified && !heavy {
                    continue;
                }
                // Замороженный долг не блокирует ось (см. baseline): в метрику долга.
                if let Some(b) = base {
                    if crate::baseline::is_debt(b, &f) {
                        *debt += 1;
                        continue;
                    }
                }
                e.0 += 1;
                if f.severity >= Severity::High {
                    e.1 += 1;
                }
            }
        }
        (outcome, refuted_n)
    }

    /// Классифицировать исход одной capability-оси по её выходу (см. T86). База —
    /// `CapabilityOutput::outcome` (различает Skipped/Failed/Ran по маркерам поломки
    /// инструмента). Сверх неё: для `verify/test` требуется ПОЗИТИВНОЕ доказательство
    /// выполненных тестов (число пройденных больше нуля либо зафиксированное падение
    /// прогона), иначе зелёная-но-недоказанная ось считается осознанным пропуском, а не
    /// «тесты прошли».
    fn axis_outcome(id: &str, out: &CapabilityOutput) -> CheckOutcome {
        let base = out.outcome();
        if id != "verify/test" || !base.did_run() {
            return base;
        }
        // Тесты числятся выполненными. Падение прогона — это доказательство, что тесты
        // исполнялись (тогда ось Ran и провалится на ok=false по находке tests-failing).
        let tests_failed = out.findings.iter().any(|f| f.rule == "tests-failing");
        if tests_failed {
            return CheckOutcome::Ran;
        }
        // Падения нет: требуем позитивного маркера пройденных тестов (N>0) в сводке.
        // Без него пустой/фиктивный прогон («test: echo ok») не считается «тесты прошли».
        if positive_test_proof(&out.summary) {
            CheckOutcome::Ran
        } else {
            CheckOutcome::Skipped(format!(
                "{id}: работоспособность не подтверждена (нет доказательства выполненных тестов)"
            ))
        }
    }
}

/// Есть ли в сводке прогона позитивное доказательство выполненных тестов (см. T86).
/// Принимается два рода доказательства:
///   1) ненулевое «N passed» прямо в сводке (cargo «test result: ok. 13 passed»,
///      pytest «13 passed», jest «Tests: 13 passed»);
///   2) утвердительный маркер прохождения от самой capability («тесты прошли»), который
///      она выставляет только при успешном прогоне; при этом маркер «не подтверждена»/
///      «не подтверждено» доказательством НЕ считается (пустой/недоказанный прогон).
///
/// Локальная реализация в ядре, потому что `ailc-capabilities` зависит от `ailc-core`,
/// а не наоборот: переиспользовать `some_tests_passed` из capabilities нельзя без цикла
/// зависимостей. Семантика численного маркера умышленно совпадает с `some_tests_passed`.
fn positive_test_proof(summary: &str) -> bool {
    let s = summary.to_lowercase();
    // Недоказанный/пустой прогон явно объявлен «не подтверждён» — это НЕ доказательство.
    if s.contains("не подтвержд") {
        return false;
    }
    // Отрицание рядом с маркером прохождения ОПРОВЕРГАЕТ доказательство: прежде проверка
    // подстроки «tests passed» принимала за успех сводки вида «not all tests passed» и
    // «no tests passed», то есть провал прогона читался как доказательство прохождения.
    for neg in [
        "not all tests passed",
        "no tests passed",
        "tests not passed",
        "тесты не прошли",
    ] {
        if s.contains(neg) {
            return false;
        }
    }
    // Утвердительный маркер прохождения от capability.
    if s.contains("тесты прошли") {
        return true;
    }
    // Маркер «tests passed»: если непосредственно перед ним стоит счётчик, он обязан быть
    // ненулевым; для формы «K of N tests passed» решает именно K («0 of 5 tests passed»
    // это провал, а не доказательство). Маркер без счётчика («jest: tests passed»)
    // остаётся утвердительным.
    if let Some(i) = s.find("tests passed") {
        match tests_passed_count(&s[..i]) {
            None => return true, // счётчика нет: утвердительный маркер
            Some(n) if n > 0 => return true,
            Some(_) => {} // нулевой счётчик: не доказательство, ищем «N passed» ниже
        }
    }
    // Численное доказательство: ненулевое «N passed».
    let mut rest = s.as_str();
    while let Some(i) = rest.find(" passed") {
        let n: u64 = rest[..i]
            .chars()
            .rev()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
            .parse()
            .unwrap_or(0);
        if n > 0 {
            return true;
        }
        rest = &rest[i + " passed".len()..];
    }
    false
}

/// Число пройденных тестов из текста, стоящего ПЕРЕД маркером «tests passed».
/// Понимает формы «… N tests passed» (возвращает N) и «… K of N tests passed»
/// (возвращает K: сколько реально прошло). `None`, если счётчика перед маркером нет.
fn tests_passed_count(before: &str) -> Option<u64> {
    let trailing_digits = |s: &str| -> Option<(u64, usize)> {
        let d: String = s
            .chars()
            .rev()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        if d.is_empty() {
            None
        } else {
            Some((d.parse().unwrap_or(0), d.len()))
        }
    };
    let b = before.trim_end();
    let (n, len) = trailing_digits(b)?;
    let rest = b[..b.len() - len].trim_end();
    if rest.ends_with(" of") || rest == "of" {
        // Форма «K of N tests passed»: решает K. Если K не удалось прочитать,
        // консервативно считаем счётчик нулевым (доказательства нет).
        let rest2 = rest[..rest.len() - 2].trim_end();
        Some(trailing_digits(rest2).map_or(0, |(k, _)| k))
    } else {
        Some(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Capability;
    use ailc_contracts::{CapabilityManifest, EngineKind, Location, Result};

    // ───────────── мок-инфраструктура (capability с предзаданным выходом) ─────────────

    /// Мок-capability: возвращает заранее сформированный выход. Реальные capability
    /// живут в `ailc-capabilities`, который зависит от `ailc-core`, поэтому в юнит-тестах
    /// ядра их использовать нельзя (цикл зависимостей). Мок реализует трейт `Capability`
    /// и позволяет точечно задать исход каждой оси DoD.
    struct MockCap {
        manifest: CapabilityManifest,
        output: CapabilityOutput,
    }

    impl Capability for MockCap {
        fn manifest(&self) -> &CapabilityManifest {
            &self.manifest
        }
        fn run(&self, _ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
            Ok(self.output.clone())
        }
    }

    fn manifest(id: &'static str, family: Family, tier: Tier) -> CapabilityManifest {
        CapabilityManifest {
            id,
            family,
            engine: EngineKind::Scan,
            when_to_use: "тест",
            input_schema: "{}",
            tier,
            deterministic: true,
            mutates: false,
        }
    }

    fn family_of(id: &str) -> Family {
        // Семейство выводим по префиксу идентификатора, как в реальных манифестах, а не
        // перечислением: иначе новая мок-ось `security.scan/*` в тесте молча получила бы
        // семейство Quality и проверяла бы не тот путь, что в продукте.
        match id.split('/').next().unwrap_or("") {
            "security.scan" | "security.ai" => Family::Security,
            "verify" => Family::Verify,
            "spec.check" => Family::Spec,
            "compliance.ru" => Family::Compliance,
            _ => Family::Quality,
        }
    }

    fn tier_of(id: &str) -> Tier {
        if id == "security.scan/sast" || id == "security.scan/taint" {
            Tier::Enterprise
        } else {
            Tier::Core
        }
    }

    /// Зарегистрировать мок-ось с заданным выходом. Семейство и тир выводятся из id,
    /// чтобы соответствовать реальному манифесту и пройти фильтр гейта по семейству.
    fn reg_axis(reg: &mut Registry, id: &'static str, out: CapabilityOutput) {
        reg.register(Box::new(MockCap {
            manifest: manifest(id, family_of(id), tier_of(id)),
            output: out,
        }));
    }

    /// Чистый прогон оси (выполнена, без находок). Для verify/test даём позитивное
    /// доказательство прогона тестов, иначе ось не будет считаться выполненной (T86).
    fn ran_clean(id: &str) -> CapabilityOutput {
        let summary = if id == "verify/test" {
            "verify/test (cargo): ✅ тесты прошли".to_string()
        } else {
            format!("{id}: выполнено, замечаний нет")
        };
        CapabilityOutput {
            summary,
            ..Default::default()
        }
    }

    /// Прогон с одной верифицированной находкой заданной severity (ось проваливается).
    fn ran_with_finding(id: &'static str, sev: Severity, rule: &str) -> CapabilityOutput {
        let f = Finding {
            rule: rule.into(),
            severity: sev,
            message: format!("{id}: тестовая находка"),
            // Без location: верификатор не может опровергнуть и оставляет находку.
            location: None,
            evidence: None,
            verified: true,
            source: id.into(),
        };
        CapabilityOutput {
            findings: vec![f],
            summary: format!("{id}: найдено 1"),
            ..Default::default()
        }
    }

    /// Осознанный пропуск оси (нет тулчейна/входных данных).
    fn skipped(id: &str, reason: &str) -> CapabilityOutput {
        CapabilityOutput {
            skipped: Some(format!("{id}: {reason}")),
            ..Default::default()
        }
    }

    /// Зарегистрировать ПОЛНЫЙ набор hard-осей DoD как чисто выполненных, чтобы базовый
    /// прогон давал подтверждённый вердикт. Отдельные тесты затем переопределяют одну ось.
    fn register_all_clean(reg: &mut Registry) {
        for id in [
            "quality.check/constitution",
            "verify/test",
            "security.scan/secret",
            "security.scan/owasp",
            "security.scan/sast",
            "security.scan/taint",
            "quality.check/completeness",
            "spec.check/drift",
            "verify/api-break",
        ] {
            reg_axis(reg, id, ran_clean(id));
        }
    }

    fn tmp_ctx() -> Ctx {
        let pid = std::process::id();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("ailc-dod-{pid}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        Ctx::new(p)
    }

    fn axis<'a>(report: &'a DodReport, name: &str) -> &'a DodAxis {
        report
            .axes
            .iter()
            .find(|a| a.name == name)
            .unwrap_or_else(|| panic!("ось «{name}» отсутствует в отчёте"))
    }

    // ────────── Сплошной скан: охват и сохранность находок ──────────

    /// РЕГРЕССИЯ. Признак пропуска и находки НЕ исключают друг друга: первый говорит о
    /// неполноте охвата, вторые о том, что успели найти. Прежде ветки были
    /// взаимоисключающими, и выставленный признак пропуска отбрасывал все находки
    /// capability. Так теряются реальные данные: проверки настольных оболочек и мобильной
    /// конфигурации выставляют пропуск при отказе движка на ОДНОЙ из своих осей, уже собрав
    /// находки по остальным.
    #[test]
    fn частичный_пропуск_не_отбрасывает_уже_найденное() {
        let mut reg = Registry::new();
        let mut out = ran_with_finding(
            "verify/desktop",
            Severity::Critical,
            "desktop/electron-node-integration",
        );
        out.skipped = Some("сборка не проверена: нет тулчейна".into());
        reg_axis(&mut reg, "verify/desktop", out);
        let ctx = tmp_ctx();
        let report = Orchestrator::scan_all(&reg, &ctx, &RunInput::default());
        assert_eq!(
            report.findings.len(),
            1,
            "находка сохранена несмотря на пропуск: {:?}",
            report.findings.iter().map(|f| &f.rule).collect::<Vec<_>>()
        );
        assert!(
            report
                .checks_skipped
                .iter()
                .any(|(id, _)| id == "verify/desktop"),
            "неполнота охвата при этом остаётся видимой"
        );
    }

    /// Семейство `Verify` обязано попадать в сплошной скан: иначе критичные находки о
    /// настольных оболочках и мобильной конфигурации, а также сломанный публичный контракт
    /// не доходят до отчёта SARIF для системы сборки.
    #[test]
    fn семейство_verify_попадает_в_сплошной_скан() {
        let mut reg = Registry::new();
        reg_axis(
            &mut reg,
            "verify/desktop",
            ran_with_finding(
                "verify/desktop",
                Severity::Critical,
                "desktop/electron-websecurity-off",
            ),
        );
        let ctx = tmp_ctx();
        let report = Orchestrator::scan_all(&reg, &ctx, &RunInput::default());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule == "desktop/electron-websecurity-off"),
            "находка семейства Verify дошла до отчёта: {:?}",
            report.findings.iter().map(|f| &f.rule).collect::<Vec<_>>()
        );
    }

    // ────────── Ось-страховка: блокер вне таблицы осей обязан валить вердикт ──────────

    /// Регрессия на разрыв между гейтом и вердиктом. `security.scan/deps` не входит в
    /// таблицу `defs`, поэтому раньше его находки ложились в карту по источнику, которую
    /// ни одна ось не читала: известная уязвимость в зависимостях была видна в SARIF и не
    /// влияла на ответ «можно ли сдавать». Теперь её обязана поймать ось по остатку.
    #[test]
    fn блокер_capability_вне_таблицы_осей_валит_вердикт() {
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        reg_axis(
            &mut reg,
            "security.scan/deps",
            ran_with_finding(
                "security.scan/deps",
                Severity::Critical,
                "vulnerable-dependency",
            ),
        );
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        assert!(
            !report.confirmed && !report.passed,
            "критичная уязвимость в зависимостях обязана валить вердикт; оси: {:?}",
            report
                .axes
                .iter()
                .map(|a| (a.name, a.ran, a.ok))
                .collect::<Vec<_>>()
        );
        let a = axis(&report, "Безопасность (прочее)");
        assert!(a.hard && !a.ok, "ось-страховка жёсткая и провалена");
        assert_eq!(a.findings, 1, "находка учтена ровно один раз");
    }

    /// Жёсткость оси-страховки берётся из СЕМЕЙСТВА capability в реестре, а не из
    /// префикса идентификатора: критичные находки `verify/desktop` (Electron с включённой
    /// интеграцией Node) не начинаются с «security.» и раньше проходили мимо вердикта.
    /// Семейство Verify не является Security, поэтому такой источник попадает в мягкую
    /// ось-страховку и вердикт не валит; проверяем, что он хотя бы ВИДЕН, а не потерян.
    #[test]
    fn блокер_немощного_семейства_попадает_в_мягкую_ось_а_не_теряется() {
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        reg_axis(
            &mut reg,
            "quality.check/layers",
            ran_with_finding("quality.check/layers", Severity::High, "layering-violation"),
        );
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        let a = axis(&report, "Качество (прочее)");
        assert!(!a.hard, "ось качества по остатку мягкая");
        assert_eq!(a.findings, 1, "находка видна в вердикте, а не потеряна");
    }

    /// Ось-страховка не имеет права появляться на пустом месте: у чистого проекта её нет,
    /// иначе вывод вердикта засоряется, а «прочее: 0» читается как отдельная проверка.
    #[test]
    fn ось_страховка_отсутствует_при_чистом_прогоне() {
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        assert!(report.confirmed, "чистый прогон подтверждён");
        assert!(
            !report.axes.iter().any(|a| a.name.contains("(прочее)")),
            "осей по остатку при отсутствии остатка быть не должно"
        );
    }

    /// Предупреждение (severity ниже порога блокировки) не имеет права валить вердикт
    /// через ось-страховку: иначе любое замечание становится блокером и гейт выключат.
    #[test]
    fn предупреждение_вне_таблицы_осей_не_валит_вердикт() {
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        reg_axis(
            &mut reg,
            "security.scan/iac",
            ran_with_finding("security.scan/iac", Severity::Low, "iac-permissive"),
        );
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        assert!(
            report.confirmed,
            "находка ниже порога блокировки вердикт не валит; оси: {:?}",
            report
                .axes
                .iter()
                .map(|a| (a.name, a.ok))
                .collect::<Vec<_>>()
        );
    }

    // ───────────────────────────── T85/T03: третье состояние ─────────────────────────────

    #[test]
    fn empty_repo_is_not_confirmed_not_passed() {
        // Пустой реестр = ни одна проверка не выполнилась = нулевой охват. Это НЕ «можно
        // сдавать», а «НЕ подтверждено» (см. T85): пустой/несорсовый репозиторий не
        // имеет права на PASS.
        let reg = Registry::new();
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        assert!(report.zero_coverage, "нулевой охват зафиксирован");
        assert!(!report.confirmed, "пустой репозиторий не подтверждён");
        assert!(
            !report.passed,
            "passed следует confirmed, ложно-зелёного нет"
        );
        assert!(
            !report.hard_not_run.is_empty(),
            "перечислены незапущенные hard-оси: {:?}",
            report.hard_not_run
        );
    }

    #[test]
    fn all_hard_axes_clean_is_confirmed() {
        // Все hard-оси реально выполнились и чисты: вердикт подтверждён.
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        assert!(
            report.confirmed,
            "все hard-оси чисты → подтверждено; незапущенные: {:?}",
            report.hard_not_run
        );
        assert!(report.passed, "passed == confirmed");
        assert!(report.hard_not_run.is_empty(), "незапущенных hard-осей нет");
        assert!(!report.zero_coverage, "охват ненулевой");
    }

    #[test]
    fn hard_axis_not_run_blocks_confirmation_even_without_findings() {
        // Ключевой сценарий T85: тесты НЕ запускались (нет тулчейна). Находок нет, но
        // итог не «можно сдавать», а «НЕ подтверждено», и ось перечислена.
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        // Переопределяем тесты на осознанный пропуск (нет тулчейна).
        reg_axis(
            &mut reg,
            "verify/test",
            skipped("verify/test", "тестов нет/не настроены"),
        );
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        assert!(
            !report.confirmed,
            "незапущенная hard-ось снимает подтверждение"
        );
        assert!(
            !report.passed,
            "passed не зелёный при незапущенной hard-оси"
        );
        assert!(
            report.hard_not_run.contains(&"Тесты"),
            "ось «Тесты» перечислена как незапущенная: {:?}",
            report.hard_not_run
        );
        let tests = axis(&report, "Тесты");
        assert!(!tests.ran, "ось не выполнялась");
        assert!(
            tests.not_run_reason.is_some(),
            "причина непустая (нет молчаливых пропусков)"
        );
    }

    #[test]
    fn hard_axis_failing_is_not_passed() {
        // Выполненная hard-ось с находкой: вердикт провален (а не просто «не подтверждён»).
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        reg_axis(
            &mut reg,
            "security.scan/secret",
            ran_with_finding("security.scan/secret", Severity::High, "aws-access-key"),
        );
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        assert!(
            !report.confirmed,
            "ось «Секреты» провалена → не подтверждено"
        );
        assert!(!report.passed);
        let secret = axis(&report, "Секреты");
        assert!(secret.ran, "ось выполнилась");
        assert!(!secret.ok, "ось не прошла");
        assert_eq!(secret.findings, 1);
    }

    #[test]
    fn secret_axis_reports_refuted_count() {
        // T03: ось «Секреты» «чистая» (0 находок), но находка БЫЛА и опровергнута
        // верификатором (секрет в комментарии). refuted>0 фиксирует, что «находок: 0» не
        // равно «секретов нет»: нужна ручная проверка, безусловного «можно сдавать» нет.
        let ctx = tmp_ctx();
        // Строка-комментарий с секрет-подобным значением: верификатор её опровергнет
        // (security + комментарий = не исполняемый код).
        std::fs::write(
            ctx.root.join("conf.py"),
            "# token = \"AKIAIOSFODNN7EXAMPLE\"\nx = 1\n",
        )
        .unwrap();
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        let out = CapabilityOutput {
            findings: vec![Finding {
                rule: "github-token".into(),
                severity: Severity::High,
                message: "секрет".into(),
                location: Some(Location {
                    file: "conf.py".into(),
                    line: 1,
                }),
                evidence: None,
                verified: true,
                source: "security.scan/secret".into(),
            }],
            summary: "security.scan/secret: 1 находка".into(),
            ..Default::default()
        };
        reg_axis(&mut reg, "security.scan/secret", out);
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        let secret = axis(&report, "Секреты");
        assert!(secret.ran, "ось секретов выполнена");
        assert_eq!(secret.findings, 0, "находка опровергнута, в зачёт не идёт");
        assert_eq!(
            secret.refuted, 1,
            "опровергнутый секрет учтён: «находок 0» не равно «секретов нет»"
        );
    }

    #[test]
    fn owasp_medium_is_ok_but_high_fails() {
        // Ось OWASP проходит при MEDIUM (нет HIGH) и валит при HIGH.
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        reg_axis(
            &mut reg,
            "security.scan/owasp",
            ran_with_finding("security.scan/owasp", Severity::Medium, "weak-hash"),
        );
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        let owasp = axis(&report, "OWASP HIGH");
        assert!(owasp.ok, "MEDIUM по OWASP допустим");
        assert!(report.confirmed, "только MEDIUM по OWASP не валит вердикт");

        let mut reg2 = Registry::new();
        register_all_clean(&mut reg2);
        reg_axis(
            &mut reg2,
            "security.scan/owasp",
            ran_with_finding("security.scan/owasp", Severity::High, "sql-injection"),
        );
        let report2 = Orchestrator::dod(&reg2, &ctx, &RunInput::default());
        let owasp2 = axis(&report2, "OWASP HIGH");
        assert!(!owasp2.ok, "HIGH по OWASP валит ось");
        assert!(!report2.confirmed);
    }

    // ───────────────────────────── T86: сбой инструмента ≠ находка ─────────────────────────────

    #[test]
    fn tool_failure_in_test_is_failed_not_finding() {
        // verify/test упал на сборке (could not compile): это сбой инструмента, а не
        // находка-дефект. Ось не выполнена (Failed), вердикт НЕ подтверждён, но это не
        // «тесты падают».
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        let broken = CapabilityOutput {
            summary: "verify/test (cargo): error[E0277] could not compile `crate`".into(),
            ..Default::default()
        };
        reg_axis(&mut reg, "verify/test", broken);
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        let tests = axis(&report, "Тесты");
        assert!(!tests.ran, "сбой инструмента не считается выполнением");
        assert_eq!(tests.findings, 0, "сбой инструмента не стал находкой");
        assert!(
            !report.confirmed,
            "незапущенная hard-ось снимает подтверждение"
        );
        assert!(
            report.hard_not_run.contains(&"Тесты"),
            "ось перечислена как незапущенная"
        );
    }

    #[test]
    fn green_test_without_proof_is_not_run() {
        // verify/test «зелёный», но без позитивного доказательства прогона («echo ok» →
        // сводка без N passed и без маркера «тесты прошли»): ось НЕ считается выполненной,
        // чтобы фиктивный прогон не выдавался за «тесты прошли» (см. T86).
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        let no_proof = CapabilityOutput {
            summary: "verify/test (custom): ok".into(),
            ..Default::default()
        };
        reg_axis(&mut reg, "verify/test", no_proof);
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        let tests = axis(&report, "Тесты");
        assert!(!tests.ran, "зелёный прогон без доказательства не выполнен");
        assert!(!report.confirmed);
    }

    #[test]
    fn failing_tests_axis_runs_and_fails() {
        // Реально упавшие тесты (находка tests-failing): ось ВЫПОЛНЕНА (прогон доказан
        // падением) и провалена. Это «провалено», а не «не подтверждено».
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        let failing = CapabilityOutput {
            findings: vec![Finding {
                rule: "tests-failing".into(),
                severity: Severity::High,
                message: "Тесты не проходят".into(),
                location: None,
                evidence: None,
                verified: true,
                source: "verify/test".into(),
            }],
            summary: "verify/test (cargo): ❌ тесты падают".into(),
            ..Default::default()
        };
        reg_axis(&mut reg, "verify/test", failing);
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        let tests = axis(&report, "Тесты");
        assert!(
            tests.ran,
            "падение тестов доказывает прогон → ось выполнена"
        );
        assert!(!tests.ok, "ось провалена");
        assert_eq!(tests.findings, 1);
        assert!(!report.passed);
        assert!(
            !report.hard_not_run.contains(&"Тесты"),
            "выполненная-но-проваленная ось не считается незапущенной"
        );
    }

    #[test]
    fn lint_tool_failure_is_not_finding() {
        // verify/lint вышел ненулём из-за поломки конфига: сбой инструмента, не Medium-
        // находка «замечания». Ось Failed, не дефект (verify/lint soft — на вердикт не
        // влияет, но и ложной находкой не становится).
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        let broken_lint = CapabilityOutput {
            summary: "verify/lint (clippy): configuration error in clippy.toml".into(),
            ..Default::default()
        };
        reg_axis(&mut reg, "verify/lint", broken_lint);
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        // verify/lint не выделен отдельной осью DoD, но не должен породить находку ни по
        // одной оси: убеждаемся, что подтверждение не сорвано ложным дефектом линтера.
        assert!(
            report.confirmed,
            "сбой линтера не должен превращаться в находку и валить вердикт"
        );
    }

    // ───────────────────────────── T36: пол безопасности SAST/taint ─────────────────────────────

    #[test]
    fn enterprise_sast_taint_run_in_dod_floor() {
        // SAST/taint помечены Tier::Enterprise и обычным гейтом отсекаются, но DoD обязан
        // их выполнять как пол безопасности (см. T36). Находка taint доходит до оси.
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        reg_axis(
            &mut reg,
            "security.scan/taint",
            ran_with_finding(
                "security.scan/taint",
                Severity::High,
                "sast/taint-command-exec",
            ),
        );
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        let taint = axis(&report, "Taint-поток");
        assert!(
            taint.ran,
            "Enterprise-taint выполнен в полу безопасности DoD"
        );
        assert_eq!(taint.findings, 1, "находка taint дошла до оси");
        assert!(!taint.ok, "ось taint провалена находкой");
        assert!(!report.confirmed, "taint-находка валит подтверждение");
    }

    #[test]
    fn sast_not_registered_is_skipped_not_clean() {
        // Если capability пола безопасности не зарегистрирована, это осознанный пропуск с
        // причиной, а не молчаливое «чисто»: hard-ось не выполнена → не подтверждено.
        let mut reg = Registry::new();
        // Регистрируем всё, кроме SAST.
        for id in [
            "quality.check/constitution",
            "verify/test",
            "security.scan/secret",
            "security.scan/owasp",
            "security.scan/taint",
            "quality.check/completeness",
            "spec.check/drift",
            "verify/api-break",
        ] {
            reg_axis(&mut reg, id, ran_clean(id));
        }
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        let sast = axis(&report, "SAST (AST)");
        assert!(!sast.ran, "незарегистрированный SAST не выполнен");
        assert!(
            sast.not_run_reason
                .as_deref()
                .is_some_and(|r| r.contains("не зарегистрирована")),
            "причина пропуска явная: {:?}",
            sast.not_run_reason
        );
        assert!(!report.confirmed);
        assert!(report.hard_not_run.contains(&"SAST (AST)"));
    }

    // ───────────────────────────── T88: единый источник достоверности ─────────────────────────────

    #[test]
    fn low_confidence_heuristic_is_not_counted_as_signal() {
        // Эвристическое правило низкой уверенности (Heuristic → Low по единой карте
        // rule_confidence) НЕ является сигналом, поэтому не попадает в blocking/warning и
        // не валит ось. Источник достоверности — contracts, локальных списков в
        // оркестраторе нет (см. T88).
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        // «long-file» — заведомо Heuristic/Low в карте достоверности.
        reg_axis(
            &mut reg,
            "quality.check/smell",
            ran_with_finding("quality.check/smell", Severity::Info, "long-file"),
        );
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        let smell = axis(&report, "Запахи кода");
        assert_eq!(
            smell.findings, 0,
            "низкоуверенная эвристика не считается сигналом-находкой оси"
        );
    }

    #[test]
    fn pattern_rule_is_counted_as_signal() {
        // Паттерн-правило (Pattern → Medium-сигнал по единой карте) учитывается как
        // находка оси, в отличие от низкоуверенной эвристики выше.
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        reg_axis(
            &mut reg,
            "quality.check/smell",
            ran_with_finding("quality.check/smell", Severity::Low, "swallowed-error"),
        );
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        let smell = axis(&report, "Запахи кода");
        assert_eq!(smell.findings, 1, "паттерн-правило — сигнал, учитывается");
    }

    // ───────────────────────────── verify-эскалация доков ─────────────────────────────

    #[test]
    fn doc_drift_escalated_blocks_dod() {
        // Дрейф доков (doc-drift) низкоуверенен и обычно уходит в advisories; в пути DoD
        // эскалация обязательна, поэтому hard-ось «Доки/Спека актуальны» реально валит
        // вердикт (см. T86 о расхождении hard/never-fails).
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        // location нужен, иначе эскалация и подсчёт всё равно сработают, но дадим honest
        // находку без локации (верификатор её не опровергнет).
        reg_axis(
            &mut reg,
            "spec.check/drift",
            ran_with_finding("spec.check/drift", Severity::Medium, "doc-drift"),
        );
        let ctx = tmp_ctx();
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        let docs = axis(&report, "Доки/Спека актуальны");
        assert!(docs.ran, "ось доков выполнена");
        assert!(
            docs.findings >= 1,
            "доковая находка дошла до оси после эскалации"
        );
        assert!(!docs.ok, "ось доков провалена");
        assert!(!report.confirmed, "дрейф доков валит подтверждение в DoD");
    }

    // ───────────────────────────── positive_test_proof ─────────────────────────────

    #[test]
    fn positive_test_proof_recognizes_n_passed() {
        assert!(positive_test_proof("test result: ok. 13 passed; 0 failed"));
        assert!(positive_test_proof("Tests: 5 passed, 5 total"));
        assert!(positive_test_proof("verify/test (cargo): ✅ тесты прошли"));
        assert!(positive_test_proof("verify/test (jest): tests passed"));
    }

    #[test]
    fn positive_test_proof_rejects_empty_and_zero() {
        assert!(!positive_test_proof("running 0 tests"));
        assert!(!positive_test_proof("0 passed"));
        assert!(!positive_test_proof("ok"));
        assert!(
            !positive_test_proof("verify/test: ⚠ тестов нет — работоспособность НЕ подтверждена"),
            "явный маркер «не подтверждена» не считается доказательством"
        );
    }

    /// РЕГРЕССИЯ. Подстрока «tests passed» не должна засчитывать отрицания и нулевые
    /// счётчики: «not all tests passed» и «0 of 5 tests passed» это провал/пустой прогон,
    /// а не доказательство прохождения.
    #[test]
    fn positive_test_proof_rejects_negations_and_zero_counters() {
        assert!(!positive_test_proof("not all tests passed"));
        assert!(!positive_test_proof("no tests passed"));
        assert!(!positive_test_proof("0 of 5 tests passed"));
        assert!(!positive_test_proof("0 tests passed"));
        assert!(!positive_test_proof("verify/test: тесты не прошли"));
        // Позитивные формы со счётчиком остаются доказательством.
        assert!(positive_test_proof("5 of 5 tests passed"));
        assert!(positive_test_proof("13 tests passed"));
    }

    #[test]
    fn axis_state_helper_finds_location_findings() {
        // Находка с location: верификатор может её обработать; убеждаемся, что
        // верифицированная находка с реальным file:line доходит до оси. Создаём файл,
        // чтобы верификатор не опроверг её как несуществующую.
        let ctx = tmp_ctx();
        std::fs::write(ctx.root.join("a.py"), "x = 1\nos.system(x)\n").unwrap();
        let mut reg = Registry::new();
        register_all_clean(&mut reg);
        let out = CapabilityOutput {
            findings: vec![Finding {
                rule: "sast/taint-command-exec".into(),
                severity: Severity::High,
                message: "поток".into(),
                location: Some(Location {
                    file: "a.py".into(),
                    line: 2,
                }),
                evidence: None,
                verified: true,
                source: "security.scan/sast".into(),
            }],
            summary: "security.scan/sast: 1 находка".into(),
            ..Default::default()
        };
        reg_axis(&mut reg, "security.scan/sast", out);
        let report = Orchestrator::dod(&reg, &ctx, &RunInput::default());
        let sast = axis(&report, "SAST (AST)");
        assert!(sast.ran);
        assert_eq!(
            sast.findings, 1,
            "заземлённая taint-находка дошла до оси SAST"
        );
        assert!(!report.confirmed);
    }
}
