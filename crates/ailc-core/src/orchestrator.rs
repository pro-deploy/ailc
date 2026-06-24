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

use crate::engines::gate::GateRunner;
use crate::pipeline::{Pipeline, PipelineEngine, Step, StepResult};
use crate::policy;
use crate::registry::Registry;
use ailc_contracts::{
    CapabilityOutput, CheckOutcome, Ctx, Family, Finding, GateReport, PolicyPack, QualityLedger,
    RunInput, Severity, Tier,
};
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Бюджет времени на один тяжёлый шаг детерминированного пола безопасности (глубокий
/// SAST/taint). Эти проверки помечены `Tier::Enterprise` и в обычный авто-гейт не
/// попадают (см. `GateRunner::run`), но DoD обязан включать их в детерминированный пол
/// (см. T36), поэтому исполняем их здесь с защитой по таймауту, согласованно с
/// пайплайном (`pipeline::STEP_TIMEOUT`), чтобы зависший разбор не блокировал вердикт.
const SECURITY_FLOOR_TIMEOUT: Duration = Duration::from_secs(180);

/// Идентификаторы capability глубокого анализа безопасности (`Tier::Enterprise`),
/// которые обычный авто-гейт отсекает по тиру, а DoD обязан включать в
/// детерминированный пол безопасности (см. T36). Карта достоверности
/// (`ailc_contracts::rule_confidence`) относит их находки к `Precise` (высокая
/// уверенность), поэтому пропуск именно этих проверок особенно опасен для вердикта.
const SECURITY_FLOOR_CAPS: &[&str] = &["security.scan/sast", "security.scan/taint"];

/// Доступ к LLM (модель клиента через MCP sampling). Реализуется транспортом
/// (бинарём), ядро от транспорта не зависит. Используется агентом и автофиксом.
pub trait Sampler {
    /// Запросить у LLM ответ. None = sampling недоступен/ошибка.
    fn sample(&mut self, system: &str, user: &str) -> Option<String>;
}

// ───────────────────── Общие хелперы (агент + детерминированные прогоны) ─────────────────────

/// Свёртка результатов шагов пайплайна: находки (до verify), что выполнено, что
/// пропущено (с причиной), артефакты генераторов и сводка-карта кода.
pub(crate) struct CollectedRun {
    pub findings: Vec<Finding>,
    pub checks_run: Vec<String>,
    pub checks_skipped: Vec<(String, String)>,
    pub artifacts: Vec<String>,
    pub map_summary: String,
}

/// Свернуть результаты шагов в `CollectedRun`. Инвариант «нет молчаливых пропусков»:
/// ошибка/skip → причина; генератор-артефакт без находок проверкой НЕ считается.
pub(crate) fn collect_results(results: Vec<StepResult>) -> CollectedRun {
    let mut c = CollectedRun {
        findings: Vec::new(),
        checks_run: Vec::new(),
        checks_skipped: Vec::new(),
        artifacts: Vec::new(),
        map_summary: String::new(),
    };
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
            c.checks_skipped.push((cap, format!("ошибка: {e}")));
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

    // Гейт: классификация подтверждённых находок по политике (порог из governance).
    let mut report = GateRunner::classify(
        inp.confirmed,
        inp.checks_run,
        inp.checks_skipped,
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
            format!("✅ Готово к сдаче. Качество {:.0}/100, прошло {} проверок, блокеров нет.{tests}", l.score, l.checks_run)
        } else {
            format!("✅ Ready to ship. Quality {:.0}/100, {} checks passed, no blockers.{tests}", l.score, l.checks_run)
        }
    } else if ru {
        format!("❌ Пока отдавать нельзя. Качество {:.0}/100, {} блокер(ов) требуют твоего решения.{tests}", l.score, l.blocking)
    } else {
        format!("❌ Not ready to ship. Quality {:.0}/100, {} blocker(s) need your decision.{tests}", l.score, l.blocking)
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
        let results = PipelineEngine::execute(reg, ctx, input, &pipeline);
        let collected = collect_results(results);
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
                artifacts: collected.artifacts,
                refuted: refuted.len(),
                strict,
                rounds: Vec::new(),
            },
        )
    }
}

// ───────────────────────── Сплошной скан для отчётов (SARIF) ─────────────────────────

/// Результат сплошного статического скана: подтверждённые находки (ложные отсеяны),
/// сколько опровергнуто Verifier'ом, и какие проверки выполнены/пропущены.
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub refuted: usize,
    pub checks_run: Vec<String>,
    pub checks_skipped: Vec<(String, String)>,
}

impl Orchestrator {
    /// Сплошной статический скан Security/Quality/Compliance/Spec (Core): гонит все
    /// не-мутирующие проверки этих семейств, состязательно опровергает ложные находки
    /// Verifier'ом и возвращает только подтверждённые. Без intent-роутинга —
    /// исчерпывающее покрытие для отчётов (SARIF) и CI.
    pub fn scan_all(reg: &Registry, ctx: &Ctx, input: &RunInput) -> ScanReport {
        let families = [
            Family::Security,
            Family::Quality,
            Family::Compliance,
            Family::Spec,
        ];
        let mut findings = Vec::new();
        let mut checks_run = Vec::new();
        let mut checks_skipped = Vec::new();
        for cap in reg.all() {
            let m = cap.manifest();
            // Защитный минимум (sast/taint) включается ПО ИДЕНТИФИКАТОРУ, даже будучи
            // Tier::Enterprise: иначе полный скан и SARIF недосчитывают потоковые
            // уязвимости, которые гейт и dod уже учитывают (см. SECURITY_FLOOR_CAPS).
            let is_floor = SECURITY_FLOOR_CAPS.contains(&m.id);
            if m.mutates || (m.tier != Tier::Core && !is_floor) || !families.contains(&m.family) {
                continue;
            }
            match cap.run(ctx, input) {
                Ok(out) => {
                    if let Some(reason) = out.skipped {
                        checks_skipped.push((m.id.to_string(), reason));
                    } else {
                        checks_run.push(m.id.to_string());
                        findings.extend(out.findings);
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
        ScanReport {
            findings: confirmed,
            refuted: refuted.len(),
            checks_run,
            checks_skipped,
        }
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
        let (pack, _note) = policy::load(&ctx.root);
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
        let mut report = GateRunner::run(reg, ctx, input, &policy);
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
        for f in report.blocking.iter().chain(report.warning.iter()) {
            if direct_caps.contains(&f.source.as_str()) {
                continue; // прямой прогон считает их сам
            }
            let e = by_src.entry(f.source.as_str()).or_default();
            e.0 += 1;
            if f.severity >= Severity::High {
                e.1 += 1;
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
            let heavy = SECURITY_FLOOR_CAPS.contains(&id);
            let (outcome, refuted) =
                Self::run_axis_direct(reg, ctx, input, id, heavy, &mut by_src);
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

        // Агрегатная ось «Комплаенс РФ» — сумма по всем compliance.ru/* (ориентир, soft:
        // регуляторные риски эвристичны, окончательно решает юрист, см. compliance-ru/).
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
        axes.push(DodAxis {
            name: "Комплаенс РФ",
            hard: false,
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
    fn run_axis_direct(
        reg: &Registry,
        ctx: &Ctx,
        input: &RunInput,
        id: &'static str,
        heavy: bool,
        by_src: &mut HashMap<&str, (usize, usize)>,
    ) -> (CheckOutcome, usize) {
        let Some(cap) = reg.get_arc(id) else {
            // Capability не зарегистрирована: это осознанный пропуск с явной причиной,
            // а не молчаливое «чисто» (инвариант «нет молчаливых пропусков»).
            return (
                CheckOutcome::Skipped(format!(
                    "{id}: capability не зарегистрирована в реестре"
                )),
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
            let left = (Instant::now() + SECURITY_FLOOR_TIMEOUT)
                .saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
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
                return (CheckOutcome::Failed(format!("{id}: ошибка анализа: {e}")), 0);
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
    // Утвердительный маркер прохождения от capability.
    if s.contains("тесты прошли") || s.contains("tests passed") {
        return true;
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
        match id {
            "security.scan/secret"
            | "security.scan/owasp"
            | "security.scan/sast"
            | "security.scan/taint" => Family::Security,
            "verify/test" | "verify/lint" | "verify/coverage" | "verify/api-break" => {
                Family::Verify
            }
            "spec.check/drift" => Family::Spec,
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
        assert!(!report.passed, "passed следует confirmed, ложно-зелёного нет");
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
        assert!(!report.passed, "passed не зелёный при незапущенной hard-оси");
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
        assert!(!report.confirmed, "ось «Секреты» провалена → не подтверждено");
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
            ran_with_finding("security.scan/owasp", Severity::Medium, "weak-crypto"),
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
        assert!(!report.confirmed, "незапущенная hard-ось снимает подтверждение");
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
        assert!(tests.ran, "падение тестов доказывает прогон → ось выполнена");
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
        assert!(taint.ran, "Enterprise-taint выполнен в полу безопасности DoD");
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
        assert!(docs.findings >= 1, "доковая находка дошла до оси после эскалации");
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
        assert_eq!(sast.findings, 1, "заземлённая taint-находка дошла до оси SAST");
        assert!(!report.confirmed);
    }
}
