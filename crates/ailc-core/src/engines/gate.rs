//! E6 GateRunner: граница ответственности.
//!
//! Разделено на:
//!   `classify`, ЧИСТАЯ классификация уже собранных находок по политике
//!                (blocking/warning плюс балл). Её зовёт пайплайн оркестратора.
//!   `run`, обёртка: сама собирает находки из применимых capability и
//!                классифицирует (для прямого вызова вне пайплайна).
//! Логика классификации существует ровно в одном месте, без дублирования.
//!
//! Принципы Волны 2 (T36, T38):
//!   • детерминированный гейт обязан включать глубокий sast/taint по ИДЕНТИФИКАТОРУ,
//!     даже если они помечены `Tier::Enterprise`: это детерминированный пол безопасности,
//!     а не опция. Их шаг обёрнут таймаутом, чтобы тяжёлый разбор не завесил цикл;
//!   • исход проверки различается через `CapabilityOutput::outcome()`: сбой инструмента
//!     («не запустилось из-за поломки») не равен находке и не равен штатному пропуску
//!     («нечего проверять»);
//!   • политика передаётся единым `PolicyPack`: классификация (`block_at`/`families`) и
//!     веса балла опираются на ОДИН источник, файл с диска повторно не перечитывается.

use crate::registry::Registry;
use ailc_contracts::{
    CapabilityOutput, CheckOutcome, Ctx, Finding, GatePolicy, GateReport, PolicyPack, RunInput,
    Severity, Thresholds, Tier,
};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub struct GateRunner;

/// Идентификаторы глубоких анализаторов (AST-SAST и taint), которые детерминированный
/// гейт обязан включать ПО ИМЕНИ как пол безопасности, невзирая на их тир (T36). Это
/// единственный источник High-уверенности по карте достоверности; без явного включения
/// dod/sarif/custodian физически не могли бы их запустить из-за фильтра `tier == Core`.
pub const SECURITY_FLOOR_IDS: &[&str] = &["security.scan/sast", "security.scan/taint"];

/// Бюджет времени на один шаг глубокого анализатора (T36). Тяжёлый разбор AST/taint не
/// должен завесить детерминированный цикл: по истечении бюджета шаг помечается как сбой
/// инструмента (а не как «находок нет»), и вердикт это видит явно.
const DEEP_STEP_TIMEOUT: Duration = Duration::from_secs(120);

impl GateRunner {
    /// Собрать находки из применимых (не мутирующих, нужного семейства) capability и
    /// классифицировать. Совместимая обёртка: принимает `GatePolicy`, остальную часть
    /// пакета (веса балла) берёт из ОДНОЙ загрузки политики, не перечитывая файл дважды
    /// (T38). Делегирует в `run_with_pack`, где живёт вся логика.
    pub fn run(reg: &Registry, ctx: &Ctx, input: &RunInput, policy: &GatePolicy) -> GateReport {
        // Единственная загрузка пакета: веса берём отсюда, а политику гейта (block_at и
        // families) подменяем переданным аргументом, чтобы не было расхождения источников.
        let (mut pack, _note) = crate::policy::load(&ctx.root);
        pack.gate = policy.clone();
        Self::run_with_pack(reg, ctx, input, &pack)
    }

    /// Полный прогон по ЕДИНОМУ `PolicyPack` (T38): классификация и веса балла опираются
    /// на один источник, файл с диска повторно не читается. Это предпочтительная точка
    /// входа для вызывающих, у которых пакет уже загружен (оркестратор/автофикс).
    pub fn run_with_pack(
        reg: &Registry,
        ctx: &Ctx,
        input: &RunInput,
        pack: &PolicyPack,
    ) -> GateReport {
        let policy = &pack.gate;
        let mut findings = Vec::new();
        let mut checks_run = Vec::new();
        let mut checks_skipped = Vec::new();

        for cap in reg.all() {
            let m = cap.manifest();
            if m.mutates {
                continue;
            }
            // Глубокий sast/taint включаем по ИМЕНИ как пол безопасности даже при
            // Tier::Enterprise (T36); прочие не-Core capability в авто-гейт не идут, чтобы
            // тяжёлый разбор не запускался в каждом цикле.
            let is_floor = SECURITY_FLOOR_IDS.contains(&m.id);
            if m.tier != Tier::Core && !is_floor {
                continue;
            }
            // Фильтр по семействам политики применяется и к полу безопасности: если старший
            // явно исключил Security из families, навязывать глубокий скан мы не вправе.
            if !policy.families.is_empty() && !policy.families.contains(&m.family) {
                continue;
            }

            // Глубокие анализаторы исполняем под таймаутом шага (T36): тяжёлый разбор не
            // должен завесить детерминированный цикл. Прочие capability дешёвые, зовём
            // напрямую. Полу безопасности берём ВЛАДЕЮЩИЙ хэндл (Arc), чтобы передать его в
            // отсоединённый поток: по таймауту мы перестаём ждать, не блокируясь на join
            // зависшего шага (как в pipeline).
            let result = if is_floor {
                match reg.get_arc(m.id) {
                    Some(owned) => run_with_timeout(owned, ctx, input, DEEP_STEP_TIMEOUT),
                    // Хэндл по id обязан существовать (мы только что взяли его из all()),
                    // но на всякий случай не паникуем, а зовём напрямую.
                    None => cap.run(ctx, input).map_err(|e| e.to_string()),
                }
            } else {
                cap.run(ctx, input).map_err(|e| e.to_string())
            };

            match result {
                Ok(out) => Self::record_outcome(
                    m.id,
                    &out,
                    &mut findings,
                    &mut checks_run,
                    &mut checks_skipped,
                ),
                // Ошибка/паника/таймаут capability считается СБОЕМ инструмента (T38), а не
                // находка и не штатный пропуск. Помечаем явной категорией, чтобы Rigor
                // Score и человек отличали поломку от «нечего проверять».
                Err(e) => checks_skipped.push((m.id.to_string(), format!("сбой инструмента: {e}"))),
            }
        }

        // Если пол безопасности не попал в реестр или был отфильтрован семействами, его
        // отсутствие в прогоне делаем ВИДИМЫМ (инвариант «нет молчаливых пропусков», T36):
        // вердикт не должен молча выглядеть «чистым» без глубокого анализа.
        for id in SECURITY_FLOOR_IDS {
            let attempted = checks_run.iter().any(|x| x.as_str() == *id)
                || checks_skipped.iter().any(|(x, _)| x.as_str() == *id);
            if !attempted {
                checks_skipped.push((
                    (*id).to_string(),
                    "глубокий SAST/taint не запускался (нет в реестре или исключён families)"
                        .to_string(),
                ));
            }
        }

        // Verify-проход (verify-максимализм): состязательно опровергаем находки,
        // то есть комментарии, плейсхолдеры, определения шаблонов. В гейт идут только выжившие.
        // Так `run` (его зовёт DoD) консистентен с оркестратором `run_with`.
        let (confirmed, _refuted) = crate::verify::Verifier::verify(ctx, findings);
        // Веса балла берём из ТОГО ЖЕ пакета, что и политику классификации (T38): без
        // повторного чтения файла и без расхождения источников.
        Self::classify(confirmed, checks_run, checks_skipped, policy, &pack.thresholds)
    }

    /// Разнести исход одной capability по спискам прогона, используя `CheckOutcome` (T38):
    /// `Ran` несёт находки и считается выполненной проверкой; `Skipped` несёт осознанную
    /// причину пропуска; `Failed` несёт причину сбоя инструмента и НЕ превращается в
    /// находку (инвариант «сбой инструмента не равен находке»). Раньше эти три состояния
    /// неразличимо сливались, из-за чего поломка инструмента выглядела как чистый прогон.
    fn record_outcome(
        id: &str,
        out: &CapabilityOutput,
        findings: &mut Vec<Finding>,
        checks_run: &mut Vec<String>,
        checks_skipped: &mut Vec<(String, String)>,
    ) {
        match out.outcome() {
            CheckOutcome::Ran => {
                checks_run.push(id.to_string());
                findings.extend(out.findings.iter().cloned());
            }
            CheckOutcome::Skipped(reason) => {
                checks_skipped.push((id.to_string(), reason));
            }
            CheckOutcome::Failed(reason) => {
                checks_skipped.push((id.to_string(), format!("сбой инструмента: {reason}")));
            }
        }
    }

    /// Чистая классификация: находки в blocking/warning по `block_at` плюс балл качества.
    pub fn classify(
        findings: Vec<Finding>,
        checks_run: Vec<String>,
        checks_skipped: Vec<(String, String)>,
        policy: &GatePolicy,
        thresholds: &Thresholds,
    ) -> GateReport {
        let mut report = GateReport {
            checks_run,
            checks_skipped,
            ..Default::default()
        };
        let mut unverified = 0usize;
        for f in findings {
            // Анти-гейминг: в балл/блокировку идут ТОЛЬКО верифицированные находки
            // (детерминированные заземлены на file:line и помечены verified=true;
            // будущие LLM-находки не считаются, пока их не подтвердит adversarial-проход).
            if !f.verified {
                unverified += 1;
                continue;
            }
            if f.severity >= policy.block_at {
                report.blocking.push(f);
            } else if f.is_signal() {
                report.warning.push(f);
            } else {
                // Низкоуверенный шум (стиль/метрики/инфо/дрейф доков) уходит в советы, а не в
                // вердикт: не блокирует и не снижает балл (см. quality_score).
                report.advisories.push(f);
            }
        }
        // Инвариант «нет молчаливых пропусков»: отброс неверифицированного это тоже
        // пропуск, человек должен его видеть, а не догадываться.
        if unverified > 0 {
            report.checks_skipped.push((
                "gate".to_string(),
                format!("{unverified} находок без верификации отброшено (в балл не идут)"),
            ));
        }
        // passed считаем безусловно по итоговому множеству блокеров (T38, защитно): любая
        // последующая переклассификация обязана пересчитать его снова, см.
        // escalate_unfinished.
        report.passed = report.blocking.is_empty();
        report.score = quality_score(&report, thresholds);
        report
            .metrics
            .push(("unverified_dropped".into(), unverified as f64));
        report
            .metrics
            .push(("checks_run".into(), report.checks_run.len() as f64));
        report
            .metrics
            .push(("blocking".into(), report.blocking.len() as f64));
        report
            .metrics
            .push(("warning".into(), report.warning.len() as f64));
        report
    }

    /// «Сдача» строже обычного прогона: недоделанное (заглушки и пустые блоки,
    /// `quality.check/completeness`) И устаревшая/отсутствующая документация
    /// (`spec.check/drift`), а также слом контракта API (`verify/api-break`) перестают
    /// быть предупреждением и БЛОКИРУЮТ. Не даём сдать незавершённое и со стухшими доками;
    /// в мид-билде это остаётся мягким. Балл не меняется (множество находок то же, меняется лишь
    /// классификация warning/advisory в block).
    ///
    /// Важно (T35): эскалация работает лишь по тем находкам, что ДОШЛИ до гейта. Если
    /// штатная политика обрезала семейства Spec/Verify, источники недоделанного не
    /// собираются на детерминированных входах, и эскалация де-факто отключается молча.
    /// Поэтому `escalate_unfinished_checked` дополнительно сверяет families с семействами
    /// недоделанного и возвращает предупреждение; штатный `ailc.policy.toml` приведён к
    /// families, включающим Spec и Verify.
    pub fn escalate_unfinished(report: &mut GateReport) {
        // Источники незавершённого: ищем И в warning, И в advisories, так как дрейф доков теперь
        // низкоуверенный (совет), но на сдаче обязан эскалировать наравне с заглушками.
        let is_unfinished =
            |f: &Finding| UNFINISHED_SOURCES.contains(&f.source.as_str());
        let (mut unfinished, warn_rest): (Vec<Finding>, Vec<Finding>) =
            std::mem::take(&mut report.warning)
                .into_iter()
                .partition(&is_unfinished);
        report.warning = warn_rest;
        let (mut adv_unfinished, adv_rest): (Vec<Finding>, Vec<Finding>) =
            std::mem::take(&mut report.advisories)
                .into_iter()
                .partition(&is_unfinished);
        report.advisories = adv_rest;
        unfinished.append(&mut adv_unfinished);
        if !unfinished.is_empty() {
            report.blocking.append(&mut unfinished);
        }
        // Пересчёт passed БЕЗУСЛОВНЫЙ (T38): даже при пустом unfinished фиксируем
        // инвариант passed == blocking.is_empty(), чтобы будущие изменения порядка не
        // оставили passed рассогласованным с blocking.
        report.passed = report.blocking.is_empty();
    }

    /// Эскалация недоделанного с проверкой охвата политики (T35). Делает то же, что
    /// `escalate_unfinished`, но дополнительно сверяет `families` со списком семейств,
    /// порождающих находки недоделанного, и возвращает ЯВНОЕ предупреждение, если хотя бы
    /// одно такое семейство исключено политикой (тогда эскалация по нему недостижима на
    /// детерминированных входах). Предупреждение нужно класть в вердикт, чтобы отключение
    /// строгости урезанными families не было молчаливым.
    pub fn escalate_unfinished_checked(report: &mut GateReport, policy: &GatePolicy) -> Option<String> {
        let warning = unfinished_coverage_warning(policy);
        Self::escalate_unfinished(report);
        warning
    }
}

/// Источники находок «недоделанного», которые на сдаче эскалируют в блокеры. Вынесены в
/// константу как единый источник истины для эскалации и для проверки охвата families
/// (T35): список и его требуемые семейства не должны расходиться.
pub const UNFINISHED_SOURCES: &[&str] = &[
    "quality.check/completeness",
    "spec.check/drift",
    "verify/api-break",
];

/// Предупреждение об охвате эскалации недоделанного политикой (T35). Возвращает текст,
/// если непустой `families` исключает семейство, нужное для какого-либо источника
/// недоделанного (Spec для дрейфа доков, Verify для слома API), иначе `None`. Пустой
/// `families` означает «все семейства» и ослаблением охвата не является.
pub fn unfinished_coverage_warning(policy: &GatePolicy) -> Option<String> {
    use ailc_contracts::Family;
    if policy.families.is_empty() {
        return None;
    }
    // Семейства, без которых соответствующий источник недоделанного не дойдёт до гейта.
    let required: &[(Family, &str)] = &[
        (Family::Quality, "quality.check/completeness (заглушки/пустые блоки)"),
        (Family::Spec, "spec.check/drift (дрейф документации)"),
        (Family::Verify, "verify/api-break (слом контракта API)"),
    ];
    let missing: Vec<&str> = required
        .iter()
        .filter(|(fam, _)| !policy.families.contains(fam))
        .map(|(_, label)| *label)
        .collect();
    if missing.is_empty() {
        None
    } else {
        Some(format!(
            "⚠ эскалация недоделанного частично отключена урезанными families: \
             не будут блокировать на сдаче следующие источники: {}",
            missing.join(", ")
        ))
    }
}

/// Исполнить одну capability под таймаутом в ОТСОЕДИНЁННОМ потоке (T36). Тяжёлый разбор
/// глубокого анализатора не должен завесить детерминированный цикл; по истечении бюджета
/// возвращается ошибка-таймаут, которую вызывающий классифицирует как СБОЙ инструмента, а
/// не как «находок нет». Поток именно отсоединённый (`std::thread::spawn`, не
/// `thread::scope`): по таймауту мы перестаём ждать результат и НЕ блокируемся на join
/// зависшего шага, иначе таймаут не давал бы выигрыша во времени (та же причина, что в
/// pipeline). Поток владеет клонами `Ctx`/`RunInput` и `Arc` capability, поэтому переживёт
/// возврат функции. Паника шага ловится `catch_unwind`, чтобы один упавший детектор не
/// ронял процесс. Возвращает `Ok(output)` либо `Err(описание)`.
fn run_with_timeout(
    cap: std::sync::Arc<dyn crate::Capability>,
    ctx: &Ctx,
    input: &RunInput,
    budget: Duration,
) -> std::result::Result<CapabilityOutput, String> {
    let deadline = Instant::now() + budget;
    let (tx, rx) = mpsc::channel();
    let (ctx2, input2) = (ctx.clone(), input.clone());
    std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cap.run(&ctx2, &input2)
        }));
        // Получатель мог уже уйти по таймауту: ошибку отправки игнорируем.
        let _ = tx.send(outcome);
    });
    let left = deadline.saturating_duration_since(Instant::now());
    match rx.recv_timeout(left) {
        Ok(Ok(Ok(out))) => Ok(out),
        Ok(Ok(Err(e))) => Err(e.to_string()),
        Ok(Err(_panic)) => Err("глубокий анализатор паниковал".to_string()),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "глубокий анализатор превысил лимит времени ({}с)",
            budget.as_secs()
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("глубокий анализатор прерван без результата".to_string())
        }
    }
}

/// Балл качества: 100 минус взвешенные штрафы по severity (веса берутся из PolicyPack).
/// Клампится в [0, 100] (T34): отрицательный вес в политике не должен поднять балл выше
/// ста, а множество тяжёлых находок не должно увести его ниже нуля.
fn quality_score(r: &GateReport, t: &Thresholds) -> f64 {
    let mut score = 100.0_f64;
    for f in r.blocking.iter().chain(r.warning.iter()) {
        score -= match f.severity {
            Severity::Critical => t.score_critical,
            Severity::High => t.score_high,
            Severity::Medium => t.score_medium,
            Severity::Low => t.score_low,
            Severity::Info => t.score_info,
        };
    }
    score.clamp(0.0, 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_contracts::{Family, Location};

    fn finding(sev: Severity, verified: bool, rule: &str, source: &str) -> Finding {
        Finding::new(
            rule,
            sev,
            "тест",
            Some(Location {
                file: "a.rs".into(),
                line: 1,
            }),
            None,
            verified,
            source,
        )
    }

    fn def_pack() -> PolicyPack {
        PolicyPack::default()
    }

    /// T38, защитно: passed пересчитывается безусловно и согласован с blocking даже при
    /// пустом множестве недоделанного.
    #[test]
    fn passed_recomputed_unconditionally_on_empty_unfinished() {
        let policy = GatePolicy {
            block_at: Severity::High,
            families: vec![],
        };
        let t = Thresholds::default();
        // Один блокер, ничего недоделанного.
        let mut report = GateRunner::classify(
            vec![finding(Severity::Critical, true, "aws-access-key", "security.scan/secret")],
            vec!["security.scan/secret".into()],
            vec![],
            &policy,
            &t,
        );
        assert!(!report.passed, "при наличии блокера вердикт не passed");
        GateRunner::escalate_unfinished(&mut report);
        // passed остаётся согласованным с blocking (инвариант пересчитан безусловно).
        assert_eq!(report.passed, report.blocking.is_empty());
        assert!(!report.passed);
    }

    /// T38: сбой инструмента (через CheckOutcome::Failed) НЕ становится находкой и
    /// помечается отдельной категорией в checks_skipped, в отличие от штатного пропуска.
    #[test]
    fn record_outcome_separates_failed_skipped_ran() {
        let mut findings = Vec::new();
        let mut run = Vec::new();
        let mut skipped = Vec::new();

        // Ran: находки уходят в общий список, проверка засчитана.
        let ran = CapabilityOutput {
            summary: "owasp: чисто".into(),
            findings: vec![finding(Severity::High, true, "sql-injection", "security.scan/owasp")],
            ..Default::default()
        };
        GateRunner::record_outcome("security.scan/owasp", &ran, &mut findings, &mut run, &mut skipped);
        assert_eq!(run, vec!["security.scan/owasp"]);
        assert_eq!(findings.len(), 1);

        // Skipped: осознанный пропуск с причиной, не сбой.
        let sk = CapabilityOutput {
            skipped: Some("нет файла конституции".into()),
            ..Default::default()
        };
        GateRunner::record_outcome("quality.check/constitution", &sk, &mut findings, &mut run, &mut skipped);
        assert!(skipped.iter().any(|(id, r)| id == "quality.check/constitution"
            && !r.contains("сбой инструмента")));

        // Failed: поломка инструмента распознана и помечена «сбой инструмента».
        let failed = CapabilityOutput {
            skipped: Some("verify/test: could not compile".into()),
            ..Default::default()
        };
        GateRunner::record_outcome("verify/test", &failed, &mut findings, &mut run, &mut skipped);
        assert!(
            skipped
                .iter()
                .any(|(id, r)| id == "verify/test" && r.contains("сбой инструмента")),
            "сбой инструмента обязан быть отдельной категорией, не штатным пропуском"
        );
        // Сбой не добавил находок и не засчитал проверку как выполненную.
        assert_eq!(findings.len(), 1, "сбой инструмента не равен находке");
        assert!(!run.iter().any(|x| x == "verify/test"));
    }

    /// T35: при урезанных families (без Spec/Verify) проверка охвата даёт предупреждение,
    /// называя недостижимые источники недоделанного.
    #[test]
    fn unfinished_coverage_warns_when_families_trimmed() {
        let policy = GatePolicy {
            block_at: Severity::High,
            families: vec![Family::Security, Family::Quality],
        };
        let w = unfinished_coverage_warning(&policy)
            .expect("обрезанные Spec и Verify дают предупреждение");
        assert!(w.contains("spec.check/drift"), "дрейф доков назван: {w}");
        assert!(w.contains("verify/api-break"), "слом API назван: {w}");
        // Quality присутствует, поэтому completeness не в списке недостижимых.
        assert!(!w.contains("quality.check/completeness"), "Quality на месте: {w}");
    }

    /// T35, негатив: полная политика (Spec и Verify включены) предупреждения не даёт.
    #[test]
    fn unfinished_coverage_silent_when_families_complete() {
        let policy = GatePolicy {
            block_at: Severity::High,
            families: vec![Family::Security, Family::Quality, Family::Spec, Family::Verify],
        };
        assert!(unfinished_coverage_warning(&policy).is_none());
        // Пустой families означает все семейства, поэтому тоже без предупреждения.
        let all = GatePolicy {
            block_at: Severity::High,
            families: vec![],
        };
        assert!(unfinished_coverage_warning(&all).is_none());
    }

    /// T35: escalate_unfinished_checked одновременно эскалирует находки и возвращает
    /// предупреждение об охвате.
    #[test]
    fn escalate_checked_escalates_and_warns() {
        let t = Thresholds::default();
        let policy = GatePolicy {
            block_at: Severity::Critical, // High не блокирует сам по себе
            families: vec![Family::Security], // Spec/Verify/Quality обрезаны
        };
        // Недоделанное (verify/api-break) пришло как сигнал-предупреждение.
        let report_findings = vec![finding(Severity::High, true, "api-break", "verify/api-break")];
        let mut report = GateRunner::classify(
            report_findings,
            vec!["verify/api-break".into()],
            vec![],
            &policy,
            &t,
        );
        // До эскалации: не блокер (block_at=critical, а severity=high).
        assert!(report.blocking.is_empty(), "до сдачи High не блокирует");
        assert_eq!(report.warning.len(), 1);
        let w = GateRunner::escalate_unfinished_checked(&mut report, &policy);
        // После эскалации недоделанное в блокерах.
        assert_eq!(report.blocking.len(), 1, "на сдаче слом API блокирует");
        assert!(!report.passed);
        // И предупреждение об охвате выдано (families обрезаны).
        assert!(w.is_some(), "урезанные families дают предупреждение охвата");
    }

    /// T34: балл клампится сверху до 100 даже при «отрицательном штрафе» (защита от
    /// политики с отрицательным весом, если бы она прошла; здесь моделируем напрямую).
    #[test]
    fn quality_score_clamped_to_100() {
        // отрицательный вес поднял бы балл выше 100
        let t = Thresholds {
            score_high: -50.0,
            ..Default::default()
        };
        let report = GateReport {
            warning: vec![finding(Severity::High, true, "sql-injection", "security.scan/owasp")],
            ..Default::default()
        };
        let s = quality_score(&report, &t);
        assert!(s <= 100.0, "балл не превышает 100 даже при отрицательном весе: {s}");
        assert_eq!(s, 100.0);
    }

    /// T34: балл клампится снизу до 0 при множестве тяжёлых находок.
    #[test]
    fn quality_score_clamped_to_0() {
        let t = Thresholds::default();
        let many: Vec<Finding> = (0..10)
            .map(|_| finding(Severity::Critical, true, "aws-access-key", "security.scan/secret"))
            .collect();
        let report = GateReport {
            blocking: many,
            ..Default::default()
        };
        let s = quality_score(&report, &t);
        assert_eq!(s, 0.0, "10 critical по 25 = -150, кламп до нуля");
    }

    /// run_with_timeout возвращает выход быстрой capability без срабатывания таймаута.
    #[test]
    fn timeout_runner_returns_fast_output() {
        use ailc_contracts::{CapabilityManifest, EngineKind, Result};
        struct Fast;
        impl crate::Capability for Fast {
            fn manifest(&self) -> &CapabilityManifest {
                static M: CapabilityManifest = CapabilityManifest {
                    id: "test/fast",
                    family: Family::Security,
                    engine: EngineKind::Scan,
                    when_to_use: "тест",
                    input_schema: "{}",
                    tier: Tier::Enterprise,
                    deterministic: true,
                    mutates: false,
                };
                &M
            }
            fn run(&self, _c: &Ctx, _i: &RunInput) -> Result<CapabilityOutput> {
                Ok(CapabilityOutput {
                    summary: "быстро".into(),
                    ..Default::default()
                })
            }
        }
        let ctx = Ctx::new(std::env::temp_dir());
        let cap: std::sync::Arc<dyn crate::Capability> = std::sync::Arc::new(Fast);
        let out = run_with_timeout(cap, &ctx, &RunInput::default(), Duration::from_secs(5))
            .expect("быстрый шаг укладывается в бюджет");
        assert_eq!(out.summary, "быстро");
    }

    /// run_with_timeout помечает зависший шаг как сбой по таймауту (T36): не «находок
    /// нет», а явная ошибка инструмента.
    #[test]
    fn timeout_runner_reports_timeout_on_hang() {
        use ailc_contracts::{CapabilityManifest, EngineKind, Result};
        struct Hang;
        impl crate::Capability for Hang {
            fn manifest(&self) -> &CapabilityManifest {
                static M: CapabilityManifest = CapabilityManifest {
                    id: "test/hang",
                    family: Family::Security,
                    engine: EngineKind::Scan,
                    when_to_use: "тест",
                    input_schema: "{}",
                    tier: Tier::Enterprise,
                    deterministic: true,
                    mutates: false,
                };
                &M
            }
            fn run(&self, _c: &Ctx, _i: &RunInput) -> Result<CapabilityOutput> {
                std::thread::sleep(Duration::from_millis(400));
                Ok(CapabilityOutput::default())
            }
        }
        let ctx = Ctx::new(std::env::temp_dir());
        let cap: std::sync::Arc<dyn crate::Capability> = std::sync::Arc::new(Hang);
        let err = run_with_timeout(cap, &ctx, &RunInput::default(), Duration::from_millis(50))
            .expect_err("зависший шаг обязан дать ошибку таймаута");
        assert!(err.contains("лимит времени"), "ошибка называет таймаут: {err}");
    }

    /// T38: run_with_pack использует ОДИН пакет для классификации и весов; явный прогон
    /// без находок проходит, веса берутся из переданного пакета.
    #[test]
    fn run_with_pack_uses_single_pack() {
        use crate::registry::Registry;
        let reg = Registry::new(); // пустой реестр: нет capability, но пол безопасности
                                   // отметится как не запущенный
        let ctx = Ctx::new(std::env::temp_dir());
        let pack = def_pack();
        let report = GateRunner::run_with_pack(&reg, &ctx, &RunInput::default(), &pack);
        assert!(report.passed, "без находок вердикт passed");
        // Пол безопасности отсутствует в пустом реестре, поэтому виден явный пропуск (T36).
        assert!(
            report
                .checks_skipped
                .iter()
                .any(|(id, _)| SECURITY_FLOOR_IDS.contains(&id.as_str())),
            "отсутствие глубокого SAST/taint должно быть видимым"
        );
    }
}
