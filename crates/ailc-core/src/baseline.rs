//! Базовая линия долга: перемирие с легаси.
//!
//! Первое знакомство с действующим проектом фиксирует все текущие подтверждённые
//! находки как ИСТОРИЧЕСКИЙ ДОЛГ в `.ailc/baseline/findings.txt`. Дальше вердикт
//! Definition of Done блокируют только НОВЫЕ находки (их нет в базовой линии), а долг
//! виден отдельной метрикой и гасится по плану. Планка «не хуже, чем вчера» — честная
//! и единственная применимая к зрелой кодовой базе с первого дня.
//!
//! Долг — это отсрочка, а не прощение: полный масштаб виден в отчёте SARIF и в файле
//! базовой линии, а команда `ailc baseline <путь>` пересобирает линию осознанно
//! (например, после большого рефакторинга). Механика повторяет `verify/api-break`:
//! снимок в `.ailc/`, сравнение при каждом прогоне.

use crate::engines::store::Store;
use ailc_contracts::{Ctx, Finding, Severity};
use std::collections::HashSet;

const NS: &str = "baseline";
const FILE: &str = "findings.txt";

/// Можно ли заморозить находку как исторический долг.
///
/// Долг это отсрочка по качеству, а НЕ амнистия по уязвимостям. Находки семейства
/// безопасности с важностью «высокая» и выше заморозке не подлежат: иначе однократный
/// вызов `ailc baseline <путь>` навсегда снимал бы блокировку по реальным уязвимостям, и
/// вердикт переставал бы что-либо гарантировать. Правило применяется симметрично при
/// записи линии и при разборе уже существующей линии, поэтому старые файлы базовой линии,
/// в которые уязвимости попали до введения этого ограничения, тоже перестают их скрывать.
pub fn is_freezable(f: &Finding) -> bool {
    !(f.source.starts_with("security.") && f.severity >= Severity::High)
}

/// Стабильный отпечаток находки.
///
/// Номер строки в отпечаток не входит: правки выше по файлу не должны «размораживать»
/// долг. Вместо номера строки берётся отпечаток самого свидетельства (`evidence`), то
/// есть фрагмента кода, вызвавшего находку. Это сохраняет устойчивость к сдвигу строк и
/// при этом РАЗЛИЧАЕТ два разных вхождения одного класса в одном файле: вновь внесённая
/// уязвимость с другим фрагментом кода не будет зачтена как ранее замороженный долг.
/// Если свидетельства нет, поведение прежнее (правило, файл, сообщение).
pub fn fingerprint(f: &Finding) -> String {
    let file = f
        .location
        .as_ref()
        .map(|l| l.file.as_str())
        .unwrap_or("<no-file>");
    // ВАЖНОСТЬ И ИСТОЧНИК ВХОДЯТ В КЛЮЧ. Прежде ключ состоял из правила, файла, сообщения и
    // 32-битного хеша свидетельства. Тридцати двух бит некриптографической функции мало,
    // чтобы исключить совпадение, а отсутствие важности и источника означало, что находка,
    // сменившая важность или пришедшая от другой capability, считалась той же самой. Обе
    // особенности ведут к одному: новая находка молча признаётся историческим долгом и
    // перестаёт блокировать сдачу.
    let base = format!(
        "{}|{}|{}|{}|{}",
        f.rule,
        f.source,
        f.severity,
        file,
        f.message.replace('\n', " ")
    );
    match f
        .evidence
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        // Свидетельство нормализуется по пробелам (переформатирование строки не должно
        // размораживать долг) и хешируется криптографической функцией, а не самодельной.
        Some(ev) => {
            let norm: String = ev.split_whitespace().collect::<Vec<_>>().join(" ");
            format!("{base}|{}", crate::policy::sha256_hex(norm.as_bytes()))
        }
        None => base,
    }
}

/// Загрузить базовую линию. Пустое множество = линии нет (проект новый или её ещё
/// не фиксировали); тогда долга нет и блокирует всё, как раньше.
pub fn load(ctx: &Ctx) -> HashSet<String> {
    std::fs::read_to_string(ctx.root.join(".ailc").join(NS).join(FILE))
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Есть ли зафиксированная базовая линия (отличаем «линии нет» от «линия пустая»).
pub fn exists(ctx: &Ctx) -> bool {
    ctx.root.join(".ailc").join(NS).join(FILE).is_file()
}

/// Итог фиксации базовой линии: сколько отпечатков заморожено и сколько находок
/// заморозить отказано (уязвимости, см. [`is_freezable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Recorded {
    /// Число замороженных отпечатков (эти находки перестают блокировать сдачу).
    pub frozen: usize,
    /// Число находок безопасности, которые заморозить отказано: они продолжают блокировать.
    pub refused: usize,
}

/// Зафиксировать базовую линию из текущих находок (перезапись целиком).
///
/// Находки безопасности с важностью «высокая» и выше в линию НЕ попадают (см.
/// [`is_freezable`]) и продолжают блокировать сдачу; их число возвращается отдельно,
/// чтобы вызывающий мог сказать об этом человеку прямо, а не умолчать.
pub fn record(ctx: &Ctx, findings: &[Finding]) -> ailc_contracts::Result<Recorded> {
    let refused = findings.iter().filter(|f| !is_freezable(f)).count();
    let mut set: Vec<String> = findings
        .iter()
        .filter(|f| is_freezable(f))
        .map(fingerprint)
        .collect();
    set.sort();
    set.dedup();
    let mut body = String::from(
        "# Базовая линия долга AILC: зафиксированные находки (правило|файл|сообщение|свидетельство).\n\
         # Вердикт сдачи блокируют только находки ВНЕ этого списка. Пересборка: ailc baseline <путь>\n\
         # Уязвимости (семейство security, важность high и выше) в линию не заносятся и блокируют всегда.\n",
    );
    for s in &set {
        body.push_str(s);
        body.push('\n');
    }
    Store::write(ctx, NS, FILE, &body)?;
    Ok(Recorded {
        frozen: set.len(),
        refused,
    })
}

/// Разделить находки на новые (блокируют) и долг (в базовой линии). Порядок сохраняется.
///
/// Уязвимость никогда не уходит в долг, даже если её отпечаток присутствует в файле
/// базовой линии: старые линии, записанные до введения ограничения, перестают её скрывать.
/// Для совместимости со старыми линиями отпечаток сверяется и в новом виде (со
/// свидетельством), и в прежнем (без него).
pub fn split(base: &HashSet<String>, findings: Vec<Finding>) -> (Vec<Finding>, Vec<Finding>) {
    if base.is_empty() {
        return (findings, Vec::new());
    }
    findings.into_iter().partition(|f| !is_debt(base, f))
}

/// Числится ли находка в базовой линии как долг.
///
/// Единственная точка принятия этого решения: гейт и Definition of Done обязаны
/// спрашивать именно её, а не сравнивать отпечаток напрямую, иначе ограничение по
/// уязвимостям и совместимость со старым форматом линии обходились бы мимо.
pub fn is_debt(base: &HashSet<String>, f: &Finding) -> bool {
    if !is_freezable(f) {
        return false;
    }
    if base.contains(&fingerprint(f)) {
        return true;
    }
    // Совместимость: линия, записанная прежней версией, содержит отпечаток без свидетельства.
    let file = f
        .location
        .as_ref()
        .map(|l| l.file.as_str())
        .unwrap_or("<no-file>");
    let legacy = format!("{}|{}|{}", f.rule, file, f.message.replace('\n', " "));
    base.contains(&legacy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_contracts::{Location, Severity};

    fn ctx(tag: &str) -> Ctx {
        let root = std::env::temp_dir().join(format!(
            "ailc-baseline-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join(".ailc")).unwrap();
        Ctx::new(root.to_str().unwrap())
    }

    /// Находка качества: заморозке подлежит (долг это отсрочка по качеству).
    fn finding(rule: &str, file: &str, msg: &str) -> Finding {
        Finding {
            rule: rule.into(),
            severity: Severity::Medium,
            message: msg.into(),
            location: Some(Location {
                file: file.into(),
                line: 3,
            }),
            evidence: None,
            verified: true,
            source: "quality.check/smell".into(),
        }
    }

    /// Уязвимость: заморозке НЕ подлежит.
    fn vuln(rule: &str, file: &str, msg: &str) -> Finding {
        Finding {
            rule: rule.into(),
            severity: Severity::High,
            message: msg.into(),
            location: Some(Location {
                file: file.into(),
                line: 3,
            }),
            evidence: None,
            verified: true,
            source: "security.scan/secret".into(),
        }
    }

    #[test]
    fn record_then_split_freezes_old_blocks_new() {
        let c = ctx("roundtrip");
        let old = finding("long-file", "src/a.py", "слишком длинный файл");
        let rec = record(&c, std::slice::from_ref(&old)).unwrap();
        assert_eq!(rec.frozen, 1);
        assert_eq!(rec.refused, 0);
        assert!(exists(&c));

        let base = load(&c);
        let fresh = finding("god-file", "src/b.py", "слишком много сущностей");
        let (new, debt) = split(&base, vec![old, fresh]);
        assert_eq!(debt.len(), 1, "старая находка ушла в долг");
        assert_eq!(new.len(), 1, "новая блокирует");
        assert_eq!(new[0].rule, "god-file");
        std::fs::remove_dir_all(&c.root).ok();
    }

    #[test]
    fn line_shift_does_not_unfreeze_debt() {
        let c = ctx("lineshift");
        let mut f = finding("long-file", "src/a.py", "слишком длинный файл");
        record(&c, &[f.clone()]).unwrap();
        // Файл отредактировали выше по тексту: находка сместилась на другую строку.
        f.location = Some(Location {
            file: "src/a.py".into(),
            line: 42,
        });
        let (new, debt) = split(&load(&c), vec![f]);
        assert!(new.is_empty());
        assert_eq!(debt.len(), 1);
        std::fs::remove_dir_all(&c.root).ok();
    }

    #[test]
    fn no_baseline_means_everything_blocks() {
        let c = ctx("nobase");
        let (new, debt) = split(&load(&c), vec![finding("r", "f", "m")]);
        assert_eq!(new.len(), 1);
        assert!(debt.is_empty());
        std::fs::remove_dir_all(&c.root).ok();
    }

    /// T-06: уязвимость нельзя заморозить ни записью линии, ни разбором старой линии.
    #[test]
    fn vulnerability_is_never_frozen() {
        let c = ctx("vuln");
        let v = vuln("secret-aws", "src/a.py", "боевой ключ AWS");
        let debt_item = finding("long-file", "src/a.py", "слишком длинный файл");
        let rec = record(&c, &[v.clone(), debt_item.clone()]).unwrap();
        assert_eq!(rec.frozen, 1, "заморожена только находка качества");
        assert_eq!(rec.refused, 1, "уязвимость заморозить отказано");

        let (new, debt) = split(&load(&c), vec![v.clone(), debt_item]);
        assert_eq!(new.len(), 1, "уязвимость продолжает блокировать");
        assert_eq!(new[0].rule, "secret-aws");
        assert_eq!(debt.len(), 1);

        // Старая линия, куда уязвимость попала до введения ограничения, её не скрывает.
        let legacy: HashSet<String> = [fingerprint(&v)].into_iter().collect();
        let (new, debt) = split(&legacy, vec![v]);
        assert_eq!(new.len(), 1);
        assert!(debt.is_empty());
        std::fs::remove_dir_all(&c.root).ok();
    }

    /// T-07: второе вхождение того же класса в том же файле с ДРУГИМ фрагментом кода
    /// считается новым и блокирует, а то же самое вхождение остаётся долгом.
    #[test]
    fn different_evidence_is_a_new_finding() {
        let c = ctx("evidence");
        let mut first = finding("debt-marker", "src/a.py", "маркер технического долга");
        first.evidence = Some("# TODO: старый долг".into());
        record(&c, &[first.clone()]).unwrap();

        let mut second = first.clone();
        second.evidence = Some("# TODO: свежая недоделка".into());
        let (new, debt) = split(&load(&c), vec![first.clone(), second]);
        assert_eq!(debt.len(), 1, "прежнее вхождение осталось долгом");
        assert_eq!(new.len(), 1, "новое вхождение блокирует");

        // Переформатирование того же фрагмента долг не размораживает.
        let mut reformatted = first;
        reformatted.evidence = Some("#   TODO:  старый  долг".into());
        let (new, debt) = split(&load(&c), vec![reformatted]);
        assert!(new.is_empty());
        assert_eq!(debt.len(), 1);
        std::fs::remove_dir_all(&c.root).ok();
    }

    /// Совместимость: линия прежнего формата (без свидетельства) продолжает работать.
    #[test]
    fn legacy_baseline_without_evidence_still_matches() {
        let mut f = finding("long-file", "src/a.py", "слишком длинный файл");
        f.evidence = Some("fn main() {}".into());
        let legacy: HashSet<String> = ["long-file|src/a.py|слишком длинный файл".to_string()]
            .into_iter()
            .collect();
        let (new, debt) = split(&legacy, vec![f]);
        assert!(new.is_empty(), "старая линия продолжает признаваться");
        assert_eq!(debt.len(), 1);
    }

    /// РЕГРЕССИЯ. В ключ замороженной находки обязаны входить ВАЖНОСТЬ и ИСТОЧНИК. Прежде
    /// ключ состоял из правила, файла, сообщения и 32-битного хеша свидетельства, поэтому
    /// находка, сменившая важность или пришедшая от другой capability, считалась той же
    /// самой и молча признавалась историческим долгом, то есть переставала блокировать сдачу.
    #[test]
    fn важность_и_источник_входят_в_ключ() {
        let mk = |sev: Severity, src: &str| Finding {
            rule: "smell".into(),
            severity: sev,
            message: "одно и то же сообщение".into(),
            location: Some(Location {
                file: "a.rs".into(),
                line: 1,
            }),
            evidence: Some("одно и то же свидетельство".into()),
            verified: true,
            source: src.into(),
        };
        let base = fingerprint(&mk(Severity::Low, "quality.check/smell"));
        assert_ne!(
            base,
            fingerprint(&mk(Severity::Critical, "quality.check/smell")),
            "смена важности обязана менять ключ"
        );
        assert_ne!(
            base,
            fingerprint(&mk(Severity::Low, "security.scan/owasp")),
            "смена источника обязана менять ключ"
        );
    }

    /// Переформатирование свидетельства по пробелам ключ НЕ меняет: иначе выравнивание кода
    /// размораживало бы весь долг разом.
    #[test]
    fn пробелы_в_свидетельстве_не_меняют_ключ() {
        let mk = |ev: &str| Finding {
            rule: "smell".into(),
            severity: Severity::Low,
            message: "сообщение".into(),
            location: Some(Location {
                file: "a.rs".into(),
                line: 1,
            }),
            evidence: Some(ev.into()),
            verified: true,
            source: "quality.check/smell".into(),
        };
        assert_eq!(
            fingerprint(&mk("let  x =   1;")),
            fingerprint(&mk("let x = 1;")),
            "нормализация пробелов сохраняется"
        );
    }
}
