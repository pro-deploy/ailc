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
use ailc_contracts::{Ctx, Finding};
use std::collections::HashSet;

const NS: &str = "baseline";
const FILE: &str = "findings.txt";

/// Стабильный отпечаток находки. Нарочно БЕЗ номера строки: правки выше по файлу не
/// должны «размораживать» долг. Правило + файл + сообщение достаточно избирательны
/// (сообщение несёт конкретику находки), а редкие слияния двух одинаковых находок в
/// одном файле консервативны в сторону долга, не в сторону ложного блока.
pub fn fingerprint(f: &Finding) -> String {
    let file = f
        .location
        .as_ref()
        .map(|l| l.file.as_str())
        .unwrap_or("<no-file>");
    format!("{}|{}|{}", f.rule, file, f.message.replace('\n', " "))
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

/// Зафиксировать базовую линию из текущих находок (перезапись целиком). Возвращает
/// число замороженных отпечатков.
pub fn record(ctx: &Ctx, findings: &[Finding]) -> ailc_contracts::Result<usize> {
    let mut set: Vec<String> = findings.iter().map(fingerprint).collect();
    set.sort();
    set.dedup();
    let mut body = String::from(
        "# Базовая линия долга AILC: зафиксированные находки (правило|файл|сообщение).\n\
         # Вердикт сдачи блокируют только находки ВНЕ этого списка. Пересборка: ailc baseline <путь>\n",
    );
    for s in &set {
        body.push_str(s);
        body.push('\n');
    }
    Store::write(ctx, NS, FILE, &body)?;
    Ok(set.len())
}

/// Разделить находки на новые (блокируют) и долг (в базовой линии). Порядок сохраняется.
pub fn split(base: &HashSet<String>, findings: Vec<Finding>) -> (Vec<Finding>, Vec<Finding>) {
    if base.is_empty() {
        return (findings, Vec::new());
    }
    findings
        .into_iter()
        .partition(|f| !base.contains(&fingerprint(f)))
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

    fn finding(rule: &str, file: &str, msg: &str) -> Finding {
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
        let old = finding("secret-aws", "src/a.py", "боевой ключ AWS");
        let n = record(&c, &[old.clone()]).unwrap();
        assert_eq!(n, 1);
        assert!(exists(&c));

        let base = load(&c);
        let fresh = finding("secret-stripe", "src/b.py", "боевой ключ Stripe");
        let (new, debt) = split(&base, vec![old, fresh]);
        assert_eq!(debt.len(), 1, "старая находка ушла в долг");
        assert_eq!(new.len(), 1, "новая блокирует");
        assert_eq!(new[0].rule, "secret-stripe");
        std::fs::remove_dir_all(&c.root).ok();
    }

    #[test]
    fn line_shift_does_not_unfreeze_debt() {
        let c = ctx("lineshift");
        let mut f = finding("secret-aws", "src/a.py", "боевой ключ AWS");
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
}
