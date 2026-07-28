//! Автокалибровка структурных порогов под размер и возраст репозитория.
//!
//! Зачем это нужно. Пороги «длинный файл», «божественный файл», «сложная функция» и
//! «глубокая вложенность» заданы одним набором чисел на все проекты. На новом небольшом
//! сервисе такие числа великодушны и пропускают начинающийся беспорядок, а на зрелой
//! кодовой базе в сотни тысяч строк они дают лавину находок по коду, который живёт годами
//! и никого не беспокоит. И то и другое вредно: в первом случае инструмент молчит, когда
//! стоило сказать, во втором человек перестаёт читать отчёт.
//!
//! Что здесь делается. Пороги ДВИГАЮТСЯ в узком, заранее ограниченном диапазоне вокруг
//! значений по умолчанию, исходя из двух наблюдаемых величин: объёма кодовой базы и её
//! возраста по истории системы контроля версий. Калибровка выполняется ТОЛЬКО для
//! структурных порогов и никогда не трогает ни порог блокировки (`block_at`), ни веса
//! балла: ослабление того, что решает вердикт, автоматике доверять нельзя.
//!
//! Инварианты. Калибровка детерминирована (одни и те же вход и репозиторий дают один и
//! тот же результат), ограничена сверху и снизу, отключается переменной окружения
//! `AILC_NO_CALIBRATION`, и никогда не применяется к значениям, заданным человеком явно в
//! файле политики: осознанное решение старшего важнее автоматики.

use crate::engines::walk::{walk_stats, WalkStats};
use ailc_contracts::{Ctx, Thresholds};
use std::path::Path;

/// Наблюдаемые характеристики репозитория, по которым ведётся калибровка.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RepoScale {
    /// Число файлов исходного кода, попавших в обход.
    ///
    /// Это ЕДИНСТВЕННАЯ наблюдаемая характеристика калибровки, и намеренно. Прежде здесь был
    /// ещё и возраст репозитория по первому коммиту, от которого зависела мягкость
    /// структурных порогов, и он вносил в вердикт две недопустимые зависимости.
    ///
    /// Первая: КАЛЕНДАРЬ. Один и тот же коммит до и после семьсот тридцатого дня жизни
    /// репозитория судился разными порогами, поэтому находки о длинных файлах, сложности и
    /// глубине вложенности появлялись и исчезали сами собой, без единой правки кода. Для
    /// инструмента, обещающего детерминированный вердикт, это прямое противоречие обещанию.
    ///
    /// Вторая: ГЛУБИНА КЛОНА. Возраст брался из `git log --max-parents=0`, а выгрузка в
    /// системе сборки обычно делается с глубиной один и корневого коммита не содержит.
    /// Возраст выходил нулевым, пороги получались СТРОЖЕ, чем на полном клоне разработчика,
    /// и одни и те же байты давали разные вердикты в двух местах.
    ///
    /// Замысел «в зрелой базе долгоживущие файлы уже доказали работоспособность» при этом не
    /// теряется: ровно для него в продукте есть базовая линия долга, которая фиксирует
    /// исторические находки явно и по решению человека, а не по ходу часов.
    pub files: usize,
}

/// Класс размера кодовой базы. Границы намеренно грубые: точность здесь не нужна, нужна
/// устойчивость решения к добавлению десятка файлов.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Size {
    /// До 50 файлов: прототип, учебный проект, небольшой сервис.
    Small,
    /// От 50 до 800 файлов: обычный продуктовый репозиторий.
    Medium,
    /// Больше 800 файлов: крупная зрелая кодовая база.
    Large,
}

impl RepoScale {
    pub fn size(&self) -> Size {
        match self.files {
            0..=49 => Size::Small,
            50..=799 => Size::Medium,
            _ => Size::Large,
        }
    }
}

/// Снять характеристики репозитория. Обход дешёвый и тот же, что у остальных движков.
pub fn observe(ctx: &Ctx) -> RepoScale {
    let mut files = 0usize;
    let mut stats = WalkStats::default();
    let _ = walk_stats(&ctx.root, &mut |_p: &Path| files += 1, &mut stats);
    RepoScale { files }
}

/// Применить калибровку к структурным порогам.
///
/// `explicit` перечисляет имена порогов, заданных человеком в файле политики: они не
/// трогаются ни при каких условиях. Возвращает заметку для человека, если хоть что-то
/// изменилось: молчаливая подмена правил недопустима, человек обязан видеть, по каким
/// числам его судили.
pub fn apply(t: &mut Thresholds, scale: RepoScale, explicit: &[&str]) -> Option<String> {
    if crate::env::is_set("AILC_NO_CALIBRATION") {
        return None;
    }
    let d = Thresholds::default();
    let untouched = |name: &str| !explicit.contains(&name);

    // Коэффициент по размеру: маленькая база строже, крупная мягче. Диапазон намеренно
    // узкий (от 0,8 до 1,5), чтобы калибровка оставалась настройкой, а не подменой правил.
    let by_size: f64 = match scale.size() {
        Size::Small => 0.8,
        Size::Medium => 1.0,
        Size::Large => 1.35,
    };
    let k: f64 = by_size;

    let mut changed: Vec<String> = Vec::new();
    if untouched("max_lines") {
        let v = ((d.max_lines as f64 * k).round() as u32).clamp(200, 1200);
        if v != t.max_lines {
            changed.push(format!("max_lines {} → {}", t.max_lines, v));
            t.max_lines = v;
        }
    }
    if untouched("max_defs_per_file") {
        let v = ((d.max_defs_per_file as f64 * k).round() as usize).clamp(15, 80);
        if v != t.max_defs_per_file {
            changed.push(format!("max_defs_per_file {} → {}", t.max_defs_per_file, v));
            t.max_defs_per_file = v;
        }
    }
    if untouched("max_complexity") {
        let v = ((d.max_complexity as f64 * k).round() as u32).clamp(25, 120);
        if v != t.max_complexity {
            changed.push(format!("max_complexity {} → {}", t.max_complexity, v));
            t.max_complexity = v;
        }
    }
    // Вложенность растёт медленнее прочих: глубина больше девяти нечитаема при любом
    // размере проекта, поэтому здесь допускается лишь единица разницы.
    if untouched("max_nesting") {
        let v = match scale.size() {
            Size::Small => d.max_nesting.saturating_sub(1),
            Size::Medium => d.max_nesting,
            Size::Large => d.max_nesting + 1,
        }
        .clamp(4, 9);
        if v != t.max_nesting {
            changed.push(format!("max_nesting {} → {}", t.max_nesting, v));
            t.max_nesting = v;
        }
    }

    (!changed.is_empty()).then(|| {
        format!(
            "пороги откалиброваны под размер репозитория ({} файлов): {}",
            scale.files,
            changed.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scale(files: usize, _age_days: u64) -> RepoScale {
        RepoScale { files }
    }

    #[test]
    fn маленький_проект_строже_дефолта() {
        let mut t = Thresholds::default();
        let note = apply(&mut t, scale(20, 30), &[]).expect("пороги изменились");
        assert!(t.max_lines < Thresholds::default().max_lines);
        assert!(t.max_nesting < Thresholds::default().max_nesting);
        assert!(
            note.contains("max_lines"),
            "заметка называет изменения: {note}"
        );
    }

    #[test]
    fn крупный_проект_мягче_дефолта() {
        let mut t = Thresholds::default();
        apply(&mut t, scale(5_000, 2_000), &[]).expect("пороги изменились");
        assert!(t.max_lines > Thresholds::default().max_lines);
        assert!(t.max_complexity > Thresholds::default().max_complexity);
    }

    #[test]
    fn средний_проект_остаётся_на_дефолте() {
        let mut t = Thresholds::default();
        assert!(
            apply(&mut t, scale(300, 100), &[]).is_none(),
            "для обычного репозитория калибровка ничего не меняет"
        );
        assert_eq!(t.max_lines, Thresholds::default().max_lines);
    }

    #[test]
    fn явно_заданный_порог_не_трогается() {
        let mut t = Thresholds {
            max_lines: 250,
            ..Default::default()
        };
        apply(&mut t, scale(5_000, 2_000), &["max_lines"]);
        assert_eq!(t.max_lines, 250, "решение человека важнее автоматики");
    }

    #[test]
    fn калибровка_ограничена_сверху_и_снизу() {
        let mut t = Thresholds::default();
        apply(&mut t, scale(1_000_000, 100_000), &[]);
        assert!(t.max_lines <= 1200 && t.max_nesting <= 9);
        let mut t = Thresholds::default();
        apply(&mut t, scale(1, 1), &[]);
        assert!(t.max_lines >= 200 && t.max_nesting >= 4);
    }

    #[test]
    fn веса_балла_и_порог_блокировки_не_калибруются() {
        let mut t = Thresholds::default();
        let before = (t.score_critical, t.score_high, t.doc_coverage_floor);
        apply(&mut t, scale(5_000, 2_000), &[]);
        assert_eq!(
            (t.score_critical, t.score_high, t.doc_coverage_floor),
            before,
            "то, что решает вердикт, автоматике не подчиняется"
        );
    }

    /// РЕГРЕССИЯ. Калибровка обязана зависеть ТОЛЬКО от содержимого дерева. Прежде в неё
    /// входил возраст репозитория по первому коммиту, из-за чего один и тот же коммит до и
    /// после семьсот тридцатого дня судился разными порогами (зависимость от календаря), а
    /// выгрузка с глубиной один давала нулевой возраст и пороги строже полного клона
    /// (зависимость от глубины клона).
    #[test]
    fn калибровка_не_зависит_от_возраста_репозитория() {
        let mut young = Thresholds::default();
        let mut old = Thresholds::default();
        // Второй аргумент сохранён в тестовом конструкторе намеренно: он показывает, что
        // возраст больше НИ НА ЧТО не влияет, каким бы он ни был.
        let n_young = apply(&mut young, scale(5_000, 0), &[]);
        let n_old = apply(&mut old, scale(5_000, 10_000), &[]);
        assert_eq!(
            (young.max_lines, young.max_complexity, young.max_nesting),
            (old.max_lines, old.max_complexity, old.max_nesting),
            "пороги одинаковы при любом возрасте репозитория"
        );
        assert_eq!(n_young, n_old, "и заметка человеку одинакова");
    }

    /// Та же калибровка при повторном применении к уже откалиброванным порогам ничего не
    /// меняет: иначе повторный прогон давал бы иной вердикт на неизменном коде.
    #[test]
    fn калибровка_идемпотентна() {
        let mut t = Thresholds::default();
        apply(&mut t, scale(5_000, 0), &[]).expect("первый прогон меняет пороги");
        let after_first = (t.max_lines, t.max_complexity, t.max_nesting);
        let second = apply(&mut t, scale(5_000, 0), &[]);
        assert_eq!(
            (t.max_lines, t.max_complexity, t.max_nesting),
            after_first,
            "повторное применение не сдвигает пороги"
        );
        assert!(
            second.is_none(),
            "и не сообщает о несуществующих изменениях"
        );
    }
}
