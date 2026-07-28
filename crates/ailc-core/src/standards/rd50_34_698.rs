//! Комплект документов на автоматизированную систему: перечень видов документов и их
//! применимость к программной системе.
//!
//! ДЕЙСТВУЮЩИЙ СТАНДАРТ. РД 50-34.698-90 в Российской Федерации заменён на
//! ГОСТ Р 59795-2021, введённый приказом Росстандарта от 25 октября 2021 года № 1297-ст
//! и действующий с 30 апреля 2022 года. Декларации строятся по действующему стандарту,
//! а ссылка на пункт руководящего документа сохраняется в таблице соответствия, поскольку
//! заказчики нередко ссылаются именно на него.
//!
//! ПРИМЕНИМОСТЬ. Полный комплект содержит виды документов, к чисто программной системе
//! неприменимые: планы расположения оборудования и проводок, схемы соединения внешних
//! проводок, таблицы соединений и подключений, ведомости потребности в материалах.
//! Выпускать их бессмысленно, а молча пропускать нечестно. Принято правило, прямо
//! предусмотренное стандартом: вид документа сохраняется в перечне комплекта, и по нему
//! приводится запись об отсутствии с указанием причины. Так перечень остаётся полным, а
//! утверждения о составе комплекта остаются правдивыми.

/// Применимость вида документа к рассматриваемой системе.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applicability {
    /// Документ выпускается ailc автоматически: декларация разделов уже объявлена.
    Generated(&'static str),
    /// Документ применим, но пока не объявлен декларацией и выпускается вручную.
    Applicable,
    /// Документ к программной системе неприменим по указанной причине.
    NotApplicable(&'static str),
}

/// Вид документа комплекта.
#[derive(Debug, Clone, Copy)]
pub struct DocKind {
    /// Пункт стандарта, устанавливающий требования к содержанию.
    pub clause: &'static str,
    /// Наименование вида документа.
    pub title: &'static str,
    pub applicability: Applicability,
}

/// Перечень видов документов комплекта с их применимостью.
///
/// Перечень намеренно приведён по разделам стандарта: общесистемные решения, решения по
/// организационному обеспечению, по техническому обеспечению, по информационному
/// обеспечению, по программному обеспечению и по математическому обеспечению.
pub static KINDS: &[DocKind] = &[
    // Общесистемные решения.
    DocKind {
        clause: "2.2",
        title: "Пояснительная записка к техническому проекту",
        applicability: Applicability::Generated("пояснительная-записка"),
    },
    DocKind {
        clause: "2.3",
        title: "Схема функциональной структуры",
        applicability: Applicability::Generated("архитектура-c4"),
    },
    DocKind {
        clause: "2.4",
        title: "Ведомость покупных изделий",
        applicability: Applicability::Applicable,
    },
    DocKind {
        clause: "2.5",
        title: "Описание автоматизируемых функций",
        applicability: Applicability::Generated("описание-функций"),
    },
    DocKind {
        clause: "2.6",
        title: "Описание постановки задачи (комплекса задач)",
        applicability: Applicability::Applicable,
    },
    DocKind {
        clause: "2.7",
        title: "Локальная смета и локальный сметный расчёт",
        applicability: Applicability::NotApplicable(
            "сметный расчёт строительно-монтажных работ к программной системе не относится",
        ),
    },
    DocKind {
        clause: "2.8",
        title: "Паспорт",
        applicability: Applicability::Applicable,
    },
    DocKind {
        clause: "2.10",
        title: "Проектная оценка надёжности системы",
        applicability: Applicability::Applicable,
    },
    DocKind {
        clause: "2.11",
        title: "Общее описание системы",
        applicability: Applicability::Generated("архитектура-arc42"),
    },
    DocKind {
        clause: "2.14",
        title: "Программа и методика испытаний",
        applicability: Applicability::Generated("программа-испытаний"),
    },
    DocKind {
        clause: "2.15",
        title: "Схема организационной структуры",
        applicability: Applicability::Applicable,
    },
    // Организационное обеспечение.
    DocKind {
        clause: "3.1",
        title: "Описание организационной структуры",
        applicability: Applicability::Applicable,
    },
    DocKind {
        clause: "3.3",
        title: "Технологическая инструкция",
        applicability: Applicability::Applicable,
    },
    DocKind {
        clause: "3.4",
        title: "Руководство пользователя",
        applicability: Applicability::Generated("руководство-пользователя"),
    },
    DocKind {
        clause: "3.5",
        title: "Описание технологического процесса обработки данных",
        applicability: Applicability::Applicable,
    },
    // Техническое обеспечение.
    DocKind {
        clause: "4.2",
        title: "Описание комплекса технических средств",
        applicability: Applicability::Applicable,
    },
    DocKind {
        clause: "4.3",
        title: "План расположения",
        applicability: Applicability::NotApplicable(
            "размещение оборудования в помещениях к программной системе не относится",
        ),
    },
    DocKind {
        clause: "4.4",
        title: "План расположения оборудования и проводок",
        applicability: Applicability::NotApplicable(
            "прокладка проводок к программной системе не относится",
        ),
    },
    DocKind {
        clause: "4.10",
        title: "Схема соединения внешних проводок",
        applicability: Applicability::NotApplicable(
            "внешние проводки у программной системы отсутствуют",
        ),
    },
    DocKind {
        clause: "4.12",
        title: "Таблица соединений и подключений",
        applicability: Applicability::NotApplicable(
            "физические соединения у программной системы отсутствуют",
        ),
    },
    DocKind {
        clause: "4.14",
        title: "Чертёж общего вида",
        applicability: Applicability::NotApplicable(
            "конструкторский чертёж у программной системы отсутствует",
        ),
    },
    DocKind {
        clause: "4.18",
        title: "Ведомость потребности в материалах",
        applicability: Applicability::NotApplicable(
            "расходные материалы при поставке программной системы не потребляются",
        ),
    },
    // Информационное обеспечение.
    DocKind {
        clause: "5.1",
        title: "Перечень входных сигналов и данных",
        applicability: Applicability::Applicable,
    },
    DocKind {
        clause: "5.2",
        title: "Перечень выходных сигналов (документов)",
        applicability: Applicability::Applicable,
    },
    DocKind {
        clause: "5.3",
        title: "Описание информационного обеспечения системы",
        applicability: Applicability::Generated("описание-ио"),
    },
    DocKind {
        clause: "5.5",
        title: "Описание организации информационной базы",
        applicability: Applicability::Applicable,
    },
    DocKind {
        clause: "5.6",
        title: "Описание систем классификации и кодирования",
        applicability: Applicability::Applicable,
    },
    DocKind {
        clause: "5.10",
        title: "Каталог базы данных",
        applicability: Applicability::Applicable,
    },
    // Программное обеспечение.
    DocKind {
        clause: "6.1",
        title: "Описание программного обеспечения",
        applicability: Applicability::Generated("описание-по"),
    },
    // Математическое обеспечение.
    DocKind {
        clause: "7.1",
        title: "Описание алгоритма (проектной процедуры)",
        applicability: Applicability::Applicable,
    },
];

/// Виды документов, неприменимые к программной системе, с причиной.
pub fn not_applicable() -> Vec<&'static DocKind> {
    KINDS
        .iter()
        .filter(|k| matches!(k.applicability, Applicability::NotApplicable(_)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// У каждой записи о неприменимости обязана быть причина: запись об отсутствии без
    /// объяснения ничем не отличается от умолчания.
    #[test]
    fn неприменимость_всегда_обоснована() {
        for k in not_applicable() {
            match k.applicability {
                Applicability::NotApplicable(why) => assert!(
                    !why.trim().is_empty(),
                    "вид документа «{}» объявлен неприменимым без причины",
                    k.title
                ),
                _ => unreachable!(),
            }
        }
    }

    /// Ссылка на объявленный документ обязана указывать на существующую декларацию:
    /// иначе перечень комплекта обещает документ, которого нет.
    #[test]
    fn ссылки_на_объявленные_документы_разрешаются() {
        for k in KINDS {
            if let Applicability::Generated(id) = k.applicability {
                assert!(
                    super::super::document(id).is_some(),
                    "вид документа «{}» ссылается на несуществующую декларацию {id}",
                    k.title
                );
            }
        }
    }
}
