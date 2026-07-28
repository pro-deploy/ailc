//! Декларация технического задания по ГОСТ 19.201-78.
//!
//! Разделы и их порядок взяты из пункта 1.4 стандарта, наименования приведены в
//! подлинной формулировке. Раздел «Требования к программной документации» стоит пятым
//! именно потому, что так он значится в перечне пункта 1.4; в самом стандарте требования
//! к его содержанию описаны пунктом 2.5а, введённым Изменением № 1 и расположенным в
//! тексте перед пунктом 2.5, из-за чего порядок номеров пунктов раздела 2 не совпадает с
//! порядком разделов перечня. Шаблоны, перенумеровывающие разделы подряд по пунктам
//! раздела 2, стандарту не соответствуют.
//!
//! Стандарт прямо допускает уточнение содержания разделов и объединение отдельных из них
//! в зависимости от особенностей программы, поэтому часть разделов объявлена условной:
//! при невыполнении условия в разделе приводится запись об отсутствии требований.

use super::{Condition, Document, Draft, Requirement, Section, Source, Standard};

pub static DOCUMENT: Document = Document {
    id: "тз-гост-19",
    designation: "ТЗ 19.201",
    title: "Техническое задание",
    path: "docs/ТЗ-ГОСТ-19.201.md",
    standard: Standard::Gost19_201,
    sections: SECTIONS,
};

static SECTIONS: &[Section] = &[
    Section {
        id: "тз.введение",
        number: "1",
        title: "Введение",
        requirement: Requirement::Mandatory,
        source: Source::Mixed,
        question: Some(
            "Как называется продукт и в какой области он применяется? Опишите кратко объект, в котором продукт используется.",
        ),
        draft: Draft::Identity,
    },
    Section {
        id: "тз.основания",
        number: "2",
        title: "Основания для разработки",
        requirement: Requirement::Mandatory,
        source: Source::FromInterview,
        question: Some(
            "На основании какого документа ведётся разработка, кто и когда его утвердил, как называется тема разработки? Если разработка инициативная, так и укажите.",
        ),
        draft: Draft::None,
    },
    Section {
        id: "тз.назначение",
        number: "3",
        title: "Назначение разработки",
        requirement: Requirement::Mandatory,
        source: Source::FromInterview,
        question: Some(
            "Каково функциональное и эксплуатационное назначение продукта: какую задачу он решает и кто им пользуется?",
        ),
        draft: Draft::None,
    },
    Section {
        id: "тз.требования",
        number: "4",
        title: "Требования к программе или программному изделию",
        requirement: Requirement::Mandatory,
        source: Source::Heading,
        question: None,
        draft: Draft::None,
    },
    Section {
        id: "тз.требования.функции",
        number: "4.1",
        title: "Требования к функциональным характеристикам",
        requirement: Requirement::Mandatory,
        source: Source::Mixed,
        question: Some(
            "Какие функции продукт обязан выполнять и какие требования предъявляются к составу выполняемых функций и к организации входных и выходных данных?",
        ),
        draft: Draft::Interfaces,
    },
    Section {
        id: "тз.требования.надёжность",
        number: "4.2",
        title: "Требования к надёжности",
        requirement: Requirement::Mandatory,
        source: Source::Mixed,
        question: Some(
            "Какое время восстановления после отказа допустимо, какое суммарное время простоя приемлемо и какие аварийные ситуации требуется предусмотреть?",
        ),
        draft: Draft::Services,
    },
    Section {
        id: "тз.требования.эксплуатация",
        number: "4.3",
        title: "Условия эксплуатации",
        requirement: Requirement::Mandatory,
        source: Source::Mixed,
        question: Some(
            "В каких условиях продукт эксплуатируется: режим работы, квалификация и численность обслуживающего персонала?",
        ),
        draft: Draft::Config,
    },
    Section {
        id: "тз.требования.технические-средства",
        number: "4.4",
        title: "Требования к составу и параметрам технических средств",
        requirement: Requirement::Mandatory,
        source: Source::Mixed,
        question: Some(
            "Какие технические средства требуются для работы продукта: тип и производительность процессора, объём оперативной памяти и дискового пространства, операционная система?",
        ),
        draft: Draft::Toolchain,
    },
    Section {
        id: "тз.требования.совместимость",
        number: "4.5",
        title: "Требования к информационной и программной совместимости",
        requirement: Requirement::Mandatory,
        source: Source::Mixed,
        question: Some(
            "С какими системами, форматами данных и версиями программных средств продукт обязан быть совместим?",
        ),
        draft: Draft::Dependencies,
    },
    Section {
        id: "тз.требования.маркировка",
        number: "4.6",
        title: "Требования к маркировке и упаковке",
        requirement: Requirement::Mandatory,
        source: Source::Mixed,
        question: Some(
            "Как маркируется и поставляется продукт: наименование и версия артефактов, канал поставки, сопроводительные сведения?",
        ),
        draft: Draft::Artifacts,
    },
    Section {
        id: "тз.требования.транспортирование",
        number: "4.7",
        title: "Требования к транспортированию и хранению",
        requirement: Requirement::Mandatory,
        source: Source::FromInterview,
        question: Some(
            "Как продукт передаётся заказчику и как хранится? Для продукта, поставляемого по сети, обычно приводится запись об отсутствии особых требований.",
        ),
        draft: Draft::None,
    },
    Section {
        id: "тз.требования.специальные",
        number: "4.8",
        title: "Специальные требования",
        requirement: Requirement::Conditional(Condition::HasPdn),
        source: Source::FromInterview,
        question: Some(
            "Какие специальные требования предъявляются к продукту, включая требования по защите обрабатываемых сведений и по соответствию нормативным актам?",
        ),
        draft: Draft::None,
    },
    Section {
        id: "тз.документация",
        number: "5",
        title: "Требования к программной документации",
        requirement: Requirement::Mandatory,
        source: Source::FromModel,
        question: None,
        draft: Draft::DocumentSet,
    },
    Section {
        id: "тз.технико-экономические",
        number: "6",
        title: "Технико-экономические показатели",
        requirement: Requirement::Optional,
        source: Source::FromInterview,
        question: Some(
            "Каковы ожидаемая экономическая эффективность, предполагаемая годовая потребность и преимущества разработки по сравнению с аналогами?",
        ),
        draft: Draft::None,
    },
    Section {
        id: "тз.стадии",
        number: "7",
        title: "Стадии и этапы разработки",
        requirement: Requirement::Mandatory,
        source: Source::Mixed,
        question: Some(
            "Какие стадии и этапы разработки предусмотрены, каково содержание работ на каждом этапе, каковы сроки и кто исполнитель?",
        ),
        draft: Draft::None,
    },
    Section {
        id: "тз.приёмка",
        number: "8",
        title: "Порядок контроля и приемки",
        requirement: Requirement::Mandatory,
        source: Source::Mixed,
        question: Some(
            "Какие виды испытаний предусмотрены и какие общие требования предъявляются к приёмке работы?",
        ),
        draft: Draft::Risks,
    },
    Section {
        id: "тз.приложения",
        number: "Приложение",
        title: "Приложения",
        requirement: Requirement::Optional,
        source: Source::FromModel,
        question: None,
        draft: Draft::Sources,
    },
];
