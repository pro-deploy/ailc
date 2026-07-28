//! Декларация описания архитектуры в модели C4 (Simon Brown).
//!
//! Модель названа по набору диаграмм статической структуры: контекст системы,
//! контейнеры, компоненты и код. Автор модели прямо указывает, что применять все четыре
//! уровня не обязательно, а большинству команд достаточно первых двух, и что уровень
//! кода для долгоживущей документации не рекомендуется, поскольку среда разработки
//! строит его по запросу. Поэтому уровни 1 и 2 объявлены обязательными, уровень 3
//! факультативным, уровень 4 факультативным, а ландшафт систем факультативным.
//!
//! Три вспомогательные диаграммы объявлены отдельно: ландшафт систем, динамическая
//! диаграмма и диаграмма развёртывания. Последняя обязательна при наличии описанного
//! развёртывания, поскольку именно она, а не диаграмма контейнеров, отвечает за
//! кластеризацию, балансировку и среды.
//!
//! Обязательные элементы нотации по требованиям модели: заголовок с указанием типа
//! диаграммы и области охвата, легенда, явно указанный тип каждого элемента, краткое
//! описание элемента, явно указанная технология для каждого контейнера и компонента,
//! однонаправленные подписанные связи и указание протокола для межконтейнерных связей.
//! Легенда вынесена отдельным разделом, поскольку модель требует её для КАЖДОЙ
//! диаграммы, в том числе выполненной в общепринятой нотации: не всякий читатель эту
//! нотацию знает.

use super::{Condition, Document, Draft, Requirement, Section, Source, Standard};

pub static DOCUMENT: Document = Document {
    id: "архитектура-c4",
    designation: "АРХ C4",
    title: "Архитектурные диаграммы по модели C4",
    path: "docs/C4.md",
    standard: Standard::C4,
    sections: SECTIONS,
};

static SECTIONS: &[Section] = &[
    Section {
        id: "c4.легенда",
        number: "0",
        title: "Легенда",
        requirement: Requirement::Mandatory,
        source: Source::FromModel,
        question: None,
        draft: Draft::Legend,
    },
    Section {
        id: "c4.контекст",
        number: "1",
        title: "Диаграмма контекста системы",
        requirement: Requirement::Mandatory,
        source: Source::FromModel,
        question: None,
        draft: Draft::Services,
    },
    Section {
        id: "c4.контейнеры",
        number: "2",
        title: "Диаграмма контейнеров",
        requirement: Requirement::Mandatory,
        source: Source::FromModel,
        question: None,
        draft: Draft::Composition,
    },
    Section {
        id: "c4.компоненты",
        number: "3",
        title: "Диаграмма компонентов",
        requirement: Requirement::Optional,
        source: Source::FromModel,
        question: None,
        draft: Draft::Composition,
    },
    Section {
        id: "c4.код",
        number: "4",
        title: "Диаграмма кода",
        requirement: Requirement::Optional,
        source: Source::FromModel,
        question: None,
        draft: Draft::Composition,
    },
    Section {
        id: "c4.динамика",
        number: "5",
        title: "Динамическая диаграмма",
        requirement: Requirement::Optional,
        source: Source::FromModel,
        question: None,
        draft: Draft::EntryPoints,
    },
    Section {
        id: "c4.развёртывание",
        number: "6",
        title: "Диаграмма развертывания",
        requirement: Requirement::Conditional(Condition::HasDeployment),
        source: Source::FromModel,
        question: None,
        draft: Draft::Deployment,
    },
    Section {
        id: "c4.ландшафт",
        number: "7",
        title: "Диаграмма ландшафта систем",
        requirement: Requirement::Optional,
        source: Source::FromModel,
        question: None,
        draft: Draft::Services,
    },
];
