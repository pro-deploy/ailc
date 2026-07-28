//! Декларация описания архитектуры по arc42, версия 8.
//!
//! Состав и порядок разделов воспроизводят шаблон arc42 версии 8: двенадцать разделов
//! верхнего уровня, из которых пять (введение и цели, контекст и рамки, представление
//! строительных блоков, представление развертывания, требования к качеству) собственного
//! содержания не имеют и объединяют подразделы.
//!
//! Наименования приведены по официальному русскому переводу шаблона со следующей
//! существенной оговоркой. В версии 8 подраздел 10.1 называется «Обзор требований к
//! качеству» (Quality Requirements Overview). Прежнее наименование «Дерево качества»
//! (Quality Tree), применявшееся в версии 7, из версии 8 исключено, однако официальный
//! русский перевод отстаёт от английского оригинала и до настоящего времени сохраняет
//! устаревшую формулировку. В настоящей декларации принято наименование версии 8, то
//! есть «Обзор требований к качеству»; шаблоны, воспроизводящие «Дерево качества»,
//! версии 8 не соответствуют.
//!
//! Раздел 7 объявлен условным: развертывание описывается только тогда, когда оно у
//! системы вообще имеется. Подразделы 5.3 и 7.2 объявлены факультативными, поскольку
//! arc42 не требует детализации строительных блоков и инфраструктуры до третьего и
//! второго уровней соответственно во всех без исключения случаях.

use super::{Condition, Document, Draft, Requirement, Section, Source, Standard};

pub static DOCUMENT: Document = Document {
    id: "архитектура-arc42",
    designation: "АРХ arc42",
    title: "Описание архитектуры",
    path: "docs/АРХИТЕКТУРА.md",
    standard: Standard::Arc42,
    sections: SECTIONS,
};

static SECTIONS: &[Section] = &[
    Section {
        id: "арх.введение",
        number: "1",
        title: "Введение и цели",
        requirement: Requirement::Mandatory,
        source: Source::Heading,
        question: None,
        draft: Draft::None,
    },
    Section {
        id: "арх.введение.обзор-требований",
        number: "1.1",
        title: "Обзор требований",
        requirement: Requirement::Mandatory,
        source: Source::Mixed,
        question: Some(
            "Какие основные функциональные требования предъявляются к системе и какие задачи пользователей она решает? Уточните перечень существенных возможностей, выведенный из состава внешних интерфейсов.",
        ),
        draft: Draft::Interfaces,
    },
    Section {
        id: "арх.цели.качество",
        number: "1.2",
        title: "Цели по качеству",
        requirement: Requirement::Mandatory,
        source: Source::FromInterview,
        question: Some(
            "Каковы три или пять важнейших целей по качеству, которым архитектура обязана удовлетворять, и в каком порядке значимости они расположены? Для каждой цели укажите мотивировку со стороны заинтересованных сторон.",
        ),
        draft: Draft::None,
    },
    Section {
        id: "арх.введение.стороны",
        number: "1.3",
        title: "Заинтересованные стороны",
        requirement: Requirement::Mandatory,
        source: Source::FromInterview,
        question: Some(
            "Кто относится к заинтересованным сторонам системы, какие роли они занимают и какие ожидания предъявляют к описанию архитектуры? Укажите, с кем именно согласовываются архитектурные решения.",
        ),
        draft: Draft::None,
    },
    Section {
        id: "арх.ограничения",
        number: "2",
        title: "Архитектурные ограничения",
        requirement: Requirement::Mandatory,
        source: Source::FromInterview,
        question: Some(
            "Какие технические, организационные и нормативные ограничения обязательны для разработчиков и сужают свободу архитектурных решений? Поясните происхождение каждого ограничения и его последствия.",
        ),
        draft: Draft::None,
    },
    Section {
        id: "арх.контекст",
        number: "3",
        title: "Контекст и рамки",
        requirement: Requirement::Mandatory,
        source: Source::Heading,
        question: None,
        draft: Draft::None,
    },
    Section {
        id: "арх.контекст.бизнес",
        number: "3.1",
        title: "Бизнес контекст",
        requirement: Requirement::Mandatory,
        source: Source::FromInterview,
        question: Some(
            "Какие внешние участники и соседние системы взаимодействуют с системой на деловом уровне и какими сведениями они с ней обмениваются? Опишите назначение каждого обмена на языке предметной области.",
        ),
        draft: Draft::None,
    },
    Section {
        id: "арх.контекст.технический",
        number: "3.2",
        title: "Технический контекст",
        requirement: Requirement::Mandatory,
        source: Source::Mixed,
        question: Some(
            "Через какие каналы, протоколы и технические интерфейсы система связана с внешними сервисами и как деловые обмены соотносятся с этими каналами? Проверьте и дополните перечень внешних сервисов, выведенный из кода.",
        ),
        draft: Draft::Services,
    },
    Section {
        id: "арх.стратегия",
        number: "4",
        title: "Стратегия решения",
        requirement: Requirement::Mandatory,
        source: Source::FromInterview,
        question: Some(
            "Какие основополагающие решения определили облик системы: выбранные технологии, способ декомпозиции, подход к достижению целей по качеству и организационные решения? Кратко обоснуйте каждое из них.",
        ),
        draft: Draft::None,
    },
    Section {
        id: "арх.блоки",
        number: "5",
        title: "Представление строительных блоков",
        requirement: Requirement::Mandatory,
        source: Source::Heading,
        question: None,
        draft: Draft::None,
    },
    Section {
        id: "арх.блоки.уровень1",
        number: "5.1",
        title: "Система в общем, «белый ящик»",
        requirement: Requirement::Mandatory,
        source: Source::FromModel,
        question: None,
        draft: Draft::Composition,
    },
    Section {
        id: "арх.блоки.уровень2",
        number: "5.2",
        title: "Уровень 2",
        requirement: Requirement::Mandatory,
        source: Source::FromModel,
        question: None,
        draft: Draft::Composition,
    },
    Section {
        id: "арх.блоки.уровень3",
        number: "5.3",
        title: "Уровень 3",
        requirement: Requirement::Optional,
        source: Source::FromModel,
        question: None,
        draft: Draft::Composition,
    },
    Section {
        id: "арх.выполнение",
        number: "6",
        title: "Представление времени выполнения",
        requirement: Requirement::Mandatory,
        source: Source::Mixed,
        question: Some(
            "Какие сценарии времени выполнения существенны для понимания системы, то есть как строительные блоки взаимодействуют при обработке основных запросов, при запуске и остановке и при обработке отказов? Уточните сценарии, опираясь на выявленные точки входа.",
        ),
        draft: Draft::EntryPoints,
    },
    Section {
        id: "арх.развертывание",
        number: "7",
        title: "Представление развертывания",
        requirement: Requirement::Conditional(Condition::HasDeployment),
        source: Source::Heading,
        question: None,
        draft: Draft::None,
    },
    Section {
        id: "арх.развертывание.уровень1",
        number: "7.1",
        title: "Инфраструктурный уровень 1",
        requirement: Requirement::Conditional(Condition::HasDeployment),
        source: Source::FromModel,
        question: None,
        draft: Draft::Deployment,
    },
    Section {
        id: "арх.развертывание.уровень2",
        number: "7.2",
        title: "Инфраструктурный уровень 2",
        requirement: Requirement::Optional,
        source: Source::FromModel,
        question: None,
        draft: Draft::Deployment,
    },
    Section {
        id: "арх.концепции",
        number: "8",
        title: "Сквозные концепции",
        requirement: Requirement::Mandatory,
        source: Source::FromInterview,
        question: Some(
            "Какие сквозные концепции действуют одновременно во многих частях системы, например модель предметной области, обработка ошибок, ведение журналов, разграничение доступа, интернационализация и правила испытаний? Опишите каждую концепцию и область её применения.",
        ),
        draft: Draft::None,
    },
    Section {
        id: "арх.решения",
        number: "9",
        title: "Архитектурные решения",
        requirement: Requirement::Mandatory,
        source: Source::Mixed,
        question: Some(
            "Какие существенные архитектурные решения приняты, какие варианты рассматривались и по каким доводам сделан выбор? Сверьте перечень с манифестами и документами, на которых основана система, и укажите дату и последствия каждого решения.",
        ),
        draft: Draft::Sources,
    },
    Section {
        id: "арх.качество",
        number: "10",
        title: "Требования к качеству",
        requirement: Requirement::Mandatory,
        source: Source::Heading,
        question: None,
        draft: Draft::None,
    },
    Section {
        id: "арх.качество.обзор",
        number: "10.1",
        title: "Обзор требований к качеству",
        requirement: Requirement::Mandatory,
        source: Source::FromInterview,
        question: Some(
            "Какие характеристики качества значимы для системы и как они соотносятся между собой по значимости? Приведите обзор требований к качеству, включая как заявленные в разделе целей, так и остальные существенные характеристики.",
        ),
        draft: Draft::None,
    },
    Section {
        id: "арх.качество.сценарии",
        number: "10.2",
        title: "Сценарии качества",
        requirement: Requirement::Mandatory,
        source: Source::FromInterview,
        question: Some(
            "Какими проверяемыми сценариями выражаются требования к качеству, то есть какой источник вызывает какое воздействие на систему и какая измеримая реакция считается приемлемой? Приведите сценарии применения и сценарии изменения.",
        ),
        draft: Draft::None,
    },
    Section {
        id: "арх.риски",
        number: "11",
        title: "Риски и технический долг",
        requirement: Requirement::Mandatory,
        source: Source::FromModel,
        question: None,
        draft: Draft::Risks,
    },
    Section {
        id: "арх.глоссарий",
        number: "12",
        title: "Глоссарий",
        requirement: Requirement::Mandatory,
        source: Source::FromModel,
        question: None,
        draft: Draft::Composition,
    },
];
