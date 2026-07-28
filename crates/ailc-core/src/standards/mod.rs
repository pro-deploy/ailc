//! Декларации документов и разделов по стандартам.
//!
//! Документ по стандарту описывается не кодом генератора, а ДАННЫМИ: перечнем разделов
//! с номером и наименованием ровно в формулировке стандарта, признаком обязательности,
//! источником содержания и, для разделов с опросом, формулировкой вопроса и правилом
//! построения черновика из модели проекта. Из этого следуют три свойства, недостижимые
//! при генерации кодом.
//!
//! Первое: полнота документа по стандарту вычисляется детерминированно как доля
//! обязательных разделов, содержание которых определено, и потому становится измеримой
//! осью готовности, а не мнением.
//!
//! Второе: один и тот же ответ человека переиспользуется во всех документах комплекта,
//! где встречается соответствующий раздел, и переносится при смене применяемого
//! стандарта, поскольку ключом ответа служит идентификатор раздела, а не место в файле.
//!
//! Третье: нумерация воспроизводится подлинная. Это важнее, чем кажется. В ГОСТ 19.201-78
//! из-за Изменения № 1 подраздел о требованиях к программной документации имеет номер
//! 2.5а и расположен перед пунктом 2.5, а порядок разделов в перечне пункта 1.4 не
//! совпадает с порядком номеров в разделе 2. Многочисленные шаблоны в сети перенумеровывают
//! разделы подряд, что стандарту не соответствует.

use crate::model::ProjectModel;
use crate::profile::ProjectProfile;

pub mod arc42;
pub mod c4;
pub mod gost19_201;
pub mod gost19_404;
pub mod gost34_602;
pub mod opis_func;
pub mod opis_io;
pub mod opis_po;
pub mod pmi;
pub mod rd50_34_698;
pub mod ruk_pol;

/// Стандарт или признанная практика, по которой построен документ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standard {
    /// ГОСТ 19.201-78 «ЕСПД. Техническое задание. Требования к содержанию и оформлению».
    Gost19_201,
    /// ГОСТ 34.602-2020 «Техническое задание на создание автоматизированной системы».
    Gost34_602,
    /// ГОСТ Р 59795-2021 «Требования к содержанию документов» (взамен РД 50-34.698-90).
    GostR59795,
    /// ГОСТ 19.404-79 «ЕСПД. Пояснительная записка».
    Gost19_404,
    /// arc42, версия 8.
    Arc42,
    /// Модель C4 (Simon Brown).
    C4,
}

impl Standard {
    /// Полное наименование стандарта для титульного листа и ссылок в тексте.
    pub fn title(&self) -> &'static str {
        match self {
            Standard::Gost19_201 => {
                "ГОСТ 19.201-78. Единая система программной документации. Техническое задание. \
                 Требования к содержанию и оформлению"
            }
            Standard::Gost34_602 => {
                "ГОСТ 34.602-2020. Информационные технологии. Комплекс стандартов на \
                 автоматизированные системы. Техническое задание на создание автоматизированной системы"
            }
            Standard::GostR59795 => {
                "ГОСТ Р 59795-2021. Информационные технологии. Комплекс стандартов на \
                 автоматизированные системы. Автоматизированные системы. Требования к содержанию документов"
            }
            Standard::Gost19_404 => {
                "ГОСТ 19.404-79. Единая система программной документации. Пояснительная записка. \
                 Требования к содержанию и оформлению"
            }
            Standard::Arc42 => "arc42, версия 8",
            Standard::C4 => "Модель C4 (Simon Brown)",
        }
    }
}

/// Условие, при котором раздел становится обязательным.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// У системы есть пользовательский интерфейс.
    HasUi,
    /// У системы есть мобильная часть.
    HasMobile,
    /// Система обрабатывает персональные данные.
    HasPdn,
    /// Система обращается к нейросетевым моделям.
    HasLlm,
    /// У системы есть внешний программный интерфейс (маршруты либо контрактные схемы).
    HasApi,
    /// У системы есть описанное развёртывание (образы, композиции, порты).
    HasDeployment,
    /// Система хранит данные (обнаружены модели данных либо миграции схемы).
    HasData,
}

impl Condition {
    /// Выполнено ли условие для конкретного проекта.
    pub fn holds(&self, m: &ProjectModel, p: &ProjectProfile) -> bool {
        match self {
            Condition::HasUi => p.has_ui,
            Condition::HasMobile => p.has_mobile,
            Condition::HasPdn => p.has_pdn,
            Condition::HasLlm => p.has_llm,
            Condition::HasApi => !m.surface.routes.is_empty() || !m.surface.api_schemas.is_empty(),
            Condition::HasDeployment => {
                !m.deployment.containers.is_empty() || !m.deployment.ports.is_empty()
            }
            Condition::HasData => {
                !m.surface.data_models.is_empty() || !m.surface.migrations.is_empty()
            }
        }
    }
}

/// Обязательность раздела по стандарту.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// Раздел обязателен безусловно. Отсутствие содержания означает несоответствие
    /// документа стандарту, а не стилистический недостаток.
    Mandatory,
    /// Раздел обязателен при выполнении условия, иначе в нём приводится запись об
    /// отсутствии требований, что прямо предусмотрено стандартом.
    Conditional(Condition),
    /// Раздел факультативен.
    Optional,
}

/// Откуда берётся содержание раздела.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Только из модели проекта: раздел заполняется без участия человека.
    FromModel,
    /// Только опросом: код таких сведений не содержит в принципе.
    FromInterview,
    /// Смешанный: машинная часть из модели, человеческая уточняется опросом.
    Mixed,
    /// Раздел-заголовок, объединяющий подразделы и не имеющий собственного содержания.
    /// В оценке полноты не участвует: закрывают его подразделы.
    Heading,
}

/// Правило построения содержания либо черновика раздела из модели проекта.
///
/// Черновик существенно меняет характер опроса: агент спрашивает не с чистого листа,
/// а на подтверждение уже выведенного из кода, и человеку остаётся согласиться или
/// поправить, вместо того чтобы сочинять раздел заново.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Draft {
    /// Черновик из модели построить нельзя.
    None,
    /// Наименование, обозначение и версия продукта.
    Identity,
    /// Состав системы: модули с числом определений.
    Composition,
    /// Функции и интерфейсы: маршруты и контрактные схемы.
    Interfaces,
    /// Переменные окружения как параметры настройки.
    EnvVars,
    /// Внешние сервисы, от которых система зависит.
    Services,
    /// Модели данных и миграции схемы.
    DataModel,
    /// Зависимости поставки с версиями.
    Dependencies,
    /// Зафиксированные версии инструментария и стек.
    Toolchain,
    /// Артефакты, производимые сборкой.
    Artifacts,
    /// Точки входа системы.
    EntryPoints,
    /// Контейнеры и объявленные порты.
    Deployment,
    /// Языки реализации.
    Languages,
    /// Перечень документов, выпускаемых по проекту.
    DocumentSet,
    /// Источники разработки: манифесты и документы, на которых основана система.
    Sources,
    /// Связи между модулями и обнаруженные циклы как риск.
    Risks,
    /// Легенда нотации. Модель C4 требует её для каждой диаграммы, включая выполненную
    /// в общепринятой нотации: не всякий читатель эту нотацию знает.
    Legend,
    /// Операции интерфейса командной строки: подкоманды и ключи.
    Cli,
    /// Конфигурационные параметры из файлов настроек.
    Config,
    /// Объявления, доступные извне, с сигнатурами и описаниями.
    Api,
}

/// Раздел документа в декларации стандарта.
#[derive(Debug, Clone, Copy)]
pub struct Section {
    /// Устойчивый идентификатор ответа. Ключ реестра ответов: именно он обеспечивает
    /// переиспользование ответа между документами и перенос при смене стандарта.
    pub id: &'static str,
    /// Номер раздела РОВНО в нумерации стандарта.
    pub number: &'static str,
    /// Наименование раздела РОВНО в формулировке стандарта.
    pub title: &'static str,
    pub requirement: Requirement,
    pub source: Source,
    /// Формулировка вопроса для опроса. Задаётся для разделов, требующих человека.
    pub question: Option<&'static str>,
    pub draft: Draft,
}

/// Документ в декларации стандарта.
#[derive(Debug, Clone, Copy)]
pub struct Document {
    /// Устойчивый идентификатор документа (например `тз-гост-19`).
    pub id: &'static str,
    /// Обозначение документа по правилам обозначения соответствующего стандарта.
    pub designation: &'static str,
    /// Наименование документа.
    pub title: &'static str,
    /// Путь файла документа относительно корня проекта.
    pub path: &'static str,
    pub standard: Standard,
    pub sections: &'static [Section],
}

/// Полный перечень объявленных документов.
pub fn documents() -> Vec<&'static Document> {
    vec![
        &gost19_201::DOCUMENT,
        &gost34_602::DOCUMENT,
        &gost19_404::DOCUMENT,
        &arc42::DOCUMENT,
        &c4::DOCUMENT,
        &opis_func::DOCUMENT,
        &opis_io::DOCUMENT,
        &opis_po::DOCUMENT,
        &ruk_pol::DOCUMENT,
        &pmi::DOCUMENT,
    ]
}

/// Документ по идентификатору.
pub fn document(id: &str) -> Option<&'static Document> {
    documents().into_iter().find(|d| d.id == id)
}

// ───────────────────────────── полнота по стандарту ─────────────────────────────

/// Итог оценки полноты документа по стандарту.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completeness {
    /// Всего разделов в декларации.
    pub total: usize,
    /// Разделов, обязательных для данного проекта (с учётом условий).
    pub required: usize,
    /// Обязательных разделов, содержание которых определено.
    pub filled: usize,
    /// Номера и наименования незакрытых обязательных разделов.
    pub missing: Vec<(&'static str, &'static str)>,
}

impl Completeness {
    /// Доля закрытых обязательных разделов в процентах. Документ без обязательных
    /// разделов считается полным (такого в объявленных стандартах не бывает, но
    /// деление на ноль недопустимо в любом случае).
    pub fn percent(&self) -> u32 {
        if self.required == 0 {
            return 100;
        }
        ((self.filled * 100) / self.required) as u32
    }

    /// Документ соответствует стандарту по составу разделов.
    pub fn complete(&self) -> bool {
        self.filled == self.required
    }
}

/// Обязателен ли раздел для конкретного проекта.
pub fn is_required(s: &Section, m: &ProjectModel, p: &ProjectProfile) -> bool {
    match s.requirement {
        Requirement::Mandatory => true,
        Requirement::Conditional(c) => c.holds(m, p),
        Requirement::Optional => false,
    }
}

/// Вычислить полноту документа.
///
/// Раздел считается закрытым, если его содержание выводится из модели и оказалось
/// непустым, либо если на него получен ответ в реестре. Смешанный раздел требует
/// ответа: машинная часть в нём дополняет человеческую, но не заменяет её.
pub fn completeness(
    doc: &Document,
    m: &ProjectModel,
    p: &ProjectProfile,
    answered: &dyn Fn(&str) -> bool,
) -> Completeness {
    let mut c = Completeness {
        total: doc.sections.len(),
        required: 0,
        filled: 0,
        missing: Vec::new(),
    };
    for s in doc.sections {
        // Заголовок собственного содержания не имеет: его закрывают подразделы.
        if s.source == Source::Heading || !is_required(s, m, p) {
            continue;
        }
        c.required += 1;
        let filled = match s.source {
            // Диаграмма модели C4 строится всегда и остаётся правдивой, даже когда
            // изображать нечего: система без внешних зависимостей это законное состояние,
            // и диаграмма контекста с одним элементом описывает его верно. Считать такой
            // раздел незакрытым значило бы требовать несуществующих зависимостей.
            Source::FromModel if doc.standard == Standard::C4 => true,
            Source::FromModel => draft_text(s.draft, m).is_some(),
            Source::FromInterview | Source::Mixed => answered(s.id),
            Source::Heading => true,
        };
        if filled {
            c.filled += 1;
        } else {
            c.missing.push((s.number, s.title));
        }
    }
    c
}

// ───────────────────────────── черновики из модели ─────────────────────────────

/// Перечень значений фактов с указанием места, где факт установлен.
fn list(items: &[crate::model::Fact<String>], limit: usize) -> Option<String> {
    if items.is_empty() {
        return None;
    }
    let mut out = String::new();
    for it in items.iter().take(limit) {
        match (&it.origin.file, it.origin.line) {
            (Some(f), Some(l)) => out.push_str(&format!("- `{}` ({}:{})\n", it.value, f, l)),
            (Some(f), None) => out.push_str(&format!("- `{}` ({})\n", it.value, f)),
            _ => out.push_str(&format!("- `{}`\n", it.value)),
        }
    }
    if items.len() > limit {
        out.push_str(&format!("- и ещё {} позиций\n", items.len() - limit));
    }
    Some(out.trim_end().to_string())
}

/// Построить содержание либо черновик раздела из модели. None означает, что модель
/// сведений для этого раздела не содержит, и раздел подлежит опросу либо записи об
/// отсутствии.
pub fn draft_text(d: Draft, m: &ProjectModel) -> Option<String> {
    match d {
        Draft::None => None,
        Draft::Identity => {
            let name = m.identity.name.as_ref()?.value.clone();
            let mut s = format!("Наименование: {name}.");
            if let Some(v) = &m.identity.version {
                s.push_str(&format!(" Версия: {}.", v.value));
            }
            if let Some(l) = &m.identity.license {
                s.push_str(&format!(" Условия использования: {}.", l.value));
            }
            if let Some(c) = &m.identity.commit {
                s.push_str(&format!(
                    " Состояние истории изменений: {}.",
                    &c.value[..c.value.len().min(12)]
                ));
            }
            Some(s)
        }
        Draft::Composition => {
            if m.structure.modules.is_empty() {
                return None;
            }
            let mut s = String::new();
            for md in &m.structure.modules {
                s.push_str(&format!(
                    "- **{}**: определений {}, из них доступных извне {}",
                    md.name, md.definitions, md.exported
                ));
                if !md.top_exports.is_empty() {
                    s.push_str(&format!(". Среди них: {}", md.top_exports.join(", ")));
                }
                s.push('\n');
            }
            Some(s.trim_end().to_string())
        }
        Draft::Interfaces => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(r) = list(&m.surface.routes, 60) {
                parts.push(format!("Маршруты обращения к системе:\n{r}"));
            }
            // Интерфейс командной строки является полноправным интерфейсом системы: для
            // продукта, у которого нет ни одного маршрута HTTP, раздел о функциональных
            // характеристиках без него остался бы пустым при заведомо существующих
            // функциях.
            if let Some(c) = list(&m.surface.cli_commands, 40) {
                parts.push(format!("Операции, доступные из командной строки:\n{c}"));
            }
            if let Some(s) = list(&m.surface.api_schemas, 20) {
                parts.push(format!("Контрактные схемы интерфейса:\n{s}"));
            }
            (!parts.is_empty()).then(|| parts.join("\n\n"))
        }
        Draft::EnvVars => list(&m.surface.env, 40)
            .map(|l| format!("Параметры настройки, задаваемые через переменные окружения:\n{l}")),
        Draft::Services => list(&m.surface.services, 30)
            .map(|l| format!("Внешние сервисы, от которых зависит работа системы:\n{l}")),
        Draft::DataModel => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(l) = list(&m.surface.data_models, 40) {
                parts.push(format!("Сущности данных:\n{l}"));
            }
            if let Some(l) = list(&m.surface.migrations, 10) {
                parts.push(format!("Каталоги миграций схемы:\n{l}"));
            }
            (!parts.is_empty()).then(|| parts.join("\n\n"))
        }
        Draft::Dependencies => {
            if m.dependencies.is_empty() {
                return None;
            }
            let mut s = String::from("| Экосистема | Наименование | Версия |\n|---|---|---|\n");
            for d in m.dependencies.iter().take(200) {
                s.push_str(&format!(
                    "| {} | {} | {} |\n",
                    d.ecosystem, d.name, d.version
                ));
            }
            if m.dependencies.len() > 200 {
                s.push_str(&format!(
                    "\nИ ещё {} зависимостей.\n",
                    m.dependencies.len() - 200
                ));
            }
            Some(s.trim_end().to_string())
        }
        Draft::Toolchain => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(l) = list(&m.environment.stacks, 20) {
                parts.push(format!("Технологический стек:\n{l}"));
            }
            if let Some(l) = list(&m.environment.toolchains, 20) {
                parts.push(format!("Зафиксированные версии инструментария:\n{l}"));
            }
            (!parts.is_empty()).then(|| parts.join("\n\n"))
        }
        Draft::Artifacts => list(&m.structure.artifacts, 30)
            .map(|l| format!("Артефакты, производимые сборкой:\n{l}")),
        Draft::EntryPoints => {
            list(&m.structure.entry_points, 20).map(|l| format!("Точки входа системы:\n{l}"))
        }
        Draft::Deployment => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(l) = list(&m.deployment.containers, 30) {
                parts.push(format!("Контейнеры:\n{l}"));
            }
            if let Some(l) = list(&m.deployment.ports, 30) {
                parts.push(format!("Объявленные порты:\n{l}"));
            }
            (!parts.is_empty()).then(|| parts.join("\n\n"))
        }
        Draft::Languages => list(&m.environment.languages, 20)
            .or_else(|| {
                let mut langs: std::collections::BTreeSet<String> =
                    std::collections::BTreeSet::new();
                for md in &m.structure.modules {
                    for l in &md.languages {
                        langs.insert(l.clone());
                    }
                }
                (!langs.is_empty()).then(|| {
                    langs
                        .into_iter()
                        .map(|l| format!("- {l}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                })
            })
            .map(|l| format!("Языки реализации:\n{l}")),
        Draft::DocumentSet => {
            let mut s = String::from(
                "По проекту выпускаются следующие документы (поддерживаются автоматически):\n",
            );
            for d in documents() {
                s.push_str(&format!("- {} ({}), {}\n", d.title, d.designation, d.path));
            }
            Some(s.trim_end().to_string())
        }
        Draft::Sources => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(l) = list(&m.environment.manifests, 20) {
                parts.push(format!("Манифесты сборки:\n{l}"));
            }
            if !m.dependencies.is_empty() {
                parts.push(format!(
                    "Использованные готовые компоненты: {} зависимостей, перечень приведён в разделе о видах обеспечения.",
                    m.dependencies.len()
                ));
            }
            (!parts.is_empty()).then(|| parts.join("\n\n"))
        }
        Draft::Cli => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(l) = list(&m.surface.cli_commands, 40) {
                parts.push(format!("Операции, доступные из командной строки:\n{l}"));
            }
            if let Some(l) = list(&m.surface.cli_flags, 40) {
                parts.push(format!("Ключи и параметры вызова:\n{l}"));
            }
            (!parts.is_empty()).then(|| parts.join("\n\n"))
        }
        Draft::Config => list(&m.surface.config_params, 40).map(|l| {
            format!(
                "Параметры настройки из файлов конфигурации (приведены только имена, \
                 поскольку значение может содержать сведения ограниченного доступа):\n{l}"
            )
        }),
        Draft::Api => {
            if m.structure.api.is_empty() {
                return None;
            }
            let mut s = String::new();
            // Описанные автором объявления идут первыми: документ ценнее там, где у
            // объявления есть человеческое пояснение, а не только сигнатура.
            let mut items: Vec<&crate::model::ApiEntry> = m.structure.api.iter().collect();
            items.sort_by(|a, b| {
                b.doc
                    .is_some()
                    .cmp(&a.doc.is_some())
                    .then(a.name.cmp(&b.name))
            });
            for it in items.iter().take(80) {
                s.push_str(&format!(
                    "- **{}** ({}): `{}`",
                    it.name, it.kind, it.signature
                ));
                if let Some(d) = &it.doc {
                    let первая: String = d
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .chars()
                        .take(200)
                        .collect();
                    if !первая.trim().is_empty() {
                        s.push_str(&format!(". {первая}"));
                    }
                }
                if !it.extends.is_empty() {
                    s.push_str(&format!(". Основано на: {}", it.extends.join(", ")));
                }
                if let (Some(f), Some(l)) = (&it.origin.file, it.origin.line) {
                    s.push_str(&format!(" ({f}:{l})"));
                }
                s.push('\n');
            }
            if m.structure.api.len() > 80 {
                s.push_str(&format!(
                    "\nВсего объявлений, доступных извне: {}; выше приведены первые восемьдесят.\n",
                    m.structure.api.len()
                ));
            }
            Some(s.trim_end().to_string())
        }
        Draft::Legend => Some(
            "Обозначения на диаграммах. Прямоугольник со скруглением обозначает человека \
             или внешнюю роль; прямоугольник обозначает программную систему, контейнер \
             или компонент; цилиндр обозначает хранилище данных. Тип элемента и \
             применяемая технология указаны в подписи самого элемента. Каждая линия \
             обозначает однонаправленную связь и подписана назначением связи, а для связи \
             между контейнерами дополнительно указан протокол взаимодействия."
                .to_string(),
        ),
        Draft::Risks => {
            if m.structure.cycles.is_empty() {
                return Some("Циклических связей между модулями не обнаружено.".to_string());
            }
            let mut s = String::from("Циклические связи между модулями (подлежат распутыванию):\n");
            for c in &m.structure.cycles {
                s.push_str(&format!("- {}\n", c.join(", ")));
            }
            Some(s.trim_end().to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Идентификаторы разделов служат ключами реестра ответов, поэтому обязаны быть
    /// уникальными в пределах документа: совпадение означало бы, что ответ на один
    /// раздел молча подставится в другой.
    #[test]
    fn идентификаторы_разделов_уникальны_в_документе() {
        for d in documents() {
            let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
            for s in d.sections {
                assert!(
                    seen.insert(s.id),
                    "документ {}: идентификатор раздела {} повторяется",
                    d.id,
                    s.id
                );
            }
        }
    }

    /// Раздел, наполняемый опросом, обязан нести формулировку вопроса: иначе агент не
    /// сможет его задать, и раздел останется незакрытым навсегда.
    #[test]
    fn разделы_опроса_несут_формулировку_вопроса() {
        for d in documents() {
            for s in d.sections {
                if matches!(s.source, Source::FromInterview | Source::Mixed) {
                    assert!(
                        s.question.is_some_and(|q| !q.trim().is_empty()),
                        "документ {}: раздел {} требует опроса, но вопрос не сформулирован",
                        d.id,
                        s.number
                    );
                }
            }
        }
    }

    /// Раздел, объявленный выводимым только из модели, обязан иметь правило построения:
    /// иначе он не заполнится ни машиной, ни человеком.
    #[test]
    fn разделы_из_модели_несут_правило_построения() {
        for d in documents() {
            for s in d.sections {
                if s.source == Source::FromModel {
                    assert!(
                        s.draft != Draft::None,
                        "документ {}: раздел {} объявлен выводимым из кода, но правила построения не имеет",
                        d.id,
                        s.number
                    );
                }
            }
        }
    }

    /// Полнота по стандарту вычисляется детерминированно и меняется ровно от наличия
    /// ответов: пока обязательный раздел не закрыт, документ стандарту не соответствует,
    /// и это утверждение проверяемо, а не является мнением.
    #[test]
    fn полнота_считается_по_обязательным_разделам() {
        let m = ProjectModel {
            schema_version: crate::model::SCHEMA_VERSION,
            ..Default::default()
        };
        let p = ProjectProfile::default();
        let doc = &gost19_201::DOCUMENT;

        let пусто = completeness(doc, &m, &p, &|_| false);
        assert!(
            пусто.required > 0,
            "у технического задания есть обязательные разделы"
        );
        assert!(
            !пусто.complete(),
            "без единого ответа документ стандарту не соответствует"
        );
        assert_eq!(
            пусто.missing.len(),
            пусто.required - пусто.filled,
            "перечень незакрытых разделов обязан совпадать с их числом"
        );

        let всё = completeness(doc, &m, &p, &|_| true);
        assert!(
            всё.filled >= пусто.filled,
            "ответы могут только увеличить полноту"
        );
        assert!(всё.percent() >= пусто.percent());
    }

    /// Заголовок собственного содержания не имеет и в оценку полноты не входит: иначе
    /// документ никогда не достиг бы соответствия, поскольку закрыть заголовок нечем.
    #[test]
    fn заголовки_в_полноту_не_входят() {
        let m = ProjectModel {
            schema_version: crate::model::SCHEMA_VERSION,
            ..Default::default()
        };
        let p = ProjectProfile::default();
        for d in documents() {
            let headings = d
                .sections
                .iter()
                .filter(|s| s.source == Source::Heading)
                .count();
            let c = completeness(d, &m, &p, &|_| true);
            assert!(
                c.required + headings <= c.total,
                "документ {}: заголовки не должны попадать в число обязательных",
                d.id
            );
        }
    }

    /// Идентификаторы документов уникальны, а пути файлов не совпадают.
    #[test]
    fn документы_различимы() {
        let mut ids: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        let mut paths: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for d in documents() {
            assert!(
                ids.insert(d.id),
                "идентификатор документа {} повторяется",
                d.id
            );
            assert!(
                paths.insert(d.path),
                "путь документа {} повторяется",
                d.path
            );
        }
    }
}
