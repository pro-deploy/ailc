//! E9 Diagram — рендер модели в текст диаграммы (без внешних бинарей).
//!
//! Движок не считает граф сам — он ПЕРЕИСПОЛЬЗУЕТ E3 CodeIntel
//! (`CodeIntelEngine::dependency_graph`) и превращает готовую модель в текст
//! Mermaid. Так логика анализа не дублируется: один источник правды о зависимостях,
//! здесь — только представление. Текст самодостаточен (его рисует любой просмотрщик
//! Mermaid), поэтому никаких сторонних инструментов не требуется.

use super::codeintel::CodeIntelEngine;
use ailc_contracts::{Ctx, Result, RunInput};
use std::collections::BTreeMap;

pub struct DiagramEngine;

impl DiagramEngine {
    /// Построить Mermaid-граф зависимостей модулей.
    ///
    /// Узлам присваиваются стабильные идентификаторы `m0, m1, …` по индексу модуля
    /// в `modules` (порядок детерминирован — `DepGraph.modules` уже отсортирован).
    /// Имена модулей экранируются в кавычках внутри узлов. Рёбра берутся из `edges`
    /// и переводятся из имён в идентификаторы. Если модулей нет — возвращается пустой
    /// граф с заголовком (честно отражает отсутствие данных, без выдумывания узлов).
    pub fn mermaid_deps(ctx: &Ctx, input: &RunInput) -> Result<String> {
        let graph = CodeIntelEngine::dependency_graph(ctx, input)?;

        // Имя модуля → стабильный id (m0, m1, …) по индексу в modules.
        let mut id_of: BTreeMap<&str, String> = BTreeMap::new();
        for (i, name) in graph.modules.iter().enumerate() {
            id_of.insert(name.as_str(), format!("m{i}"));
        }

        let mut s = String::new();
        s.push_str("graph LR\n");

        // Узлы: каждому модулю — строка `mN["имя"]` (имя экранировано в кавычках).
        for name in &graph.modules {
            let id = match id_of.get(name.as_str()) {
                Some(id) => id,
                None => continue, // недостижимо: id построены из тех же modules
            };
            s.push_str(&format!("  {id}[\"{}\"]\n", escape(name)));
        }

        // Рёбра: `from --> to`, имена отображаются на их идентификаторы.
        // Ребро с неизвестным концом (нет в modules) молча не рисуем — узла для него нет.
        for (from, to) in &graph.edges {
            if let (Some(fid), Some(tid)) = (id_of.get(from.as_str()), id_of.get(to.as_str())) {
                s.push_str(&format!("  {fid} --> {tid}\n"));
            }
        }

        Ok(s)
    }
}

// ───────────────────────────── модель C4 ─────────────────────────────

/// Технология внешнего сервиса по схеме адреса или по имени переменной окружения.
///
/// Модель C4 требует явно указывать технологию у каждого элемента: диаграмма без неё
/// сообщает, что связь есть, но не сообщает, чем она осуществляется, и потому непригодна
/// ни для эксплуатации, ни для оценки рисков.
fn service_technology(value: &str) -> &'static str {
    let v = value.to_ascii_lowercase();
    let by = |needles: &[&str]| needles.iter().any(|n| v.contains(n));
    if by(&["postgres", "mysql", "mariadb", "clickhouse"]) {
        "реляционная база данных"
    } else if by(&["mongodb", "mongo"]) {
        "документная база данных"
    } else if by(&["redis"]) {
        "хранилище в памяти"
    } else if by(&["amqp", "rabbit"]) {
        "брокер сообщений AMQP"
    } else if by(&["kafka", "broker"]) {
        "брокер сообщений Kafka"
    } else if by(&["nats", "stan"]) {
        "брокер сообщений NATS"
    } else if by(&["elastic", "es://", "es_url"]) {
        "поисковый движок"
    } else if by(&["s3://", "gs://", "gcs://", "wasb", "amazonaws"]) {
        "объектное хранилище"
    } else if by(&["grpc"]) {
        "вызов процедур gRPC"
    } else if by(&["sqs", "queue"]) {
        "очередь сообщений"
    } else {
        "внешний сервис"
    }
}

/// Безопасный идентификатор узла Mermaid.
fn node_id(prefix: &str, i: usize) -> String {
    format!("{prefix}{i}")
}

/// Подпись узла: без кавычек, ограниченной длины, с сохранением переводов строк разметки.
fn label(s: &str) -> String {
    s.replace('"', "'")
        .replace('\n', " ")
        .chars()
        .take(56)
        .collect()
}

impl DiagramEngine {
    /// Диаграмма уровня «Контекст системы».
    ///
    /// Основной элемент это сама система, вспомогательные это человек и внешние системы,
    /// от которых она зависит. Каждый элемент несёт свой тип и технологию, каждая связь
    /// подписана назначением, как того требует нотация модели.
    pub fn c4_context(m: &crate::model::ProjectModel) -> String {
        let name = m
            .identity
            .name
            .as_ref()
            .map(|f| f.value.clone())
            .unwrap_or_else(|| "система".to_string());
        let mut s = String::from("flowchart TD\n");
        s.push_str("  человек([\"Пользователь<br/>[Человек]<br/>Работает с системой\"])\n");
        s.push_str(&format!(
            "  система[\"{}<br/>[Программная система]<br/>Рассматриваемая система\"]\n",
            label(&name)
        ));
        s.push_str("  человек -->|\"Ставит задачи и получает результат\"| система\n");

        // Внешние системы: только уникальные по значению, чтобы одна и та же зависимость
        // не рисовалась столько раз, сколько раз она упомянута в коде.
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut i = 0usize;
        for f in &m.surface.services {
            if !seen.insert(f.value.clone()) {
                continue;
            }
            if i >= 12 {
                break;
            }
            let id = node_id("внеш", i);
            s.push_str(&format!(
                "  {id}[(\"{}<br/>[Внешняя система]<br/>{}\")]\n",
                label(&f.value),
                service_technology(&f.value)
            ));
            s.push_str(&format!("  система -->|\"Обращается по сети\"| {id}\n"));
            i += 1;
        }
        if i == 0 {
            s.push_str("  %% внешних систем в коде не обнаружено\n");
        }
        s
    }

    /// Диаграмма уровня «Контейнеры».
    ///
    /// Контейнером в модели C4 является исполняемая единица либо хранилище, поэтому
    /// контейнерами объявлены модули верхнего уровня с указанием языков реализации как
    /// технологии. Связи берутся из графа зависимостей и подписаны.
    pub fn c4_containers(m: &crate::model::ProjectModel) -> String {
        let mut s = String::from("flowchart TD\n");
        let mut ids: std::collections::BTreeMap<&str, String> = std::collections::BTreeMap::new();
        // Порядок по числу определений: крупные модули системы важнее для читателя.
        let mut mods: Vec<&crate::model::Module> = m.structure.modules.iter().collect();
        mods.sort_by(|a, b| b.definitions.cmp(&a.definitions).then(a.name.cmp(&b.name)));
        for (i, md) in mods.iter().take(14).enumerate() {
            let id = node_id("к", i);
            let tech = if md.languages.is_empty() {
                "язык не распознан".to_string()
            } else {
                md.languages.join(", ")
            };
            s.push_str(&format!(
                "  {id}[\"{}<br/>[Контейнер: {}]<br/>Определений {}, доступно извне {}\"]\n",
                label(&md.name),
                tech,
                md.definitions,
                md.exported
            ));
            ids.insert(md.name.as_str(), id);
        }
        let mut edges = 0usize;
        for (from, to) in &m.structure.dependencies {
            if edges >= 40 {
                break;
            }
            if let (Some(a), Some(b)) = (ids.get(from.as_str()), ids.get(to.as_str())) {
                s.push_str(&format!("  {a} -->|\"Использует\"| {b}\n"));
                edges += 1;
            }
        }
        if ids.is_empty() {
            s.push_str("  %% модули системы не распознаны\n");
        }
        s
    }

    /// Диаграмма уровня «Компоненты» для наиболее крупного контейнера.
    ///
    /// Область охвата уровня по модели C4 это ОДИН контейнер, поэтому берётся самый
    /// крупный модуль, а его компонентами объявляются доступные извне определения.
    pub fn c4_components(m: &crate::model::ProjectModel) -> String {
        let Some(biggest) = m
            .structure
            .modules
            .iter()
            .max_by_key(|md| (md.exported, md.definitions))
        else {
            return "flowchart LR\n  %% контейнеров не распознано\n".to_string();
        };
        let mut s = format!(
            "flowchart LR\n  subgraph контейнер[\"{}<br/>[Контейнер]\"]\n",
            label(&biggest.name)
        );
        if biggest.top_exports.is_empty() {
            s.push_str("    %% доступных извне определений не обнаружено\n");
        }
        for (i, e) in biggest.top_exports.iter().take(12).enumerate() {
            s.push_str(&format!("    ко{i}[\"{}<br/>[Компонент]\"]\n", label(e)));
        }
        s.push_str("  end\n");
        s
    }

    /// Динамическая диаграмма: последовательность обращений от точки входа.
    ///
    /// Взаимодействия пронумерованы, как того требует нотация: без порядка диаграмма
    /// перестаёт быть динамической и вырождается в ещё одну статическую.
    pub fn c4_dynamic(m: &crate::model::ProjectModel) -> String {
        let mut s = String::from("flowchart LR\n");
        if m.structure.entry_points.is_empty() {
            s.push_str("  %% точек входа не обнаружено\n");
            return s;
        }
        s.push_str("  человек([\"Пользователь\"])\n");
        for (i, e) in m.structure.entry_points.iter().take(6).enumerate() {
            let id = node_id("вх", i);
            s.push_str(&format!(
                "  {id}[\"{}<br/>[Точка входа]\"]\n",
                label(&e.value)
            ));
            s.push_str(&format!("  человек -->|\"{}. Запускает\"| {id}\n", i + 1));
        }
        s
    }

    /// Диаграмма развёртывания: узлы, экземпляры и объявленные порты.
    pub fn c4_deployment(m: &crate::model::ProjectModel) -> String {
        let mut s = String::from("flowchart TD\n");
        if m.deployment.containers.is_empty() && m.deployment.ports.is_empty() {
            s.push_str("  %% описаний развёртывания в проекте не обнаружено\n");
            return s;
        }
        for (i, c) in m.deployment.containers.iter().take(12).enumerate() {
            s.push_str(&format!(
                "  у{i}[\"{}<br/>[Узел развёртывания]\"]\n",
                label(&c.value)
            ));
        }
        for (i, p) in m.deployment.ports.iter().take(12).enumerate() {
            s.push_str(&format!(
                "  п{i}[\"Порт {}<br/>[Инфраструктурный узел]\"]\n",
                label(&p.value)
            ));
            if !m.deployment.containers.is_empty() {
                s.push_str(&format!("  у0 -->|\"Слушает\"| п{i}\n"));
            }
        }
        s
    }
}

/// Экранировать кавычки и переводы строк в подписи узла, чтобы не сломать синтаксис.
fn escape(name: &str) -> String {
    name.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
}
