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
            if let (Some(fid), Some(tid)) =
                (id_of.get(from.as_str()), id_of.get(to.as_str()))
            {
                s.push_str(&format!("  {fid} --> {tid}\n"));
            }
        }

        Ok(s)
    }
}

/// Экранировать кавычки и переводы строк в подписи узла, чтобы не сломать синтаксис.
fn escape(name: &str) -> String {
    name.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
}
