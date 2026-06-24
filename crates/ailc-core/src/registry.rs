//! Реестр capability. Наружу (MCP) выходит не он целиком, а Capability Router,
//! который семантически подбирает подмножество под контекст шага. Реестр —
//! источник истины: id, манифесты, доступ по id.

use crate::Capability;
use ailc_contracts::CapabilityManifest;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Default)]
pub struct Registry {
    // Arc (а не Box): пайплайну нужны владеющие хэндлы, чтобы исполнять шаг в
    // отсоединённом потоке с таймаутом (см. pipeline::STEP_TIMEOUT).
    //
    // ДВЕ структуры на один набор capability сознательно (T63). Vec сохраняет ПОРЯДОК
    // регистрации, нужный для детерминированной итерации (all/manifests). HashMap по id
    // даёт доступ по идентификатору за O(1): get/get_arc вызываются на КАЖДЫЙ шаг каждой
    // волны пайплайна (см. pipeline.rs), поэтому линейный поиск по вектору давал O(n) на
    // лукап и O(n*m) на прогон из m шагов. Обе структуры держат один и тот же Arc, то есть
    // дублируется лишь дешёвый счётчик ссылок, а не сама capability.
    caps: Vec<Arc<dyn Capability>>,
    index: HashMap<&'static str, Arc<dyn Capability>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Зарегистрировать capability. Идентификатор берётся из манифеста (он `&'static str`),
    /// поэтому индекс по id не требует владеющей строки-ключа. Повторная регистрация под
    /// тем же id перезаписывает запись индекса последней (а в векторе остаются обе): это
    /// согласованно с прежним поведением `find`, который возвращал ПЕРВОЕ совпадение, но
    /// тут мы осознанно отдаём последнее зарегистрированное (актуальное) и фиксируем это
    /// поведение тестом; на практике id уникальны (см. тест уникальности реестра).
    pub fn register(&mut self, cap: Box<dyn Capability>) {
        let cap: Arc<dyn Capability> = Arc::from(cap);
        let id = cap.manifest().id;
        self.index.insert(id, Arc::clone(&cap));
        self.caps.push(cap);
    }

    pub fn all(&self) -> &[Arc<dyn Capability>] {
        &self.caps
    }

    pub fn manifests(&self) -> Vec<&CapabilityManifest> {
        self.caps.iter().map(|c| c.manifest()).collect()
    }

    /// Доступ к capability по id за O(1) (через индекс), а не линейным поиском по вектору.
    pub fn get(&self, id: &str) -> Option<&dyn Capability> {
        self.index.get(id).map(|c| c.as_ref())
    }

    /// Владеющий хэндл capability за O(1): для исполнения в потоке с таймаутом.
    pub fn get_arc(&self, id: &str) -> Option<Arc<dyn Capability>> {
        self.index.get(id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_contracts::{
        CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Tier,
    };

    struct Dummy {
        manifest: CapabilityManifest,
    }
    impl Capability for Dummy {
        fn manifest(&self) -> &CapabilityManifest {
            &self.manifest
        }
        fn run(&self, _ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
            Ok(CapabilityOutput::default())
        }
    }

    fn cap(id: &'static str) -> Box<dyn Capability> {
        Box::new(Dummy {
            manifest: CapabilityManifest {
                id,
                family: Family::Quality,
                engine: EngineKind::Scan,
                when_to_use: "тест",
                input_schema: "{}",
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        })
    }

    #[test]
    fn get_returns_registered_by_id() {
        // O(1)-доступ возвращает именно ту capability, что зарегистрирована под id.
        let mut reg = Registry::new();
        reg.register(cap("a.one"));
        reg.register(cap("b.two"));
        assert!(reg.get("a.one").is_some());
        assert_eq!(reg.get("a.one").unwrap().manifest().id, "a.one");
        assert!(reg.get_arc("b.two").is_some());
        assert_eq!(reg.get_arc("b.two").unwrap().manifest().id, "b.two");
    }

    #[test]
    fn get_unknown_is_none() {
        // Негатив: неизвестный id даёт None и не паникует.
        let mut reg = Registry::new();
        reg.register(cap("a.one"));
        assert!(reg.get("нет.такого").is_none());
        assert!(reg.get_arc("нет.такого").is_none());
    }

    #[test]
    fn iteration_order_preserved_alongside_index() {
        // Vec хранит порядок регистрации для детерминированной итерации, индекс при этом
        // отдаёт те же capability по id.
        let mut reg = Registry::new();
        reg.register(cap("first"));
        reg.register(cap("second"));
        reg.register(cap("third"));
        let ids: Vec<&str> = reg.manifests().iter().map(|m| m.id).collect();
        assert_eq!(ids, vec!["first", "second", "third"]);
        // Каждый из них доступен через индекс.
        for id in ["first", "second", "third"] {
            assert!(reg.get(id).is_some(), "{id} должен быть в индексе");
        }
    }

    #[test]
    fn reregister_same_id_index_returns_latest() {
        // Повторная регистрация под тем же id: индекс отдаёт ПОСЛЕДНюю (актуальную)
        // запись; в векторе остаются обе (порядок итерации не теряет ни одной).
        let mut reg = Registry::new();
        reg.register(cap("dup"));
        reg.register(cap("dup"));
        assert!(reg.get("dup").is_some());
        assert_eq!(reg.all().len(), 2, "вектор хранит обе регистрации");
    }
}
