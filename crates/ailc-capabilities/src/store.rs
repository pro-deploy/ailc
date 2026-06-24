//! CORE-capability на E7 Store — состояние проекта как файлы под `.co/`.
//!
//! ПРИНЦИП тот же, что и у сканеров: capability = тонкий конфиг поверх одного движка.
//! Память, журнал решений и бэклог — это разные пространства имён одного `Store`,
//! без дублирования логики путей/чтения/записи. Все мутирующие операции честно
//! помечены `mutates: true` (проходят через gate + confirm в оркестраторе).

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Tier,
};
use ailc_core::engines::store::Store;
use ailc_core::registry::Registry;
use ailc_core::Capability;

/// Схема входа для писателей памяти/бэклога: имя записи и текстовое содержимое.
const STORE_SCHEMA: &str =
    r#"{"type":"object","properties":{"target":{"type":"string"},"query":{"type":"string"}}}"#;
/// Схема для чисто читающих операций — без обязательных полей.
const READ_SCHEMA: &str = r#"{"type":"object","properties":{}}"#;

/// Пространство имён памяти и бэклога (каталоги под `.co/`).
const NS_MEMORY: &str = "memory-bank";
const NS_BACKLOG: &str = "backlog";

/// Первая непустая строка содержимого (краткая выжимка для списков), обрезанная.
fn excerpt(content: &str) -> String {
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("(пусто)");
    line.chars().take(120).collect()
}

// ───────────────────────── memory/read ─────────────────────────

pub struct MemoryRead {
    manifest: CapabilityManifest,
}

impl Default for MemoryRead {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryRead {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "memory/read",
                family: Family::Memory,
                engine: EngineKind::Store,
                when_to_use: "Прочитать рабочую память проекта (контекст, заметки) перед началом работы.",
                input_schema: READ_SCHEMA,
                tier: Tier::Core,
                deterministic: false,
                mutates: false,
            },
        }
    }
}

impl Capability for MemoryRead {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let items = Store::read_all(ctx, NS_MEMORY)?;

        // Инвариант «нет молчаливых пропусков»: пустая память — явная причина.
        if items.is_empty() {
            out.skipped = Some("память пуста (нет .co/memory-bank)".into());
            out.summary = "memory/read: память пуста".into();
            return Ok(out);
        }

        for (name, content) in &items {
            out.records.push(format!("{name}: {}", excerpt(content)));
        }
        out.metrics.push(("files".into(), items.len() as f64));
        out.summary = format!("memory/read: {} файлов памяти", items.len());
        Ok(out)
    }
}

// ───────────────────────── memory/update ─────────────────────────

pub struct MemoryUpdate {
    manifest: CapabilityManifest,
}

impl Default for MemoryUpdate {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryUpdate {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "memory/update",
                family: Family::Memory,
                engine: EngineKind::Store,
                when_to_use: "Сохранить рабочий контекст в память проекта (имя файла — target, содержимое — query).",
                input_schema: STORE_SCHEMA,
                tier: Tier::Core,
                deterministic: false,
                mutates: true,
            },
        }
    }
}

impl Capability for MemoryUpdate {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        // Без содержимого писать нечего — явная причина, не молчаливый пропуск.
        let content = match input.query.as_deref().filter(|q| !q.is_empty()) {
            Some(q) => q,
            None => {
                out.skipped = Some("нужен параметр query — содержимое для записи в память".into());
                out.summary = "memory/update: пропущено (нет содержимого)".into();
                return Ok(out);
            }
        };

        // Имя файла берём из target, по умолчанию — активный контекст.
        let name = input
            .target
            .as_deref()
            .filter(|t| !t.is_empty())
            .unwrap_or("active-context.md");

        Store::write(ctx, NS_MEMORY, name, content)?;
        let artifact = format!(".co/{NS_MEMORY}/{name}");
        out.artifacts.push(artifact.clone());
        out.summary = format!("memory/update: память сохранена → {artifact}");
        Ok(out)
    }
}

// ───────────────────────── memory/decision-log ─────────────────────────

pub struct DecisionLog {
    manifest: CapabilityManifest,
}

impl Default for DecisionLog {
    fn default() -> Self {
        Self::new()
    }
}

impl DecisionLog {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "memory/decision-log",
                family: Family::Memory,
                engine: EngineKind::Store,
                when_to_use: "Записать принятое решение строкой в журнал решений проекта (текст — query).",
                input_schema: STORE_SCHEMA,
                tier: Tier::Core,
                deterministic: false,
                mutates: true,
            },
        }
    }
}

impl Capability for DecisionLog {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        // Пустое решение записывать незачем — явная причина.
        let line = match input.query.as_deref().filter(|q| !q.is_empty()) {
            Some(q) => q,
            None => {
                out.skipped = Some("нужен параметр query — текст решения для записи".into());
                out.summary = "memory/decision-log: пропущено (нет текста решения)".into();
                return Ok(out);
            }
        };

        Store::append(ctx, NS_MEMORY, "decision-log.md", line)?;
        let artifact = format!(".co/{NS_MEMORY}/decision-log.md");
        out.artifacts.push(artifact.clone());
        out.summary = format!("memory/decision-log: решение записано → {artifact}");
        Ok(out)
    }
}

// ───────────────────────── backlog/add ─────────────────────────

pub struct BacklogAdd {
    manifest: CapabilityManifest,
}

impl Default for BacklogAdd {
    fn default() -> Self {
        Self::new()
    }
}

impl BacklogAdd {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "backlog/add",
                family: Family::Backlog,
                engine: EngineKind::Store,
                when_to_use: "Добавить задачу в бэклог проекта (описание задачи — query); id выдаётся автоматически.",
                input_schema: STORE_SCHEMA,
                tier: Tier::Core,
                deterministic: false,
                mutates: true,
            },
        }
    }
}

impl Capability for BacklogAdd {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        // Без описания задачу не создаём — явная причина.
        let body = match input.query.as_deref().filter(|q| !q.is_empty()) {
            Some(q) => q,
            None => {
                out.skipped = Some("нужен параметр query — описание задачи".into());
                out.summary = "backlog/add: пропущено (нет описания задачи)".into();
                return Ok(out);
            }
        };

        // Атомарно выделяем id-файл, затем наполняем его описанием.
        let name = Store::alloc_id(ctx, NS_BACKLOG, "md")?;
        Store::write(ctx, NS_BACKLOG, &name, body)?;
        let artifact = format!(".co/{NS_BACKLOG}/{name}");
        out.artifacts.push(artifact.clone());
        out.summary = format!("backlog/add: задача создана → {artifact}");
        Ok(out)
    }
}

// ───────────────────────── backlog/list ─────────────────────────

pub struct BacklogList {
    manifest: CapabilityManifest,
}

impl Default for BacklogList {
    fn default() -> Self {
        Self::new()
    }
}

impl BacklogList {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "backlog/list",
                family: Family::Backlog,
                engine: EngineKind::Store,
                when_to_use: "Перечислить задачи бэклога проекта с их заголовками.",
                input_schema: READ_SCHEMA,
                tier: Tier::Core,
                deterministic: false,
                mutates: false,
            },
        }
    }
}

impl Capability for BacklogList {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let items = Store::read_all(ctx, NS_BACKLOG)?;

        // Инвариант «нет молчаливых пропусков»: пустой бэклог — явная причина.
        if items.is_empty() {
            out.skipped = Some("бэклог пуст (нет .co/backlog)".into());
            out.summary = "backlog/list: бэклог пуст".into();
            return Ok(out);
        }

        for (name, content) in &items {
            out.records.push(format!("{name}: {}", excerpt(content)));
        }
        out.metrics.push(("tasks".into(), items.len() as f64));
        out.summary = format!("backlog/list: {} задач в бэклоге", items.len());
        Ok(out)
    }
}

/// Регистрирует все capability, реализованные на движке E7 Store.
pub fn register(reg: &mut Registry) {
    reg.register(Box::new(MemoryRead::new()));
    reg.register(Box::new(MemoryUpdate::new()));
    reg.register(Box::new(DecisionLog::new()));
    reg.register(Box::new(BacklogAdd::new()));
    reg.register(Box::new(BacklogList::new()));
}
