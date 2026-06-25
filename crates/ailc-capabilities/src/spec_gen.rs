//! Генераторы документации из кода (Фаза 3) — спека, архитектура, C4, модель данных,
//! глоссарий. Структуры по признанным практикам: спека — ГОСТ 19.201/34.602, архитектура
//! — arc42, диаграммы — C4 (Simon Brown), решения — ADR (Nygard).
//!
//! ПРИНЦИП «всё как код»: код-производные разделы живут в авто-блоке `<!-- co:auto -->`
//! (движок Generator актуализирует их идемпотентно), а человеческие разделы (цели,
//! ограничения, НФТ) скаффолдятся ОДИН раз вне блока — правки человека переживают
//! регенерацию. Это и есть «проектировать, когда доков нет, и держать в синхроне».
//! Все генераторы mutates:true (семейство Generate) — гоняются по намерению и в custodian.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, SymbolKind,
    Tier,
};
use ailc_core::engines::codeintel::CodeIntelEngine;
use ailc_core::engines::generator::{Generator, WriteAction};
use ailc_core::engines::surface;
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::collections::BTreeSet;
use std::fs;

const TARGET_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;

fn gen_manifest(id: &'static str, engine: EngineKind, when: &'static str) -> CapabilityManifest {
    CapabilityManifest {
        id,
        family: Family::Generate,
        engine,
        when_to_use: when,
        input_schema: TARGET_SCHEMA,
        tier: Tier::Core,
        deterministic: true,
        mutates: true,
    }
}

/// Имя проекта = имя корневой папки.
fn project_name(ctx: &Ctx) -> String {
    ctx.root
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "проект".to_string())
}

/// Скаффолд человеческих разделов создаётся ОДИН раз (вне авто-блока), затем авто-блок
/// дописывается/обновляется. Правки человека в скаффолде переживают регенерацию.
fn write_doc(
    ctx: &Ctx,
    rel: &str,
    key: &str,
    scaffold: &str,
    auto: &str,
) -> Result<(String, WriteAction)> {
    let path = ctx.root.join(rel);
    if !path.exists() {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&path, scaffold);
    }
    Generator::write_block(ctx, rel, key, auto)
}

/// Безопасный mermaid-идентификатор (ASCII-alnum, иначе «_»; не начинается с цифры).
fn mid(s: &str) -> String {
    let id: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if id.is_empty() || id.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("n_{id}")
    } else {
        id
    }
}

/// Подпись узла (без кавычек, ограниченная длина).
fn lbl(s: &str) -> String {
    s.replace('"', "'").chars().take(48).collect()
}

fn fmt_list(items: &[surface::SurfaceItem], limit: usize) -> String {
    if items.is_empty() {
        return "— не обнаружено —".to_string();
    }
    let mut lines: Vec<String> = items
        .iter()
        .take(limit)
        .map(|it| format!("- `{}` — {}:{}", it.value, it.file, it.line))
        .collect();
    if items.len() > limit {
        lines.push(format!("- … ещё {}", items.len() - limit));
    }
    lines.join("\n")
}

fn out_with(path: String, action: WriteAction, id: &str) -> CapabilityOutput {
    let mut out = CapabilityOutput::default();
    out.artifacts.push(path.clone());
    out.summary = format!("{id}: {path} ({action})");
    out
}

// ───────────────────────── generate/spec (ГОСТ 19.201/34.602) ─────────────────────────

const SPEC_SCAFFOLD: &str = "# Спецификация продукта\n\n\
> Структура по мотивам ГОСТ 19.201-78 / 34.602-2020. Разделы ниже заполняет человек; \
раздел «Состав и интерфейсы (из кода)» ailc поддерживает автоматически.\n\n\
## 1. Общие сведения\n_Назначение и область применения продукта — заполни._\n\n\
## 2. Цели и задачи создания\n_Какую задачу решает, для кого — заполни._\n\n\
## Нефункциональные требования\n_Производительность, надёжность, безопасность, ограничения — заполни._\n";

pub(crate) fn build_spec_auto(ctx: &Ctx, input: &RunInput) -> Result<String> {
    let stats = CodeIntelEngine::module_stats(ctx, input)?;
    let syms = CodeIntelEngine::symbols(ctx, input)?;
    let s = surface::extract(ctx, input)?;
    let public = syms.iter().filter(|x| x.exported).count();
    let mut langs: BTreeSet<String> = BTreeSet::new();
    for st in stats.values() {
        for l in &st.langs {
            langs.insert(l.clone());
        }
    }

    let mut d = String::from("## Состав и интерфейсы (из кода — обновляется автоматически)\n\n");
    d.push_str("### Состав системы\n");
    if stats.is_empty() {
        d.push_str("— модули не распознаны —\n");
    } else {
        for (name, st) in &stats {
            d.push_str(&format!(
                "- **{name}** — {} определений ({} публичных)",
                st.total, st.exported
            ));
            if !st.top_exports.is_empty() {
                let mut tops = st.top_exports.clone();
                tops.sort(); // детерминированный порядок → идемпотентная регенерация
                d.push_str(&format!(". Среди них: {}", tops.join(", ")));
            }
            d.push('\n');
        }
    }
    d.push_str(&format!("\n### Функции и интерфейсы\nПубличных символов: {public}.\n\n"));
    d.push_str("Эндпоинты (HTTP):\n");
    d.push_str(&fmt_list(&s.routes, 40));
    d.push_str("\n\n### Виды обеспечения\n");
    d.push_str(&format!(
        "Языки: {}.\n\nВнешние сервисы:\n{}\n\nПеременные окружения:\n{}\n",
        if langs.is_empty() {
            "—".to_string()
        } else {
            langs.iter().cloned().collect::<Vec<_>>().join(", ")
        },
        fmt_list(&s.services, 20),
        fmt_list(&s.env, 30),
    ));
    d.push_str("\n### Модель данных\n");
    if s.models.is_empty() {
        d.push_str("— не обнаружена (см. docs/МОДЕЛЬ-ДАННЫХ.md) —\n");
    } else {
        d.push_str(&fmt_list(&s.models, 30));
        d.push('\n');
    }
    Ok(d.trim_end().to_string())
}

pub struct GenerateSpec {
    manifest: CapabilityManifest,
}
impl Default for GenerateSpec {
    fn default() -> Self {
        Self::new()
    }
}
impl GenerateSpec {
    pub fn new() -> Self {
        Self {
            manifest: gen_manifest(
                "generate/spec",
                EngineKind::Generator,
                "Собрать спецификацию продукта из кода (по ГОСТ 19/34): состав, функции, эндпоинты, обеспечение, модель данных. Идемпотентно.",
            ),
        }
    }
}
impl Capability for GenerateSpec {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let auto = build_spec_auto(ctx, input)?;
        let (p, a) = write_doc(ctx, "docs/СПЕЦИФИКАЦИЯ.md", "spec", SPEC_SCAFFOLD, &auto)?;
        Ok(out_with(p, a, "generate/spec"))
    }
}

// ───────────────────────── generate/architecture (arc42) ─────────────────────────

const ARCH_SCAFFOLD: &str = "# Архитектура\n\n\
> Структура по arc42. Разделы ниже заполняет человек; разделы «из кода» ailc \
поддерживает автоматически.\n\n\
## 1. Введение и цели\n_Главная задача системы и качественные цели — заполни._\n\n\
## 2. Ограничения\n_Технологические и организационные ограничения — заполни._\n\n\
## 4. Стратегия решения\n_Ключевые архитектурные решения и их обоснование — заполни \
(или веди ADR в .ailc/decisions)._\n";

/// Грубое определение стека по манифестам сборки в корне.
/// Стек проекта для раздела «Развёртывание». Единый источник распознавания —
/// `ailc_core::stack` (общий с планировщиком), покрывает все 15 языков.
fn detect_stack(ctx: &Ctx) -> String {
    let found = ailc_core::stack::detect(&ctx.root);
    if found.is_empty() {
        "стек не распознан".to_string()
    } else {
        found.join(", ")
    }
}

pub(crate) fn build_arch_auto(ctx: &Ctx, input: &RunInput) -> Result<String> {
    let stats = CodeIntelEngine::module_stats(ctx, input)?;
    let graph = CodeIntelEngine::dependency_graph(ctx, input)?;
    let pmap = CodeIntelEngine::project_map(ctx, input)?;
    let s = surface::extract(ctx, input)?;
    let cycles = graph.cycles();
    let adr_n = fs::read_dir(ctx.root.join(".ailc/decisions"))
        .map(|d| d.flatten().count())
        .unwrap_or(0);

    let mut d = String::from("## Из кода (обновляется автоматически)\n\n");
    d.push_str("### 3. Контекст\n");
    d.push_str(&format!("Внешние сервисы:\n{}\n\n", fmt_list(&s.services, 20)));
    d.push_str(&format!("Переменные окружения:\n{}\n\n", fmt_list(&s.env, 30)));
    d.push_str("### 5. Строительные блоки\n");
    if stats.is_empty() {
        d.push_str("— модули не распознаны —\n");
    } else {
        for (name, st) in &stats {
            d.push_str(&format!(
                "- **{name}** — {} определений ({} публичных)\n",
                st.total, st.exported
            ));
        }
    }
    let entries = if pmap.entry_points.is_empty() {
        "— не найдено —".to_string()
    } else {
        pmap.entry_points.join(", ")
    };
    d.push_str(&format!(
        "\n### 7. Развёртывание\nСтек: {}. Точки входа: {entries}.\n\n",
        detect_stack(ctx)
    ));
    d.push_str(&format!(
        "### 9. Архитектурные решения\nADR в .ailc/decisions: {adr_n}. {}\n\n",
        if adr_n == 0 {
            "Фиксируй решения: `ailc cap generate/adr <путь> \"заголовок\"`."
        } else {
            "См. .ailc/decisions/."
        }
    ));
    d.push_str("### 10–11. Качество и риски\n");
    if cycles.is_empty() {
        d.push_str("Циклов зависимостей между модулями нет.\n");
    } else {
        d.push_str("Циклические зависимости (распутать):\n");
        for c in &cycles {
            d.push_str(&format!("- {}\n", c.join(" → ")));
        }
    }
    d.push_str("Полный вердикт качества/безопасности: `ailc <путь> \"проверь перед сдачей\"`.\n\n");
    d.push_str("### 12. Глоссарий\nСм. docs/ГЛОССАРИЙ.md\n");
    Ok(d.trim_end().to_string())
}

pub struct GenerateArchitecture {
    manifest: CapabilityManifest,
}
impl Default for GenerateArchitecture {
    fn default() -> Self {
        Self::new()
    }
}
impl GenerateArchitecture {
    pub fn new() -> Self {
        Self {
            manifest: gen_manifest(
                "generate/architecture",
                EngineKind::Generator,
                "Собрать описание архитектуры из кода (по arc42): контекст, строительные блоки, развёртывание, решения, риски, глоссарий. Идемпотентно.",
            ),
        }
    }
}
impl Capability for GenerateArchitecture {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let auto = build_arch_auto(ctx, input)?;
        let (p, a) = write_doc(ctx, "docs/АРХИТЕКТУРА.md", "arch", ARCH_SCAFFOLD, &auto)?;
        Ok(out_with(p, a, "generate/architecture"))
    }
}

// ───────────────────────── generate/c4 (C4 model, Mermaid) ─────────────────────────

pub(crate) fn build_c4(ctx: &Ctx, input: &RunInput) -> Result<String> {
    let stats = CodeIntelEngine::module_stats(ctx, input)?;
    let graph = CodeIntelEngine::dependency_graph(ctx, input)?;
    let cg = CodeIntelEngine::call_graph(ctx, input)?;
    let s = surface::extract(ctx, input)?;
    let name = project_name(ctx);
    let sys = mid(&name);

    // Уникальные внешние сервисы по значению.
    let mut ext_seen: BTreeSet<String> = BTreeSet::new();
    let ext: Vec<&surface::SurfaceItem> = s
        .services
        .iter()
        .filter(|it| ext_seen.insert(it.value.clone()))
        .take(8)
        .collect();

    let mut d = String::from("## C4-модель (из кода — обновляется автоматически)\n\n");

    // Уровень 1 — Контекст.
    d.push_str("### Уровень 1 — Контекст\n```mermaid\nflowchart TD\n");
    d.push_str("  user([\"Пользователь\"])\n");
    d.push_str(&format!("  {sys}[\"{}\"]\n", lbl(&name)));
    d.push_str(&format!("  user --> {sys}\n"));
    for (i, e) in ext.iter().enumerate() {
        let id = format!("ext{i}");
        d.push_str(&format!("  {sys} --> {id}[(\"{}\")]\n", lbl(&e.value)));
    }
    if ext.is_empty() {
        d.push_str("  %% внешние сервисы из кода не обнаружены\n");
    }
    d.push_str("```\n\n");

    // Уровень 2 — Контейнеры (модули верхнего уровня).
    d.push_str("### Уровень 2 — Контейнеры\n```mermaid\nflowchart TD\n");
    let mods: Vec<(&String, u32)> = {
        let mut v: Vec<(&String, u32)> = stats.iter().map(|(k, st)| (k, st.total)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0))); // tie-break по имени → стабильно
        v.into_iter().take(12).collect()
    };
    for (m, total) in &mods {
        d.push_str(&format!("  {}[\"{}<br/>{} опр.\"]\n", mid(m), lbl(m), total));
    }
    for (from, to) in graph.edges.iter().take(30) {
        if mods.iter().any(|(m, _)| *m == from) && mods.iter().any(|(m, _)| *m == to) {
            d.push_str(&format!("  {} --> {}\n", mid(from), mid(to)));
        }
    }
    if mods.is_empty() {
        d.push_str("  %% модули не распознаны\n");
    }
    d.push_str("```\n\n");

    // Уровень 3 — Компоненты (топ рёбер графа вызовов).
    d.push_str("### Уровень 3 — Компоненты (вызовы)\n```mermaid\nflowchart LR\n");
    let mut comp = 0usize;
    for (from, to) in cg.edges.iter() {
        if comp >= 18 {
            break;
        }
        d.push_str(&format!("  {}[\"{}\"] --> {}[\"{}\"]\n", mid(from), lbl(from), mid(to), lbl(to)));
        comp += 1;
    }
    if comp == 0 {
        d.push_str("  %% граф вызовов пуст (нет AST-разбираемых исходников)\n");
    }
    d.push_str("```\n");
    Ok(d.trim_end().to_string())
}

pub struct GenerateC4 {
    manifest: CapabilityManifest,
}
impl Default for GenerateC4 {
    fn default() -> Self {
        Self::new()
    }
}
impl GenerateC4 {
    pub fn new() -> Self {
        Self {
            manifest: gen_manifest(
                "generate/c4",
                EngineKind::Diagram,
                "Построить C4-диаграммы из кода (Контекст/Контейнеры/Компоненты, Mermaid) — наглядная архитектура. Идемпотентно.",
            ),
        }
    }
}
impl Capability for GenerateC4 {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let auto = build_c4(ctx, input)?;
        let (p, a) = Generator::write_block(ctx, "docs/C4.md", "c4", &auto)?;
        Ok(out_with(p, a, "generate/c4"))
    }
}

// ───────────────────────── generate/data-model ─────────────────────────

pub(crate) fn build_data_model_auto(ctx: &Ctx, input: &RunInput) -> Result<String> {
    let s = surface::extract(ctx, input)?;
    let mut d = String::from("## Сущности (из кода — обновляется автоматически)\n\n");
    if s.models.is_empty() {
        d.push_str("— модели данных в коде не обнаружены (опиши вручную ниже) —\n");
    } else {
        for it in &s.models {
            d.push_str(&format!("- **{}** — {}:{}\n", it.value, it.file, it.line));
        }
    }
    Ok(d.trim_end().to_string())
}

pub struct GenerateDataModel {
    manifest: CapabilityManifest,
}
impl Default for GenerateDataModel {
    fn default() -> Self {
        Self::new()
    }
}
impl GenerateDataModel {
    pub fn new() -> Self {
        Self {
            manifest: gen_manifest(
                "generate/data-model",
                EngineKind::Generator,
                "Собрать модель данных из кода (ORM-модели, Prisma, SQL CREATE TABLE). Идемпотентно.",
            ),
        }
    }
}
impl Capability for GenerateDataModel {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let d = build_data_model_auto(ctx, input)?;
        let scaffold = "# Модель данных\n\n> Сущности «из кода» ailc поддерживает сам. \
Связи и описания полей заполняй ниже.\n\n## Связи и пояснения\n_Заполни._\n";
        let (p, a) = write_doc(ctx, "docs/МОДЕЛЬ-ДАННЫХ.md", "data-model", scaffold, &d)?;
        Ok(out_with(p, a, "generate/data-model"))
    }
}

// ───────────────────────── generate/glossary (arc42 §12) ─────────────────────────

pub(crate) fn build_glossary_auto(ctx: &Ctx, input: &RunInput) -> Result<String> {
    let syms = CodeIntelEngine::symbols(ctx, input)?;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut terms: Vec<&ailc_contracts::Symbol> = syms
        .iter()
        .filter(|s| {
            s.exported
                && matches!(
                    s.kind,
                    SymbolKind::Type
                        | SymbolKind::Class
                        | SymbolKind::Interface
                        | SymbolKind::Enum
                        | SymbolKind::Trait
                )
                && s.name.chars().count() >= 3
                && seen.insert(s.name.clone())
        })
        .collect();
    terms.sort_by(|a, b| a.name.cmp(&b.name));
    let mut d = String::from("## Термины (из кода — обновляется автоматически)\n\n");
    if terms.is_empty() {
        d.push_str("— публичных типов не обнаружено —\n");
    } else {
        d.push_str("| Термин | Где определён |\n|---|---|\n");
        for s in terms.iter().take(60) {
            d.push_str(&format!("| `{}` | {}:{} |\n", s.name, s.file, s.line));
        }
    }
    Ok(d.trim_end().to_string())
}

pub struct GenerateGlossary {
    manifest: CapabilityManifest,
}
impl Default for GenerateGlossary {
    fn default() -> Self {
        Self::new()
    }
}
impl GenerateGlossary {
    pub fn new() -> Self {
        Self {
            manifest: gen_manifest(
                "generate/glossary",
                EngineKind::Generator,
                "Собрать глоссарий из кода: публичные типы/классы/интерфейсы как термины предметной области. Идемпотентно.",
            ),
        }
    }
}
impl Capability for GenerateGlossary {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let d = build_glossary_auto(ctx, input)?;
        let scaffold = "# Глоссарий\n\n> Термины «из кода» ailc поддерживает сам. \
Определения на человеческом языке заполняй ниже.\n\n## Определения\n_Опиши ключевые термины._\n";
        let (p, a) = write_doc(ctx, "docs/ГЛОССАРИЙ.md", "glossary", scaffold, &d)?;
        Ok(out_with(p, a, "generate/glossary"))
    }
}

/// Декларация генерируемого документа: путь, ключ авто-блока, человеко-название и
/// функция его авто-содержимого. Единый источник истины для генераторов и детектора
/// дрейфа — `spec.check/drift` сверяет авто-блок документа с результатом `build`.
pub(crate) struct DocSpec {
    pub rel: &'static str,
    pub key: &'static str,
    pub title: &'static str,
    pub build: fn(&Ctx, &RunInput) -> Result<String>,
}

pub(crate) fn doc_specs() -> Vec<DocSpec> {
    vec![
        DocSpec { rel: "docs/СПЕЦИФИКАЦИЯ.md", key: "spec", title: "спецификация", build: build_spec_auto },
        DocSpec { rel: "docs/АРХИТЕКТУРА.md", key: "arch", title: "архитектура", build: build_arch_auto },
        DocSpec { rel: "docs/C4.md", key: "c4", title: "C4-диаграммы", build: build_c4 },
        DocSpec { rel: "docs/МОДЕЛЬ-ДАННЫХ.md", key: "data-model", title: "модель данных", build: build_data_model_auto },
        DocSpec { rel: "docs/ГЛОССАРИЙ.md", key: "glossary", title: "глоссарий", build: build_glossary_auto },
    ]
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(GenerateSpec::new()));
    reg.register(Box::new(GenerateArchitecture::new()));
    reg.register(Box::new(GenerateC4::new()));
    reg.register(Box::new(GenerateDataModel::new()));
    reg.register(Box::new(GenerateGlossary::new()));
}
