//! Генераторы, работающие по принципу авто-блока: модель проекта, модель данных,
//! глоссарий.
//!
//! ПРИНЦИП «всё как код»: выводимые из кода разделы живут в авто-блоке
//! `<!-- ailc:auto -->`, который движок генерации актуализирует идемпотентно, а
//! человеческие приписки снаружи блока переживают регенерацию.
//!
//! ЧТО ОТСЮДА УШЛО И ПОЧЕМУ. Прежние генераторы спецификации, описания архитектуры и
//! диаграмм C4 выводили документ из кода лишь наполовину: человеческие разделы
//! скаффолдились заглушками вида «заполни», полнота по стандарту не измерялась, а один и
//! тот же ответ приходилось дублировать в каждом документе. Их заменил выпуск документа
//! ЦЕЛИКОМ по декларации стандарта (`generate/doc`), где содержание раздела берётся из
//! модели проекта либо из реестра ответов, полученных опросом, а соответствие составу
//! разделов вычисляется детерминированно. Смена публичного состава возможностей записана
//! архитектурным решением в журнале решений.
//!
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

/// Символ принадлежит продукту, а не его тестам.
fn is_product_symbol(s: &ailc_contracts::Symbol) -> bool {
    !ailc_core::engines::walk::is_test_path(&s.file)
        && !ailc_core::engines::walk::is_test_dir_path(&s.file)
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

fn out_with(path: String, action: WriteAction, id: &str) -> CapabilityOutput {
    let mut out = CapabilityOutput::default();
    out.artifacts.push(path.clone());
    out.summary = format!("{id}: {path} ({action})");
    out
}

// ───────────────────────── generate/model (модель проекта) ─────────────────────────

pub struct GenerateModel {
    manifest: CapabilityManifest,
}
impl Default for GenerateModel {
    fn default() -> Self {
        Self::new()
    }
}
impl GenerateModel {
    pub fn new() -> Self {
        Self {
            manifest: gen_manifest(
                "generate/model",
                EngineKind::Generator,
                "Собрать модель проекта: единый машинный свод фактов о системе (состав, поверхность, зависимости, развёртывание) с происхождением каждого факта. Источник для всех документов комплекта.",
            ),
        }
    }
}
impl Capability for GenerateModel {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let m = ailc_core::model::build(ctx, input)?;
        let (model_path, schema_path) = ailc_core::model::write(ctx, &m)?;
        let mut out = CapabilityOutput::default();
        out.artifacts.push(model_path.clone());
        out.artifacts.push(schema_path);
        out.metrics
            .push(("model_modules".into(), m.structure.modules.len() as f64));
        out.metrics.push(("model_gaps".into(), m.gaps.len() as f64));
        // Пробел это сведение об отсутствии, а не ошибка: он честно виден в записях и
        // становится записью об отсутствии в соответствующем разделе документа.
        for g in &m.gaps {
            out.records
                .push(format!("не установлено: {} ({})", g.what, g.why));
        }
        out.summary = format!(
            "generate/model: {model_path} (модулей {}, зависимостей {}, не установлено {})",
            m.structure.modules.len(),
            m.dependencies.len(),
            m.gaps.len()
        );
        Ok(out)
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
                && is_product_symbol(s)
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
    // Перечень намеренно сузился до документов, у которых ещё нет декларации стандарта.
    // Спецификация, описание архитектуры и диаграммы C4 выпускаются теперь целиком по
    // декларациям (`generate/doc`), и сверка их авто-блоков стала бессмысленной: у
    // документа, принадлежащего машине полностью, авто-блока нет, а есть весь файл.
    // Свежесть таких документов проверяет тот же `spec.check/drift`, пересобирая их и
    // сравнивая с тем, что лежит на диске.
    vec![
        DocSpec {
            rel: "docs/МОДЕЛЬ-ДАННЫХ.md",
            key: "data-model",
            title: "модель данных",
            build: build_data_model_auto,
        },
        DocSpec {
            rel: "docs/ГЛОССАРИЙ.md",
            key: "glossary",
            title: "глоссарий",
            build: build_glossary_auto,
        },
    ]
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(GenerateModel::new()));
    reg.register(Box::new(GenerateDataModel::new()));
    reg.register(Box::new(GenerateGlossary::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> Ctx {
        let root = std::env::temp_dir().join(format!(
            "ailc-specgen-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "pub fn прикладная_функция() {}\npub struct Заказ;\n",
        )
        .unwrap();
        fs::write(
            root.join("tests/проверки.rs"),
            "pub fn вспомогательная_для_теста() {}\npub struct Фикстура;\n",
        )
        .unwrap();
        Ctx::new(root.to_str().unwrap())
    }

    /// Глоссарий описывает предметную область продукта, а не его тесты, поэтому вместе
    /// с составом системы проверяется и он: прежняя проверка состава системы переехала в
    /// сборщик документов по декларациям, где состав системы теперь и формируется.
    /// Глоссарий это термины предметной области продукта, а не имена тестовых фикстур.
    #[test]
    fn глоссарий_не_содержит_тестовых_типов() {
        let ctx = tmp("глоссарий");
        let doc = build_glossary_auto(&ctx, &RunInput::default()).unwrap();
        assert!(
            doc.contains("Заказ"),
            "публичный тип продукта обязан быть термином:\n{doc}"
        );
        assert!(
            !doc.contains("Фикстура"),
            "тип из тестов термином предметной области не является:\n{doc}"
        );
        let _ = fs::remove_dir_all(&ctx.root);
    }
}
