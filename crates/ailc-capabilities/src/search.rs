//! `code.intel/search` — поиск по проекту детерминированным лексическим индексом.
//!
//! Место движка индексации в перечне девяти движков оставалось незанятым после удаления
//! встроенной модели эмбеддингов: перечень обещал возможность, которой не было. Здесь оно
//! занято честно, то есть обратным индексом термов с оценкой релевантности по классической
//! формуле, без нейросети и без обращений в сеть. Выдача воспроизводима: одинаковый запрос
//! на неизменном дереве всегда даёт один и тот же порядок.
//!
//! Отличие от `code.intel/find_usages`: тот ищет ВХОЖДЕНИЯ конкретного символа как
//! идентификатора, а этот отвечает на вопрос «где про это написано», разбирая составные
//! имена на составляющие и учитывая документацию наравне с кодом.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Tier,
};
use ailc_core::engines::index::IndexEngine;
use ailc_core::registry::Registry;
use ailc_core::Capability;

/// Сколько мест показывать. Больше человеку не нужно, а модели агента длинная выдача
/// только засоряет контекст.
const LIMIT: usize = 12;

pub struct Search {
    manifest: CapabilityManifest,
}

impl Default for Search {
    fn default() -> Self {
        Self::new()
    }
}

impl Search {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "code.intel/search",
                family: Family::CodeIntel,
                engine: EngineKind::Index,
                when_to_use: "Найти, где в проекте написано про запрошенное: поиск по коду и документации лексическим индексом с оценкой релевантности. Запрос словами в query.",
                input_schema: r#"{"type":"object","properties":{"query":{"type":"string","description":"что искать, словами"},"target":{"type":"string"}},"required":["query"]}"#,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for Search {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let Some(query) = input.query.as_deref().filter(|q| !q.trim().is_empty()) else {
            out.skipped = Some("нужен запрос в query".into());
            out.summary = "code.intel/search: пропущено (пустой запрос)".into();
            return Ok(out);
        };

        let idx = IndexEngine::build(ctx, input)?;
        let hits = idx.search(query, LIMIT);

        out.metrics
            .push(("index_documents".into(), idx.documents() as f64));
        out.metrics.push(("index_terms".into(), idx.terms() as f64));
        out.metrics.push(("search_hits".into(), hits.len() as f64));

        if hits.is_empty() {
            out.summary = format!(
                "code.intel/search: по запросу «{query}» ничего не найдено (документов в индексе {})",
                idx.documents()
            );
            return Ok(out);
        }
        for h in &hits {
            out.records.push(format!(
                "{} (оценка {:.2}, совпало: {})",
                h.file,
                h.score,
                h.matched.join(", ")
            ));
        }
        // Усечение охвата не замалчивается: файл, у которого в индекс попала лишь часть
        // терминов, мог не найтись именно поэтому.
        let truncated = idx.truncated_files();
        if !truncated.is_empty() {
            out.records.push(format!(
                "охват неполон: у {} файлов в индекс попала лишь часть терминов",
                truncated.len()
            ));
        }
        out.summary = format!(
            "code.intel/search: по запросу «{query}» найдено мест {} (документов в индексе {}, терминов {})",
            hits.len(),
            idx.documents(),
            idx.terms()
        );
        Ok(out)
    }
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(Search::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Поиск находит место по слову из составного имени и честно сообщает, что именно
    /// совпало: без этого человек не может проверить, почему выдача такая.
    #[test]
    fn поиск_находит_место_по_составному_имени() {
        let root = std::env::temp_dir().join(format!(
            "ailc-search-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/оплата.rs"),
            "pub fn chargeUserAccount() {}\n",
        )
        .unwrap();
        std::fs::write(root.join("src/прочее.rs"), "pub fn nothing() {}\n").unwrap();
        let ctx = Ctx::new(root.to_str().unwrap());

        let out = Search::new()
            .run(
                &ctx,
                &RunInput {
                    query: Some("account".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(
            out.records.iter().any(|r| r.contains("оплата.rs")),
            "искомое место обязано найтись: {:?}",
            out.records
        );
        assert!(
            out.records
                .iter()
                .any(|r| r.contains("совпало") && r.contains("account")),
            "выдача обязана сообщать, что именно совпало: {:?}",
            out.records
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Пустой запрос это осознанный пропуск, а не выдача всего подряд.
    #[test]
    fn пустой_запрос_это_пропуск() {
        let ctx = Ctx::new(".");
        let out = Search::new().run(&ctx, &RunInput::default()).unwrap();
        assert!(out.skipped.is_some());
    }
}
