//! E0 Index — статические эмбеддинги (model2vec) для семантического роутера.
//!
//! Модель ВШИТА в бинарь через include_bytes → один файл, офлайн, CPU, микросекунды
//! (статические эмбеддинги = таблица + пулинг, без инференса трансформера).
//! Мультиязычная (дистилляция из paraphrase-multilingual-MiniLM, int8, 128-мерная) —
//! понимает русский и английский. Если модель не загрузилась — `available()` = false,
//! и роутер откатывается на ключевые слова.

use model2vec_rs::model::StaticModel;
use std::sync::OnceLock;

static TOKENIZER: &[u8] = include_bytes!("../../assets/embed/tokenizer.json");
static WEIGHTS: &[u8] = include_bytes!("../../assets/embed/model.safetensors");
static CONFIG: &[u8] = include_bytes!("../../assets/embed/config.json");

fn model() -> Option<&'static StaticModel> {
    static M: OnceLock<Option<StaticModel>> = OnceLock::new();
    M.get_or_init(|| StaticModel::from_bytes(TOKENIZER, WEIGHTS, CONFIG, None).ok())
        .as_ref()
}

pub struct Index;

impl Index {
    /// Загрузилась ли встроенная модель.
    pub fn available() -> bool {
        model().is_some()
    }

    /// Закодировать тексты в векторы (None — модель недоступна).
    pub fn embed(texts: &[String]) -> Option<Vec<Vec<f32>>> {
        Some(model()?.encode(texts))
    }

    /// Ранжировать items (id, текст) по близости к query.
    /// Возвращает (id, оценка) по убыванию — порог/обрезку решает вызывающий.
    pub fn rank(query: &str, items: &[(String, String)]) -> Option<Vec<(String, f32)>> {
        let m = model()?;
        let mut texts: Vec<String> = Vec::with_capacity(items.len() + 1);
        texts.push(query.to_string());
        for (_, t) in items {
            texts.push(t.clone());
        }
        let emb = m.encode(&texts);
        if emb.len() != items.len() + 1 {
            return None;
        }
        let q = &emb[0];
        let mut scored: Vec<(String, f32)> = items
            .iter()
            .enumerate()
            .map(|(i, (id, _))| (id.clone(), cosine(q, &emb[i + 1])))
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        Some(scored)
    }
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for i in 0..n {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
    }
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    dot / (na.sqrt() * nb.sqrt())
}
