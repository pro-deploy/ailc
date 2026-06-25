//! Режим проектирования новой фичи (Фаза 5) — `spec/feature`.
//!
//! Вайбкодер говорит «хочу X» — ailc выдаёт ЗАГОТОВКУ «как в ИТ принято»: спека фичи
//! (зачем / что / критерии приёмки / затрагиваемые части / НФТ / риски) + связанный
//! ADR (Nygard: Контекст/Решение/Последствия). Структуру и карту кода даёт ailc
//! (детерминированная гарантия), прозу заполняет человек/ИИ. Создаётся ОДИН раз —
//! повторный вызов не плодит дубли (и не создаёт лишний ADR).
//!
//! Перекрёстная ссылка. Этот модуль только проектирует фичу как документ и НЕ
//! проводит аудит интерфейса. Детерминированные эвристики доступности и адаптивной
//! разметки (изображение без текстовой альтернативы, поле ввода без подписи,
//! заблокированное масштабирование, отсутствие тёмной темы и видимого фокуса, мелкие
//! цели нажатия, нативная доступность Android/iOS/Flutter) вынесены в отдельную
//! capability семейства Quality, см. модуль `ui_ux` (идентификаторы quality.ui/*).

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Tier,
};
use ailc_core::engines::codeintel::CodeIntelEngine;
use ailc_core::engines::store::Store;
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::fs;

const QUERY_SCHEMA: &str = r#"{"type":"object","properties":{"query":{"type":"string"},"target":{"type":"string"}},"required":["query"]}"#;

/// Слаг имени файла: нижний регистр, юникод-буквы/цифры как есть (кириллица допустима
/// в имени файла), прочее → один «-». Пусто → «фича».
fn slug(s: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for ch in s.chars() {
        let l = ch.to_lowercase().next().unwrap_or(ch);
        if l.is_alphanumeric() {
            out.push(l);
            dash = false;
        } else if !out.is_empty() && !dash {
            out.push('-');
            dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "фича".to_string()
    } else {
        trimmed.chars().take(60).collect()
    }
}

pub struct FeatureSpec {
    manifest: CapabilityManifest,
}

impl Default for FeatureSpec {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureSpec {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "spec/feature",
                family: Family::Spec,
                engine: EngineKind::Generator,
                when_to_use: "Спроектировать новую фичу: заготовка спеки (зачем/что/критерии приёмки/затрагиваемые части) + ADR-решение. Описание фичи — в query.",
                input_schema: QUERY_SCHEMA,
                tier: Tier::Core,
                deterministic: false, // номер ADR зависит от состояния журнала решений
                mutates: true,
            },
        }
    }
}

impl Capability for FeatureSpec {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        let feature = match input.query.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
            Some(q) => q,
            None => {
                out.skipped = Some("нужно описание фичи в query".into());
                out.summary = "spec/feature: пропущено (нет описания фичи)".into();
                return Ok(out);
            }
        };

        let rel = format!("docs/фичи/{}.md", slug(feature));
        let path = ctx.root.join(&rel);
        if path.exists() {
            out.skipped = Some(format!("фича уже спроектирована: {rel}"));
            out.summary = format!("spec/feature: {rel} уже существует — не трогаю");
            return Ok(out);
        }

        // ADR (Nygard) — отдельной записью в журнал решений, со ссылкой на фичу.
        let adr_name = Store::alloc_id(ctx, "decisions", "md")?;
        let number = adr_name.split('.').next().unwrap_or(&adr_name);
        let adr = format!(
            "# ADR-{number}: {feature}\n\n- Статус: предложено\n\n\
## Контекст\n_Силы и обстоятельства: что в проекте сейчас, почему нужна фича — заполни._\n\n\
## Решение\n_Что решено сделать — заполни._\n\n\
## Последствия\n_Что станет проще/сложнее после — заполни._\n"
        );
        Store::write(ctx, "decisions", &adr_name, &adr)?;
        let adr_rel = format!(".ailc/decisions/{adr_name}");

        // Карта кода — куда встраивать (снимок на момент проектирования).
        let stats = CodeIntelEngine::module_stats(ctx, input)?;
        let mut parts = String::new();
        if stats.is_empty() {
            parts.push_str("— модули не распознаны —\n");
        } else {
            for (name, st) in &stats {
                parts.push_str(&format!(
                    "- **{name}** — {} определений ({} публичных)\n",
                    st.total, st.exported
                ));
            }
        }

        let doc = format!(
            "# Фича: {feature}\n\n\
> Заготовка проектирования (ailc). Структура «как в ИТ принято» — заполни разделы.\n\
> Архитектурное решение: {adr_rel} (ADR).\n\n\
## Зачем (проблема и цель)\n_Какую задачу пользователя решает фича — заполни._\n\n\
## Что делаем (объём работ)\n_Краткое описание решения — заполни._\n\n\
## Критерии приёмки (Definition of Done)\n- [ ] _проверяемый критерий — заполни_\n- [ ] _ещё критерий_\n\n\
## Затрагиваемые части (карта кода)\n{parts}\n\
## Нефункциональные требования\n_Производительность, безопасность, совместимость — заполни._\n\n\
## Риски и открытые вопросы\n_Что может пойти не так, что пока неясно — заполни._\n"
        );

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, doc)?;

        out.artifacts.push(rel.clone());
        out.artifacts.push(adr_rel.clone());
        out.summary = format!("spec/feature: заготовка {rel} + {adr_rel}");
        Ok(out)
    }
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(FeatureSpec::new()));
}
