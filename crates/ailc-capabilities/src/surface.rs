//! `code.intel/surface` — поверхность проекта из кода (Фаза 2): эндпоинты, окружение,
//! внешние сервисы, модели данных. Тонкая обёртка над движком `engines::surface`.
//! Это ФАКТЫ (records), не находки — основа для спеки и C4-Context (Фаза 3).

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Tier,
};
use ailc_core::engines::surface;
use ailc_core::registry::Registry;
use ailc_core::Capability;

const TARGET_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;

pub struct SurfaceCap {
    manifest: CapabilityManifest,
}

impl Default for SurfaceCap {
    fn default() -> Self {
        Self::new()
    }
}

impl SurfaceCap {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "code.intel/surface",
                family: Family::CodeIntel,
                engine: EngineKind::CodeIntel,
                when_to_use: "Извлечь из кода поверхность продукта: HTTP-эндпоинты, переменные окружения, внешние сервисы (БД/очереди/хранилища), модели данных — основа спеки и C4.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for SurfaceCap {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let s = surface::extract(ctx, input)?;
        let mut out = CapabilityOutput::default();

        if s.is_empty() {
            out.skipped = Some("в коде не найдено эндпоинтов/ENV/сервисов/моделей".into());
            out.summary = "code.intel/surface: поверхность не обнаружена".into();
            return Ok(out);
        }

        out.metrics.push(("routes".into(), s.routes.len() as f64));
        out.metrics.push(("env_vars".into(), s.env.len() as f64));
        out.metrics.push(("services".into(), s.services.len() as f64));
        out.metrics.push(("data_models".into(), s.models.len() as f64));

        let mut section = |title: &str, items: &[surface::SurfaceItem]| {
            if items.is_empty() {
                return;
            }
            out.records.push(format!("— {title} —"));
            for it in items.iter().take(60) {
                out.records.push(format!("{}  ({}:{})", it.value, it.file, it.line));
            }
            if items.len() > 60 {
                out.records.push(format!("… ещё {}", items.len() - 60));
            }
        };
        section("эндпоинты", &s.routes);
        section("переменные окружения", &s.env);
        section("внешние сервисы", &s.services);
        section("модели данных", &s.models);

        out.summary = format!(
            "code.intel/surface: эндпоинтов {}, ENV {}, сервисов {}, моделей {}",
            s.routes.len(),
            s.env.len(),
            s.services.len(),
            s.models.len()
        );
        Ok(out)
    }
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(SurfaceCap::new()));
}
