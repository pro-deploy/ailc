//! Supply-chain из ailc, офлайн: SBOM (`generate/sbom`) и лицензии зависимостей
//! (`security.scan/licenses`). Переиспользуют разбор lock-файлов движка OSV
//! (`osv::packages`) — единый источник списка зависимостей.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Finding, Result, RunInput,
    Severity, Tier,
};
use ailc_core::engines::osv;
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::collections::BTreeMap;
use std::fs;

const TARGET_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;

/// Экосистема OSV → тип в package-URL (purl).
fn purl_type(eco: &str) -> &'static str {
    match eco {
        "PyPI" => "pypi",
        "crates.io" => "cargo",
        "npm" => "npm",
        "Go" => "golang",
        "Maven" => "maven",
        "Pub" => "pub",
        "CocoaPods" => "cocoapods",
        _ => "generic",
    }
}

fn jesc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ───────────────────────── generate/sbom (CycloneDX) ─────────────────────────

pub struct GenerateSbom {
    manifest: CapabilityManifest,
}
impl Default for GenerateSbom {
    fn default() -> Self {
        Self::new()
    }
}
impl GenerateSbom {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "generate/sbom",
                family: Family::Generate,
                engine: EngineKind::Generator,
                when_to_use: "Сгенерировать SBOM (CycloneDX) из lock-файлов проекта — состав зависимостей для CI/supply-chain.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: true,
            },
        }
    }
}
impl Capability for GenerateSbom {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let (pkgs, _manifests) = osv::packages(&ctx.root);
        let mut out = CapabilityOutput::default();
        if pkgs.is_empty() {
            out.skipped = Some("lock-файлов не найдено — состав зависимостей неизвестен".into());
            out.summary = "generate/sbom: нет зависимостей".into();
            return Ok(out);
        }
        let components: Vec<String> = pkgs
            .iter()
            .map(|(eco, name, ver)| {
                format!(
                    "    {{\"type\":\"library\",\"name\":\"{}\",\"version\":\"{}\",\"purl\":\"pkg:{}/{}@{}\"}}",
                    jesc(name), jesc(ver), purl_type(eco), jesc(name), jesc(ver)
                )
            })
            .collect();
        let json = format!(
            "{{\n  \"bomFormat\": \"CycloneDX\",\n  \"specVersion\": \"1.5\",\n  \"version\": 1,\n  \"components\": [\n{}\n  ]\n}}\n",
            components.join(",\n")
        );
        fs::write(ctx.root.join("sbom.json"), &json)?;
        out.artifacts.push("sbom.json".into());
        out.metrics.push(("components".into(), pkgs.len() as f64));
        out.summary = format!("generate/sbom: sbom.json ({} компонент)", pkgs.len());
        Ok(out)
    }
}

// ───────────────────────── security.scan/licenses ─────────────────────────

/// Класс лицензии: копилефт сильный/слабый/неизвестна → severity.
fn license_risk(lic: &str) -> Option<(Severity, &'static str)> {
    let u = lic.to_uppercase();
    if u.contains("AGPL") {
        Some((Severity::High, "AGPL — сильный сетевой копилефт"))
    } else if u.contains("GPL") && !u.contains("LGPL") {
        Some((Severity::Medium, "GPL — копилефт (вирусная лицензия)"))
    } else if u.contains("LGPL") {
        Some((Severity::Low, "LGPL — слабый копилефт"))
    } else {
        None
    }
}

pub struct LicenseCheck {
    manifest: CapabilityManifest,
}
impl Default for LicenseCheck {
    fn default() -> Self {
        Self::new()
    }
}
impl LicenseCheck {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "security.scan/licenses",
                family: Family::Security,
                engine: EngineKind::Scan,
                when_to_use: "Проверить лицензии зависимостей: копилефт (GPL/AGPL/LGPL) в проприетарном проекте, неуказанные лицензии. Офлайн из package-lock.json.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}
impl Capability for LicenseCheck {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let lock = ctx.root.join("package-lock.json");
        let txt = match fs::read_to_string(&lock) {
            Ok(t) => t,
            Err(_) => {
                // Лицензии надёжно офлайн есть только в npm-lock; для прочих экосистем нужен
                // отдельный инструмент (cargo metadata / pip-licenses) — честный skip.
                let (_pkgs, manifests) = osv::packages(&ctx.root);
                out.skipped = Some(if manifests.is_empty() {
                    "нет lock-файлов".into()
                } else {
                    "лицензии не в lock-файле (для не-npm нужен cargo-license/pip-licenses)".into()
                });
                out.summary = "security.scan/licenses: пропущено".into();
                return Ok(out);
            }
        };

        let val: serde_json::Value = match serde_json::from_str(&txt) {
            Ok(v) => v,
            Err(_) => {
                out.skipped = Some("package-lock.json нечитаем (битый JSON)".into());
                out.summary = "security.scan/licenses: пропущено (битый lock)".into();
                return Ok(out);
            }
        };

        let mut by_license: BTreeMap<String, usize> = BTreeMap::new();
        let mut checked = 0usize;
        if let Some(pkgs) = val.get("packages").and_then(|v| v.as_object()) {
            for (path, meta) in pkgs {
                if path.is_empty() {
                    continue; // корневой пакет — не зависимость
                }
                let name = path.rsplit("node_modules/").next().unwrap_or(path);
                let lic = meta
                    .get("license")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .or_else(|| {
                        meta.get("licenses")
                            .and_then(|v| v.as_array())
                            .and_then(|a| a.first())
                            .and_then(|x| x.get("type").and_then(|t| t.as_str()))
                            .map(str::to_string)
                    });
                checked += 1;
                let lic = lic.unwrap_or_else(|| "UNKNOWN".to_string());
                *by_license.entry(lic.clone()).or_default() += 1;
                if let Some((sev, why)) = license_risk(&lic) {
                    out.findings.push(Finding {
                        rule: "copyleft-license".into(),
                        severity: sev,
                        message: format!("Зависимость `{name}` под {lic}: {why} — проверь совместимость с лицензией проекта"),
                        location: None,
                        evidence: None,
                        verified: true,
                        source: "security.scan/licenses".into(),
                    });
                }
            }
        }

        if checked == 0 {
            out.skipped = Some("в package-lock.json нет пакетов с лицензиями".into());
            out.summary = "security.scan/licenses: лицензий не найдено".into();
            return Ok(out);
        }
        for (lic, n) in &by_license {
            out.records.push(format!("{lic}: {n}"));
        }
        out.metrics.push(("deps_checked".into(), checked as f64));
        out.summary = format!(
            "security.scan/licenses: {checked} зависимостей, копилефт-находок {}",
            out.findings.len()
        );
        Ok(out)
    }
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(GenerateSbom::new()));
    reg.register(Box::new(LicenseCheck::new()));
}
