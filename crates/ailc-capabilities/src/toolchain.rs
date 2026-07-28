//! `verify/toolchain` — паспорт средств разработки, которыми выполняется прогон.
//!
//! Прогон, о котором неизвестно, какой версией инструмента он выполнен, невоспроизводим,
//! а невоспроизводимый прогон доказательством не является. Раздел о средствах разработки
//! в документах по стандартам требует того же: перечень применяемых средств без версий
//! бесполезен.
//!
//! Версии намеренно НЕ попадают в модель проекта и в документы: они различаются от машины
//! к машине, и документ, зависящий от них, расходился бы сам собой при переносе проекта на
//! другую машину. В документы идут версии, ЗАФИКСИРОВАННЫЕ в самом проекте
//! (`rust-toolchain.toml`, `.nvmrc` и подобные), поскольку они являются его свойством, а
//! не свойством чужого рабочего места.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Tier,
};
use ailc_core::engines::runner::Runner;
use ailc_core::registry::Registry;
use ailc_core::Capability;

/// Инструменты, уместные для стека. Спрашивать версию у всего, что бывает на свете,
/// незачем: это десятки запусков процессов на каждый прогон.
fn tools_for(stacks: &[&'static str]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = vec!["git"];
    for s in stacks {
        let low = s.to_ascii_lowercase();
        let add: &[&str] = if low.contains("rust") {
            &["cargo", "rustc"]
        } else if low.contains("node") || low.contains("ts") || low.contains("js") {
            &["node", "npm"]
        } else if low.contains("python") {
            &["python3"]
        } else if low.contains("go") {
            &["go"]
        } else if low.contains("java") || low.contains("maven") {
            &["java", "mvn"]
        } else if low.contains("gradle") || low.contains("kotlin") {
            &["gradle"]
        } else if low.contains("swift") {
            &["swift"]
        } else if low.contains("ruby") {
            &["ruby"]
        } else if low.contains("php") {
            &["php"]
        } else if low.contains("dart") || low.contains("flutter") {
            &["dart"]
        } else if low.contains("scala") {
            &["sbt"]
        } else if low.contains(".net") || low.contains("c#") {
            &["dotnet"]
        } else if low.contains("c/c++") || low.contains("cmake") {
            &["cmake"]
        } else {
            &[]
        };
        for a in add {
            if !out.contains(a) {
                out.push(a);
            }
        }
    }
    out
}

pub struct ToolchainPassport {
    manifest: CapabilityManifest,
}

impl Default for ToolchainPassport {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolchainPassport {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "verify/toolchain",
                family: Family::Verify,
                engine: EngineKind::Runner,
                when_to_use: "Узнать, какими средствами разработки и какими их версиями выполняется прогон: перечень инструментов стека с путями и версиями, а также честный перечень отсутствующих.",
                input_schema: r#"{"type":"object","properties":{"target":{"type":"string"}}}"#,
                tier: Tier::Core,
                deterministic: false, // версии зависят от рабочего места, а не от проекта
                mutates: false,
            },
        }
    }
}

impl Capability for ToolchainPassport {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let stacks = ailc_core::stack::detect(&ctx.root);
        let tools = tools_for(&stacks);

        let mut найдено = 0usize;
        let mut без_версии: Vec<&str> = Vec::new();
        let mut отсутствуют: Vec<&str> = Vec::new();

        for t in &tools {
            match Runner::passport(ctx, t) {
                Some(p) => {
                    найдено += 1;
                    match &p.version {
                        Some(v) => out.records.push(format!("{}: {} ({})", p.name, v, p.path)),
                        None => {
                            без_версии.push(t);
                            out.records.push(format!(
                                "{}: версия не сообщена инструментом ({})",
                                p.name, p.path
                            ));
                        }
                    }
                }
                None => отсутствуют.push(t),
            }
        }

        // Отсутствие инструмента это не ошибка, а сведение: часть проверок будет честно
        // пропущена, и знать заранее, какая именно, полезнее, чем узнать это на сдаче.
        for t in &отсутствуют {
            out.records.push(format!(
                "{t}: не установлен, зависящие проверки будут пропущены"
            ));
        }

        out.metrics.push(("tools_found".into(), найдено as f64));
        out.metrics
            .push(("tools_missing".into(), отсутствуют.len() as f64));
        out.summary = format!(
            "verify/toolchain: стек {}, инструментов найдено {}, без версии {}, отсутствуют {}",
            if stacks.is_empty() {
                "не распознан".to_string()
            } else {
                stacks.join(", ")
            },
            найдено,
            без_версии.len(),
            отсутствуют.len()
        );
        Ok(out)
    }
}

pub fn register(reg: &mut Registry) {
    reg.register(Box::new(ToolchainPassport::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Перечень инструментов подбирается по стеку, а не спрашивается у всего, что бывает
    /// на свете: иначе каждый прогон делал бы десятки лишних запусков процессов.
    #[test]
    fn перечень_инструментов_зависит_от_стека() {
        let rust = tools_for(&["Rust"]);
        assert!(
            rust.contains(&"cargo"),
            "для Rust спрашивается cargo: {rust:?}"
        );
        assert!(
            !rust.contains(&"php"),
            "лишние инструменты не спрашиваются: {rust:?}"
        );
        let пусто = tools_for(&[]);
        assert_eq!(
            пусто,
            vec!["git"],
            "без стека остаётся только система контроля версий"
        );
    }

    /// Паспорт содержит путь, а версию только если инструмент её сообщил: выдумывать
    /// версию недопустимо, поскольку на неё ссылается документ.
    #[test]
    fn паспорт_не_выдумывает_версию() {
        let ctx = Ctx::new(".");
        // git есть практически всюду, но если его нет, проверка не о том.
        if let Some(p) = Runner::passport(&ctx, "git") {
            assert_eq!(p.name, "git");
            assert!(!p.path.trim().is_empty(), "путь инструмента обязателен");
            if let Some(v) = &p.version {
                assert!(!v.trim().is_empty(), "пустая версия версией не является");
            }
        }
        assert!(
            Runner::passport(&ctx, "инструмента-с-таким-именем-нет").is_none(),
            "отсутствующий инструмент паспорта не получает"
        );
    }
}
