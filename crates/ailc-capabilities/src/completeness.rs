//! Страж недоделанного — ловит то, что ИИ-ассистент оставил незавершённым.
//!
//! Вайбкодер не обязан знать, что важный участок остался заглушкой: за него это
//! видит ailc. Два детектора поверх готовых движков (ноль новой инфраструктуры):
//!   `quality.check/completeness` — E1 Scan: заглушки (`unimplemented!`/`TODO()`/
//!     `NotImplementedError`/…), пустые обработчики исключений, пустые функции.
//!   `quality.check/undocumented`  — E3 CodeIntel: публичное API без описания.
//!
//! ПРИНЦИП тот же, что в остальном крейте: правило = строка таблицы, а не новый код.
//! Семейство Quality → детекторы гоняются в КАЖДОМ прогоне рядом с безопасностью
//! (Quality уже в дефолтном гейте), не мутируют. Срабатывания в комментариях
//! отсеивает verify-проход оркестратора (см. verify.rs `code_presence`).

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Finding, Location, Result,
    RunInput, Severity, Symbol, SymbolKind, Tier,
};
use ailc_core::engines::codeintel::CodeIntelEngine;
use ailc_core::engines::scan::{Matcher, Rule, SOURCE_CODE};
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::collections::HashMap;
use std::fs;

use crate::{scan_manifest, ScanCapability};

const TARGET_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;

// ───────────────────────── quality.check/completeness (E1 Scan) ─────────────────────────

/// Заглушка: тело-маркер «ещё не реализовано». Без пробелов — устойчиво к форматированию.
/// Покрывает идиомы всех 15 языков движка (кроме C/C++ — у них нет стандартной идиомы).
fn is_unimplemented_stub(l: &str) -> bool {
    let c: String = l.chars().filter(|ch| !ch.is_whitespace()).collect();
    let cl = c.to_lowercase();
    // Самодостаточные идиомы-заглушки (сами по себе бросают/означают «не реализовано»).
    if c.contains("unimplemented!(")            // Rust: unimplemented!()
        || c.contains("todo!(")                 // Rust: todo!()
        || c.contains("TODO(")                  // Kotlin: TODO("…")
        || c.contains("=???")                   // Scala: def f = ???
        || cl.contains("unimplementederror(")   // Dart: throw UnimplementedError()
    {
        return true;
    }
    // Бросок/паника/раннее завершение + маркер «не реализовано/todo» в сообщении или типе.
    // Покрывает Python/Ruby (raise NotImplementedError), Java/C# (throw new
    // NotImplementedException), Go (panic("not implemented")), JS/TS/PHP
    // (throw new Error("not implemented")), Swift (fatalError("unimplemented")).
    let thrower = cl.contains("throw")
        || cl.contains("raise")
        || cl.contains("panic(")
        || cl.contains("fatalerror(")
        || cl.contains("preconditionfailure(")
        || cl.contains("abort(")      // C/C++
        || cl.contains("assert(")     // C/C++: assert(0 && "not implemented")
        || cl.contains("#error"); // C/C++ препроцессор: #error Not implemented
    let marker = cl.contains("notimplement")
        || cl.contains("unimplement")
        || cl.contains("\"todo")
        || cl.contains("'todo");
    thrower && marker
}

/// Детекторы незавершённости. Строгие формы — низкий процент ложных; в комментариях
/// их добивает verify-проход. Дополняют (не дублируют) `quality.check/smell`
/// (swallowed-error ловит безаргументный `catch{}` / `except:pass`).
pub fn completeness_scan() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "quality.check/completeness",
            Family::Quality,
            "Найти недоделанное, что ИИ мог пропустить: заглушки (unimplemented/TODO/NotImplementedError), пустые обработчики ошибок, пустые функции.",
        ),
        vec![
            Rule {
                id: "unimplemented-stub",
                severity: Severity::Medium,
                exts: SOURCE_CODE,
                matcher: Matcher::Predicate(is_unimplemented_stub),
                message: "Заглушка вместо реализации — участок не доделан",
            },
            // Пустой обработчик С параметром: `catch (e) {}` / `catch(Exception ex){ }`.
            // Безаргументный `catch{}` уже ловит smell/swallowed-error — не дублируем.
            Rule {
                id: "empty-catch",
                severity: Severity::Low,
                exts: &[
                    "java", "kt", "kts", "js", "ts", "tsx", "jsx", "mjs", "cjs", "cs", "swift",
                    "scala", "c", "cc", "cpp", "php", "dart",
                ],
                matcher: Matcher::regex(r"catch\s*\([^)]*\)\s*\{\s*\}"),
                message: "Пустой обработчик исключения — ошибка молча проглатывается",
            },
            // Ruby: инлайн `x rescue nil` молча подавляет исключение.
            Rule {
                id: "swallowed-rescue",
                severity: Severity::Low,
                exts: &["rb"],
                matcher: Matcher::regex(r"\brescue\s+nil\b"),
                message: "Проглоченная ошибка (rescue nil) — исключение молча подавляется",
            },
            // Python `except SomeError: pass` (типизированный — безтиповый ловит smell).
            Rule {
                id: "empty-except",
                severity: Severity::Low,
                exts: &["py"],
                matcher: Matcher::regex(r"except\s+[A-Za-z_][^:\n]*:\s*pass\b"),
                message: "Пустой обработчик исключения (except … : pass) — ошибка проглатывается",
            },
            // Python однострочная пустая функция `def f(...): pass` — заготовка без тела.
            Rule {
                id: "empty-function",
                severity: Severity::Low,
                exts: &["py"],
                matcher: Matcher::regex(r"^\s*def\s+\w+\s*\([^)]*\)\s*(?:->[^:]+)?:\s*pass\s*$"),
                message: "Пустая функция (тело — pass) — заготовка без реализации",
            },
        ],
    )
}

// ───────────────────────── quality.check/undocumented (E3 CodeIntel) ─────────────────────────

/// Символ, который «положено» описывать: публичный контракт, а не локальная мелочь.
fn is_doc_worthy(kind: SymbolKind) -> bool {
    matches!(
        kind,
        SymbolKind::Function
            | SymbolKind::Method
            | SymbolKind::Type
            | SymbolKind::Class
            | SymbolKind::Interface
            | SymbolKind::Trait
            | SymbolKind::Enum
    )
}

/// Тест-файл/фикстура — их публичность не значит «внешнее API», описание не требуем.
fn is_test_file(file: &str) -> bool {
    let f = file.to_lowercase();
    f.ends_with("_test.go")
        || f.contains("/test")
        || f.contains("__tests__")
        || f.contains("/tests/")
        || f.contains(".test.")
        || f.contains(".spec.")
        || f.rsplit(['/', '\\']).next().is_some_and(|n| n.starts_with("test_"))
}

/// Точка входа/служебное имя — её «вызывает» рантайм, описание необязательно.
fn is_entry_name(name: &str) -> bool {
    name == "main" || name == "init" || name.starts_with("Test") || name.starts_with("Benchmark")
}

/// Есть ли у символа в `line` (1-based) описание. Для Python — докстринг ПОСЛЕ
/// сигнатуры (внутри тела); для прочих — doc-комментарий НАД определением, через
/// возможные атрибуты/аннотации/декораторы (`#[…]`, `@…`), но НЕ через пустую строку.
fn is_documented(lines: &[String], line_1based: u32, lang: &str) -> bool {
    let idx = (line_1based as usize).saturating_sub(1);
    if idx >= lines.len() {
        return false;
    }

    if lang == "python" {
        // Докстринг — первая строка тела после `def …:` (сигнатура может занять >1 строки).
        for j in idx..(idx + 6).min(lines.len()) {
            if lines[j].trim_end().ends_with(':') {
                let body = lines.get(j + 1).map(|s| s.trim()).unwrap_or("");
                return body.starts_with("\"\"\"")
                    || body.starts_with("'''")
                    || body.starts_with("r\"\"\"")
                    || body.starts_with("r'''");
            }
        }
        return false;
    }

    // Прочие языки: идём вверх. Атрибуты/аннотации/декораторы — перешагиваем;
    // комментарий над ними = документация; пустая строка или код = не документировано.
    let mut j = idx;
    while j > 0 {
        j -= 1;
        let t = lines[j].trim();
        if t.is_empty() {
            return false;
        }
        if t.starts_with('@') || t.starts_with("#[") {
            continue; // декоратор/атрибут — описание может быть выше них
        }
        return t.starts_with("///")
            || t.starts_with("//!")
            || t.starts_with("//")
            || t.starts_with("/*")
            || t.starts_with('*')
            || t.starts_with("#"); // ruby/php-hash-комментарий
    }
    false
}

pub struct UndocumentedCheck {
    manifest: CapabilityManifest,
}

impl Default for UndocumentedCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl UndocumentedCheck {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "quality.check/undocumented",
                family: Family::Quality,
                engine: EngineKind::CodeIntel,
                when_to_use: "Найти публичные функции/типы/классы без описания — пропущенная документация внешнего API.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for UndocumentedCheck {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        // Порог покрытия документацией — из PolicyPack (а не магическое число).
        let floor = ailc_core::policy::load(&ctx.root).0.thresholds.doc_coverage_floor;
        let syms = CodeIntelEngine::symbols(ctx, input)?;
        let mut out = CapabilityOutput::default();

        // Кандидаты: публичные, описываемого вида, не тест/точка входа, имя ≥ 3 симв.
        let candidates: Vec<&Symbol> = syms
            .iter()
            .filter(|s| {
                s.exported
                    && is_doc_worthy(s.kind)
                    && !is_test_file(&s.file)
                    && !is_entry_name(&s.name)
                    && s.name.chars().count() >= 3
            })
            .collect();

        if candidates.is_empty() {
            out.skipped = Some("нет публичных символов для проверки описания".into());
            out.summary = "quality.check/undocumented: нет публичного API".into();
            return Ok(out);
        }

        let mut file_cache: HashMap<String, Vec<String>> = HashMap::new();
        let mut undocumented: Vec<&Symbol> = Vec::new();
        for s in &candidates {
            let lines = file_cache
                .entry(s.file.clone())
                .or_insert_with(|| read_lines(ctx, &s.file));
            if !is_documented(lines, s.line, &s.lang) {
                undocumented.push(s);
            }
        }

        let total = candidates.len();
        let documented = total - undocumented.len();
        let coverage = 100.0 * documented as f64 / total as f64;

        for s in undocumented.iter().take(40) {
            out.records
                .push(format!("{}:{} [{}] {} {}", s.file, s.line, s.lang, s.kind, s.name));
        }
        if undocumented.len() > 40 {
            out.records
                .push(format!("… ещё {} символов без описания", undocumented.len() - 40));
        }
        out.metrics.push(("public_symbols".into(), total as f64));
        out.metrics.push(("documented".into(), documented as f64));
        out.metrics.push(("doc_coverage".into(), coverage));

        // Находка — одна агрегатная (а не спам по каждому символу): для вайбкодера это
        // «у тебя X% публичного кода без описания», а не сотня предупреждений.
        if !undocumented.is_empty() && coverage < floor {
            out.findings.push(Finding {
                rule: "undocumented-api".into(),
                severity: Severity::Info,
                message: format!(
                    "{} публичных символов без описания (покрытие {coverage:.0}%)",
                    undocumented.len()
                ),
                // Привязываем к первому такому символу — чтобы было куда перейти.
                location: undocumented.first().map(|s| Location {
                    file: s.file.clone(),
                    line: s.line,
                }),
                evidence: None,
                verified: true,
                source: "quality.check/undocumented".into(),
            });
        }

        out.summary = format!(
            "quality.check/undocumented: {documented}/{total} описано ({coverage:.0}%), без описания {}",
            undocumented.len()
        );
        Ok(out)
    }
}

fn read_lines(ctx: &Ctx, rel: &str) -> Vec<String> {
    fs::read_to_string(ctx.root.join(rel))
        .map(|c| c.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Регистрирует детекторы недоделанного (семейство Quality поверх Scan/CodeIntel).
pub fn register(reg: &mut Registry) {
    reg.register(Box::new(completeness_scan())); // E1 Scan
    reg.register(Box::new(UndocumentedCheck::new())); // E3 CodeIntel
}
