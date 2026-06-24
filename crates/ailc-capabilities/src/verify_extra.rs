//! Дополнительные capability семейств Verify и Quality поверх готовых движков.
//!
//! ПРИНЦИП: capability = тонкий конфиг поверх движка, без новой инфраструктуры.
//! `verify/coverage` — конфиг команд покрытия поверх E2 Runner. `verify/symbol` и
//! `quality.check/antipattern` — агрегаты поверх E3 CodeIntel (символы + обход файлов).
//! Все три без `unwrap`/`panic`: только `match`/`?`/`unwrap_or`. Любой невыполненный
//! шаг даёт `skipped` с причиной на русском — инвариант «нет молчаливых пропусков».

use ailc_contracts::{
    looks_like_tool_failure, CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Finding,
    Location, Result, RunInput, Severity, SymbolKind, Tier,
};
use ailc_core::engines::codeintel::CodeIntelEngine;
use ailc_core::engines::runner::Runner;
use ailc_core::engines::walk::{ext_of, walk, MAX_SCAN_BYTES};
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Единая JSON-схема входа для проверок «по проекту».
const TARGET_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;
/// Схема входа для проверок, требующих имя символа.
const QUERY_SCHEMA: &str =
    r#"{"type":"object","properties":{"query":{"type":"string"},"target":{"type":"string"}},"required":["query"]}"#;

// ───────────────────────── verify/coverage (E2 Runner) ─────────────────────────

/// План покрытия по типу проекта.
/// `(бинарь, аргументы, метка языка)`. Для Rust есть фолбэк-пропуск, если `cargo
/// llvm-cov` не установлен (это отдельный subcommand, а не сам `cargo`).
enum CoveragePlan {
    /// Прямой запуск инструмента покрытия.
    Run {
        bin: &'static str,
        args: Vec<&'static str>,
        label: &'static str,
    },
}

/// Определить план покрытия по маркерам проекта. None → тип проекта не распознан.
fn detect_coverage(root: &Path) -> Option<CoveragePlan> {
    let has = |f: &str| root.join(f).exists();
    if has("go.mod") {
        Some(CoveragePlan::Run {
            bin: "go",
            args: vec!["test", "-cover", "./..."],
            label: "go",
        })
    } else if has("Cargo.toml") {
        Some(CoveragePlan::Run {
            bin: "cargo",
            args: vec!["llvm-cov", "--summary-only"],
            label: "rust",
        })
    } else if has("package.json") {
        Some(CoveragePlan::Run {
            bin: "npx",
            args: vec!["jest", "--coverage", "--silent"],
            label: "node",
        })
    } else if has("pyproject.toml") || has("requirements.txt") {
        Some(CoveragePlan::Run {
            bin: "pytest",
            args: vec!["--cov", "-q"],
            label: "python",
        })
    } else if has("build.sbt") {
        Some(CoveragePlan::Run { bin: "sbt", args: vec!["coverage", "test"], label: "scala" })
    } else if has("build.gradle.kts") || has("build.gradle") {
        Some(CoveragePlan::Run { bin: "gradle", args: vec!["jacocoTestReport", "-q"], label: "jvm" })
    } else if has("pom.xml") {
        Some(CoveragePlan::Run { bin: "mvn", args: vec!["-q", "test", "jacoco:report"], label: "java" })
    } else if has("Package.swift") {
        Some(CoveragePlan::Run { bin: "swift", args: vec!["test", "--enable-code-coverage"], label: "swift" })
    } else if has("pubspec.yaml") {
        Some(CoveragePlan::Run { bin: "dart", args: vec!["test", "--coverage=coverage"], label: "dart" })
    } else if ailc_core::stack::has_ext(root, &[".sln", ".csproj"]) {
        Some(CoveragePlan::Run {
            bin: "dotnet",
            args: vec!["test", "--collect", "XPlat Code Coverage"],
            label: "dotnet",
        })
    } else {
        None
    }
}

pub struct CoverageRun {
    manifest: CapabilityManifest,
}

impl Default for CoverageRun {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageRun {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "verify/coverage",
                family: Family::Verify,
                engine: EngineKind::Runner,
                when_to_use: "Посчитать покрытие тестами (go test -cover / cargo llvm-cov / jest / pytest-cov) реальным прогоном.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: false, // зависит от окружения и тулчейна
                mutates: false,
            },
        }
    }
}

impl Capability for CoverageRun {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        let plan = match detect_coverage(&ctx.root) {
            Some(p) => p,
            None => {
                out.skipped = Some(
                    "тип проекта не распознан (нет go.mod/Cargo.toml/package.json/pyproject/requirements)"
                        .into(),
                );
                out.summary = "verify/coverage: пропущено (проект не распознан)".into();
                return Ok(out);
            }
        };

        let CoveragePlan::Run { bin, args, label } = plan;

        // Для Rust покрытие даёт отдельный subcommand `cargo llvm-cov`. Если его нет,
        // голый `cargo` всё равно «доступен» — поэтому проверяем наличие subcommand
        // явно и пропускаем с понятной причиной, а не ловим невнятную ошибку запуска.
        if label == "rust" && !cargo_llvm_cov_available() {
            out.skipped = Some(
                "покрытие для Rust требует cargo-llvm-cov — установите: cargo install cargo-llvm-cov"
                    .into(),
            );
            out.summary = "verify/coverage (rust): пропущено (нет cargo-llvm-cov)".into();
            return Ok(out);
        }

        let res = Runner::run(ctx, bin, &args);
        if !res.ran {
            let reason = res
                .skipped_reason
                .unwrap_or_else(|| format!("инструмент `{bin}` недоступен"));
            out.skipped = Some(reason.clone());
            out.summary = format!("verify/coverage ({label}): пропущено — {reason}");
            return Ok(out);
        }

        if res.exit_ok {
            for l in res.tail(10) {
                out.records.push(l);
            }
            out.metrics.push(("exit_ok".into(), 1.0));
            out.summary = format!("verify/coverage ({label}): покрытие посчитано");
        } else {
            // Различаем «инструмент покрытия сам не отработал» (не собралось, ошибка
            // конфигурации, отсутствует модуль, паника) от «инструмент отработал и
            // покрытие посчитать не удалось содержательно» (T86). По инварианту README
            // «сбой инструмента не равен находке» крах раннера НЕ должен превращаться в
            // дефект кода и занижать балл: при маркерах сбоя в stdout/stderr ставим
            // skipped с причиной, и CapabilityOutput::outcome классифицирует это как
            // Failed (инструмент упал), а не как находку. Иначе оставляем содержательную
            // находку coverage-failed реального прогона.
            let blob = format!("{}\n{}", res.stdout, res.stderr);
            for l in res.tail(10) {
                out.records.push(l);
            }
            out.metrics.push(("exit_ok".into(), 0.0));
            if looks_like_tool_failure(&blob) {
                let reason = format!(
                    "инструмент покрытия `{bin}` не отработал (сборка/конфиг/импорт), покрытие не запускалось (код {:?})",
                    res.code
                );
                out.summary = format!("verify/coverage ({label}): {reason}");
                out.skipped = Some(reason);
            } else {
                out.findings.push(Finding {
                    rule: "coverage-failed".into(),
                    severity: Severity::Low,
                    message: "Не удалось посчитать покрытие".into(),
                    location: None,
                    evidence: None,
                    verified: true, // реальный прогон: неуспех подтверждён
                    source: "verify/coverage".into(),
                });
                out.summary = format!(
                    "verify/coverage ({label}): не удалось посчитать покрытие (код {:?})",
                    res.code
                );
            }
        }
        Ok(out)
    }
}

/// Доступен ли subcommand `cargo llvm-cov` (а не просто `cargo`).
/// `cargo llvm-cov --version` завершается успешно только при установленном плагине.
fn cargo_llvm_cov_available() -> bool {
    if !Runner::available("cargo") {
        return false;
    }
    match std::process::Command::new("cargo")
        .args(["llvm-cov", "--version"])
        .output()
    {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

// ───────────────────────── verify/symbol (E3 CodeIntel) ─────────────────────────

pub struct SymbolVerify {
    manifest: CapabilityManifest,
}

impl Default for SymbolVerify {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolVerify {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "verify/symbol",
                family: Family::Verify,
                engine: EngineKind::CodeIntel,
                when_to_use: "Проверить, что символ с таким именем реально существует в коде — защита от выдуманных имён в утверждениях ИИ.",
                input_schema: QUERY_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for SymbolVerify {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        // Инвариант «нет молчаливых пропусков»: без имени символа — явная причина.
        let query = match input.query.as_deref().filter(|q| !q.is_empty()) {
            Some(q) => q,
            None => {
                out.skipped = Some("нужен параметр query — имя символа".into());
                out.summary = "verify/symbol: пропущено (нет query)".into();
                return Ok(out);
            }
        };

        // Разбираем квалифицированное имя на компоненты. Поддерживаем разделители
        // `.`/`::`/`/`/`\`, поэтому `Foo::bar`, `foo.bar`, `pkg/Class` и `pkg\Class`
        // распознаются единообразно. Лист — последняя компонента (искомый символ),
        // контейнер — компонента, непосредственно ему предшествующая (тип/класс/модуль).
        let parts: Vec<&str> = query
            .split(['.', ':', '/', '\\'])
            .filter(|p| !p.is_empty())
            .collect();
        let leaf = parts.last().copied().unwrap_or(query);
        // Контейнер есть только у действительно квалифицированного имени (две и более
        // непустых компоненты). Для простого имени `bar` контейнера нет, и проверка
        // принадлежности не применяется.
        let container = if parts.len() >= 2 {
            Some(parts[parts.len() - 2])
        } else {
            None
        };

        let syms = CodeIntelEngine::symbols(ctx, input)?;

        // Прямое совпадение по полному имени символа (некоторые языки/извлекатели хранят
        // квалифицированную форму целиком): это безусловное подтверждение существования.
        let exact: Vec<&ailc_contracts::Symbol> =
            syms.iter().filter(|s| s.name == query).collect();

        // Определения листа по короткому имени.
        let leaf_defs: Vec<&ailc_contracts::Symbol> =
            syms.iter().filter(|s| s.name == leaf).collect();

        match container {
            // ── Квалифицированное имя: проверяем принадлежность листа контейнеру ──
            Some(cont) if exact.is_empty() => {
                // Определения контейнера: символ с именем контейнера и «контейнерным»
                // видом (тип/класс/перечисление/трейт/интерфейс). Модуль/пакет тоже
                // выступает контейнером для квалификаций вида `pkg.Func`, но извлекатель
                // символов модуль самостоятельной сущностью не отдаёт, поэтому для
                // имён-модулей принадлежность подтверждается совпадением файла-владельца.
                let container_defs: Vec<&ailc_contracts::Symbol> = syms
                    .iter()
                    .filter(|s| s.name == cont && is_container_kind(s.kind))
                    .collect();

                // Лист принадлежит контейнеру, если в одном и том же файле объявлены и
                // контейнер, и лист, причём лист идёт ниже строки контейнера (находится
                // в его теле). Совпадение файла без модели вложенности AST является
                // сильным и доступным здесь приближением принадлежности; требование
                // «лист ниже контейнера» отсекает случай, когда контейнер и не связанный
                // лист просто оказались в одном файле выше определения контейнера.
                let confirmed: Vec<&ailc_contracts::Symbol> = leaf_defs
                    .iter()
                    .copied()
                    .filter(|lf| {
                        container_defs
                            .iter()
                            .any(|c| c.file == lf.file && c.line <= lf.line)
                    })
                    .collect();

                if !confirmed.is_empty() {
                    for s in &confirmed {
                        out.records
                            .push(format!("{}:{} {} {}", s.file, s.line, s.kind, s.name));
                    }
                    out.metrics.push(("definitions".into(), confirmed.len() as f64));
                    out.metrics.push(("container_confirmed".into(), 1.0));
                    out.summary = format!(
                        "verify/symbol «{query}»: символ существует и принадлежит `{cont}` ({} определений)",
                        confirmed.len()
                    );
                } else if !leaf_defs.is_empty() {
                    // Лист найден, но в файле объявляющего контейнера он не подтверждён:
                    // это ровно сценарий выдуманного имени `Foo::bar`, где `bar` есть
                    // где-то ещё, но не в `Foo`. Не выдаём ложное «существует»: помечаем
                    // как находку с честным вердиктом и фиксируем расположение похожих.
                    for s in &leaf_defs {
                        out.records
                            .push(format!("{}:{} {} {}", s.file, s.line, s.kind, s.name));
                    }
                    out.findings.push(Finding {
                        rule: "symbol-container-unconfirmed".into(),
                        severity: Severity::Medium,
                        message: format!(
                            "Найдено похожее имя `{leaf}`, но принадлежность контейнеру `{cont}` не подтверждена — возможно выдумано (`{query}`)"
                        ),
                        location: None,
                        evidence: None,
                        verified: true, // вывод сделан обходом кода
                        source: "verify/symbol".into(),
                    });
                    out.metrics.push(("definitions".into(), 0.0));
                    out.metrics.push(("leaf_only".into(), leaf_defs.len() as f64));
                    out.summary =
                        format!("verify/symbol «{query}»: найдено похожее, принадлежность не подтверждена");
                } else {
                    // Ни листа, ни принадлежности: символ не найден.
                    out.findings.push(Finding {
                        rule: "symbol-not-found".into(),
                        severity: Severity::High,
                        message: format!("Символ `{query}` не найден — возможно выдуман"),
                        location: None,
                        evidence: None,
                        verified: true,
                        source: "verify/symbol".into(),
                    });
                    out.metrics.push(("definitions".into(), 0.0));
                    out.summary = format!("verify/symbol «{query}»: не найден");
                }
            }
            // ── Простое имя либо прямое совпадение по полному имени ──
            _ => {
                let defs: Vec<&ailc_contracts::Symbol> = if !exact.is_empty() {
                    exact
                } else {
                    leaf_defs
                };
                if defs.is_empty() {
                    out.findings.push(Finding {
                        rule: "symbol-not-found".into(),
                        severity: Severity::High,
                        message: format!("Символ `{query}` не найден — возможно выдуман"),
                        location: None,
                        evidence: None,
                        verified: true, // утверждение проверено обходом кода
                        source: "verify/symbol".into(),
                    });
                    out.metrics.push(("definitions".into(), 0.0));
                    out.summary = format!("verify/symbol «{query}»: не найден");
                } else {
                    for s in &defs {
                        out.records
                            .push(format!("{}:{} {} {}", s.file, s.line, s.kind, s.name));
                    }
                    out.metrics.push(("definitions".into(), defs.len() as f64));
                    out.summary = format!(
                        "verify/symbol «{query}»: символ существует ({} определений)",
                        defs.len()
                    );
                }
            }
        }
        Ok(out)
    }
}

// ───────────────────────── quality.check/antipattern (E3 CodeIntel) ─────────────────────────


pub struct AntipatternCheck {
    manifest: CapabilityManifest,
}

impl Default for AntipatternCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl AntipatternCheck {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "quality.check/antipattern",
                family: Family::Quality,
                engine: EngineKind::CodeIntel,
                when_to_use: "Найти структурные антипаттерны: перегруженные файлы (God-файл) и чрезмерно глубокую вложенность.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for AntipatternCheck {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        // Пороги — из PolicyPack (governance как данные), а не магические числа.
        let t = ailc_core::policy::load(&ctx.root).0.thresholds;

        // ── God-файлы: группируем символы по файлу ──
        let syms = CodeIntelEngine::symbols(ctx, input)?;
        let mut by_file: BTreeMap<String, usize> = BTreeMap::new();
        for s in &syms {
            *by_file.entry(s.file.clone()).or_default() += 1;
        }
        let mut god_files: u32 = 0;
        for (file, count) in &by_file {
            if *count > t.max_defs_per_file {
                god_files += 1;
                out.findings.push(Finding {
                    rule: "god-file".into(),
                    severity: Severity::Low,
                    message: format!("Слишком много сущностей в одном файле ({count})"),
                    location: Some(Location {
                        file: file.clone(),
                        line: 1,
                    }),
                    evidence: None,
                    verified: true,
                    source: "quality.check/antipattern".into(),
                });
            }
        }

        // ── Глубокая вложенность: максимальная глубина отступа по каждому исходнику ──
        // База прогона проходит через ctx.base(input)?: эта проверка отвергает абсолютный
        // путь и компоненты «..», поэтому target от MCP-клиента не уводит обход за корень
        // проекта (T42). Раньше тут стоял прямой ctx.root.join(target), который при
        // абсолютном target подменял весь путь, а при «..» поднимался вверх по дереву.
        let base = ctx.base(input)?;
        let root = ctx.root.clone();
        let mut deep_files: u32 = 0;
        let mut deep_hits: Vec<(String, usize, u32)> = Vec::new();

        walk(&base, &mut |path| {
            if !is_source(ext_of(path)) {
                return;
            }
            // Ограничиваем размер файла перед чтением в память (T91): огромный сгенерированный
            // или минифицированный исходник раздувал бы потребление памяти на read_to_string.
            // Порог единый с движком обхода (walk::MAX_SCAN_BYTES), чтобы антипаттерн считался
            // по тем же файлам, что и остальные сканеры, без расхождения охвата.
            match fs::metadata(path) {
                Ok(m) if m.len() > MAX_SCAN_BYTES => return,
                Ok(_) => {}
                Err(_) => return,
            }
            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => return,
            };
            // Ширину одного уровня отступа определяем по самому файлу (T91), а не делением
            // на жёсткую константу четыре. Файл на двух пробелах раньше давал вдвое
            // завышенную глубину (ложные срабатывания), а файл на восьми пробелах, наоборот,
            // занижал её (пропуски). indent_unit берёт преобладающий (модальный) шаг
            // ведущих пробелов между соседними строками; при отступах табами это не влияет.
            let unit = indent_unit(&content);
            let mut max_depth = 0usize;
            let mut max_line = 0u32;
            for (i, line) in content.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let depth = indent_depth(line, unit);
                if depth > max_depth {
                    max_depth = depth;
                    max_line = (i as u32) + 1;
                }
            }
            if max_depth > t.max_nesting {
                let rel = path
                    .strip_prefix(&root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string();
                deep_hits.push((rel, max_depth, max_line));
            }
        })?;

        for (file, depth, line) in &deep_hits {
            deep_files += 1;
            out.findings.push(Finding {
                rule: "deep-nesting".into(),
                severity: Severity::Medium,
                message: format!("Слишком глубокая вложенность (уровень {depth})"),
                location: Some(Location {
                    file: file.clone(),
                    line: *line,
                }),
                evidence: None,
                verified: true,
                source: "quality.check/antipattern".into(),
            });
        }

        out.metrics.push(("god_files".into(), god_files as f64));
        out.metrics.push(("deep_files".into(), deep_files as f64));
        out.summary = format!(
            "quality.check/antipattern: {god_files} перегруженных файлов, {deep_files} с глубокой вложенностью"
        );
        Ok(out)
    }
}

/// Является ли вид символа «контейнером», способным владеть листом квалифицированного
/// имени `Container::leaf` (тип, класс, перечисление, трейт, интерфейс). Функция или
/// переменная контейнером для метода/поля не являются.
fn is_container_kind(kind: SymbolKind) -> bool {
    matches!(
        kind,
        SymbolKind::Type
            | SymbolKind::Class
            | SymbolKind::Enum
            | SymbolKind::Trait
            | SymbolKind::Interface
    )
}

/// Считаем глубину вложенности только в известных исходниках (как другие движки).
fn is_source(ext: &str) -> bool {
    // Единый источник «что считать исходником» (был урезанный список — терял
    // Ruby/PHP/Scala/C/C++/Dart на проверке вложенности).
    ailc_core::engines::scan::SOURCE_CODE.contains(&ext)
}

/// Число ведущих пробелов и табов строки (до первого непустого символа).
fn leading_indent(line: &str) -> (usize, usize) {
    let mut tabs = 0usize;
    let mut spaces = 0usize;
    for ch in line.chars() {
        match ch {
            '\t' => tabs += 1,
            ' ' => spaces += 1,
            _ => break,
        }
    }
    (tabs, spaces)
}

/// Ширина одного уровня отступа в пробелах, определённая по содержимому файла (T91).
/// Раньше ширина была зашита константой четыре, из-за чего файл на двух пробелах давал
/// вдвое завышенную глубину (ложные срабатывания deep-nesting), а файл на восьми пробелах
/// её занижал (пропуски). Здесь берётся преобладающий (модальный) положительный шаг
/// ведущих пробелов между последовательными непустыми строками: это и есть фактический
/// размер одного уровня. Если пробельных отступов в файле нет (только табы или плоский
/// файл), возвращаем дефолт четыре, поскольку деление на ноль недопустимо, а табы
/// считаются отдельно и от этой ширины не зависят.
fn indent_unit(content: &str) -> usize {
    let mut steps: BTreeMap<usize, u32> = BTreeMap::new();
    let mut prev: Option<usize> = None;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let (_, spaces) = leading_indent(line);
        if let Some(p) = prev {
            // Учитываем только увеличение отступа на положительную величину: шаг входа в
            // новый блок. Уменьшение (выход из блока) ширину уровня не характеризует.
            if spaces > p {
                *steps.entry(spaces - p).or_default() += 1;
            }
        }
        prev = Some(spaces);
    }
    // Модальный шаг: при равенстве частот берём наименьшую ширину (детерминированно,
    // BTreeMap упорядочен по возрастанию ключа). Это консервативно: меньший юнит даёт
    // не меньшую расчётную глубину, что не маскирует реальную вложенность.
    let mut best: Option<(usize, u32)> = None;
    for (step, freq) in &steps {
        match best {
            Some((_, bf)) if *freq <= bf => {}
            _ => best = Some((*step, *freq)),
        }
    }
    match best {
        Some((step, _)) if step > 0 => step,
        _ => 4,
    }
}

/// Глубина вложенности строки по ведущим отступам: число табов плюс число ведущих
/// пробелов, делённое на фактическую ширину уровня `unit` (определяется по файлу,
/// см. [`indent_unit`]). Смешанные отступы складываются.
fn indent_depth(line: &str, unit: usize) -> usize {
    let (tabs, spaces) = leading_indent(line);
    let unit = unit.max(1); // страховка от деления на ноль
    tabs + spaces / unit
}

/// Регистрирует capability семейств Verify и Quality поверх готовых движков.
pub fn register(reg: &mut Registry) {
    reg.register(Box::new(CoverageRun::new())); // E2 Runner
    reg.register(Box::new(SymbolVerify::new())); // E3 CodeIntel
    reg.register(Box::new(AntipatternCheck::new())); // E3 CodeIntel
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_contracts::CheckOutcome;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CNT: AtomicU64 = AtomicU64::new(0);

    /// Уникальная пустая временная папка для файловых фикстур.
    fn tmp() -> PathBuf {
        let n = CNT.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("ailc-verify-extra-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }

    // ───────────────────────── T42: ctx.base в AntipatternCheck ─────────────────────────

    #[test]
    fn t42_antipattern_абсолютный_target_отвергается() {
        let dir = tmp();
        let input = RunInput {
            target: Some("/etc".to_string()),
            ..Default::default()
        };
        let res = AntipatternCheck::new().run(&Ctx::new(&dir), &input);
        assert!(
            res.is_err(),
            "абсолютный target должен отвергаться через ctx.base, а не уводить обход за корень"
        );
    }

    #[test]
    fn t42_antipattern_двойные_точки_отвергаются() {
        let dir = tmp();
        let input = RunInput {
            target: Some("../../etc".to_string()),
            ..Default::default()
        };
        let res = AntipatternCheck::new().run(&Ctx::new(&dir), &input);
        assert!(
            res.is_err(),
            "target с компонентами .. должен отвергаться через ctx.base"
        );
    }

    #[test]
    fn t42_antipattern_корректный_подпуть_исполняется() {
        let dir = tmp();
        write(&dir, "src/lib.rs", "fn main() {}\n");
        let input = RunInput {
            target: Some("src".to_string()),
            ..Default::default()
        };
        let res = AntipatternCheck::new().run(&Ctx::new(&dir), &input);
        assert!(res.is_ok(), "обычный относительный подпуть должен исполняться");
    }

    // ───────────────────────── T91: ширина отступа по файлу ─────────────────────────

    #[test]
    fn t91_indent_unit_определяет_двойной_пробел() {
        // Файл, целиком отформатированный двумя пробелами на уровень.
        let content = "a\n  b\n    c\n      d\n";
        assert_eq!(indent_unit(content), 2, "ширина уровня должна определиться как 2");
        // Глубина строки «      d» (6 пробелов) при unit=2 равна 3, а не 1 (как было бы
        // при зашитой ширине 4 с округлением вниз).
        assert_eq!(indent_depth("      d", 2), 3);
    }

    #[test]
    fn t91_indent_unit_определяет_четыре_пробела() {
        let content = "a\n    b\n        c\n";
        assert_eq!(indent_unit(content), 4);
        assert_eq!(indent_depth("        c", 4), 2);
    }

    #[test]
    fn t91_двойной_пробел_не_занижает_глубину_против_фиксированной_четвёрки() {
        // Регрессия: при зашитой ширине 4 глубоко вложенный файл на двух пробелах
        // считался бы вдвое мельче и мог проскочить порог max_nesting. Теперь юнит=2
        // даёт честную глубину.
        let content = "a\n  b\n    c\n      d\n        e\n          f\n";
        let unit = indent_unit(content);
        assert_eq!(unit, 2);
        // Самая глубокая строка «          f» (10 пробелов) при unit=2 даёт глубину 5.
        let max = content
            .lines()
            .map(|l| indent_depth(l, unit))
            .max()
            .unwrap();
        assert_eq!(max, 5, "глубина не должна занижаться шириной отступа");
    }

    #[test]
    fn t91_табы_не_зависят_от_ширины_пробелов() {
        // Файл на табах: indent_unit отдаёт дефолт, но табы считаются напрямую.
        let content = "a\n\tb\n\t\tc\n";
        let unit = indent_unit(content);
        assert_eq!(indent_depth("\t\tc", unit), 2);
    }

    #[test]
    fn t91_deep_nesting_срабатывает_на_двух_пробелах() {
        let dir = tmp();
        // Пороги по умолчанию max_nesting обычно невелики; строим заведомо глубокий файл
        // на двух пробелах. При прежней зашитой четвёрке глубина была бы вдвое меньше.
        let mut src = String::from("fn main() {\n");
        let mut indent = String::new();
        for i in 0..12 {
            indent.push_str("  ");
            src.push_str(&format!("{indent}let x{i} = {i};\n"));
        }
        src.push_str("}\n");
        write(&dir, "deep.rs", &src);
        let out = AntipatternCheck::new()
            .run(&Ctx::new(&dir), &RunInput::default())
            .expect("antipattern должен отработать");
        assert!(
            out.findings.iter().any(|f| f.rule == "deep-nesting"),
            "глубокая вложенность на двух пробелах должна обнаружиться, summary={}",
            out.summary
        );
    }

    // ───────────────────────── T91: размер файла ─────────────────────────

    #[test]
    fn t91_крупный_файл_пропускается_по_размеру() {
        let dir = tmp();
        // Файл крупнее MAX_SCAN_BYTES не должен читаться в память (защита от OOM).
        // Защита двухслойная: walk не передаёт такой файл в обработчик (T64), а сам
        // обработчик дополнительно проверяет fs::metadata перед read_to_string (T91),
        // чтобы инвариант держался даже при смене обходчика. Наблюдаемый результат:
        // огромный исходник в охват антипаттернов не попадает и не роняет проверку.
        // Делаем файл глубоко вложенным, чтобы при ошибочном чтении он гарантированно
        // дал бы deep-nesting; отсутствие находки подтверждает пропуск по размеру.
        let mut deep = String::new();
        for i in 0..20 {
            deep.push_str(&" ".repeat(i * 2));
            deep.push_str("x;\n");
        }
        let unit = (MAX_SCAN_BYTES as usize) / deep.len() + 2;
        let big = deep.repeat(unit);
        assert!(big.len() as u64 > MAX_SCAN_BYTES);
        write(&dir, "huge.rs", &big);
        let out = AntipatternCheck::new()
            .run(&Ctx::new(&dir), &RunInput::default())
            .expect("antipattern должен отработать без падения на крупном файле");
        assert!(
            !out.findings.iter().any(|f| f.rule == "deep-nesting"),
            "крупный файл должен быть пропущен по размеру, а не прочитан и обработан"
        );
    }

    // ───────────────────────── T91: verify/symbol принадлежность контейнеру ─────────────

    #[test]
    fn t91_symbol_лист_принадлежит_контейнеру_подтверждён() {
        let dir = tmp();
        // Контейнер Foo и метод bar внутри него в одном файле.
        write(
            &dir,
            "src/foo.rs",
            "struct Foo {}\nimpl Foo {\n    fn bar(&self) {}\n}\n",
        );
        let input = RunInput {
            query: Some("Foo::bar".to_string()),
            ..Default::default()
        };
        let out = SymbolVerify::new().run(&Ctx::new(&dir), &input).unwrap();
        assert!(
            out.findings.is_empty(),
            "лист bar принадлежит Foo: находок быть не должно, summary={}",
            out.summary
        );
        assert!(
            out.summary.contains("принадлежит"),
            "вердикт должен подтвердить принадлежность, summary={}",
            out.summary
        );
    }

    #[test]
    fn t91_symbol_лист_в_чужом_контейнере_не_подтверждён() {
        let dir = tmp();
        // bar существует, но принадлежит Other, а контейнер Foo пуст. Запрос Foo::bar
        // не должен ложно подтверждаться лишь по совпадению листа bar.
        write(&dir, "src/foo.rs", "struct Foo {}\nimpl Foo {\n}\n");
        write(
            &dir,
            "src/other.rs",
            "struct Other {}\nimpl Other {\n    fn bar(&self) {}\n}\n",
        );
        let input = RunInput {
            query: Some("Foo::bar".to_string()),
            ..Default::default()
        };
        let out = SymbolVerify::new().run(&Ctx::new(&dir), &input).unwrap();
        assert!(
            out.findings
                .iter()
                .any(|f| f.rule == "symbol-container-unconfirmed"),
            "лист bar в чужом контейнере должен дать вердикт «принадлежность не подтверждена», summary={}",
            out.summary
        );
        // Это НЕ должно классифицироваться как «существует».
        assert!(
            !out.summary.contains("символ существует"),
            "не должно ложно подтверждать существование Foo::bar, summary={}",
            out.summary
        );
    }

    #[test]
    fn t91_symbol_квалифицированный_не_найден_вовсе() {
        let dir = tmp();
        write(&dir, "src/foo.rs", "struct Foo {}\n");
        let input = RunInput {
            query: Some("Foo::missing".to_string()),
            ..Default::default()
        };
        let out = SymbolVerify::new().run(&Ctx::new(&dir), &input).unwrap();
        assert!(
            out.findings.iter().any(|f| f.rule == "symbol-not-found"),
            "несуществующий лист должен дать symbol-not-found, summary={}",
            out.summary
        );
    }

    #[test]
    fn t91_symbol_простое_имя_по_прежнему_находится() {
        let dir = tmp();
        write(&dir, "src/foo.rs", "fn standalone() {}\n");
        let input = RunInput {
            query: Some("standalone".to_string()),
            ..Default::default()
        };
        let out = SymbolVerify::new().run(&Ctx::new(&dir), &input).unwrap();
        assert!(
            out.findings.is_empty() && out.summary.contains("существует"),
            "простое имя без квалификации должно подтверждаться как раньше, summary={}",
            out.summary
        );
    }

    #[test]
    fn t91_symbol_простое_имя_не_найдено() {
        let dir = tmp();
        write(&dir, "src/foo.rs", "fn real() {}\n");
        let input = RunInput {
            query: Some("imaginary".to_string()),
            ..Default::default()
        };
        let out = SymbolVerify::new().run(&Ctx::new(&dir), &input).unwrap();
        assert!(
            out.findings.iter().any(|f| f.rule == "symbol-not-found"),
            "выдуманное простое имя должно давать symbol-not-found"
        );
    }

    #[test]
    fn t42_symbol_абсолютный_target_отвергается() {
        let dir = tmp();
        let input = RunInput {
            query: Some("Foo".to_string()),
            target: Some("/etc".to_string()),
        };
        // CodeIntelEngine::symbols вызывает ctx.base(input)?, поэтому абсолютный target
        // отвергается и здесь (единообразие границы T42).
        let res = SymbolVerify::new().run(&Ctx::new(&dir), &input);
        assert!(res.is_err(), "абсолютный target должен отвергаться и в verify/symbol");
    }

    // ───────────────────────── T86: сбой инструмента покрытия не равен находке ─────────────

    /// Воспроизводит классификацию ветки exit!=0 из CoverageRun::run: при маркерах сбоя
    /// инструмента в выводе ставится skipped, и outcome() даёт Failed (не находку); иначе
    /// эмитится находка coverage-failed и outcome() = Ran.
    fn coverage_branch(blob: &str) -> CapabilityOutput {
        let mut out = CapabilityOutput::default();
        out.metrics.push(("exit_ok".into(), 0.0));
        if looks_like_tool_failure(blob) {
            out.skipped = Some(format!(
                "инструмент покрытия `cargo` не отработал (сборка/конфиг/импорт), покрытие не запускалось (код {:?})",
                Some(101)
            ));
            out.summary = "verify/coverage (rust): сбой инструмента".into();
        } else {
            out.findings.push(Finding {
                rule: "coverage-failed".into(),
                severity: Severity::Low,
                message: "Не удалось посчитать покрытие".into(),
                location: None,
                evidence: None,
                verified: true,
                source: "verify/coverage".into(),
            });
            out.summary = "verify/coverage (rust): не удалось посчитать покрытие".into();
        }
        out
    }

    #[test]
    fn t86_coverage_крах_сборки_не_находка() {
        // Ошибка компиляции в выводе раннера покрытия: это сбой инструмента, не дефект.
        let out = coverage_branch("error[E0277]: the trait bound is not satisfied\ncould not compile `crate`");
        assert!(
            out.findings.is_empty(),
            "крах сборки не должен превращаться в находку coverage-failed"
        );
        assert!(
            matches!(out.outcome(), CheckOutcome::Failed(_)),
            "outcome краха инструмента должен быть Failed, а не Ran/Skipped: {:?}",
            out.outcome()
        );
    }

    #[test]
    fn t86_coverage_отсутствие_модуля_python_не_находка() {
        let out = coverage_branch("ModuleNotFoundError: No module named 'pytest_cov'");
        assert!(out.findings.is_empty());
        assert!(matches!(out.outcome(), CheckOutcome::Failed(_)));
    }

    #[test]
    fn t86_coverage_паника_раннера_не_находка() {
        let out = coverage_branch("thread 'main' panicked at 'boom'");
        assert!(out.findings.is_empty());
        assert!(matches!(out.outcome(), CheckOutcome::Failed(_)));
    }

    #[test]
    fn t86_coverage_содержательный_неуспех_остаётся_находкой() {
        // Раннер отработал, но покрытие содержательно не посчиталось (нет маркеров сбоя):
        // это законная находка coverage-failed, outcome = Ran.
        let out = coverage_branch("coverage: 0.0% of statements\nFAIL\tpkg 0.1s");
        assert!(
            out.findings.iter().any(|f| f.rule == "coverage-failed"),
            "содержательный неуспех должен оставаться находкой coverage-failed"
        );
        assert!(
            matches!(out.outcome(), CheckOutcome::Ran),
            "реальный прогон с находкой должен давать outcome Ran: {:?}",
            out.outcome()
        );
    }

    #[test]
    fn t86_coverage_пустой_вывод_остаётся_находкой() {
        // Пустой/нейтральный вывод при ненулевом коде: маркеров сбоя нет, поэтому это
        // находка, а не Failed. Иначе любой ненулевой код молча скрывался бы.
        let out = coverage_branch("");
        assert!(out.findings.iter().any(|f| f.rule == "coverage-failed"));
        assert!(matches!(out.outcome(), CheckOutcome::Ran));
    }
}
