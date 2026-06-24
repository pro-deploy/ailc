//! Capability семейства governance — конституция и слои как ДАННЫЕ.
//!
//! Обе проверки читают декларативный файл правил (governance как данные: старший
//! пишет один раз, джун наследует) и кормят гейт типизированными findings.
//! Никакой новой логики обхода/графа: переиспользуют общие движки `walk` и
//! `CodeIntelEngine` — capability здесь это лишь чтение правил и сопоставление.

use ailc_contracts::{
    rule_confidence, CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Finding,
    Location, Result, RunInput, Severity, Tier,
};
use ailc_core::engines::codeintel::CodeIntelEngine;
use ailc_core::engines::walk::{ext_of, is_test_path, walk};
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

/// Схема входа: проверка по всему проекту, опциональный подпуть.
const TARGET_SCHEMA: &str =
    r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;

/// Исходник ли это — единый источник `scan::SOURCE_CODE` (был свой урезанный список).
fn is_source_ext(ext: &str) -> bool {
    ailc_core::engines::scan::SOURCE_CODE.contains(&ext)
}

// ───────────────────────── quality.check/constitution ─────────────────────────

/// Одно правило конституции.
///
/// Семантика трёх директив намеренно различна и уточнена в рамках задачи T37, потому
/// что прежнее правило REQUIRE по голой подстроке закрывалось единственным вхождением
/// маркера где угодно по дереву и создавало ложное ощущение контроля покрытия:
///
/// FORBID запрещает подстроку: нарушением считается каждое исполняемое вхождение
/// (комментарии, строковые литералы и тест-файлы исключаются, см. ниже), а не только
/// первое; раньше фиксировалось лишь первое вхождение, и остальные нарушения скрывались.
///
/// REQUIRE требует наличия подстроки хотя бы один раз в исполняемом коде проекта:
/// это «глобальное» требование присутствия маркера (например, наличия некоторой
/// обязательной директивы где-то в кодовой базе). Тривиально-зелёным оно больше не
/// становится за счёт фейкового вхождения, потому что вхождения в комментариях,
/// строковых литералах и тест-файлах не засчитываются.
///
/// REQUIRE_EACH требует наличия подстроки в КАЖДОМ релевантном (нетестовом) исходном
/// файле проекта: это контроль ПОКРЫТИЯ. Нарушением считается каждый релевантный файл,
/// в исполняемом коде которого маркер отсутствует. Именно эта директива закрывает
/// исходный дефект «одно вхождение по всему дереву закрывает требование».
enum ConstRule {
    /// Подстрока запрещена: нарушение на каждое исполняемое вхождение.
    Forbid(String),
    /// Подстрока обязательна хотя бы один раз в исполняемом коде всего проекта.
    Require(String),
    /// Подстрока обязательна в КАЖДОМ релевантном (нетестовом) исходном файле.
    RequireEach(String),
}

/// Разобрать текст конституции в список правил. Игнорирует строки, не начинающиеся
/// с FORBID/REQUIRE/REQUIRE_EACH (комментарии, заголовки и пр.).
///
/// Порядок разбора важен: префикс REQUIRE_EACH проверяется раньше REQUIRE, иначе
/// `strip_prefix("REQUIRE ")` никогда не сработал бы для строки `REQUIRE_EACH ...`,
/// поскольку после слова REQUIRE в ней идёт символ подчёркивания, а не пробел; явная
/// проверка более длинного префикса первой исключает любую двусмысленность.
fn parse_constitution(text: &str) -> Vec<ConstRule> {
    let mut rules = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("REQUIRE_EACH ") {
            let needle = rest.trim();
            if !needle.is_empty() {
                rules.push(ConstRule::RequireEach(needle.to_string()));
            }
        } else if let Some(rest) = t.strip_prefix("FORBID ") {
            let needle = rest.trim();
            if !needle.is_empty() {
                rules.push(ConstRule::Forbid(needle.to_string()));
            }
        } else if let Some(rest) = t.strip_prefix("REQUIRE ") {
            let needle = rest.trim();
            if !needle.is_empty() {
                rules.push(ConstRule::Require(needle.to_string()));
            }
        }
    }
    rules
}

/// Стиль однострочного комментария по семейству синтаксиса исходного файла. Возвращает
/// набор префиксов, начиная с которых остаток строки является комментарием. Карта
/// расширений намеренно повторяет соглашения движка `codeintel::lang_for_ext`, но
/// заведена локально, поскольку та функция доступна лишь внутри своего пакета.
fn line_comment_markers(ext: &str) -> &'static [&'static str] {
    match ext {
        // C-подобные: Go, Rust, TypeScript/JavaScript и их варианты, Java, Kotlin,
        // Swift, C#, C/C++, PHP, Scala, Dart.
        "go" | "rs" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "java" | "kt" | "kts"
        | "swift" | "cs" | "c" | "cc" | "cpp" | "h" | "hpp" | "scala" | "dart" => &["//"],
        // PHP допускает и `//`, и `#`.
        "php" => &["//", "#"],
        // Python, Ruby, Elixir: однострочный комментарий начинается с `#`.
        "py" | "rb" | "ex" | "exs" => &["#"],
        // Clojure: однострочный комментарий начинается с `;`.
        "clj" => &[";"],
        _ => &["//"],
    }
}

/// Открывающая и закрывающая последовательности блочного комментария по расширению.
/// `None` означает «у языка нет блочного комментария данного семейства» (например,
/// у Python мы трактуем тройные кавычки отдельно, ниже).
fn block_comment_delims(ext: &str) -> Option<(&'static str, &'static str)> {
    match ext {
        // C-подобные и большинство языков: /* ... */.
        "go" | "rs" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "java" | "kt" | "kts"
        | "swift" | "cs" | "c" | "cc" | "cpp" | "h" | "hpp" | "scala" | "dart" | "php" => {
            Some(("/*", "*/"))
        }
        _ => None,
    }
}

/// Маркер тройной кавычки (строка-документация Python). В Python тройные кавычки чаще
/// всего служат докстрингом, поэтому для целей конституции их содержимое трактуется
/// как неисполняемый текст наравне со строковыми литералами.
fn triple_quote(ext: &str) -> Option<&'static str> {
    match ext {
        "py" => Some("\"\"\""),
        _ => None,
    }
}

/// Замаскировать в исходном тексте комментарии и строковые литералы пробелами, сохранив
/// разбивку на строки и позиции исполняемых лексем. Возвращает текст той же длины по
/// строкам, где любой символ внутри комментария или строкового литерала заменён на
/// пробел, а переводы строк сохранены. Этим достигается две цели: поиск подстроки
/// FORBID/REQUIRE идёт ТОЛЬКО по исполняемому коду (комментарий вида «не делай unwrap()»
/// больше не триггерит правило), и номера строк остаются корректными для находок.
///
/// Реализация однопроходная и учитывает три перекрывающихся состояния: блочный
/// комментарий, тройная кавычка и строковый литерал (одинарная, двойная или обратная
/// кавычка). Внутри строкового литерала распознаётся экранирование обратной косой чертой,
/// чтобы `"\""` не закрывал литерал преждевременно. Однострочный комментарий гасит
/// остаток строки до перевода строки.
fn mask_comments_and_strings(ext: &str, content: &str) -> String {
    let block = block_comment_delims(ext);
    let triple = triple_quote(ext);
    let line_markers = line_comment_markers(ext);

    let mut out = String::with_capacity(content.len());
    let bytes = content.as_bytes();
    let mut i = 0usize;

    // Текущее состояние лексера.
    let mut in_block = false;
    let mut in_triple = false;
    // Активная кавычка строкового литерала, если мы внутри строки.
    let mut in_string: Option<char> = None;
    // Внутри однострочного комментария до конца текущей строки.
    let mut in_line_comment = false;

    while i < bytes.len() {
        let rest = &content[i..];
        let ch = content[i..].chars().next().unwrap();

        // Перевод строки завершает однострочный комментарий и сбрасывается дословно.
        if ch == '\n' {
            in_line_comment = false;
            out.push('\n');
            i += 1;
            continue;
        }

        // Внутри однострочного комментария всё гасится до конца строки.
        if in_line_comment {
            out.push(' ');
            i += ch.len_utf8();
            continue;
        }

        // Внутри блочного комментария ищем его закрытие.
        if in_block {
            if let Some((_, close)) = block {
                if rest.starts_with(close) {
                    in_block = false;
                    for _ in 0..close.chars().count() {
                        out.push(' ');
                    }
                    i += close.len();
                    continue;
                }
            }
            out.push(' ');
            i += ch.len_utf8();
            continue;
        }

        // Внутри тройной кавычки ищем её закрытие.
        if in_triple {
            if let Some(tq) = triple {
                if rest.starts_with(tq) {
                    in_triple = false;
                    for _ in 0..tq.chars().count() {
                        out.push(' ');
                    }
                    i += tq.len();
                    continue;
                }
            }
            out.push(' ');
            i += ch.len_utf8();
            continue;
        }

        // Внутри строкового литерала ищем закрывающую кавычку с учётом экранирования.
        if let Some(q) = in_string {
            if ch == '\\' {
                // Экранирующая пара: гасим оба символа, не давая `\"` закрыть строку.
                out.push(' ');
                i += ch.len_utf8();
                if i < bytes.len() {
                    let next = content[i..].chars().next().unwrap();
                    out.push(' ');
                    i += next.len_utf8();
                }
                continue;
            }
            if ch == q {
                in_string = None;
                out.push(' ');
                i += ch.len_utf8();
                continue;
            }
            out.push(' ');
            i += ch.len_utf8();
            continue;
        }

        // Вне всех специальных состояний: распознаём начало нового состояния.
        // Тройная кавычка проверяется раньше одинарной двойной, чтобы не принять её
        // за пустой строковый литерал.
        if let Some(tq) = triple {
            if rest.starts_with(tq) {
                in_triple = true;
                for _ in 0..tq.chars().count() {
                    out.push(' ');
                }
                i += tq.len();
                continue;
            }
        }
        if let Some((open, _)) = block {
            if rest.starts_with(open) {
                in_block = true;
                for _ in 0..open.chars().count() {
                    out.push(' ');
                }
                i += open.len();
                continue;
            }
        }
        if line_markers.iter().any(|m| rest.starts_with(m)) {
            in_line_comment = true;
            out.push(' ');
            i += ch.len_utf8();
            continue;
        }
        if ch == '"' || ch == '\'' || ch == '`' {
            in_string = Some(ch);
            out.push(' ');
            i += ch.len_utf8();
            continue;
        }

        // Обычный исполняемый символ сохраняется без изменения.
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

/// Достоверность находки правила конституции, выведенная централизованно из карты
/// `contracts::rule_confidence`. Раньше находки получали `verified = true` безусловно;
/// теперь подтверждённой считается лишь находка правила, классифицированного как
/// `Pattern` или выше (то есть надёжного структурного сигнала). Эвристические правила
/// (если такие появятся) и любое неклассифицированное правило подтверждёнными не
/// становятся, чтобы подстрочное совпадение не выдавалось за заземлённый факт.
fn rule_verified(rule: &str) -> bool {
    use ailc_contracts::RuleConfidence;
    matches!(
        rule_confidence(rule),
        Some(RuleConfidence::Pattern | RuleConfidence::Precise)
    )
}

pub struct ConstitutionCheck {
    manifest: CapabilityManifest,
}

impl Default for ConstitutionCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstitutionCheck {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "quality.check/constitution",
                family: Family::Quality,
                engine: EngineKind::Scan,
                when_to_use: "Проверить код на соответствие конституции проекта (правила FORBID/REQUIRE/REQUIRE_EACH из .co/constitution.md).",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for ConstitutionCheck {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        // Файл правил: сначала .co/constitution.md, затем constitution.md в корне.
        let primary = ctx.root.join(".co").join("constitution.md");
        let fallback = ctx.root.join("constitution.md");
        let rules_path = if primary.is_file() {
            primary
        } else if fallback.is_file() {
            fallback
        } else {
            out.skipped = Some("нет файла конституции (.co/constitution.md)".into());
            out.summary = "quality.check/constitution: пропущено (нет файла конституции)".into();
            return Ok(out);
        };

        let text = match fs::read_to_string(&rules_path) {
            Ok(t) => t,
            Err(e) => {
                out.skipped = Some(format!(
                    "не удалось прочитать файл конституции ({}): {e}",
                    rules_path.display()
                ));
                out.summary = "quality.check/constitution: пропущено (файл нечитаем)".into();
                return Ok(out);
            }
        };

        let rules = parse_constitution(&text);
        if rules.is_empty() {
            out.skipped = Some(
                "файл конституции не содержит правил FORBID/REQUIRE/REQUIRE_EACH".into(),
            );
            out.summary = "quality.check/constitution: пропущено (нет правил)".into();
            return Ok(out);
        }

        let base = match &input.target {
            Some(t) => ctx.root.join(t),
            None => ctx.root.clone(),
        };
        let root = ctx.root.clone();

        // Один проход по дереву собирает по каждому правилу полную картину, а не первое
        // совпадение: для FORBID накапливаются ВСЕ исполняемые вхождения; для REQUIRE
        // отмечается факт хотя бы одного исполняемого вхождения по всему проекту; для
        // REQUIRE_EACH ведётся раздельный учёт релевантных файлов и тех из них, где
        // маркер действительно присутствует в исполняемом коде. Комментарии, строковые
        // литералы и тест-файлы из учёта исключаются, чтобы фейк-маркер не подделывал
        // ни срабатывание FORBID, ни закрытие требования.

        // Все исполняемые вхождения запрещённой подстроки: индекс правила -> [(file,line)].
        let mut forbid_hits: BTreeMap<usize, Vec<(String, u32)>> = BTreeMap::new();
        // Индексы REQUIRE-правил, для которых найдено хотя бы одно исполняемое вхождение.
        let mut require_seen: BTreeSet<usize> = BTreeSet::new();
        // Для REQUIRE_EACH: сколько релевантных (нетестовых исходных) файлов всего и в
        // каких из них маркер отсутствует. Индекс правила -> множество файлов без маркера.
        let mut require_each_missing: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
        // Сколько релевантных файлов суммарно осмотрено правилами REQUIRE_EACH (для метрик
        // и осознанного пропуска, когда релевантных файлов нет вовсе).
        let mut require_each_relevant_files: usize = 0;
        // Есть ли в конституции хотя бы одно правило REQUIRE_EACH.
        let has_require_each = rules
            .iter()
            .any(|r| matches!(r, ConstRule::RequireEach(_)));

        walk(&base, &mut |path| {
            let ext = ext_of(path);
            if !is_source_ext(ext) {
                return;
            }
            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => return,
            };
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            // Нормализуем разделитель пути для устойчивого вывода и для is_test_path.
            let rel = rel.replace('\\', "/");
            let is_test = is_test_path(&rel);

            // Маскируем комментарии и строковые литералы: поиск идёт по исполняемому коду.
            let masked = mask_comments_and_strings(ext, &content);
            let masked_lines: Vec<&str> = masked.lines().collect();

            // Учёт релевантных файлов для REQUIRE_EACH: тест-файлы не входят в покрытие.
            if has_require_each && !is_test {
                require_each_relevant_files += 1;
            }

            for (ri, rule) in rules.iter().enumerate() {
                match rule {
                    ConstRule::Forbid(needle) => {
                        // Запреты в тест-файлах не считаем нарушением: тесты легитимно
                        // содержат запрещённые в проде конструкции как фикстуры.
                        if is_test {
                            continue;
                        }
                        for (i, line) in masked_lines.iter().enumerate() {
                            if line.contains(needle.as_str()) {
                                forbid_hits
                                    .entry(ri)
                                    .or_default()
                                    .push((rel.clone(), (i as u32) + 1));
                            }
                        }
                    }
                    ConstRule::Require(needle) => {
                        // Глобальное требование присутствия: фейк-маркер из тестов не
                        // закрывает его, поэтому тест-файлы в зачёт не идут.
                        if is_test {
                            continue;
                        }
                        if !require_seen.contains(&ri)
                            && masked_lines.iter().any(|l| l.contains(needle.as_str()))
                        {
                            require_seen.insert(ri);
                        }
                    }
                    ConstRule::RequireEach(needle) => {
                        // Покрытие считаем только по релевантным (нетестовым) файлам.
                        if is_test {
                            continue;
                        }
                        let present = masked_lines.iter().any(|l| l.contains(needle.as_str()));
                        if !present {
                            require_each_missing
                                .entry(ri)
                                .or_default()
                                .insert(rel.clone());
                        }
                    }
                }
            }
        })?;

        // Эмитим findings. Достоверность каждой находки берётся из централизованной карты
        // contracts::rule_confidence через rule_verified, а не выставляется безусловно.
        let forbid_verified = rule_verified("constitution-forbid");
        let require_verified = rule_verified("constitution-require");

        for (ri, rule) in rules.iter().enumerate() {
            match rule {
                ConstRule::Forbid(needle) => {
                    // Находка на КАЖДОЕ исполняемое вхождение, а не только на первое.
                    if let Some(hits) = forbid_hits.get(&ri) {
                        for (file, line) in hits {
                            out.findings.push(Finding::new(
                                "constitution-forbid",
                                Severity::High,
                                format!("Запрещённое: {needle} найдено"),
                                Some(Location {
                                    file: file.clone(),
                                    line: *line,
                                }),
                                None,
                                forbid_verified,
                                "quality.check/constitution",
                            ));
                        }
                    }
                }
                ConstRule::Require(needle) => {
                    if !require_seen.contains(&ri) {
                        out.findings.push(Finding::new(
                            "constitution-require",
                            Severity::Medium,
                            format!("Требуемое отсутствует во всём проекте: {needle}"),
                            None,
                            None,
                            require_verified,
                            "quality.check/constitution",
                        ));
                    }
                }
                ConstRule::RequireEach(needle) => {
                    // Находка на КАЖДЫЙ релевантный файл, где маркер отсутствует: это и
                    // есть контроль покрытия, которого не давало старое REQUIRE.
                    if let Some(missing) = require_each_missing.get(&ri) {
                        for file in missing {
                            out.findings.push(Finding::new(
                                "constitution-require",
                                Severity::Medium,
                                format!(
                                    "Требуемое отсутствует в файле (REQUIRE_EACH): {needle}"
                                ),
                                Some(Location {
                                    file: file.clone(),
                                    line: 1,
                                }),
                                None,
                                require_verified,
                                "quality.check/constitution",
                            ));
                        }
                    }
                }
            }
        }

        out.metrics
            .push(("rules_checked".into(), rules.len() as f64));
        out.metrics
            .push(("violations".into(), out.findings.len() as f64));
        if has_require_each {
            out.metrics.push((
                "require_each_relevant_files".into(),
                require_each_relevant_files as f64,
            ));
        }
        out.summary = format!(
            "quality.check/constitution: проверено правил {}, нарушений {}",
            rules.len(),
            out.findings.len()
        );
        Ok(out)
    }
}

// ───────────────────────── quality.check/layers ─────────────────────────

/// Разобрать файл слоёв: строки вида `модуль: разрешённый1, разрешённый2`.
/// Возвращает карту модуль -> множество разрешённых зависимостей.
fn parse_layers(text: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let (module, rest) = match t.split_once(':') {
            Some(p) => p,
            None => continue,
        };
        let module = module.trim();
        if module.is_empty() {
            continue;
        }
        let allowed: BTreeSet<String> = rest
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        map.entry(module.to_string())
            .or_default()
            .extend(allowed);
    }
    map
}

pub struct LayersCheck {
    manifest: CapabilityManifest,
}

impl Default for LayersCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl LayersCheck {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "quality.check/layers",
                family: Family::Quality,
                engine: EngineKind::CodeIntel,
                when_to_use: "Проверить архитектурные слои: какие модули кому разрешено зависеть (правила из .co/layers.txt).",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for LayersCheck {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        let rules_path: PathBuf = ctx.root.join(".co").join("layers.txt");
        if !rules_path.is_file() {
            out.skipped = Some("нет файла слоёв (.co/layers.txt)".into());
            out.summary = "quality.check/layers: пропущено (нет файла слоёв)".into();
            return Ok(out);
        }

        let text = match fs::read_to_string(&rules_path) {
            Ok(t) => t,
            Err(e) => {
                out.skipped = Some(format!(
                    "не удалось прочитать файл слоёв ({}): {e}",
                    rules_path.display()
                ));
                out.summary = "quality.check/layers: пропущено (файл нечитаем)".into();
                return Ok(out);
            }
        };

        let layers = parse_layers(&text);
        if layers.is_empty() {
            out.skipped = Some(
                "файл слоёв не содержит правил вида `модуль: разрешённый1, разрешённый2`".into(),
            );
            out.summary = "quality.check/layers: пропущено (нет правил)".into();
            return Ok(out);
        }

        let graph = CodeIntelEngine::dependency_graph(ctx, input)?;

        // Нарушение: ребро from→to, где from под правилами, to тоже под правилами,
        // и to не в списке разрешённых для from.
        for (from, to) in &graph.edges {
            let allowed = match layers.get(from) {
                Some(a) => a,
                None => continue, // from не описан правилами — не наша зона
            };
            if !layers.contains_key(to) {
                continue; // to не под правилами — не ограничиваем
            }
            if !allowed.contains(to) {
                out.findings.push(Finding {
                    rule: "layer-violation".into(),
                    severity: Severity::Medium,
                    message: format!(
                        "Нарушение слоёв: {from} не должен зависеть от {to}"
                    ),
                    location: None,
                    evidence: None,
                    verified: true,
                    source: "quality.check/layers".into(),
                });
            }
        }

        out.metrics.push(("edges".into(), graph.edges.len() as f64));
        out.metrics
            .push(("violations".into(), out.findings.len() as f64));
        out.summary = format!(
            "quality.check/layers: рёбер {}, нарушений слоёв {}",
            graph.edges.len(),
            out.findings.len()
        );
        Ok(out)
    }
}

/// Регистрирует governance-capability.
pub fn register(reg: &mut Registry) {
    reg.register(Box::new(ConstitutionCheck::new()));
    reg.register(Box::new(LayersCheck::new()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Уникальная пустая временная папка для файловых фикстур (без внешних зависимостей).
    fn tmp() -> PathBuf {
        let n = CNT.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("ailc-governance-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Записать файл по относительному пути внутри корня, создав родительские каталоги.
    fn write(dir: &Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }

    /// Прогнать ConstitutionCheck по корню без подпути.
    fn run_const(root: &Path) -> CapabilityOutput {
        ConstitutionCheck::new()
            .run(&Ctx::new(root), &RunInput::default())
            .unwrap()
    }

    /// Сколько находок данного правила в выводе.
    fn count_rule(out: &CapabilityOutput, rule: &str) -> usize {
        out.findings.iter().filter(|f| f.rule == rule).count()
    }

    // ───────────────────────── разбор директив ─────────────────────────

    #[test]
    fn parse_recognises_three_directives() {
        let text = "\
FORBID unwrap()
REQUIRE LICENSE
REQUIRE_EACH // SPDX
# комментарий, не правило
просто строка
";
        let rules = parse_constitution(text);
        assert_eq!(rules.len(), 3, "должно разобраться ровно три правила");
        assert!(matches!(&rules[0], ConstRule::Forbid(s) if s == "unwrap()"));
        assert!(matches!(&rules[1], ConstRule::Require(s) if s == "LICENSE"));
        assert!(matches!(&rules[2], ConstRule::RequireEach(s) if s == "// SPDX"));
    }

    #[test]
    fn parse_require_each_is_not_misread_as_require() {
        // REQUIRE_EACH не должен попасть в ветку REQUIRE: иначе игла стала бы «_EACH ...».
        let rules = parse_constitution("REQUIRE_EACH marker");
        assert_eq!(rules.len(), 1);
        assert!(matches!(&rules[0], ConstRule::RequireEach(s) if s == "marker"));
    }

    #[test]
    fn parse_skips_empty_needles() {
        let rules = parse_constitution("FORBID \nREQUIRE \nREQUIRE_EACH ");
        assert!(rules.is_empty(), "правила с пустой иглой игнорируются");
    }

    // ───────────────────────── маскировка комментариев и литералов ─────────────────────────

    #[test]
    fn mask_hides_line_comment_c_family() {
        let src = "let x = foo(); // не делай unwrap() здесь\n";
        let masked = mask_comments_and_strings("rs", src);
        assert!(masked.contains("foo()"), "исполняемый код сохраняется");
        assert!(
            !masked.contains("unwrap()"),
            "слово из комментария замаскировано: {masked:?}"
        );
        // Число строк сохраняется (важно для номеров строк находок).
        assert_eq!(masked.lines().count(), src.lines().count());
    }

    #[test]
    fn mask_hides_python_hash_comment() {
        let src = "x = 1  # unwrap() в комментарии\n";
        let masked = mask_comments_and_strings("py", src);
        assert!(!masked.contains("unwrap()"));
        assert!(masked.contains("x = 1"));
    }

    #[test]
    fn mask_hides_string_literal() {
        // Подстрока внутри строкового литерала не является исполняемым кодом.
        let src = "let s = \"содержит unwrap() как текст\";\n";
        let masked = mask_comments_and_strings("rs", src);
        assert!(
            !masked.contains("unwrap()"),
            "литерал замаскирован: {masked:?}"
        );
    }

    #[test]
    fn mask_hides_block_comment_across_lines() {
        let src = "a();\n/* unwrap()\n still unwrap() */\nb();\n";
        let masked = mask_comments_and_strings("rs", src);
        assert!(!masked.contains("unwrap()"));
        assert!(masked.contains("a()"));
        assert!(masked.contains("b()"));
        assert_eq!(masked.lines().count(), src.lines().count());
    }

    #[test]
    fn mask_keeps_executable_occurrence() {
        let src = "value.unwrap();\n";
        let masked = mask_comments_and_strings("rs", src);
        assert!(
            masked.contains("unwrap()"),
            "исполняемый вызов остаётся видимым: {masked:?}"
        );
    }

    #[test]
    fn mask_handles_escaped_quote_in_string() {
        // Экранированная кавычка не закрывает строку преждевременно, поэтому unwrap()
        // внутри неё остаётся замаскированным до настоящего закрытия литерала.
        let src = "let s = \"a\\\" unwrap() b\"; real.unwrap();\n";
        let masked = mask_comments_and_strings("rs", src);
        // Внутристроковое вхождение исчезло, исполняемый вызов после литерала остался.
        let occurrences = masked.matches("unwrap()").count();
        assert_eq!(
            occurrences, 1,
            "ровно одно исполняемое вхождение должно уцелеть: {masked:?}"
        );
    }

    // ───────────────────────── достоверность из contracts ─────────────────────────

    #[test]
    fn verified_is_derived_from_rule_confidence() {
        // Оба правила конституции классифицированы как Pattern (Medium-сигнал),
        // следовательно подтверждены; неизвестное правило подтверждённым не считается.
        assert!(rule_verified("constitution-forbid"));
        assert!(rule_verified("constitution-require"));
        assert!(!rule_verified("несуществующее-правило-конституции"));
    }

    // ───────────────────────── поведение FORBID ─────────────────────────

    #[test]
    fn forbid_reports_every_executable_occurrence() {
        let dir = tmp();
        write(&dir, ".co/constitution.md", "FORBID unwrap()\n");
        write(
            &dir,
            "src/a.rs",
            "fn a() { x.unwrap(); }\nfn b() { y.unwrap(); }\n",
        );
        write(&dir, "src/b.rs", "fn c() { z.unwrap(); }\n");
        let out = run_const(&dir);
        assert_eq!(
            count_rule(&out, "constitution-forbid"),
            3,
            "должны найтись все три исполняемых вхождения, а не только первое"
        );
        // У каждой находки есть привязка к file:line.
        for f in out.findings.iter().filter(|f| f.rule == "constitution-forbid") {
            assert!(f.location.is_some());
            assert!(f.verified, "достоверность взята из rule_confidence (Pattern)");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn forbid_ignores_comments_and_string_literals() {
        let dir = tmp();
        write(&dir, ".co/constitution.md", "FORBID unwrap()\n");
        // Только комментарий и строковый литерал: ни одной находки быть не должно.
        write(
            &dir,
            "src/a.rs",
            "// не делай unwrap() тут\nlet s = \"unwrap() как текст\";\n",
        );
        let out = run_const(&dir);
        assert_eq!(
            count_rule(&out, "constitution-forbid"),
            0,
            "комментарий и литерал не являются нарушением FORBID"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn forbid_ignores_test_files() {
        let dir = tmp();
        write(&dir, ".co/constitution.md", "FORBID unwrap()\n");
        // Исполняемое вхождение, но в тест-файле: фикстура, не нарушение прод-кода.
        write(&dir, "src/foo_test.go", "func T() { x.unwrap() }\n");
        let out = run_const(&dir);
        assert_eq!(
            count_rule(&out, "constitution-forbid"),
            0,
            "запрет в тест-файле не считается нарушением"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // ───────────────────────── поведение REQUIRE ─────────────────────────

    #[test]
    fn require_not_satisfied_by_comment_only_occurrence() {
        let dir = tmp();
        write(&dir, ".co/constitution.md", "REQUIRE LICENSE-HEADER\n");
        // Маркер встречается ТОЛЬКО в комментарии: требование не закрыто.
        write(&dir, "src/a.rs", "// LICENSE-HEADER\nfn a() {}\n");
        let out = run_const(&dir);
        assert_eq!(
            count_rule(&out, "constitution-require"),
            1,
            "вхождение в комментарии не закрывает REQUIRE"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn require_not_satisfied_by_test_file_only() {
        let dir = tmp();
        write(&dir, ".co/constitution.md", "REQUIRE MARKER\n");
        // Маркер только в тест-файле: фейк-маркер не должен подделывать покрытие.
        write(&dir, "src/foo_test.go", "// MARKER\nfunc T() {}\n");
        write(&dir, "src/a.go", "package a\n");
        let out = run_const(&dir);
        assert_eq!(
            count_rule(&out, "constitution-require"),
            1,
            "маркер только в тесте не закрывает REQUIRE"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn require_satisfied_by_real_executable_occurrence() {
        let dir = tmp();
        write(&dir, ".co/constitution.md", "REQUIRE register_all\n");
        write(&dir, "src/a.rs", "fn boot() { register_all(); }\n");
        let out = run_const(&dir);
        assert_eq!(
            count_rule(&out, "constitution-require"),
            0,
            "настоящее исполняемое вхождение закрывает REQUIRE"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // ───────────────────────── поведение REQUIRE_EACH ─────────────────────────

    #[test]
    fn require_each_flags_only_files_without_marker() {
        let dir = tmp();
        write(&dir, ".co/constitution.md", "REQUIRE_EACH GUARD\n");
        // Один файл содержит маркер как исполняемую подстроку (покрыт), другой нет.
        write(&dir, "src/has.rs", "fn f() { let GUARD = 1; }\n");
        write(&dir, "src/missing.rs", "fn g() { do_work(); }\n");
        let out = run_const(&dir);
        let each: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.rule == "constitution-require" && f.message.contains("REQUIRE_EACH"))
            .collect();
        assert_eq!(
            each.len(),
            1,
            "ровно один файл без маркера должен попасть в находки покрытия"
        );
        assert!(
            each[0]
                .location
                .as_ref()
                .is_some_and(|l| l.file.ends_with("missing.rs")),
            "находка указывает на файл без маркера"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn require_each_ignores_marker_in_comment_or_test() {
        let dir = tmp();
        write(&dir, ".co/constitution.md", "REQUIRE_EACH MARK\n");
        // Маркер только в комментарии: покрытие НЕ закрыто, файл нарушает требование.
        write(&dir, "src/a.rs", "// MARK\nfn a() {}\n");
        // Тест-файл вообще не входит в покрытие (не релевантен) и находки не даёт.
        write(&dir, "src/a_test.go", "// MARK\nfunc T() {}\n");
        let out = run_const(&dir);
        let each = out
            .findings
            .iter()
            .filter(|f| f.rule == "constitution-require" && f.message.contains("REQUIRE_EACH"))
            .count();
        assert_eq!(
            each, 1,
            "файл a.rs нарушает покрытие (маркер только в комментарии), тест не учитывается"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn require_each_all_covered_yields_no_findings() {
        let dir = tmp();
        write(&dir, ".co/constitution.md", "REQUIRE_EACH MARK\n");
        write(&dir, "src/a.rs", "fn a() { let MARK = 1; }\n");
        write(&dir, "src/b.rs", "fn b() { use_MARK(); }\n");
        let out = run_const(&dir);
        let each = out
            .findings
            .iter()
            .filter(|f| f.rule == "constitution-require" && f.message.contains("REQUIRE_EACH"))
            .count();
        assert_eq!(each, 0, "все релевантные файлы покрыты — нарушений нет");
        let _ = fs::remove_dir_all(&dir);
    }

    // ───────────────────────── пропуски и метрики ─────────────────────────

    #[test]
    fn skipped_when_no_constitution_file() {
        let dir = tmp();
        write(&dir, "src/a.rs", "fn a() {}\n");
        let out = run_const(&dir);
        assert!(out.skipped.is_some(), "без файла конституции проверка пропущена");
        assert!(out.findings.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }
}
