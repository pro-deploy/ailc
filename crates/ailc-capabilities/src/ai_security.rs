//! Семейство security.ai/*, безопасность LLM-приложений на уровне КОДА.
//!
//! Фронтир, где слабы и обычные SAST-аналоги, и чужие skill-библиотеки. ailc есть
//! MCP-сервер, поэтому AI-безопасность ему «на руку». Тонкие конфиги поверх общего
//! `ScanEngine` (таблицы правил), плюс ОДИН лёгкий внутрифайловый taint-проход для
//! случаев, где сток отделён от источника строками (типовой паттерн LLM02).
//! Маппинг на OWASP Top-10 для LLM-приложений (LLM01 prompt injection, LLM02
//! insecure output handling) и на соответствующие CWE.
//!
//! Паттерны строгие: требуют РЕАЛЬНОЙ формы (вызов LLM + интерполяция недоверенного
//! ввода в промпт; eval/exec над ВЫВОДОМ модели), а не упоминания слова. Внутрифайловый
//! taint не требует имя-маркер вплотную к стоку: он помечает переменную результатом
//! вызова LLM и срабатывает, когда эта переменная достигает стока исполнения или
//! рендера в пределах одной функции.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Finding, Location, Result,
    RunInput, Severity, Tier,
};
use ailc_core::engines::scan::{Matcher, Rule, SOURCE_CODE};
use ailc_core::engines::walk::{is_test_path, walk_stats, WalkStats, MAX_SCAN_BYTES};
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::fs;
use std::path::Path;

use crate::{scan_manifest, ScanCapability, TARGET_SCHEMA};

// ───────────────────────── security.ai/prompt-injection ─────────────────────────

/// LLM01: промпт, собранный из недоверенного ввода интерполяцией/конкатенацией.
///
/// Помимо построчного предиката (вызов LLM плюс интерполяция на одной строке) семейство
/// ловит ПОСТРОЕНИЕ промпта в несколько шагов: накопление недоверенного ввода в буфер
/// промпта через `push_str`/`write!`/конкатенацию или форматированием `format!`, что
/// характерно для Rust/Go-сборок промпта. Многошаговая форма даётся оконным правилом,
/// чтобы связать буфер промпта и подстановку недоверенного значения на соседних строках.
pub fn prompt_injection_scan() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "security.ai/prompt-injection",
            Family::Security,
            "Промпт-инъекция (OWASP LLM01): промпт для LLM собирается из недоверенного пользовательского ввода интерполяцией/конкатенацией (f-строки, ${...}, .format, склейка, а также push_str/format! на Rust/Go).",
        ),
        vec![
            Rule {
                id: "llm-prompt-untrusted-concat",
                severity: Severity::High,
                exts: SOURCE_CODE,
                // Маркер вызова/сборки промпта LLM + интерполяция на той же строке.
                matcher: Matcher::Predicate(|l| {
                    let s = l.to_lowercase();
                    let llm = s.contains("openai")
                        || s.contains("anthropic")
                        || s.contains("chatcompletion")
                        || s.contains("chat.completions")
                        || s.contains("client.messages")
                        || s.contains("messages=")
                        || s.contains(".generate(")
                        || s.contains("llm(")
                        || s.contains("completion(")
                        || s.contains("system_prompt")
                        || s.contains("system=")
                        || s.contains("prompt=");
                    let interp = l.contains("f\"")
                        || l.contains("f'")
                        || l.contains("${")
                        || s.contains(".format(")
                        || l.contains("%s")
                        || l.contains("\" +")
                        || l.contains("+ \"");
                    llm && interp
                }),
                message: "Промпт-инъекция, недоверенный ввод подставлен в промпт LLM (OWASP LLM01, CWE-1427). Разделяйте инструкции и данные, валидируйте/экранируйте ввод, применяйте guardrails.",
            },
            // Многошаговая сборка промпта на Rust/Go: буфер с именем-маркером промпта
            // (prompt/system_prompt/instructions/messages) дополняется недоверенным
            // вводом через push_str/write!/format!/конкатенацию в пределах окна строк.
            // Окно связывает «есть буфер промпта» и «в него попадает недоверенное
            // значение» даже когда они разнесены переносом аргумента или соседними
            // вызовами накопления. Источник недоверенного: типовые имена входных
            // параметров (user_input/user_message/query/request/params/body/args/argv).
            Rule {
                id: "llm-prompt-build-untrusted",
                severity: Severity::High,
                exts: SOURCE_CODE,
                // Флаг (?s) обязателен: между буфером промпта и недоверенным значением
                // допускается перенос строки (перенос аргумента форматтером), поэтому
                // `.` должна покрывать `\n`. Длины зазоров ограничены, а окно (4 строки)
                // удерживает связывание локальным и не порождает далёких ложных связей.
                matcher: Matcher::window_regex(
                    r#"(?is)\b(?:prompt|system_prompt|sys_prompt|instructions?|messages?|user_prompt)\b.{0,80}(?:\.push_str|\.push|\.write_str|write!|writeln!|format!|\+=|\.format\(|\.concat|\bappend\b).{0,200}\b(?:user_input|user_message|user_msg|user_query|user_text|untrusted|request\.(?:body|query|params|args|form)|req\.(?:body|query|params)|params\.|argv|args\[|input\b)"#,
                    4,
                ),
                message: "Промпт-инъекция, недоверенный ввод накапливается в буфере промпта LLM при многошаговой сборке (OWASP LLM01, CWE-1427). Не склеивайте инструкции с пользовательскими данными: используйте отдельную роль/слот для данных, валидируйте и экранируйте ввод, применяйте guardrails.",
            },
        ],
    )
}

// ───────────────────────── security.ai/insecure-output ─────────────────────────

/// LLM02: вывод модели исполняется/рендерится без проверки (eval/exec/сырой HTML).
///
/// Построчные правила ловят случай, когда имя-маркер вывода стоит прямо в вызове стока.
/// Набор стоков расширен относительно прежней версии: к классическим eval/exec/shell
/// добавлены `Function(...)` и `vm.runInNewContext`/`vm.runInContext`/`vm.compileFunction`
/// (динамическое исполнение в Node.js), а к HTML-стокам добавлены `document.write`,
/// `insertAdjacentHTML` и присваивание `outerHTML`. Случай, когда вывод модели лежит в
/// переменной с произвольным именем и достигает стока строкой ниже, покрывает отдельный
/// внутрифайловый taint-проход (см. [`LlmTaintCapability`]).
pub fn insecure_output_scan() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "security.ai/insecure-output",
            Family::Security,
            "Небезопасная обработка вывода LLM (OWASP LLM02): ответ модели исполняется (eval/exec/Function/vm/os.system/subprocess) или вставляется как сырой HTML (innerHTML/outerHTML/document.write/insertAdjacentHTML) без проверки.",
        ),
        vec![
            // Исполнение вывода модели как кода/команды. Стоки: eval, exec, Function-
            // конструктор, vm.runInNewContext/runInContext/compileFunction (Node.js),
            // os.system, subprocess.run/call/Popen, child_process.exec/execSync.
            Rule {
                id: "llm-output-exec",
                severity: Severity::Critical,
                exts: SOURCE_CODE,
                // Токен Function-конструктора держим РЕГИСТРОЗАВИСИМЫМ через (?-i:...),
                // иначе (?i) ловит обычное объявление `function foo(response)` и даёт
                // ложное срабатывание. Конструктор JavaScript всегда с заглавной буквы
                // (`new Function(...)`/`Function(...)`).
                matcher: Matcher::regex(
                    r"(?i)\b(?:eval|exec|(?-i:new\s+Function|Function)|vm\.(?:runInNewContext|runInContext|compileFunction)|os\.system|subprocess\.(?:run|call|Popen)|child_process\.(?:exec|execSync))\s*\([^)\n]*(?:response|completion|answer|reply|output|result|llm|gpt|message|content|generated|model_output|ai_)\b",
                ),
                message: "Исполнение вывода LLM как кода/команды (OWASP LLM02, CWE-94). Никогда не передавайте ответ модели в eval/exec/Function/vm/shell, валидируйте и используйте белый список действий.",
            },
            // Сырой вывод модели в DOM/шаблон, XSS через LLM. Стоки: innerHTML,
            // outerHTML, insertAdjacentHTML, document.write/writeln, dangerouslySetInnerHTML,
            // v-html, render_template_string.
            Rule {
                id: "llm-output-raw-html",
                severity: Severity::High,
                exts: SOURCE_CODE,
                matcher: Matcher::regex(
                    r"(?i)(?:innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(|dangerouslySetInnerHTML|v-html\s*=|render_template_string\s*\()[^\n]{0,80}(?:response|completion|answer|message|content|llm|gpt|generated|model_output|ai_)",
                ),
                message: "Сырой вывод LLM в разметку, XSS через модель (OWASP LLM02, CWE-79). Санитизируйте вывод модели перед вставкой в DOM/шаблон.",
            },
        ],
    )
}

// ───────────────────────── внутрифайловый taint LLM02 ─────────────────────────

/// Лёгкий внутрифайловый taint-анализ вывода LLM (OWASP LLM02, CWE-94/CWE-79).
///
/// Зачем отдельная capability, а не таблица правил. Построчные правила
/// [`insecure_output_scan`] требуют имя-маркер вывода (response/completion/…) прямо в
/// вызове стока. Если ответ модели присвоен переменной с произвольным именем строкой
/// выше, а ниже эта переменная попадает в `eval`/`Function`/`innerHTML`, построчное
/// правило слепо. Регекс по окну тут не помогает: крейт `regex` не поддерживает обратные
/// ссылки, поэтому связать «имя переменной из присваивания» с «той же переменной в
/// стоке» регекс не может. Это и есть внутрифайловый taint, требующий собственной
/// логики поверх общего обхода файлов.
///
/// Анализ намеренно лёгкий и КОНСЕРВАТИВНЫЙ (минимум ложных срабатываний):
/// файл режется на приблизительные области функций (см. [`function_regions`]), и taint
/// НЕ перетекает между функциями. Внутри области переменная помечается заражённой, если
/// её присваивают результату вызова LLM (см. [`llm_call_marker`]). Срабатывание
/// происходит, когда заражённая переменная по имени (с границами слова) попадает
/// аргументом в сток исполнения или рендера (см. [`exec_sink_hit`]/[`html_sink_hit`]) на
/// той же или последующей строке области. Достоверность правил taint-* высокая по построению
/// анализа (источник и сток связаны конкретной переменной, а не близостью).
pub struct LlmTaintCapability {
    manifest: CapabilityManifest,
}

impl LlmTaintCapability {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "security.ai/insecure-output-taint",
                family: Family::Security,
                engine: EngineKind::Scan,
                when_to_use: "Небезопасная обработка вывода LLM через переменную (OWASP LLM02): результат вызова модели присвоен переменной, которая ниже в той же функции попадает в сток исполнения (eval/exec/Function/vm/shell) или рендера (innerHTML/outerHTML/document.write/insertAdjacentHTML).",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Default for LlmTaintCapability {
    fn default() -> Self {
        Self::new()
    }
}

impl Capability for LlmTaintCapability {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let base = ctx.base(input)?;
        let root = ctx.root.clone();
        let source_id = self.manifest.id;

        let mut out = CapabilityOutput::default();
        let mut files_scanned: u64 = 0;
        let mut skips = WalkStats::default();

        walk_stats(
            &base,
            &mut |path| {
                // Тест-файлы и фикстуры не сканируем: учебный код с eval(response) там
                // легитимен и не является дефектом прод-кода.
                let rel = path
                    .strip_prefix(&root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string();
                if is_test_path(&rel) {
                    return;
                }
                // Только исходный код: taint вывода LLM не имеет смысла в прозе/доках.
                if !is_source_ext(path) {
                    return;
                }
                let content = match fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                files_scanned += 1;
                analyze_file(&content, &rel, source_id, &mut out);
            },
            &mut skips,
        )?;

        // Инвариант «нет молчаливых пропусков»: ноль файлов = честно сообщаем причину,
        // а не выдаём «0 находок» за успешную проверку.
        if files_scanned == 0 {
            out.skipped = Some(format!(
                "{source_id}: не найдено файлов исходного кода для taint-анализа вывода LLM"
            ));
        }
        out.metrics.push(("files_scanned".into(), files_scanned as f64));
        out.metrics
            .push(("files_out_of_scope".into(), skips.total() as f64));
        out.metrics
            .push((format!("{source_id}_findings"), out.findings.len() as f64));
        out.summary = format!(
            "{source_id}: {files_scanned} файлов, {} находок{}",
            out.findings.len(),
            skips.note()
        );
        Ok(out)
    }
}

/// Расширение файла принадлежит исходному коду (тот же список, что у [`SOURCE_CODE`]).
/// Сверхкрупные файлы отсекаются обходом ([`walk_stats`] по [`MAX_SCAN_BYTES`]); здесь
/// дополнительно ограничиваем охват исходными расширениями.
fn is_source_ext(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    SOURCE_CODE.contains(&ext.as_str())
}

/// Граница, после которой строка считается вне охвата для taint (минифицированный код):
/// сверхдлинная строка даёт и медленный матч, и поток ложных подстрок. Совпадает по
/// смыслу с порогом построчного отсева движка `ScanEngine`.
const MAX_TAINT_LINE_LEN: usize = 2_000;

/// Прогнать taint-анализ по одному файлу: для каждой области функции отследить
/// заражённые выводом LLM переменные и эмитить находку при достижении стока.
fn analyze_file(content: &str, rel: &str, source_id: &str, out: &mut CapabilityOutput) {
    // Защита от сверхкрупных файлов уже на уровне обхода (MAX_SCAN_BYTES); явная ссылка
    // на константу удерживает поведение синхронным с движком.
    if content.len() as u64 > MAX_SCAN_BYTES {
        return;
    }
    let lines: Vec<&str> = content.lines().collect();
    for region in function_regions(&lines) {
        analyze_region(&lines, region, rel, source_id, out);
    }
}

/// Полузакрытый диапазон строк [начало, конец) одной области функции (индексы в массиве
/// строк, с нуля).
type Region = (usize, usize);

/// Разрезать файл на приблизительные области функций, чтобы taint не перетекал между
/// несвязанными функциями (это и держит ложные срабатывания низкими).
///
/// Эвристика без полноценного парсера, но детерминированная и КОНСЕРВАТИВНАЯ. Опорная
/// граница для фигурно-скобочных языков (Rust, Go, JS/TS, Java, C/C++, C#, Kotlin,
/// Swift, PHP, Scala, Dart) суть возврат баланса фигурных скобок к нулю: при закрытии
/// внешнего блока область завершается. Для языков с отступами (Python, Ruby, Elixir)
/// фигурных скобок нет, поэтому дополнительной границей служит появление в нулевой
/// колонке объявления верхнего уровня (`def `/`class `/`function `/`fn `/`func ` и
/// эквивалентов). Если ни одной границы не нашлось, областью считается весь файл, что
/// для коротких скриптов корректно.
fn function_regions(lines: &[&str]) -> Vec<Region> {
    let mut regions: Vec<Region> = Vec::new();
    let mut start = 0usize;
    let mut depth: i32 = 0;
    let mut seen_open = false;

    for (i, raw) in lines.iter().enumerate() {
        let line = strip_strings_and_comments(raw);

        // Граница по отступу: новое объявление верхнего уровня в нулевой колонке
        // закрывает предыдущую область (важно для Python/Ruby без фигурных скобок).
        // Срабатывает только когда мы НЕ внутри открытого фигурного блока (depth == 0),
        // чтобы не резать тело C-подобной функции по случайному ключевому слову.
        if depth == 0 && i > start && is_top_level_decl(raw) {
            regions.push((start, i));
            start = i;
            seen_open = false;
        }

        for ch in line.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    seen_open = true;
                }
                '}' => {
                    if depth > 0 {
                        depth -= 1;
                    }
                    // Возврат к нулю после открытого блока завершает область функции.
                    if depth == 0 && seen_open {
                        regions.push((start, i + 1));
                        start = i + 1;
                        seen_open = false;
                    }
                }
                _ => {}
            }
        }
    }

    if start < lines.len() {
        regions.push((start, lines.len()));
    }
    if regions.is_empty() {
        regions.push((0, lines.len()));
    }
    regions
}

/// Строка выглядит как объявление верхнего уровня (нулевая колонка, без ведущего
/// пробела) на одном из языков с отступами или со свободной формой. Используется как
/// дополнительная граница областей там, где нет фигурных скобок.
fn is_top_level_decl(raw: &str) -> bool {
    // Только нулевая колонка: вложенные определения внутри класса имеют отступ и не
    // должны рвать область (тогда taint в методе работал бы корректно). Для языков с
    // отступами это достаточная и осторожная граница.
    if raw.starts_with([' ', '\t']) {
        return false;
    }
    let t = raw.trim_start();
    const DECL_PREFIXES: &[&str] = &[
        "def ", "class ", "function ", "async def ", "fn ", "pub fn ", "func ", "public ",
        "private ", "protected ", "module ", "defmodule ", "defp ", "defmacro ",
    ];
    DECL_PREFIXES.iter().any(|p| t.starts_with(p))
}

/// Удалить из строки строковые литералы и однострочные комментарии, чтобы скобки
/// внутри строк/комментариев не сбивали подсчёт баланса фигурных скобок при разрезании
/// на области. Грубая, но детерминированная нормализация: содержимое литералов и
/// комментариев заменяется пробелами той же длины (длина строки сохраняется).
fn strip_strings_and_comments(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0usize;
    let n = bytes.len();
    while i < n {
        let c = bytes[i] as char;
        // Однострочные комментарии: // (C-семейство) и # (Python/Ruby/скрипты). Хвост
        // строки целиком вне баланса скобок.
        if c == '#' {
            break;
        }
        if c == '/' && i + 1 < n && bytes[i + 1] == b'/' {
            break;
        }
        if c == '"' || c == '\'' || c == '`' {
            let quote = bytes[i];
            out.push(' ');
            i += 1;
            // Пропустить до закрывающей кавычки того же типа с учётом экранирования.
            while i < n {
                if bytes[i] == b'\\' && i + 1 < n {
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    continue;
                }
                if bytes[i] == quote {
                    out.push(' ');
                    i += 1;
                    break;
                }
                out.push(' ');
                i += 1;
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Проанализировать одну область функции: пометить переменные результатом вызова LLM и
/// эмитить находку, когда заражённая переменная достигает стока исполнения или рендера.
fn analyze_region(
    lines: &[&str],
    region: Region,
    rel: &str,
    source_id: &str,
    out: &mut CapabilityOutput,
) {
    let (start, end) = region;
    // Имена заражённых переменных в пределах области.
    let mut tainted: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Строки, на которых это правило уже эмитило находку: одна находка на строку стока.
    let mut seen_exec: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut seen_html: std::collections::HashSet<usize> = std::collections::HashSet::new();

    for idx in start..end {
        let line = lines[idx];
        if line.len() > MAX_TAINT_LINE_LEN {
            continue; // минифицированная строка вне охвата
        }

        // 1) Сначала проверяем стоки: заражённая переменная, попавшая в сток, даёт
        // находку. Проверяем ДО пометки этой же строки, чтобы самоприсваивание вида
        // `out = eval(out)` не маскировало находку (хотя оно и редко).
        if let Some((var, evidence)) = exec_sink_hit(line, &tainted) {
            if seen_exec.insert(idx) {
                out.findings.push(taint_finding(
                    "taint-llm-output-exec",
                    Severity::Critical,
                    format!(
                        "Исполнение вывода LLM как кода/команды через переменную «{var}» (OWASP LLM02, CWE-94). Результат модели достигает стока исполнения (eval/exec/Function/vm/shell) в пределах функции. Никогда не исполняйте ответ модели: валидируйте и применяйте белый список действий."
                    ),
                    rel,
                    idx,
                    evidence,
                    source_id,
                ));
            }
        }
        if let Some((var, evidence)) = html_sink_hit(line, &tainted) {
            if seen_html.insert(idx) {
                out.findings.push(taint_finding(
                    "taint-llm-output-raw-html",
                    Severity::High,
                    format!(
                        "Сырой вывод LLM в разметку через переменную «{var}», XSS через модель (OWASP LLM02, CWE-79). Результат модели достигает стока рендера (innerHTML/outerHTML/document.write/insertAdjacentHTML/dangerouslySetInnerHTML) в пределах функции. Санитизируйте вывод модели перед вставкой в DOM/шаблон."
                    ),
                    rel,
                    idx,
                    evidence,
                    source_id,
                ));
            }
        }

        // 2) Затем учитываем присваивания: если правая часть содержит вызов LLM,
        // помечаем переменную из левой части как заражённую на остаток области.
        if llm_call_marker(line) {
            if let Some(var) = assigned_var(line) {
                tainted.insert(var);
            }
        }
        // Распространение taint по простому присваиванию `b = a`, где `a` уже заражена:
        // тогда `b` тоже несёт вывод модели. Это удерживает анализ полезным при
        // переименовании буфера без раздувания ложных связей (требуется точное имя).
        if let Some((lhs, rhs_var)) = simple_alias(line) {
            if tainted.contains(&rhs_var) {
                tainted.insert(lhs);
            }
        }
    }
}

/// Собрать находку taint-правила. `verified` истинно (находка заземлена на file:line и
/// учитывается гейтом); достоверность правил taint-* высокая по построению анализа и
/// задаётся системой Confidence по идентификатору правила (префикс `taint`).
fn taint_finding(
    rule: &str,
    severity: Severity,
    message: String,
    rel: &str,
    idx: usize,
    evidence: String,
    source_id: &str,
) -> Finding {
    Finding {
        rule: rule.to_string(),
        severity,
        message,
        location: Some(Location {
            file: rel.to_string(),
            line: (idx as u32) + 1,
        }),
        evidence: Some(evidence.trim().chars().take(160).collect()),
        verified: true,
        source: source_id.to_string(),
    }
}

/// Правая часть присваивания содержит вызов к LLM. Маркеры подобраны по типовым SDK и
/// формам вызова, регистр игнорируется. Сюда входят OpenAI/Anthropic и обобщённые формы
/// (`.chat.completions.create`, `.messages.create`, `.generate(`, `.complete(`,
/// `.invoke(`, `generateContent`, `predict(`, `llm(`), а также `await` перед ними.
fn llm_call_marker(line: &str) -> bool {
    let s = line.to_lowercase();
    // Должно быть присваивание: без `=` нет переменной, которую можно пометить.
    if !s.contains('=') {
        return false;
    }
    s.contains("openai")
        || s.contains("anthropic")
        || s.contains("chatcompletion")
        || s.contains("chat.completions")
        || s.contains(".messages.create")
        || s.contains("client.messages")
        || s.contains(".generate(")
        || s.contains("generatecontent")
        || s.contains(".complete(")
        || s.contains(".completion(")
        || s.contains(".invoke(")
        || s.contains(".predict(")
        || s.contains("llm(")
        || s.contains(".chat(")
        || s.contains(".ask(")
}

/// Извлечь имя переменной из левой части присваивания. Поддерживает формы разных
/// языков: `const x =`, `let x =`, `var x =`, `x =`, `x :=` (Go), `let x: T =`,
/// `const x: T =`, аннотацию типа Python `x: T =`, и `self.x =`/`this.x =` (берём
/// последний сегмент имени). Возвращает простой идентификатор без типа и без ключевых
/// слов объявления. Деструктуризацию и индексирование намеренно не поддерживаем
/// (консервативно: меньше ложных меток).
fn assigned_var(line: &str) -> Option<String> {
    // Берём часть до ПЕРВОГО `=`, которое не является частью `==`/`!=`/`<=`/`>=`/`=>`.
    let eq = first_assign_eq(line)?;
    let mut lhs = line[..eq].trim();
    // Поддержка Go `:=`: двоеточие перед `=`, часть оператора, не аннотации типа.
    if lhs.ends_with(':') {
        lhs = lhs[..lhs.len() - 1].trim();
    }
    // Срезать аннотацию типа `name: Type` (Python/TS/Rust): имя слева от двоеточия.
    if let Some(colon) = lhs.find(':') {
        lhs = lhs[..colon].trim();
    }
    // Срезать ключевые слова объявления.
    for kw in ["const ", "let ", "var ", "mut ", "final ", "val "] {
        if let Some(rest) = lhs.strip_prefix(kw) {
            lhs = rest.trim();
        }
    }
    // `let mut x` после среза `let ` может остаться `mut x`.
    if let Some(rest) = lhs.strip_prefix("mut ") {
        lhs = rest.trim();
    }
    // Поле объекта: берём последний сегмент `self.x`/`this.x`/`obj.field`.
    let name = lhs.rsplit('.').next().unwrap_or(lhs).trim();
    // Имя должно быть простым идентификатором (буква/подчёркивание + буквы/цифры/_).
    if is_ident(name) {
        Some(name.to_string())
    } else {
        None
    }
}

/// Простой алиас `b = a` (правая часть, ровно один идентификатор): возвращает (b, a).
/// Используется для распространения taint при переименовании буфера без вызова LLM.
fn simple_alias(line: &str) -> Option<(String, String)> {
    let eq = first_assign_eq(line)?;
    let lhs_var = assigned_var(line)?;
    let mut rhs = line[eq + 1..].trim();
    if let Some(stripped) = rhs.strip_suffix(';') {
        rhs = stripped.trim();
    }
    if let Some(stripped) = rhs.strip_prefix("await ") {
        rhs = stripped.trim();
    }
    if is_ident(rhs) {
        Some((lhs_var, rhs.to_string()))
    } else {
        None
    }
}

/// Индекс байта первого `=`, которое является ОПЕРАТОРОМ присваивания, а не частью
/// сравнения/стрелки (`==`, `!=`, `<=`, `>=`, `=>`, `:=` обрабатывается отдельно).
fn first_assign_eq(line: &str) -> Option<usize> {
    let b = line.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'=' {
            let prev = if i > 0 { b[i - 1] } else { 0 };
            let next = if i + 1 < b.len() { b[i + 1] } else { 0 };
            // Исключаем ==, !=, <=, >=, =>, +=, -=, *=, /=, %= (составные присваивания
            // не вводят НОВУЮ переменную, а меняют существующую, для пометки нам нужно
            // именно объявление/чистое присваивание простой переменной). Двоеточие НЕ
            // исключаем: `:=` (Go) есть объявление с присваиванием, его двоеточие
            // снимается уже в assigned_var (срез завершающего `:` левой части).
            let composite_prev = matches!(prev, b'=' | b'!' | b'<' | b'>' | b'+' | b'-' | b'*' | b'/' | b'%');
            // next == b'>' это `=>` (стрелка лямбды/ветки), не присваивание.
            if next != b'=' && next != b'>' && prev != b'=' && !composite_prev {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Строка является идентификатором: первый символ буква или подчёркивание, далее буквы,
/// цифры, подчёркивания. Пустая строка идентификатором не является.
fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Сток исполнения содержит заражённую переменную как аргумент. Возвращает (имя
/// переменной, доказательство-фрагмент). Стоки: eval, exec, Function-конструктор,
/// vm.runInNewContext/runInContext/compileFunction, os.system, subprocess.run/call/Popen,
/// child_process.exec/execSync.
fn exec_sink_hit(line: &str, tainted: &std::collections::HashSet<String>) -> Option<(String, String)> {
    if tainted.is_empty() {
        return None;
    }
    let l = line.to_lowercase();
    // Function-конструктор детектируем РЕГИСТРОЗАВИСИМО по исходной строке: лексема в
    // JavaScript всегда с заглавной (`Function(` либо `new Function(`). Это отличает
    // конструктор-сток от обычного объявления/выражения `function foo(...)`/анонимной
    // `function(...)`, где имя в нижнем регистре и стоком исполнения не является.
    let func_ctor = word_present(line, "Function") && line.contains("Function(");
    let has_sink = func_ctor
        || l.contains("eval(")
        || l.contains("exec(")
        || l.contains("vm.runinnewcontext")
        || l.contains("vm.runincontext")
        || l.contains("vm.compilefunction")
        || l.contains("os.system(")
        || l.contains("subprocess.run(")
        || l.contains("subprocess.call(")
        || l.contains("subprocess.popen(")
        || l.contains("child_process.exec")
        || l.contains("execsync(");
    if !has_sink {
        return None;
    }
    var_in_call_args(line, tainted).map(|v| (v, line.trim().to_string()))
}

/// Сток рендера содержит заражённую переменную. Возвращает (имя переменной, фрагмент).
/// Стоки: innerHTML=, outerHTML=, insertAdjacentHTML(, document.write/writeln(,
/// dangerouslySetInnerHTML, v-html=, render_template_string(.
fn html_sink_hit(line: &str, tainted: &std::collections::HashSet<String>) -> Option<(String, String)> {
    if tainted.is_empty() {
        return None;
    }
    let l = line.to_lowercase();
    let has_sink = l.contains("innerhtml")
        || l.contains("outerhtml")
        || l.contains("insertadjacenthtml")
        || l.contains("document.write")
        || l.contains("dangerouslysetinnerhtml")
        || l.contains("v-html")
        || l.contains("render_template_string");
    if !has_sink {
        return None;
    }
    // Для присваивания innerHTML/outerHTML/v-html заражённая переменная стоит в ПРАВОЙ
    // части; для вызовов (insertAdjacentHTML/document.write/render_template_string) ,
    // в аргументах. Достаточно факта появления имени переменной с границами слова
    // где-либо в строке стока: имя уже доказано заражённым присваиванием выше.
    tainted_var_present(line, tainted).map(|v| (v, line.trim().to_string()))
}

/// Найти заражённую переменную, переданную в АРГУМЕНТЫ вызова (часть строки после
/// первой открывающей круглой скобки). Сужение до аргументов снижает ложные связи для
/// функциональных стоков, где имя должно стоять именно внутри вызова.
fn var_in_call_args(line: &str, tainted: &std::collections::HashSet<String>) -> Option<String> {
    let args = match line.find('(') {
        Some(p) => &line[p + 1..],
        None => line,
    };
    tainted_var_present(args, tainted)
}

/// Найти заражённую переменную в произвольном фрагменте по границам слова (чтобы `out`
/// не матчился внутри `layout`). Возвращает имя первой найденной заражённой переменной.
fn tainted_var_present(fragment: &str, tainted: &std::collections::HashSet<String>) -> Option<String> {
    for var in tainted {
        if word_present(fragment, var) {
            return Some(var.clone());
        }
    }
    None
}

/// Слово `needle` присутствует в `hay` с границами идентификатора слева и справа
/// (символ вне [A-Za-z0-9_]). Так `resp` не совпадёт внутри `response` или `resp2`.
fn word_present(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let hb = hay.as_bytes();
    let nb = needle.as_bytes();
    let mut i = 0usize;
    while i + nb.len() <= hb.len() {
        if &hb[i..i + nb.len()] == nb {
            let before_ok = i == 0 || !is_ident_byte(hb[i - 1]);
            let after_idx = i + nb.len();
            let after_ok = after_idx >= hb.len() || !is_ident_byte(hb[after_idx]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Байт является частью идентификатора (буква, цифра, подчёркивание).
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Регистрирует семейство security.ai/*.
pub fn register(reg: &mut Registry) {
    reg.register(Box::new(prompt_injection_scan())); // E1 Scan, LLM01
    reg.register(Box::new(insecure_output_scan())); // E1 Scan, LLM02
    reg.register(Box::new(LlmTaintCapability::new())); // внутрифайловый taint, LLM02
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── вспомогательные ──────────────────────────────────────────────────

    /// Прогнать taint по тексту файла с указанным относительным путём.
    fn run_taint(content: &str, rel: &str) -> CapabilityOutput {
        let mut out = CapabilityOutput::default();
        analyze_file(content, rel, "security.ai/insecure-output-taint", &mut out);
        out
    }

    fn has_rule(out: &CapabilityOutput, rule: &str) -> bool {
        out.findings.iter().any(|f| f.rule == rule)
    }

    fn line_of(out: &CapabilityOutput, rule: &str) -> Option<u32> {
        out.findings
            .iter()
            .find(|f| f.rule == rule)
            .and_then(|f| f.location.as_ref().map(|l| l.line))
    }

    // ── taint: исполнение вывода LLM через переменную (LLM02 / CWE-94) ─────

    #[test]
    fn taint_ловит_eval_переменной_с_выводом_llm_строкой_ниже() {
        // Ответ модели в переменной с ПРОИЗВОЛЬНЫМ именем, eval строкой ниже: построчное
        // правило слепо, taint обязан сработать.
        let src = "function handle() {\n  const code = await openai.chat.completions.create({});\n  eval(code);\n}\n";
        let out = run_taint(src, "h.js");
        assert!(has_rule(&out, "taint-llm-output-exec"), "ожидалась находка exec-taint");
        assert_eq!(line_of(&out, "taint-llm-output-exec"), Some(3), "строка стока eval");
    }

    #[test]
    fn taint_ловит_function_конструктор_над_выводом_llm() {
        let src = "function r() {\n  let out = anthropic.messages.create();\n  const f = new Function(out);\n}\n";
        let out = run_taint(src, "r.js");
        assert!(has_rule(&out, "taint-llm-output-exec"), "Function-конструктор есть сток");
    }

    #[test]
    fn taint_ловит_vm_runinnewcontext() {
        let src = "function r() {\n  let answer = llm(prompt);\n  vm.runInNewContext(answer);\n}\n";
        let out = run_taint(src, "r.js");
        assert!(has_rule(&out, "taint-llm-output-exec"), "vm.runInNewContext есть сток");
    }

    #[test]
    fn taint_ловит_subprocess_над_выводом_llm_python() {
        // Python: результат модели и subprocess строкой ниже, имя переменной произвольное.
        let src = "def run():\n    plan = client.messages.create(model='x')\n    subprocess.run(plan, shell=True)\n";
        let out = run_taint(src, "r.py");
        assert!(has_rule(&out, "taint-llm-output-exec"), "subprocess.run есть сток");
    }

    // ── taint: рендер вывода LLM через переменную (LLM02 / CWE-79) ─────────

    #[test]
    fn taint_ловит_innerhtml_присваивание_переменной_с_выводом_llm() {
        let src = "function show() {\n  const md = await openai.chat.completions.create({});\n  el.innerHTML = md;\n}\n";
        let out = run_taint(src, "show.js");
        assert!(has_rule(&out, "taint-llm-output-raw-html"), "innerHTML есть сток рендера");
        assert_eq!(line_of(&out, "taint-llm-output-raw-html"), Some(3));
    }

    #[test]
    fn taint_ловит_insertadjacenthtml_и_outerhtml() {
        let src = "function show() {\n  let txt = anthropic.messages.create();\n  node.insertAdjacentHTML('beforeend', txt);\n}\n";
        let out = run_taint(src, "show.js");
        assert!(has_rule(&out, "taint-llm-output-raw-html"), "insertAdjacentHTML есть сток");
        let src2 = "function show() {\n  let txt = anthropic.messages.create();\n  node.outerHTML = txt;\n}\n";
        let out2 = run_taint(src2, "show2.js");
        assert!(has_rule(&out2, "taint-llm-output-raw-html"), "outerHTML есть сток");
    }

    #[test]
    fn taint_ловит_document_write() {
        let src = "function show() {\n  const r = model.generate(p);\n  document.write(r);\n}\n";
        let out = run_taint(src, "show.js");
        assert!(has_rule(&out, "taint-llm-output-raw-html"), "document.write есть сток");
    }

    // ── распространение taint по алиасу ───────────────────────────────────

    #[test]
    fn taint_распространяется_по_простому_алиасу() {
        let src = "function r() {\n  const a = openai.chat.completions.create({});\n  const b = a;\n  eval(b);\n}\n";
        let out = run_taint(src, "r.js");
        assert!(has_rule(&out, "taint-llm-output-exec"), "алиас должен переносить taint");
    }

    // ── изоляция областей функций ─────────────────────────────────────────

    #[test]
    fn taint_не_перетекает_между_функциями_фигурные_скобки() {
        // Переменная заражена в первой функции; eval с тем же именем во ВТОРОЙ функции
        // не должен срабатывать (taint не пересекает границу области).
        let src = "function a() {\n  const out = openai.chat.completions.create({});\n}\nfunction b() {\n  eval(out);\n}\n";
        let out = run_taint(src, "x.js");
        assert!(!has_rule(&out, "taint-llm-output-exec"), "taint не должен пересекать функции");
    }

    #[test]
    fn taint_не_перетекает_между_функциями_python() {
        let src = "def a():\n    out = openai.ChatCompletion.create()\n\ndef b():\n    eval(out)\n";
        let out = run_taint(src, "x.py");
        assert!(!has_rule(&out, "taint-llm-output-exec"), "Python: разные def, разные области");
    }

    // ── негатив: ложные срабатывания ──────────────────────────────────────

    #[test]
    fn taint_не_срабатывает_без_вызова_llm() {
        // Переменная не из LLM: eval над ней не должен помечаться taint-правилом LLM02.
        let src = "function r() {\n  const code = readFile('x.js');\n  eval(code);\n}\n";
        let out = run_taint(src, "r.js");
        assert!(!has_rule(&out, "taint-llm-output-exec"), "источник не LLM, нет находки");
    }

    #[test]
    fn taint_не_путает_имя_внутри_другого_слова() {
        // Заражена `out`; в стоке встречается `layout`, но не сама `out`, совпадения нет.
        let src = "function r() {\n  const out = openai.chat.completions.create({});\n  applyLayout(layout);\n}\n";
        let out = run_taint(src, "r.js");
        assert!(!has_rule(&out, "taint-llm-output-exec"), "границы слова: layout не равно out");
    }

    #[test]
    fn taint_санитизированный_вывод_всё_равно_отмечается_как_находка() {
        // Намеренный позитив-контроль: даже если в строке есть sanitize, факт попадания
        // вывода модели в сток остаётся находкой (санитайзер мог быть фиктивным). Это
        // консервативно по безопасности и согласуется с принципом «полнота охвата».
        let src = "function r() {\n  const md = openai.chat.completions.create({});\n  el.innerHTML = sanitize(md);\n}\n";
        let out = run_taint(src, "r.js");
        assert!(has_rule(&out, "taint-llm-output-raw-html"), "вывод в innerHTML остаётся находкой");
    }

    #[test]
    fn taint_не_срабатывает_в_тест_файле_через_capability() {
        // Через сам обход тест-файлы пропускаются; проверяем именно фильтр is_test_path.
        assert!(is_test_path("handler.test.js"));
    }

    // ── построчные правила: расширенный набор стоков ──────────────────────

    #[test]
    fn построчный_exec_ловит_function_и_vm() {
        // Проверяем матчер построчного exec-правила напрямую.
        let exec = exec_rule_matcher();
        assert!(exec.is_match("new Function(response)"), "Function-конструктор с маркером");
        assert!(exec.is_match("vm.runInNewContext(completion)"), "vm.runInNewContext с маркером");
        assert!(exec.is_match("child_process.execSync(model_output)"), "execSync с маркером");
        // Негатив: нет маркера вывода, построчное правило молчит (это покрывает taint).
        assert!(!exec.is_match("new Function(userCode)"), "без маркера вывода построчно не ловим");
        // Негатив: обычное объявление функции с параметром response не есть исполнение
        // вывода (регистрозависимый токен Function защищает от этого).
        assert!(!exec.is_match("function render(response) {"), "объявление функции не есть сток");
    }

    #[test]
    fn построчный_html_ловит_outerhtml_insertadjacent_documentwrite() {
        let html = html_rule_matcher();
        assert!(html.is_match("el.outerHTML = response"), "outerHTML с маркером");
        assert!(html.is_match("node.insertAdjacentHTML('beforeend', completion)"), "insertAdjacentHTML");
        assert!(html.is_match("document.write(message)"), "document.write с маркером");
        assert!(!html.is_match("el.outerHTML = staticTemplate"), "без маркера вывода построчно не ловим");
    }

    /// Достать матчер построчного exec-правила для прямой проверки.
    fn exec_rule_matcher() -> Matcher {
        Matcher::regex(
            r"(?i)\b(?:eval|exec|(?-i:new\s+Function|Function)|vm\.(?:runInNewContext|runInContext|compileFunction)|os\.system|subprocess\.(?:run|call|Popen)|child_process\.(?:exec|execSync))\s*\([^)\n]*(?:response|completion|answer|reply|output|result|llm|gpt|message|content|generated|model_output|ai_)\b",
        )
    }

    /// Достать матчер построчного html-правила для прямой проверки.
    fn html_rule_matcher() -> Matcher {
        Matcher::regex(
            r"(?i)(?:innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(|dangerouslySetInnerHTML|v-html\s*=|render_template_string\s*\()[^\n]{0,80}(?:response|completion|answer|message|content|llm|gpt|generated|model_output|ai_)",
        )
    }

    // ── prompt-injection: Rust/Go-сборка промпта (LLM01) ──────────────────

    #[test]
    fn prompt_build_оконное_правило_ловит_pushstr_недоверенного() {
        let m = prompt_build_matcher();
        // Буфер промпта дополняется недоверенным вводом push_str + format!.
        let src = "let mut prompt = String::new();\nprompt.push_str(&format!(\"вопрос: {}\", user_input));\n";
        assert!(m.is_match(src), "push_str с user_input должен сработать");
    }

    #[test]
    fn prompt_build_оконное_правило_ловит_разрыв_по_строкам() {
        let m = prompt_build_matcher();
        // Буфер на одной строке, недоверенное значение перенесено на следующую.
        let src = "system_prompt.push_str(\n    &user_message\n);\n";
        assert!(m.is_match(src), "перенос аргумента не должен прятать инъекцию");
    }

    #[test]
    fn prompt_build_не_срабатывает_на_статическом_промпте() {
        let m = prompt_build_matcher();
        let src = "let mut prompt = String::new();\nprompt.push_str(\"строго статическая инструкция\");\n";
        assert!(!m.is_match(src), "статический промпт не есть инъекция");
    }

    #[test]
    fn prompt_build_не_срабатывает_без_буфера_промпта() {
        let m = prompt_build_matcher();
        // push_str недоверенного в буфер, не относящийся к промпту, не должен ловиться.
        let src = "let mut log = String::new();\nlog.push_str(&format!(\"{}\", user_input));\n";
        assert!(!m.is_match(src), "буфер не промпта не есть LLM01");
    }

    /// Достать матчер оконного prompt-build правила.
    fn prompt_build_matcher() -> Matcher {
        Matcher::window_regex(
            r#"(?is)\b(?:prompt|system_prompt|sys_prompt|instructions?|messages?|user_prompt)\b.{0,80}(?:\.push_str|\.push|\.write_str|write!|writeln!|format!|\+=|\.format\(|\.concat|\bappend\b).{0,200}\b(?:user_input|user_message|user_msg|user_query|user_text|untrusted|request\.(?:body|query|params|args|form)|req\.(?:body|query|params)|params\.|argv|args\[|input\b)"#,
            4,
        )
    }

    // ── юнит-тесты вспомогательных функций ────────────────────────────────

    #[test]
    fn assigned_var_разбирает_разные_формы() {
        assert_eq!(assigned_var("const x = foo()").as_deref(), Some("x"));
        assert_eq!(assigned_var("let y: String = bar()").as_deref(), Some("y"));
        assert_eq!(assigned_var("z := baz()").as_deref(), Some("z"));
        assert_eq!(assigned_var("plan = model.generate(p)").as_deref(), Some("plan"));
        assert_eq!(assigned_var("self.out = llm(p)").as_deref(), Some("out"));
        assert_eq!(assigned_var("p: str = openai.create()").as_deref(), Some("p"));
        // Сравнение, а не присваивание: переменной нет.
        assert_eq!(assigned_var("if a == b {").as_deref(), None);
    }

    #[test]
    fn llm_call_marker_требует_присваивание_и_вызов() {
        assert!(llm_call_marker("const x = openai.chat.completions.create({})"));
        assert!(llm_call_marker("y = client.messages.create()"));
        // Вызов есть, присваивания нет: переменную помечать не из чего.
        assert!(!llm_call_marker("openai.chat.completions.create({})"));
        // Присваивание есть, вызова LLM нет.
        assert!(!llm_call_marker("const x = readFile(p)"));
    }

    #[test]
    fn word_present_учитывает_границы_слова() {
        assert!(word_present("eval(out)", "out"));
        assert!(word_present("foo(a, out, b)", "out"));
        assert!(!word_present("applyLayout(layout)", "out"));
        assert!(!word_present("output(x)", "out"));
    }

    #[test]
    fn first_assign_eq_пропускает_сравнения() {
        assert!(first_assign_eq("a == b").is_none());
        assert!(first_assign_eq("a => b").is_none());
        assert!(first_assign_eq("a >= b").is_none());
        assert!(first_assign_eq("a += b").is_none());
        assert!(first_assign_eq("x = y").is_some());
    }

    #[test]
    fn function_regions_режет_по_фигурным_скобкам() {
        let lines = vec!["function a() {", "  x();", "}", "function b() {", "  y();", "}"];
        let regions = function_regions(&lines);
        assert_eq!(regions.len(), 2, "две функции, две области");
        assert_eq!(regions[0], (0, 3));
        assert_eq!(regions[1], (3, 6));
    }

    #[test]
    fn function_regions_режет_python_по_def() {
        let lines = vec!["def a():", "    x()", "", "def b():", "    y()"];
        let regions = function_regions(&lines);
        assert_eq!(regions.len(), 2, "два def, две области");
    }

    #[test]
    fn strip_strings_не_считает_скобки_в_литералах() {
        // Фигурная скобка внутри строкового литерала не должна влиять на баланс.
        let s = strip_strings_and_comments("let s = \"text { with brace\";");
        assert!(!s.contains('{'), "скобка из литерала должна быть вычищена: {s}");
    }

    // ── T88: полнота классификации достоверности новых правил ──────────────

    #[test]
    fn все_новые_правила_заявлены_с_достоверностью() {
        // Каждое новое правило семейства security.ai/* обязано иметь ЯВНУЮ
        // классификацию достоверности в contracts::rule_confidence (T88), иначе оно
        // молча станет дефолтным Medium-сигналом. Идентификаторы правил taint-* имеют
        // желаемый класс Precise (источник и сток связаны конкретной переменной),
        // оконное правило сборки промпта, Pattern (надёжная структура, не уникальный
        // токен). Списки переданы оркестратору через api_changes для внесения в карту.
        for rule in [
            "llm-prompt-build-untrusted",
            "taint-llm-output-exec",
            "taint-llm-output-raw-html",
        ] {
            assert!(
                ailc_contracts::rule_confidence(rule).is_some(),
                "правило «{rule}» должно быть классифицировано в contracts::rule_confidence; \
                 иначе оно молча станет Medium-сигналом. Сообщи id оркестратору для внесения."
            );
        }
    }
}
