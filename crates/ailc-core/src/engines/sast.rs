//! Глубокий SAST на AST — структурный анализ безопасности через tree-sitter.
//!
//! Включается ТОЛЬКО по явному намерению «полный пентест» (Tier::Enterprise) — в
//! обычном прогоне не участвует. Преимущество над regex-OWASP: смотрит не на текст,
//! а на СТРУКТУРУ. Напр. `eval("const")` не находка, а `eval(userInput)` — находка
//! (аргумент не литерал). Это режет ложные срабатывания, на которых шумит regex.

use super::codeintel::{callee_name, is_call_node, lang_for_ext, ts_language};
use super::walk::{ext_of, walk};
use ailc_contracts::{Ctx, Finding, Location, Result, RunInput, Severity};
use std::collections::{HashMap, HashSet};
use std::fs;
use tree_sitter::{Node, Parser};

/// Предел глубины рекурсии taint-обхода (T13): на типичном исходнике AST редко
/// глубже нескольких десятков уровней, поэтому порог 256 заведомо не режет реальные
/// деревья, но защищает процесс от переполнения стека на патологически вложенном вводе.
/// При panic=abort в release-профиле переполнение стека убивает весь процесс, поэтому
/// лимит обязателен.
const MAX_TAINT_DEPTH: u32 = 256;

#[derive(Default)]
pub struct SastReport {
    pub findings: Vec<Finding>,
    /// Файлов разобрано через AST.
    pub files: usize,
    /// Пропущено из-за ошибки чтения файла (T15): счётчик честного охвата.
    pub skipped_read: usize,
    /// Пропущено из-за отсутствия AST-грамматики/taint-профиля для языка (T15).
    pub skipped_lang: usize,
    /// Пропущено из-за ошибки установки грамматики или разбора (T15).
    pub skipped_parse: usize,
}

/// Структурный SAST по дереву (или по `input.target`). Только AST-языки.
pub fn scan(ctx: &Ctx, input: &RunInput) -> Result<SastReport> {
    // target валидируется (абсолютный путь / `..` не выводят за корень проекта).
    let base = ctx.base(input)?;
    let root = ctx.root.clone();
    let mut rep = SastReport::default();

    walk(&base, &mut |path| {
        let lang = lang_for_ext(ext_of(path));
        let Some(language) = ts_language(lang) else {
            // язык без AST-грамматики: исходник не относится к области охвата движка,
            // но это всё равно файл, не покрытый структурным анализом (T15).
            if is_source_like(path) {
                rep.skipped_lang += 1;
            }
            return;
        };
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => {
                rep.skipped_read += 1;
                return;
            }
        };
        let mut parser = Parser::new();
        if parser.set_language(&language).is_err() {
            rep.skipped_parse += 1;
            return;
        }
        let Some(tree) = parser.parse(&content, None) else {
            rep.skipped_parse += 1;
            return;
        };
        rep.files += 1;
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        let bytes = content.as_bytes();

        // Обход всех узлов; для каждого вызова — структурные правила.
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if is_call_node(lang, node.kind()) {
                if let Some(callee) = callee_name(&node, bytes) {
                    check_call(&node, &callee, bytes, &rel, &mut rep.findings);
                }
            }
            let mut cur = node.walk();
            for ch in node.children(&mut cur) {
                stack.push(ch);
            }
        }
    })?;

    Ok(rep)
}

/// Похоже ли расширение на исходный код (для честного счётчика «язык вне охвата», T15).
/// Документация/манифесты/данные исключаются, чтобы не раздувать skipped_lang шумом.
fn is_source_like(path: &std::path::Path) -> bool {
    const SRC_EXT: &[&str] = &[
        "rs", "py", "js", "jsx", "ts", "tsx", "go", "java", "rb", "php", "cs", "kt", "kts",
        "scala", "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "swift", "dart", "m", "mm", "lua",
        "pl", "pm", "sh", "bash", "zsh", "ps1", "groovy", "vb", "fs", "ex", "exs", "erl", "clj",
        "hs", "ml", "r", "jl", "nim", "zig", "vala", "d",
    ];
    SRC_EXT.contains(&ext_of(path))
}

/// Узел аргументов вызова: поле `arguments` (большинство грамматик) или
/// `value_arguments`/`call_suffix` (Kotlin/Swift — их call_expression без полей).
fn call_args<'a>(call: &Node<'a>) -> Option<Node<'a>> {
    if let Some(a) = call.child_by_field_name("arguments") {
        return Some(a);
    }
    let mut cur = call.walk();
    let kids: Vec<Node> = call.children(&mut cur).collect();
    for k in &kids {
        if matches!(k.kind(), "value_arguments" | "arguments" | "argument_list") {
            return Some(*k);
        }
        if k.kind() == "call_suffix" {
            let mut c2 = k.walk();
            let inner: Vec<Node> = k.children(&mut c2).collect();
            if let Some(v) = inner.into_iter().find(|n| n.kind() == "value_arguments") {
                return Some(v);
            }
        }
    }
    None
}

/// Kotlin/Swift оборачивают аргумент в `value_argument` — разворачиваем до значения.
/// T16: у именованного аргумента `foo(name = taintedVar)` первым именованным ребёнком
/// идёт МЕТКА (simple_identifier `name`), а не значение. Сначала пробуем поле `value`
/// (большинство грамматик его выставляют), затем при наличии метки берём ПОСЛЕДНИЙ
/// именованный ребёнок (значение), и лишь как крайний случай первый именованный.
fn unwrap_arg(n: Node) -> Node {
    if n.kind() != "value_argument" {
        return n;
    }
    if let Some(v) = n.child_by_field_name("value") {
        return v;
    }
    let mut cur = n.walk();
    let kids: Vec<Node> = n.named_children(&mut cur).collect();
    // Именованный аргумент: есть поле/узел-метка `name`, значение — последний ребёнок.
    let has_label = n.child_by_field_name("name").is_some()
        || (kids.len() >= 2 && matches!(kids[0].kind(), "simple_identifier" | "identifier"));
    if has_label {
        if let Some(last) = kids.last() {
            return *last;
        }
    }
    kids.first().copied().unwrap_or(n)
}

/// Полный текст вызываемого (`logger.info`, `pickle.load`): поле `function` или
/// первый именованный ребёнок (Kotlin/Swift, где поля нет).
fn callee_full<'a>(call: &Node<'a>) -> Option<Node<'a>> {
    call.child_by_field_name("function")
        .or_else(|| call.named_child(0))
}

/// Текст вызываемого как строка, обобщённо по грамматикам: поле `function`
/// (Python/JS/Go/PHP-func) ЛИБО `object/receiver/scope` + `name/method`
/// (Java `method_invocation`, Ruby `call`, PHP member/scoped) — даёт «obj.method».
fn callee_text(call: &Node, bytes: &[u8]) -> Option<String> {
    if let Some(f) = call.child_by_field_name("function") {
        return f.utf8_text(bytes).ok().map(String::from);
    }
    // Java `new File(...)` / `new ProcessBuilder(...)` — вызываемое = имя типа.
    if let Some(t) = call.child_by_field_name("type") {
        return t.utf8_text(bytes).ok().map(String::from);
    }
    let name = call
        .child_by_field_name("name")
        .or_else(|| call.child_by_field_name("method"));
    let recv = call
        .child_by_field_name("object")
        .or_else(|| call.child_by_field_name("receiver"))
        .or_else(|| call.child_by_field_name("scope"));
    match (recv, name) {
        (Some(r), Some(n)) => {
            let rt = r.utf8_text(bytes).ok()?;
            let nt = n.utf8_text(bytes).ok()?;
            Some(format!("{rt}.{nt}"))
        }
        (None, Some(n)) => n.utf8_text(bytes).ok().map(String::from),
        _ => callee_full(call).and_then(|f| f.utf8_text(bytes).ok().map(String::from)),
    }
}

/// Структурные правила на одном вызове.
fn check_call(call: &Node, callee: &str, bytes: &[u8], rel: &str, out: &mut Vec<Finding>) {
    let line = call.start_position().row as u32 + 1;
    let lc = callee.to_lowercase();
    let args = call_args(call);
    let first = args.and_then(|a| a.named_child(0)).map(unwrap_arg);

    // (1) Динамическое исполнение с НЕ-литеральным первым аргументом → инъекция.
    // Берём только высокосигнальные имена (без bare exec/spawn — те шумят: regex.exec).
    // eval/exec ПЕРЕНЕСЕНЫ в потоковый сток `sast/taint-dynamic-exec`: структурный
    // предикат `is_dynamic` (не литерал) флагует и eval(bar) с уже свёрнутой ветвью
    // константой, давая ложные срабатывания на безопасных файлах. Поток к стоку строит
    // taint-проход; здесь остаются командные исполнители ОС, у которых сам факт
    // непостоянного аргумента самодостаточно подозрителен.
    const EXEC: &[&str] = &["system", "popen", "execsync", "execfile", "spawnsync"];
    if EXEC.contains(&lc.as_str()) {
        if let Some(arg) = first {
            if is_dynamic(arg) {
                push(out, rel, line, "sast/dynamic-exec", Severity::High, true, None,
                    format!("Динамическое исполнение `{callee}(…)` с непроверенным аргументом — инъекция кода/команд; валидируй ввод или избегай {callee}"));
            }
        }
    }

    // (2) SQL через интерполяцию/конкатенацию строк в execute/query.
    // T11: ловим не только бинарную конкатенацию, но и f-string/template literal/
    // string-интерполяцию с ДИНАМИЧЕСКИМ операндом; склейку двух констант («a» + «b»)
    // исключаем (это не инъекция).
    const SQL: &[&str] = &["execute", "query", "rawquery", "executequery", "prepare"];
    if SQL.contains(&lc.as_str()) {
        if let Some(a) = args {
            let mut cur = a.walk();
            if a.named_children(&mut cur).any(is_dynamic_string_build) {
                push(out, rel, line, "sast/sql-injection", Severity::High, true, None,
                    "SQL-запрос собран интерполяцией/конкатенацией строк с динамическим операндом — используй параметризованный запрос".into());
            }
        }
    }

    // (3) Небезопасная десериализация — по ПОЛНОМУ имени вызова (точно, не json.loads).
    if let Some(func) = callee_full(call) {
        if let Ok(ftext) = func.utf8_text(bytes) {
            let f = ftext.to_lowercase();
            // T07: leaf-имя ловит yaml.full_load/unsafe_load/load_all/loads (подстрока
            // «yaml.load» их НЕ содержит) и алиасы. pickle.loads сохраняем подстрокой.
            let leaf = f.rsplit('.').next().unwrap_or(f.as_str());
            let yaml_de = f.contains("yaml")
                && matches!(leaf, "load" | "full_load" | "unsafe_load" | "load_all" | "loads");
            let unsafe_de = f.contains("pickle.load")
                || (leaf == "loads" && f.contains("pickle"))
                || yaml_de
                || f.contains("marshal.load")
                || f.contains("unserialize")
                || f.ends_with("objectinputstream");
            // T07: безопасно ТОЛЬКО при явном безопасном загрузчике. Loader=SafeLoader/
            // CSafeLoader/BaseLoader — ок; Loader=UnsafeLoader/Loader/FullLoader — НЕ ок
            // (FullLoader исторически имел дыры; считаем небезопасным консервативно).
            let args_lc = args
                .and_then(|a| a.utf8_text(bytes).ok())
                .map(|t| t.to_lowercase())
                .unwrap_or_default();
            let safe = args_lc.contains("safeloader") || args_lc.contains("baseloader");
            if unsafe_de && !safe {
                push(out, rel, line, "sast/unsafe-deserialize", Severity::High, true, None,
                    format!("Небезопасная десериализация `{callee}(…)` — источник данных может исполнить код; используй безопасный загрузчик"));
            }
        }
    }
}

/// Аргумент не является статическим литералом (значит — переменная/выражение/ввод).
fn is_dynamic(arg: Node) -> bool {
    let k = arg.kind();
    // Строковые литералы во всех грамматиках: string_literal, line_string_literal
    // (Swift), string_literal_double_quotes (Dart), multiline_string_literal (Kotlin)…
    if k.contains("string") && (k.contains("literal") || k == "string" || k == "string_content") {
        return false;
    }
    !matches!(
        k,
        "character_literal"
            | "char_literal"
            | "integer_literal"
            | "number"
            | "integer"
            | "float"
            | "true"
            | "false"
            | "nil"
            | "null"
            | "none"
    )
}

/// T11: узел — динамическая сборка строки запроса. Истинно, если в поддереве есть либо
/// бинарная конкатенация строки с ДИНАМИЧЕСКИМ операндом (`"..." + var`), либо
/// интерполяция/шаблонный литерал/f-строка с непостоянной вставкой (Python f-string,
/// JS template_string `${x}`, Ruby `#{x}`, PHP `"...$x..."`, C#/Kotlin интерполяция).
/// Склейка двух констант (`"a" + "b"`) НЕ считается сборкой запроса (исключаем FP).
fn is_dynamic_string_build(node: Node) -> bool {
    let k = node.kind();
    // Бинарная конкатенация: нужен строковый литерал И хотя бы один динамический операнд.
    if k.contains("binary") && has_string_descendant(node) && binary_has_dynamic_operand(node) {
        return true;
    }
    // Интерполяция/шаблон/f-строка: динамическая, если есть вставка-подвыражение.
    if is_interpolated_string(k) && interpolation_has_dynamic_part(node) {
        return true;
    }
    let mut cur = node.walk();
    let kids: Vec<Node> = node.named_children(&mut cur).collect();
    kids.into_iter().any(is_dynamic_string_build)
}

/// Узел — интерполируемый строковый литерал (шаблон/f-строка) в любой грамматике.
fn is_interpolated_string(kind: &str) -> bool {
    matches!(
        kind,
        "template_string"            // js/ts  `...${x}...`
            | "string"               // python f-строка / ruby "#{x}" / scala / kotlin
            | "f_string"             // python (некоторые версии грамматики)
            | "string_literal"       // c#/kotlin/swift интерполяция внутри
            | "interpolated_string_expression" // c#
            | "encapsed_string"      // php  "...$x..."
            | "heredoc"              // php heredoc
            | "interpolation"        // обёртка-вставка в ряде грамматик
    )
}

/// В интерполируемой строке есть динамическая вставка (а не только текст/escape).
/// Узлы-вставки в tree-sitter: `interpolation`, `template_substitution`,
/// `string_interpolation`, `substitution` либо встроенное выражение-идентификатор.
fn interpolation_has_dynamic_part(node: Node) -> bool {
    let mut stack = vec![node];
    let root_id = node.id();
    while let Some(n) = stack.pop() {
        let k = n.kind();
        if n.id() != root_id
            && matches!(
                k,
                "interpolation"
                    | "template_substitution"
                    | "string_interpolation"
                    | "substitution"
                    | "embedded_expression"
            )
        {
            // Внутри вставки должен быть НЕ только литерал (иначе это не динамика).
            let mut cur = n.walk();
            if n.named_children(&mut cur).any(is_dynamic) {
                return true;
            }
        }
        // PHP encapsed_string держит переменную прямо среди детей (variable_name);
        // встроенный идентификатор внутри строки — тоже признак динамической вставки.
        if matches!(k, "variable_name" | "simple_identifier")
            || (k == "identifier" && n.id() != root_id)
        {
            return true;
        }
        let mut cur = n.walk();
        for ch in n.named_children(&mut cur) {
            stack.push(ch);
        }
    }
    false
}

/// Бинарное выражение содержит хотя бы один НЕ-литеральный (динамический) операнд.
fn binary_has_dynamic_operand(node: Node) -> bool {
    let left = node.child_by_field_name("left");
    let right = node.child_by_field_name("right");
    match (left, right) {
        (Some(l), Some(r)) => {
            // Рекурсивно: вложенная конкатенация тоже даёт операнды.
            operand_is_dynamic(l) || operand_is_dynamic(r)
        }
        _ => {
            // Грамматика без полей left/right: обходим именованных детей.
            let mut cur = node.walk();
            let dynamic = node.named_children(&mut cur).any(operand_is_dynamic);
            dynamic
        }
    }
}

/// Операнд конкатенации динамичен: либо сам не-литерал, либо вложенная конкатенация,
/// в которой есть динамический операнд.
fn operand_is_dynamic(node: Node) -> bool {
    if node.kind().contains("binary") {
        return binary_has_dynamic_operand(node);
    }
    is_dynamic(node)
}

fn has_string_descendant(node: Node) -> bool {
    if matches!(
        node.kind(),
        "string" | "string_literal" | "interpreted_string_literal" | "string_content"
    ) {
        return true;
    }
    let mut cur = node.walk();
    let kids: Vec<Node> = node.named_children(&mut cur).collect();
    kids.into_iter().any(has_string_descendant)
}

/// Запись находки. T14: `verified` теперь параметр — детерминированные структурные
/// правила (dynamic-exec/sql-injection/unsafe-deserialize по литералу/полному имени)
/// ставят verified=true, а эвристические taint-находки (подстрочные источники, грубые
/// санитайзеры, проход насквозь) ставят verified=false до фактической верификации, и
/// заполняют `evidence` фрагментом исходного текста узла-стока.
#[allow(clippy::too_many_arguments)]
fn push(
    out: &mut Vec<Finding>,
    rel: &str,
    line: u32,
    rule: &str,
    sev: Severity,
    verified: bool,
    evidence: Option<String>,
    msg: String,
) {
    out.push(Finding {
        rule: rule.into(),
        severity: sev,
        message: msg,
        location: Some(Location {
            file: rel.to_string(),
            line,
        }),
        evidence,
        verified,
        source: "security.scan/sast".into(),
    });
}

/// Срез исходного текста узла для поля evidence (T14), обрезанный до ~120 символов и
/// схлопнутый по пробелам, чтобы многострочный сток читался в отчёте одной строкой.
fn node_evidence(node: &Node, bytes: &[u8]) -> Option<String> {
    let text = node.utf8_text(bytes).ok()?;
    let mut compact = String::new();
    let mut last_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !last_space && !compact.is_empty() {
                compact.push(' ');
            }
            last_space = true;
        } else {
            compact.push(ch);
            last_space = false;
        }
    }
    let trimmed = compact.trim_end();
    Some(trimmed.chars().take(120).collect())
}

// ───────────────────── Compliance-проход на том же AST (ПДн в логах) ─────────────────────

/// ПДн в логах СТРУКТУРНО: вызов логирования, среди аргументов которого есть
/// идентификатор с ПДн-токеном (passport/snils/inn/ssn/birthdate). Преимущества
/// над line-regex `compliance.ru/pdn-logs`: видит многострочные вызовы (аргумент
/// на другой строке) и НЕ флагует замаскированные значения (mask/redact/anonym).
pub fn scan_pii_logs(ctx: &Ctx, input: &RunInput) -> Result<SastReport> {
    let base = ctx.base(input)?;
    let root = ctx.root.clone();
    let mut rep = SastReport::default();

    walk(&base, &mut |path| {
        let lang = lang_for_ext(ext_of(path));
        let Some(language) = ts_language(lang) else {
            if is_source_like(path) {
                rep.skipped_lang += 1;
            }
            return;
        };
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => {
                rep.skipped_read += 1;
                return;
            }
        };
        let mut parser = Parser::new();
        if parser.set_language(&language).is_err() {
            rep.skipped_parse += 1;
            return;
        }
        let Some(tree) = parser.parse(&content, None) else {
            rep.skipped_parse += 1;
            return;
        };
        rep.files += 1;
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        let bytes = content.as_bytes();

        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if is_call_node(lang, node.kind()) {
                check_pii_log(&node, bytes, &rel, &mut rep.findings);
            }
            let mut cur = node.walk();
            for ch in node.children(&mut cur) {
                stack.push(ch);
            }
        }
    })?;

    Ok(rep)
}

/// Вызов похож на логирование: полное имя содержит log/console/print/fmt.
fn is_log_callee(full: &str) -> bool {
    full.contains("log") // logger.info, logging.info, log.Print, console.log
        || full.contains("console.")
        || full.starts_with("print")
        || full.starts_with("fmt.")
}

/// ПДн-токен в идентификаторе: точное совпадение токена после разбиения
/// snake_case/camelCase (чтобы `inn` не ловил `inner`/`winner`).
fn has_pii_token(ident: &str) -> bool {
    const PII: &[&str] = &["passport", "snils", "inn", "ssn", "birthdate"];
    let mut tokens: Vec<String> = Vec::new();
    for part in ident.split(['_', '.']) {
        let mut cur = String::new();
        for ch in part.chars() {
            if ch.is_uppercase() && !cur.is_empty() {
                tokens.push(cur.to_lowercase());
                cur = String::new();
            }
            cur.push(ch);
        }
        if !cur.is_empty() {
            tokens.push(cur.to_lowercase());
        }
    }
    // birthdate как пара соседних токенов (birth_date / birthDate).
    if tokens.windows(2).any(|w| w[0] == "birth" && w[1] == "date") {
        return true;
    }
    tokens.iter().any(|t| PII.contains(&t.as_str()))
}

// ───────────────────── Taint-анализ: межоператорный поток источник→сток ─────────────────────
//
// То, чего не видят ни одно-операторный SAST/regex, ни markdown-скиллы, ни базовый
// Semgrep: переменная получает значение из недоверенного источника, проходит через
// присваивания и достигает опасного стока В ПРЕДЕЛАХ ОДНОЙ ФУНКЦИИ.
//   x = request.args.get('q');  ...;  os.system(x)   → внедрение команды.
// Точность (ради которой ailc и существует): проверяется ТОЛЬКО первый аргумент
// стока — поэтому параметризованный `cursor.execute(sql, params)` НЕ ложно-срабатывает,
// и каждая функция — отдельный scope (заражение не течёт между функциями).
// Полиглот: Python, JavaScript/TypeScript, Go — на тех же tree-sitter грамматиках.

/// Источники недоверенного ввода по языку — подстрока в тексте выражения.
///
/// УГРОЗО-МОДЕЛЬ: источником считается УДАЛЁННЫЙ недоверенный ввод (HTTP-запрос, заголовки,
/// cookie, тело, сетевой поток) и переменные окружения. Аргументы командной строки (argv) и
/// интерактивный stdin НЕ источники: их контролирует ОПЕРАТОР, запускающий программу, а не
/// удалённый злоумышленник. Иначе любой CLI-инструмент (включая сам ailc), читающий путь из
/// argv и открывающий файл, давал бы поток argv→file/command как уязвимость, что является
/// самосрабатыванием на штатной функции CLI, а не дефектом.
fn taint_sources(lang: &str) -> &'static [&'static str] {
    const PY: &[&str] = &[
        "request.args", "request.form", "request.values", "request.json", "request.data",
        "request.get_json", "request.cookies", "request.headers", "request.GET", "request.POST",
        "request.query_params", "request.META", "request.FILES", "self.get_argument",
        "os.environ", "os.getenv", "flask.request",
    ];
    const JS: &[&str] = &[
        "req.body", "req.query", "req.params", "req.headers", "req.cookies", "req.url",
        "req.originalUrl", "request.body", "request.query", "request.params", "ctx.query",
        "ctx.request", "process.env", "location.search", "location.hash",
        "location.href", "document.location", "document.referrer", "window.name",
    ];
    const GO: &[&str] = &[
        ".URL.Query", ".URL.RawQuery", ".FormValue", ".PostFormValue", ".URL.Path", ".Form",
        ".PostForm", ".Body", ".Header.Get", ".Cookie", "mux.Vars", "os.Getenv",
    ];
    const JAVA: &[&str] = &[
        ".getParameter", ".getParameterValues", ".getParameterMap", ".getHeader",
        ".getHeaders", ".getQueryString", ".getCookies", ".getInputStream", ".getReader",
        ".getPathInfo", ".getRequestURI", ".getRequestURL", "System.getenv", "System.getProperty",
    ];
    const RUBY: &[&str] = &[
        "params[", "params.", "cookies[", "ENV[", "request.params", "request.body",
        "request.GET", "request.POST", "request.query_parameters", "request.env",
        "request.path", "request.url", "request.referer",
    ];
    // PHP-суперглобалы + getenv/заголовки — основной источник недоверенного ввода.
    const PHP: &[&str] = &[
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES", "php://input",
        "getenv", "apache_request_headers",
    ];
    const CSHARP: &[&str] = &[
        "Request.QueryString", "Request.Query", "Request.Form", "Request.Params",
        "Request.Headers", "Request.Cookies", "Request.Body", "Request.Files", "Request.RawUrl",
        "Environment.GetEnvironmentVariable",
    ];
    const RUST: &[&str] = &[
        "env::var", ".query_string", ".query_pairs", "web::Query", "web::Path",
        "web::Form", ".headers(",
    ];
    const KOTLIN: &[&str] = &[
        "call.parameters", ".queryParameters", ".formParameters", ".receiveText", ".receive(",
        ".getParameter", ".getHeader", ".getStringExtra", ".getExtras", "System.getenv",
    ];
    const SCALA: &[&str] = &[
        ".getQueryString", ".queryString", ".rawQueryString", "request.body", ".getParameter",
        ".getHeader", ".headers", ".cookies", "sys.env",
    ];
    // C/C++: return-value источник getenv; argv/stdin исключены как ввод оператора, ввод из
    // сети ловит mark_input_buffer.
    const C: &[&str] = &["getenv", "std::getenv"];
    // Swift (Vapor): req.query/parameters/content, окружение. CommandLine.arguments исключён
    // как ввод оператора.
    const SWIFT: &[&str] = &[
        ".query", "req.parameters", "req.content", ".queryParameters", ".headers",
        "ProcessInfo", ".environment",
    ];
    // Dart (shelf/io/CLI): request.url.queryParameters, headers, окружение, args.
    const DART: &[&str] = &[
        ".queryParameters", "request.headers", ".requestedUri", "request.url",
        "Platform.environment", "request.context",
    ];
    match lang {
        "python" => PY,
        "javascript" | "typescript" => JS,
        "go" => GO,
        "java" => JAVA,
        "ruby" => RUBY,
        "php" => PHP,
        "csharp" => CSHARP,
        "rust" => RUST,
        "kotlin" => KOTLIN,
        "scala" => SCALA,
        "c" | "cpp" => C,
        "swift" => SWIFT,
        "dart" => DART,
        _ => &[],
    }
}

/// Узел-присваивание по языку → Some(augmented). augmented не снимает заражение при
/// чистом правом значении (`x += y`, а также Go `=` — консервативно, без операторного разбора).
fn assignment_kind(kind: &str) -> Option<bool> {
    match kind {
        "assignment" => Some(false),                     // python  x = y
        "augmented_assignment" => Some(true),            // python  x += y
        "assignment_expression" => Some(false),          // js/ts   x = y
        "augmented_assignment_expression" => Some(true), // js/ts   x += y
        "variable_declarator" => Some(false),            // js/ts   let/const x = y
        "short_var_declaration" => Some(false),          // go      x := y
        "assignment_statement" => Some(true),            // go      x = y / x += y
        "operator_assignment" => Some(true),             // ruby    x += y
        "let_declaration" => Some(false),                // rust    let x = y
        "compound_assignment_expr" => Some(true),        // rust    x += y
        "property_declaration" => Some(false),           // kotlin  val/var x = y
        "val_definition" | "var_definition" => Some(false), // scala val/var x = y
        "init_declarator" => Some(false),                // c/c++  T x = y
        "initialized_variable_definition" => Some(false), // dart var x = y
        _ => None,
    }
}

/// C/C++: функция ввода пишет недоверенные данные в свой буфер-аргумент — заражаем его
/// (модель «output-параметра», которой нет у return-value источников).
/// T08: исправлены позиции буфера. У `scanf(fmt, &buf, …)` целевые буферы идут со 2-го
/// аргумента; у `sscanf(src, fmt, &buf, …)` и `fscanf(stream, fmt, &buf, …)` буфер с 3-го.
/// `gets(buf)` пишет в позицию 0. `read(fd, buf, n)`/`recv(fd, buf, …)`/`fread(buf, …)`
/// заполняют свой буфер. Для scanf-семейства помечаем ВСЕ целевые буферы, а не один.
fn mark_input_buffer(call: &Node, tainted: &mut HashSet<String>, bytes: &[u8]) {
    let Some(full) = callee_text(call, bytes) else {
        return;
    };
    let Some(args) = call_args(call) else {
        return;
    };
    // scanf-семейство: все аргументы-приёмники начиная с указанной позиции заражаются.
    let scan_start: Option<usize> = match full.as_str() {
        "scanf" => Some(1),            // scanf(fmt, &a, &b, …)
        "sscanf" | "fscanf" => Some(2), // (src|stream), fmt, &a, &b, …
        _ => None,
    };
    if let Some(start) = scan_start {
        let mut cur = args.walk();
        let kids: Vec<Node> = args.named_children(&mut cur).collect();
        for arg in kids.into_iter().skip(start) {
            if let Some(name) = inner_ident(&unwrap_arg(arg), bytes) {
                tainted.insert(name);
            }
        }
        return;
    }
    // Одно-буферные функции ввода: позиция целевого буфера фиксирована.
    let pos: usize = match full.as_str() {
        "gets" | "fgets" => 0,
        "fread" => 0,                 // fread(ptr, size, n, stream)
        "read" | "recv" | "recvfrom" => 1, // read(fd, buf, n) / recv(s, buf, …)
        _ => return,
    };
    if let Some(arg) = args.named_child(pos) {
        if let Some(name) = inner_ident(&unwrap_arg(arg), bytes) {
            tainted.insert(name);
        }
    }
}

/// Первый идентификатор в поддереве — для C-деклараторов (`*p`, `buf[100]`) и
/// Swift-паттернов (simple_identifier).
fn inner_ident(node: &Node, bytes: &[u8]) -> Option<String> {
    if matches!(node.kind(), "identifier" | "simple_identifier") {
        return node.utf8_text(bytes).ok().map(String::from);
    }
    let mut cur = node.walk();
    let kids: Vec<Node> = node.named_children(&mut cur).collect();
    kids.iter().find_map(|ch| inner_ident(ch, bytes))
}

/// Граница функции по языку — новый scope заражения (не течёт между функциями).
fn is_function_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "function_definition"                  // python
            | "function_declaration"           // js/ts/go
            | "function_expression"            // js
            | "arrow_function"                 // js
            | "generator_function"             // js
            | "generator_function_declaration" // js
            | "method_definition"              // js/ts
            | "method_declaration"             // go/java
            | "func_literal"                   // go closure
            | "constructor_declaration"        // java/c#
            | "lambda_expression"              // java/c#
            | "method"                         // ruby
            | "singleton_method"               // ruby
            | "local_function_statement"       // c#
            | "function_item"                  // rust
            | "closure_expression"             // rust
            | "anonymous_function"             // kotlin
            | "lambda_literal" // kotlin
    )
}

/// Квалифицированный ключ доступа к полю/индексу: `receiver.field`, `obj.attr`,
/// `this.x`, `arr[i]` (как `arr`), `m[k]` (как `m`). T05: помечаем такие цели строковым
/// ключом, чтобы поток через поля объекта и коллекции не терялся. Для `field_expression`/
/// `attribute`/`member_expression` нормализуем точечную запись; для индекс-доступа берём
/// базовую переменную (заражение элемента консервативно заражает контейнер).
fn qualified_path(node: &Node, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "variable_name" | "simple_identifier" | "field_identifier"
        | "property_identifier" | "this" | "self" => node.utf8_text(bytes).ok().map(String::from),
        // python attribute (obj.attr), js member_expression (obj.field),
        // go selector_expression (x.Field), java field_access, rust field_expression,
        // c#/php member access, kotlin navigation_expression.
        "attribute" | "member_expression" | "selector_expression" | "field_access"
        | "field_expression" | "member_access_expression" | "scoped_property_access_expression"
        | "navigation_expression" | "property_access_expression" => {
            // Нормализуем весь текст доступа, схлопнув пробелы (`self . cmd` → `self.cmd`).
            let text = node.utf8_text(bytes).ok()?;
            let key: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            if key.contains('(') || key.is_empty() {
                None // не доступ к полю, а вызов/сложное выражение
            } else {
                Some(key)
            }
        }
        // Python-подписка: ПОЛЕ-ЧУВСТВИТЕЛЬНОСТЬ при литеральном ключе (`m['k']`, `a[0]`).
        // Полный нормализованный ключ связывает `m['k']=x` с чтением `m['k']`, при этом
        // `m['k2']='const'` не затирает заражение `m['k']` (модель «весь контейнер» так
        // теряла связность на dict-отмывании OWASP). Срез/динамический индекс — база.
        "subscript" => {
            let idx = node
                .child_by_field_name("subscript")
                .or_else(|| node.named_child(1));
            let literal = idx.is_some_and(|i| matches!(i.kind(), "string" | "integer"));
            if literal {
                let text = node.utf8_text(bytes).ok()?;
                let key: String = text.chars().filter(|c| !c.is_whitespace()).collect();
                if !key.contains('(') && !key.is_empty() {
                    return Some(key);
                }
            }
            let base = node
                .child_by_field_name("value")
                .or_else(|| node.named_child(0))?;
            qualified_path(&base, bytes)
        }
        // index-присваивание arr[i]=/m[k]= (прочие языки): заражаем базовую переменную.
        "subscript_expression" | "index_expression" | "element_reference"
        | "element_access_expression" | "subscript_argument_list" => {
            let base = node
                .child_by_field_name("object")
                .or_else(|| node.child_by_field_name("value"))
                .or_else(|| node.child_by_field_name("array"))
                .or_else(|| node.named_child(0))?;
            qualified_path(&base, bytes)
        }
        _ => None,
    }
}

/// Имя простой цели присваивания: идентификатор, декларатор, либо квалифицированный путь
/// (T05: поле/индекс возвращают строковый ключ вместо None).
fn left_name(left: &Node, bytes: &[u8]) -> Option<String> {
    match left.kind() {
        "identifier" | "variable_name" | "simple_identifier" => {
            left.utf8_text(bytes).ok().map(String::from)
        }
        // c/c++: декларатор оборачивает имя (`*p`, `buf[100]`); swift: pattern.
        "pointer_declarator" | "array_declarator" | "reference_declarator" | "pattern" => {
            inner_ident(left, bytes)
        }
        // kotlin: имя цели внутри variable_declaration → identifier (kotlin-ng).
        "variable_declaration" => {
            let mut cur = left.walk();
            let kids: Vec<Node> = left.named_children(&mut cur).collect();
            kids.iter()
                .find(|c| matches!(c.kind(), "identifier" | "simple_identifier"))
                .and_then(|n| n.utf8_text(bytes).ok().map(String::from))
        }
        "expression_list" => {
            let mut cur = left.walk();
            let kids: Vec<Node> = left.named_children(&mut cur).collect();
            if kids.len() == 1 {
                left_name(&kids[0], bytes)
            } else {
                None // множественную цель обрабатывает left_names (tuple)
            }
        }
        // T05: квалифицированный путь к полю/индексу.
        _ => qualified_path(left, bytes),
    }
}

/// Все имена-цели присваивания, включая кортежную распаковку (T05). Для `a, b = ...`
/// или `[a, b] = ...` возвращает оба имени; для одиночной цели — её одну.
fn left_names(left: &Node, bytes: &[u8]) -> Vec<String> {
    match left.kind() {
        // python tuple/list pattern, js array/object pattern, go expression_list,
        // rust tuple_pattern, ruby left_assignment_list.
        "pattern_list" | "tuple_pattern" | "list_pattern" | "array_pattern"
        | "expression_list" | "left_assignment_list" | "tuple_type" => {
            let mut cur = left.walk();
            let kids: Vec<Node> = left.named_children(&mut cur).collect();
            let names: Vec<String> = kids.iter().filter_map(|c| left_name(c, bytes)).collect();
            if names.is_empty() {
                left_name(left, bytes).into_iter().collect()
            } else {
                names
            }
        }
        _ => left_name(left, bytes).into_iter().collect(),
    }
}

/// Мутирующие методы, заражающие РЕСИВЕР при заражённом аргументе (T05):
/// `parts.append(user)`/`list.push(x)`/`set.add(x)`/`m.insert(k,v)`/`a.extend(b)`.
fn is_mutating_method(leaf: &str) -> bool {
    matches!(
        leaf,
        "append" | "push" | "push_str" | "add" | "insert" | "extend" | "put" | "addall"
            | "concat" | "write" | "set" | "unshift" | "merge" | "update"
    )
}

/// Двунаправленная межпроцедурная сводка по ВСЕМУ дереву (T09). Собирается за первый
/// проход и используется во втором: source-функции возвращают заражение (прямой поток),
/// sink-параметры — формальные параметры функций, достигающие опасного стока (обратный
/// поток: заражённый фактический аргумент на месте вызова порождает находку).
#[derive(Default)]
struct InterProc {
    /// Имена функций, возвращающих заражённые данные (хелпер вокруг request/argv).
    source_fns: HashSet<String>,
    /// (имя_функции → множество индексов формальных параметров, текущих в сток).
    sink_params: HashMap<String, HashSet<usize>>,
}

/// Полиглот taint-анализ на 15 языках. Возвращает находки «источник→сток».
/// T09: двухпроходно и глобально. Первый проход собирает source-функции и sink-параметры
/// по ВСЕМ файлам одного языка вместе (межфайловые цепочки хелперов), второй проход ищет
/// потоки с учётом этой сводки. Языки анализируются независимо (грамматики не смешиваются).
pub fn scan_taint(ctx: &Ctx, input: &RunInput) -> Result<SastReport> {
    let base = ctx.base(input)?;
    let root = ctx.root.clone();
    let mut rep = SastReport::default();

    // Первый проход: накапливаем тексты файлов по языку (чтобы второй проход не перечитывал
    // диск и чтобы межпроцедурная сводка считалась глобально на наборе одного языка).
    struct FileSrc {
        rel: String,
        content: String,
    }
    let mut by_lang: HashMap<&'static str, Vec<FileSrc>> = HashMap::new();

    walk(&base, &mut |path| {
        let lang = lang_for_ext(ext_of(path));
        if taint_sources(lang).is_empty() {
            if is_source_like(path) {
                rep.skipped_lang += 1; // язык вне taint-профиля — честный счётчик охвата
            }
            return;
        }
        if ts_language(lang).is_none() {
            rep.skipped_lang += 1;
            return;
        }
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => {
                rep.skipped_read += 1;
                return;
            }
        };
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        by_lang.entry(lang).or_default().push(FileSrc { rel, content });
    })?;

    // Второй проход: по каждому языку отдельно строим межпроцедурную сводку и ищем потоки.
    for (lang, srcs) in &by_lang {
        let Some(language) = ts_language(lang) else {
            continue;
        };
        // Отбираем разбираемые файлы языка (валидность грамматики/parse — один раз).
        let mut ok: Vec<&FileSrc> = Vec::new();
        for s in srcs {
            let mut parser = Parser::new();
            if parser.set_language(&language).is_err() {
                rep.skipped_parse += 1;
                continue;
            }
            if parser.parse(&s.content, None).is_none() {
                rep.skipped_parse += 1;
                continue;
            }
            rep.files += 1;
            ok.push(s);
        }
        if ok.is_empty() {
            continue;
        }

        // Межпроцедурная сводка по всему набору файлов языка (T09): source-функции +
        // sink-параметры. Парсим каждый файл заново внутри (tree-sitter Tree самоссылочно,
        // дёшево перепарсить, чем хранить дерево рядом с источником через unsafe).
        let inter = collect_interproc(&ok.iter().map(|s| s.content.as_str()).collect::<Vec<_>>(), &language, lang);

        // Поиск потоков с учётом сводки.
        for s in &ok {
            let mut parser = Parser::new();
            if parser.set_language(&language).is_err() {
                continue;
            }
            let Some(tree) = parser.parse(&s.content, None) else {
                continue;
            };
            let bytes = s.content.as_bytes();
            let mut tainted: HashSet<String> = HashSet::new();
            let mut sanitized: HashMap<String, SanClass> = HashMap::new();
            let mut freed: HashSet<String> = HashSet::new();
            walk_taint(
                tree.root_node(),
                &mut tainted,
                &mut sanitized,
                &mut freed,
                bytes,
                &s.rel,
                lang,
                &inter,
                0,
                &mut rep.findings,
            );
        }
    }

    Ok(rep)
}

/// Сбор межпроцедурной сводки (T09) по набору исходников одного языка: source-функции и
/// sink-параметры, обе через фикспойнт. Парсит каждый файл, объединяет функции в общий
/// список «имя → тело» (межфайловость), затем итеративно достраивает обе сводки до
/// неподвижной точки. Граф вызовов обходится за O(V+E) на итерацию, число итераций
/// ограничено числом функций — приемлемо и без квадратичного повторного обхода тел.
fn collect_interproc(contents: &[&str], language: &tree_sitter::Language, lang: &str) -> InterProc {
    // Деревья держим живыми на всё время сбора, чтобы Node оставались валидными.
    let mut trees: Vec<tree_sitter::Tree> = Vec::new();
    for c in contents {
        let mut parser = Parser::new();
        if parser.set_language(language).is_err() {
            continue;
        }
        if let Some(t) = parser.parse(c, None) {
            trees.push(t);
        }
    }
    // (имя, тело, параметры, индекс_файла) по всем функциям набора. Индекс файла прямо
    // указывает на нужные байты, поэтому привязка узла к источнику однозначна.
    let mut funcs: Vec<(String, Node, Vec<String>, usize)> = Vec::new();
    for (i, t) in trees.iter().enumerate() {
        let bytes = contents[i].as_bytes();
        let mut local: Vec<(String, Node, Vec<String>)> = Vec::new();
        collect_functions_full(t.root_node(), bytes, &mut local);
        for (name, body, params) in local {
            funcs.push((name, body, params, i));
        }
    }

    let mut inter = InterProc::default();

    // Фикспойнт source-функций (прямой поток через возвращаемое значение).
    loop {
        let mut changed = false;
        for (name, body, _params, fi) in &funcs {
            if inter.source_fns.contains(name) {
                continue;
            }
            let bytes = contents[*fi].as_bytes();
            if function_returns_taint(*body, bytes, lang, &inter.source_fns) {
                inter.source_fns.insert(name.clone());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Фикспойнт sink-параметров (обратный поток): формальный параметр функции достигает
    // стока, если внутри тела он (как заражённая переменная) течёт в опасный сток ЛИБО
    // передаётся в позицию уже известного sink-параметра другой функции (транзитивность
    // обёрток вида run(cmd){exec(cmd)} и outer(x){run(x)}).
    loop {
        let mut changed = false;
        for (name, body, params, fi) in &funcs {
            let bytes = contents[*fi].as_bytes();
            let mut reached = inter.sink_params.get(name).cloned().unwrap_or_default();
            for (idx, pname) in params.iter().enumerate() {
                if reached.contains(&idx) {
                    continue;
                }
                if param_reaches_sink(*body, pname, bytes, lang, &inter) {
                    reached.insert(idx);
                    changed = true;
                }
            }
            if !reached.is_empty() {
                inter.sink_params.insert(name.clone(), reached);
            }
        }
        if !changed {
            break;
        }
    }

    inter
}

/// Имя, тело и имена формальных параметров каждой именованной функции (T09). Параметры
/// нужны для обратного межпроцедурного потока: формальный параметр, текущий в сток.
fn collect_functions_full<'a>(
    root: Node<'a>,
    bytes: &[u8],
    out: &mut Vec<(String, Node<'a>, Vec<String>)>,
) {
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if is_function_boundary(n.kind()) {
            if let (Some(name), Some(body)) =
                (n.child_by_field_name("name"), n.child_by_field_name("body"))
            {
                if let Ok(nm) = name.utf8_text(bytes) {
                    let params = function_param_names(&n, bytes);
                    out.push((nm.to_string(), body, params));
                }
            }
        }
        let mut cur = n.walk();
        for ch in n.children(&mut cur) {
            stack.push(ch);
        }
    }
}

/// Имена формальных параметров функции по порядку (T09). Поле `parameters` есть почти у
/// всех грамматик; внутри каждого параметра берём первый идентификатор (имя), пропуская
/// типы/модификаторы/значения по умолчанию. Это даёт устойчивое сопоставление по индексу.
fn function_param_names(func: &Node, bytes: &[u8]) -> Vec<String> {
    let params = func
        .child_by_field_name("parameters")
        .or_else(|| func.child_by_field_name("parameter_list"));
    let Some(params) = params else {
        return Vec::new();
    };
    let mut cur = params.walk();
    let mut names = Vec::new();
    for p in params.named_children(&mut cur) {
        // Пропускаем self/this/receiver — не позиционные пользовательские аргументы.
        if matches!(p.kind(), "self_parameter" | "self" | "this") {
            continue;
        }
        // Имя параметра: поле name/pattern, иначе первый идентификатор поддерева.
        let name = p
            .child_by_field_name("name")
            .or_else(|| p.child_by_field_name("pattern"))
            .and_then(|n| inner_ident(&n, bytes))
            .or_else(|| inner_ident(&p, bytes));
        if let Some(nm) = name {
            // Go-сигнатуры вида (ctx Context, r *Request) дают по одному имени на параметр.
            names.push(nm);
        }
    }
    names
}

/// Достигает ли формальный параметр опасного стока внутри тела функции (T09, обратный
/// поток). Помечаем параметр как заражённый и прогоняем тот же intra-проход поиска
/// стоков; вложенные функции пропускаем (свой scope).
fn param_reaches_sink(
    body: Node,
    param: &str,
    bytes: &[u8],
    lang: &str,
    inter: &InterProc,
) -> bool {
    let mut tainted: HashSet<String> = HashSet::new();
    tainted.insert(param.to_string());
    let mut sanitized: HashMap<String, SanClass> = HashMap::new();
    param_sink_walk(body, &mut tainted, &mut sanitized, bytes, lang, inter, 0)
}

/// Intra-проход поиска стока с заранее заражённым параметром (T09). Возвращает true, если
/// заражённое значение достигает классифицированного стока (включая транзит в sink-параметр
/// другой функции через граф вызовов).
#[allow(clippy::too_many_arguments)]
fn param_sink_walk(
    node: Node,
    tainted: &mut HashSet<String>,
    sanitized: &mut HashMap<String, SanClass>,
    bytes: &[u8],
    lang: &str,
    inter: &InterProc,
    depth: u32,
) -> bool {
    if depth > MAX_TAINT_DEPTH {
        return false;
    }
    let kind = node.kind();
    if let Some(augmented) = assignment_kind(kind) {
        update_taint(&node, tainted, sanitized, bytes, lang, &inter.source_fns, augmented);
    }
    if matches!(lang, "c" | "cpp") && is_call_node(lang, kind) {
        mark_input_buffer(&node, tainted, bytes);
    }
    if is_call_node(lang, kind)
        || (matches!(lang, "java" | "csharp") && kind == "object_creation_expression")
    {
        // Прямой классифицированный сток с заражённым аргументом.
        if sink_is_dangerous(&node, tainted, sanitized, bytes, lang, &inter.source_fns) {
            return true;
        }
        // Транзит: вызов функции с известным sink-параметром, куда идёт заражённый аргумент.
        if call_into_sink_param(&node, tainted, sanitized, bytes, lang, inter) {
            return true;
        }
    }
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        if is_function_boundary(ch.kind()) {
            continue; // вложенная функция — отдельный scope
        }
        if param_sink_walk(ch, tainted, sanitized, bytes, lang, inter, depth + 1) {
            return true;
        }
    }
    false
}

/// Возвращает ли функция заражённое значение: локальный intra-проход по телу, на
/// каждом `return` проверяем выражение. Вложенные функции пропускаем (свой анализ).
/// T09: для C/C++ внутри прохода тоже вызываем mark_input_buffer, чтобы хелпер ввода
/// (читает в буфер и возвращает его) распознавался как source-функция.
fn function_returns_taint(body: Node, bytes: &[u8], lang: &str, source_fns: &HashSet<String>) -> bool {
    let mut tainted: HashSet<String> = HashSet::new();
    let mut sanitized: HashMap<String, SanClass> = HashMap::new();
    returns_taint_walk(body, &mut tainted, &mut sanitized, bytes, lang, source_fns, 0)
}

fn returns_taint_walk(
    node: Node,
    tainted: &mut HashSet<String>,
    sanitized: &mut HashMap<String, SanClass>,
    bytes: &[u8],
    lang: &str,
    source_fns: &HashSet<String>,
    depth: u32,
) -> bool {
    if depth > MAX_TAINT_DEPTH {
        return false; // T13: лимит глубины — защита от переполнения стека
    }
    let kind = node.kind();
    if let Some(augmented) = assignment_kind(kind) {
        update_taint(&node, tainted, sanitized, bytes, lang, source_fns, augmented);
    }
    // T09: C/C++ хелпер ввода, читающий в буфер и возвращающий его, тоже source-функция.
    if matches!(lang, "c" | "cpp") && is_call_node(lang, kind) {
        mark_input_buffer(&node, tainted, bytes);
    }
    if kind == "return_statement" {
        let mut cur = node.walk();
        for ch in node.named_children(&mut cur) {
            if expr_tainted(&ch, tainted, sanitized, bytes, lang, source_fns, SinkClass::Other, 0) {
                return true;
            }
        }
    }
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        if is_function_boundary(ch.kind()) {
            continue; // вложенная функция анализируется отдельно
        }
        if returns_taint_walk(ch, tainted, sanitized, bytes, lang, source_fns, depth + 1) {
            return true;
        }
    }
    false
}

/// Обход в исходном порядке с taint-множеством. Присваивание обновляет множество ДО
/// спуска в детей; вызов-сток проверяется на месте; вложенная функция = новый scope.
/// T08: `freed` — множество освобождённых указателей (C/C++) для use-after-free и
/// double-free. T09: `inter` — двунаправленная межпроцедурная сводка (source-функции и
/// sink-параметры). T12: ветвления (if/else, switch, try) обрабатываются join-ом
/// состояний, чтобы переприсваивание в ОДНОЙ ветке не снимало заражение path-insensitive.
/// T13: `depth` ограничивает рекурсию.
#[allow(clippy::too_many_arguments)]
fn walk_taint(
    node: Node,
    tainted: &mut HashSet<String>,
    sanitized: &mut HashMap<String, SanClass>,
    freed: &mut HashSet<String>,
    bytes: &[u8],
    rel: &str,
    lang: &str,
    inter: &InterProc,
    depth: u32,
    out: &mut Vec<Finding>,
) {
    if depth > MAX_TAINT_DEPTH {
        return; // T13: лимит глубины рекурсии
    }
    let kind = node.kind();
    let source_fns = &inter.source_fns;
    if let Some(augmented) = assignment_kind(kind) {
        // Граница доверия (CWE-501): запись в серверную сессию проверяется ДО update_taint,
        // пока множество отражает состояние перед этим присваиванием (ключ/значение могли
        // быть заражены ранее).
        check_trust_boundary(&node, tainted, bytes, rel, lang, source_fns, out);
        update_taint(&node, tainted, sanitized, bytes, lang, source_fns, augmented);
        // T08: переназначение указателя снимает его из множества освобождённых
        // (после `p = malloc(...)`/`p = NULL` использование p снова корректно).
        if matches!(lang, "c" | "cpp") && !freed.is_empty() {
            clear_freed_on_reassign(&node, freed, bytes);
        }
    }
    // T05: мутирующий метод заражает ресивер при заражённом аргументе (parts.append(user)).
    if is_call_node(lang, kind) {
        mark_mutating_receiver(&node, tainted, sanitized, bytes, lang, source_fns);
    }
    // T08: модель памяти C/C++ — free/malloc/format-string до классификации обычного стока.
    if matches!(lang, "c" | "cpp") && is_call_node(lang, kind) {
        check_memory_safety(&node, tainted, sanitized, freed, bytes, rel, lang, source_fns, out);
        mark_input_buffer(&node, tainted, bytes);
    }
    // Стоком может быть и вызов, и конструктор (Java/C# `new ProcessBuilder/SqlCommand(...)`).
    if is_call_node(lang, kind)
        || (matches!(lang, "java" | "csharp") && kind == "object_creation_expression")
    {
        check_taint_sink(&node, tainted, sanitized, bytes, rel, lang, source_fns, out);
        // T09: вызов функции с известным sink-параметром и заражённым фактическим аргументом.
        check_call_into_sink_param(&node, tainted, sanitized, bytes, rel, lang, inter, out);
    }
    // Серверный XSS (CWE-79): возврат заражённой строки как тела ответа — сток это сам
    // return, а не вызов. Только Python/Flask-форма обработчика.
    if lang == "python" && kind == "return_statement" {
        check_response_sink(&node, tainted, sanitized, bytes, rel, lang, source_fns, out);
    }

    // T12: ветвление — join состояний веток (объединение заражённых), чтобы реассайн в
    // одной ветке не гасил заражение для кода ПОСЛЕ ветвления.
    if is_branching(kind) {
        walk_branching(node, tainted, sanitized, freed, bytes, rel, lang, inter, depth, out);
        return;
    }

    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        if is_function_boundary(ch.kind()) {
            let mut inner: HashSet<String> = HashSet::new();
            let mut inner_san: HashMap<String, SanClass> = HashMap::new();
            let mut inner_freed: HashSet<String> = HashSet::new();
            walk_taint(ch, &mut inner, &mut inner_san, &mut inner_freed, bytes, rel, lang, inter, depth + 1, out);
        } else {
            walk_taint(ch, tainted, sanitized, freed, bytes, rel, lang, inter, depth + 1, out);
        }
    }
}

/// Узел вводит ветвление (T12): условный/выбор/исключение. Внутри его веток заражение
/// не должно снимать друг друга, а на выходе состояния объединяются.
fn is_branching(kind: &str) -> bool {
    matches!(
        kind,
        "if_statement"
            | "if_expression"
            | "match_statement"
            | "match_expression"
            | "switch_statement"
            | "switch_expression"
            | "when_expression" // kotlin
            | "case_statement"  // ruby/php
            | "try_statement"
            | "try_expression"
            | "conditional_expression"
            | "ternary_expression"
    )
}

/// Обработка ветвления с join (T12). Каждая ветка анализируется на КОПИИ входного
/// состояния; сток внутри ветки регистрируется как обычно (находки добавляются), но
/// СНЯТИЕ заражения в одной ветке не влияет на другие. На выходе исходное множество
/// заменяется объединением (union) всех веток: переменная остаётся заражённой, если она
/// заражена хотя бы в одной достижимой ветке. freed объединяется аналогично консервативно.
#[allow(clippy::too_many_arguments)]
fn walk_branching(
    node: Node,
    tainted: &mut HashSet<String>,
    sanitized: &mut HashMap<String, SanClass>,
    freed: &mut HashSet<String>,
    bytes: &[u8],
    rel: &str,
    lang: &str,
    inter: &InterProc,
    depth: u32,
    out: &mut Vec<Finding>,
) {
    let mut union_tainted = tainted.clone();
    let mut union_freed = freed.clone();
    // Санитизация: при join переменная считается очищенной ТОЛЬКО если очищена во всех
    // ветках одним классом (пересечение), иначе на выходе она снова может быть опасной.
    // Консервативно: после ветвления сбрасываем записи санитизации, поднятые лишь в части
    // веток (оставляем только те, что были до ветвления и не переопределены).
    let base_sanitized = sanitized.clone();
    let mut union_sanitized = base_sanitized.clone();

    let mut cur = node.walk();
    let kids: Vec<Node> = node.children(&mut cur).collect();
    for ch in kids {
        // Условие/селектор ветвления исполняется всегда — анализируем в общем состоянии.
        if ch.is_named() && is_condition_part(node.kind(), &ch, &node) {
            walk_taint(ch, tainted, sanitized, freed, bytes, rel, lang, inter, depth + 1, out);
            union_tainted.extend(tainted.iter().cloned());
            union_freed.extend(freed.iter().cloned());
            union_sanitized = sanitized.clone();
            continue;
        }
        // Тело ветки — на копии входного состояния (плюс эффекты условия).
        let mut branch_tainted = union_tainted.clone();
        let mut branch_sanitized = union_sanitized.clone();
        let mut branch_freed = union_freed.clone();
        walk_taint(
            ch,
            &mut branch_tainted,
            &mut branch_sanitized,
            &mut branch_freed,
            bytes,
            rel,
            lang,
            inter,
            depth + 1,
            out,
        );
        // Join: заражение из любой ветки сохраняется (union). Для санитизации берём
        // пересечение по классу: переменная остаётся «очищенной», только если та же запись
        // присутствует во всех веточных состояниях.
        union_tainted.extend(branch_tainted);
        union_freed.extend(branch_freed);
        union_sanitized.retain(|k, v| branch_sanitized.get(k) == Some(v));
    }
    *tainted = union_tainted;
    *freed = union_freed;
    *sanitized = union_sanitized;
}

/// Часть ветвления, исполняемая безусловно (условие/селектор), а не тело ветки (T12).
/// Для большинства грамматик это поле `condition`/`value`. Консервативно: если узел —
/// поле условия родителя, считаем его условием.
fn is_condition_part(_parent_kind: &str, child: &Node, parent: &Node) -> bool {
    for field in ["condition", "value", "subject"] {
        if let Some(c) = parent.child_by_field_name(field) {
            if c.id() == child.id() {
                return true;
            }
        }
    }
    false
}

// ─── Свёртка константного условия (Python) для тернарника `A if C else B` ───
// Реальная фича точности: если условие C сворачивается в константу (литералы плюс
// переменные, присвоенные литералам в том же блоке), мёртвая ветка не должна заражать
// цель. OWASP Benchmark строит «безопасные» двойники именно так: `bar = const if
// 7*18 + num > 200 else param` при num = 106 всегда выбирает const, но без свёртки
// движок консервативно красит bar по формально присутствующей ветке `else param`.

/// Узел живой ветки константного тернарника Python; исходный узел, если не сворачивается.
fn fold_constant_ternary<'a>(right: Node<'a>, lang: &str, bytes: &[u8]) -> Node<'a> {
    if lang != "python" || right.kind() != "conditional_expression" {
        return right;
    }
    // Грамматика python: conditional_expression = consequence `if` condition `else`
    // alternative; именованные дети идут в этом порядке.
    let (Some(conseq), Some(cond), Some(alt)) =
        (right.named_child(0), right.named_child(1), right.named_child(2))
    else {
        return right;
    };
    match fold_const_condition(cond, bytes) {
        Some(true) => conseq,
        Some(false) => alt,
        None => right,
    }
}

/// Свёртка целочисленного сравнения в bool, если обе стороны вычислимы как константы.
fn fold_const_condition(cond: Node, bytes: &[u8]) -> Option<bool> {
    match cond.kind() {
        "parenthesized_expression" => fold_const_condition(cond.named_child(0)?, bytes),
        "comparison_operator" => {
            let l = eval_const_int(cond.named_child(0)?, true, bytes)?;
            let r = eval_const_int(cond.named_child(1)?, true, bytes)?;
            let op = cond.child_by_field_name("operators")?.utf8_text(bytes).ok()?;
            Some(match op {
                ">" => l > r,
                "<" => l < r,
                ">=" => l >= r,
                "<=" => l <= r,
                "==" => l == r,
                "!=" | "<>" => l != r,
                _ => return None,
            })
        }
        _ => None,
    }
}

/// Вычислить целочисленное выражение. `allow_vars` разрешает разрешить идентификатор в
/// литерал из предыдущего присваивания блока (один уровень, без рекурсии по переменным).
fn eval_const_int(node: Node, allow_vars: bool, bytes: &[u8]) -> Option<i64> {
    match node.kind() {
        "integer" => node
            .utf8_text(bytes)
            .ok()?
            .trim()
            .replace('_', "")
            .parse::<i64>()
            .ok(),
        "parenthesized_expression" => eval_const_int(node.named_child(0)?, allow_vars, bytes),
        "unary_operator" => {
            let arg = eval_const_int(node.child_by_field_name("argument")?, allow_vars, bytes)?;
            match node.child_by_field_name("operator")?.utf8_text(bytes).ok()? {
                "-" => Some(-arg),
                "+" => Some(arg),
                _ => None,
            }
        }
        "binary_operator" => {
            let l = eval_const_int(node.child_by_field_name("left")?, allow_vars, bytes)?;
            let r = eval_const_int(node.child_by_field_name("right")?, allow_vars, bytes)?;
            match node.child_by_field_name("operator")?.utf8_text(bytes).ok()? {
                "+" => Some(l + r),
                "-" => Some(l - r),
                "*" => Some(l * r),
                "/" if r != 0 => Some(l / r),
                "%" if r != 0 => Some(l % r),
                _ => None,
            }
        }
        "identifier" if allow_vars => {
            let name = node.utf8_text(bytes).ok()?;
            resolve_literal_var(name, node, bytes)
        }
        _ => None,
    }
}

/// Последнее присваивание `name = <литерал>` перед позицией `anchor` в охватывающей
/// функции/модуле (минимальное распространение констант для свёртки условия).
fn resolve_literal_var(name: &str, anchor: Node, bytes: &[u8]) -> Option<i64> {
    let mut scope = anchor;
    while let Some(p) = scope.parent() {
        scope = p;
        if matches!(scope.kind(), "function_definition" | "module") {
            break;
        }
    }
    let limit = anchor.start_byte();
    let mut best: Option<(usize, i64)> = None;
    collect_literal_assign(scope, name, limit, bytes, &mut best);
    best.map(|(_, v)| v)
}

fn collect_literal_assign(
    node: Node,
    name: &str,
    limit: usize,
    bytes: &[u8],
    best: &mut Option<(usize, i64)>,
) {
    let mut cur = node.walk();
    for ch in node.children(&mut cur) {
        if ch.kind() == "assignment" && ch.start_byte() < limit {
            if let (Some(l), Some(r)) =
                (ch.child_by_field_name("left"), ch.child_by_field_name("right"))
            {
                if l.kind() == "identifier" && l.utf8_text(bytes).ok() == Some(name) {
                    if let Some(v) = eval_const_int(r, false, bytes) {
                        let pos = ch.start_byte();
                        if best.map_or(true, |(b, _)| pos > b) {
                            *best = Some((pos, v));
                        }
                    }
                }
            }
        }
        collect_literal_assign(ch, name, limit, bytes, best);
    }
}

/// `x = <expr>`: если expr заражён — пометить x; иначе (обычное присваивание) снять
/// заражение. Поля left/right (или name/value у js-декларатора) + простая цель.
/// T06: если правое значение прошло через КОНТЕКСТНЫЙ санитайзер (`safe = shlex.quote(t)`),
/// цель помечается заражённой, НО с записью класса санитайзера в `sanitized`; на стоке
/// совместимого класса она будет считаться чистой, а на несовместимом — опасной.
#[allow(clippy::too_many_arguments)]
fn update_taint(
    assign: &Node,
    tainted: &mut HashSet<String>,
    sanitized: &mut HashMap<String, SanClass>,
    bytes: &[u8],
    lang: &str,
    source_fns: &HashSet<String>,
    augmented: bool,
) {
    let (left, right) = match assign.kind() {
        // js/ts/java: name + value; C#: значение в equals_value_clause — берём последний
        // именованный ребёнок, не равный имени (устойчиво к различиям грамматик).
        "variable_declarator" => {
            let name = assign.child_by_field_name("name");
            let val = assign.child_by_field_name("value").or_else(|| {
                let mut cur = assign.walk();
                let kids: Vec<Node> = assign
                    .named_children(&mut cur)
                    .filter(|c| Some(c.id()) != name.map(|n| n.id()))
                    .collect();
                kids.last().copied()
            });
            (name, val)
        }
        // rust: `let <pattern> = <value>`
        "let_declaration" => (
            assign.child_by_field_name("pattern"),
            assign.child_by_field_name("value"),
        ),
        // kotlin/swift: `val/let x = expr` — имя в variable_declaration (kotlin) / pattern
        // (swift), значение — последнее выражение.
        "property_declaration" => {
            let mut cur = assign.walk();
            let kids: Vec<Node> = assign.named_children(&mut cur).collect();
            let name = kids
                .iter()
                .find(|c| matches!(c.kind(), "variable_declaration" | "pattern"))
                .copied();
            let val = kids
                .iter()
                .rev()
                .find(|c| {
                    !matches!(
                        c.kind(),
                        "variable_declaration"
                            | "pattern"
                            | "modifiers"
                            | "value_binding_pattern"
                            | "type_annotation"
                    )
                })
                .copied();
            (name, val)
        }
        // scala val/var, dart var: имя identifier (первый), значение последнее выражение.
        "val_definition" | "var_definition" | "initialized_variable_definition" => {
            let mut cur = assign.walk();
            let kids: Vec<Node> = assign.named_children(&mut cur).collect();
            let name = kids.first().copied();
            let val = kids
                .last()
                .copied()
                .filter(|c| name.map(|n| n.id()) != Some(c.id()));
            (name, val)
        }
        // c/c++: `T x = expr` — declarator (имя) + value.
        "init_declarator" => (
            assign.child_by_field_name("declarator"),
            assign.child_by_field_name("value"),
        ),
        _ => (
            assign.child_by_field_name("left"),
            assign.child_by_field_name("right"),
        ),
    };
    let (Some(left), Some(right)) = (left, right) else {
        return; // напр. `let x;` без инициализатора — цель остаётся чистой
    };
    // T05: кортежная распаковка (a, b = ...) и квалифицированные пути (self.x, arr[i]).
    let names = left_names(&left, bytes);
    if names.is_empty() {
        return; // нераспознанная цель — не отслеживаем
    }
    // Свёртка константного тернарника (Python): берём только живую ветку, чтобы мёртвая
    // `else param` не заражала цель в заведомо безопасном коде (см. fold_constant_ternary).
    let right = fold_constant_ternary(right, lang, bytes);
    // T06: контекстный санитайзер на правом значении (numeric очищает уже на этом шаге,
    // он вернёт rhs_tainted=false; контекстный пропускает заражение, но мы запомним класс).
    let rhs_san = outer_sanitizer_class(&right, bytes, lang);
    // rhs считается заражённым, если значение опасно для контекста стока. Для оценки на
    // присваивании используем «сырой» источник: численный санитайзер уже очистил (Other),
    // контекстный санитайзер заражение НЕ снимает (вернёт true при заражённом аргументе).
    let rhs_tainted = expr_tainted(&right, tainted, sanitized, bytes, lang, source_fns, SinkClass::Other, 0);
    for name in names {
        if rhs_tainted {
            tainted.insert(name.clone());
            // запоминаем санитайзер; либо переносим класс с заражённой переменной-источника
            // (`safe = clean(t)` где clean — обёртка, не курируемый санитайзер, класс не
            // известен — тогда снимаем прежнюю запись, чтобы не считать чистым ошибочно).
            match rhs_san {
                Some(sc) => {
                    sanitized.insert(name, sc);
                }
                None => {
                    sanitized.remove(&name);
                }
            }
        } else if !augmented {
            tainted.remove(&name);
            sanitized.remove(&name);
        }
    }
}

/// T06: класс санитайзера ВНЕШНЕГО вызова правого значения присваивания, если оно само
/// является вызовом санитайзера (`shlex.quote(...)`/`html.escape(...)`/`int(...)`). None,
/// если правое значение не санитайзер.
fn outer_sanitizer_class(right: &Node, bytes: &[u8], lang: &str) -> Option<SanClass> {
    if !is_call_node(lang, right.kind()) {
        return None;
    }
    let full_raw = callee_text(right, bytes)?;
    let full = full_raw.to_lowercase();
    let leaf = full.rsplit(['.', ':']).next().unwrap_or(full.as_str());
    sanitizer_class(&full, leaf)
}

/// T05: мутирующий метод (`parts.append(user)`/`list.push(x)`) заражает РЕСИВЕР, если
/// хотя бы один аргумент заражён. Ресивер — квалифицированный ключ (имя переменной или
/// путь `obj.field`), который далее сверяется в expr_tainted/expr_refs_tainted.
fn mark_mutating_receiver(
    call: &Node,
    tainted: &mut HashSet<String>,
    sanitized: &HashMap<String, SanClass>,
    bytes: &[u8],
    lang: &str,
    source_fns: &HashSet<String>,
) {
    let Some(full) = callee_text(call, bytes) else {
        return;
    };
    let lc = full.to_lowercase();
    let leaf = lc.rsplit(['.', ':']).next().unwrap_or(lc.as_str());
    if !is_mutating_method(leaf) {
        return;
    }
    // Ресивер — часть вызываемого до последнего сегмента (`parts` из `parts.append`).
    let Some(func) = callee_full(call) else {
        return;
    };
    let recv = receiver_of(&func);
    let Some(recv) = recv else {
        return;
    };
    let Some(recv_key) = qualified_path(&recv, bytes) else {
        return;
    };
    // Любой заражённый аргумент заражает ресивер.
    if let Some(args) = call_args(call) {
        let mut cur = args.walk();
        let any = args
            .named_children(&mut cur)
            .any(|a| expr_tainted(&unwrap_arg(a), tainted, sanitized, bytes, lang, source_fns, SinkClass::Other, 0));
        if any {
            tainted.insert(recv_key);
        }
    }
}

/// Ресивер из узла вызываемого `obj.method`/`pkg::f`: левая часть доступа к члену.
fn receiver_of<'a>(func: &Node<'a>) -> Option<Node<'a>> {
    match func.kind() {
        "attribute" | "member_expression" | "selector_expression" | "field_access"
        | "field_expression" | "member_access_expression" | "navigation_expression"
        | "scoped_identifier" | "scoped_call_expression" => func
            .child_by_field_name("object")
            .or_else(|| func.child_by_field_name("value"))
            .or_else(|| func.child_by_field_name("operand"))
            .or_else(|| func.child_by_field_name("scope"))
            .or_else(|| func.named_child(0)),
        _ => None,
    }
}

/// Класс санитайзера (T06): защищает только ОТ своего класса атак. Числовое приведение
/// делает значение безопасным для всех текстовых стоков (нет управляющих символов).
#[derive(Clone, Copy, PartialEq, Eq)]
enum SanClass {
    /// Числовое приведение (int/float): результат не содержит метасимволов — безопасен
    /// для shell/sql/html/path, но НЕ для контекста размера буфера (там важна величина).
    Numeric,
    Shell,
    Sql,
    Html,
    Path,
}

/// Класс стока (T06): с каким классом санитайзера он совместим.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SinkClass {
    Command,
    Sql,
    /// Сток разметки (XSS): класс санитайзера html снимает заражение. Используется
    /// серверным XSS-стоком `sast/taint-xss` (возврат заражённой строки как тела ответа).
    Html,
    Path,
    /// Размер/копирование буфера: числовой санитайзер НЕ снимает риск переполнения.
    Size,
    /// Прочее (десериализация и т.п.) — санитайзеры не сопоставлены, считаем общими.
    Other,
}

/// Класс санитайзера по имени (T06). КУРИРУЕМЫЙ список с привязкой к контексту: shell-quote
/// защищает только команду, escapeshellarg/escapeshellcmd — shell; SQL-escape — SQL;
/// html-escape — HTML; basename/realpath — path; числовые приведения — Numeric. Общий
/// `parse` УДАЛЁН (слишком широк, глушил инъекции из чужого namespace).
fn sanitizer_class(full: &str, leaf: &str) -> Option<SanClass> {
    // Числовые приведения: безопасны для всех текстовых стоков.
    const NUMERIC: &[&str] = &[
        "int", "float", "atoi", "atol", "atof", "strtol", "strtoul", "strtod", "itoa",
        "parseint", "parsefloat", "number", "bool", "intval", "floatval", "toint32",
        "toint64", "toint16", "todouble", "tosingle",
    ];
    // Shell-санитайзеры.
    const SHELL: &[&str] = &["escapeshellarg", "escapeshellcmd"];
    // SQL-санитайзеры.
    const SQL: &[&str] = &[
        "escapesql", "mysqli_real_escape_string", "real_escape_string", "quote_ident",
        "quote_literal",
    ];
    // HTML/markup-санитайзеры.
    const HTML: &[&str] = &[
        "escape", "escapestring", "escapehtml", "escapehtml4", "htmlescape", "jsescape",
        "htmlescapestring", "html_escape", "escape_for_html", "encodeuricomponent", "encodeuri",
        "htmlspecialchars", "htmlentities", "htmlencode", "urlencode", "escapedatastring",
        "escapeuristring", "sanitize", "clean",
    ];
    // Path-санитайзеры (нормализация пути убирает обход каталога).
    const PATH: &[&str] = &["basename", "realpath", "canonicalize", "normpath", "abspath"];

    if NUMERIC.contains(&leaf) {
        return Some(SanClass::Numeric);
    }
    if SHELL.contains(&leaf)
        || full.contains("shlex.quote")
        || (leaf == "quote" && full.contains("shlex"))
    {
        return Some(SanClass::Shell);
    }
    if SQL.contains(&leaf) {
        return Some(SanClass::Sql);
    }
    if HTML.contains(&leaf)
        || full.contains("markupsafe.escape")
        || full.contains("dompurify.sanitize")
        || full.contains("validator.escape")
        || full.contains("stringescapeutils")
        || full.contains("escapeutils")
    {
        return Some(SanClass::Html);
    }
    if PATH.contains(&leaf) {
        return Some(SanClass::Path);
    }
    // shlex.quote с leaf "quote" покрыт выше; addslashes — слабый, считаем SQL+shell нейтральным.
    if leaf == "addslashes" {
        return Some(SanClass::Sql);
    }
    // re.escape экранирует regex-метасимволы — близко к html/общему текстовому.
    if full.contains("re.escape") {
        return Some(SanClass::Html);
    }
    None
}

/// Совместим ли санитайзер со стоком (T06). Numeric безопасен для любого ТЕКСТОВОГО стока,
/// но не для контекста размера (Size). Прочие санитайзеры снимают риск только своего класса.
fn sanitizer_clears(san: SanClass, sink: SinkClass) -> bool {
    match san {
        SanClass::Numeric => !matches!(sink, SinkClass::Size),
        SanClass::Shell => matches!(sink, SinkClass::Command),
        SanClass::Sql => matches!(sink, SinkClass::Sql),
        SanClass::Html => matches!(sink, SinkClass::Html),
        SanClass::Path => matches!(sink, SinkClass::Path),
    }
}


/// Поддерево ссылается на заражённую переменную/source-функцию (для проверки ресивера).
fn expr_refs_tainted(
    node: &Node,
    tainted: &HashSet<String>,
    bytes: &[u8],
    source_fns: &HashSet<String>,
) -> bool {
    let mut stack = vec![*node];
    while let Some(n) = stack.pop() {
        if matches!(n.kind(), "identifier" | "variable_name" | "simple_identifier") {
            if let Ok(t) = n.utf8_text(bytes) {
                if tainted.contains(t) || source_fns.contains(t) {
                    return true;
                }
            }
        }
        let mut cur = n.walk();
        for ch in n.children(&mut cur) {
            stack.push(ch);
        }
    }
    false
}

/// Структурная оценка заражённости выражения. Вызов решается по вызываемому:
/// контекстный санитайзер (T06: класс совпадает со стоком) → чисто; source-функция или
/// источник в цепочке → заражено; прочая функция — заражение проходит насквозь от
/// аргументов/ресивера (консервативно, без сигнатур). `sink` задаёт класс стока для
/// контекстной проверки санитайзера; на присваивании/возврате используется SinkClass::Other.
/// T10: источники сопоставляются по сегментам (граница `.`/`::`/`->`), не подстрокой.
/// T13: `depth` ограничивает рекурсию.
#[allow(clippy::too_many_arguments)]
fn expr_tainted(
    node: &Node,
    tainted: &HashSet<String>,
    sanitized: &HashMap<String, SanClass>,
    bytes: &[u8],
    lang: &str,
    source_fns: &HashSet<String>,
    sink: SinkClass,
    depth: u32,
) -> bool {
    if depth > MAX_TAINT_DEPTH {
        return false; // T13: лимит глубины
    }
    let kind = node.kind();

    if is_call_node(lang, kind) {
        if let Some(full_raw) = callee_text(node, bytes) {
            let full = full_raw.to_lowercase();
            let leaf = full.rsplit(['.', ':']).next().unwrap_or(full.as_str());
            // (1) Санитайзер (T06): снимает заражение, только если его класс совместим с
            // классом стока (для SinkClass::Other снимаем лишь универсальный числовой).
            if let Some(sc) = sanitizer_class(&full, leaf) {
                let clears = match sink {
                    SinkClass::Other => sc == SanClass::Numeric,
                    _ => sanitizer_clears(sc, sink),
                };
                if clears {
                    return false;
                }
                // несовместимый санитайзер: заражение НЕ снимаем, идём дальше насквозь.
            }
            // (2) Source-функция (inter-procedural) → заражение.
            if source_fns.contains(leaf) || source_fns.contains(full.as_str()) {
                return true;
            }
            // (3) Источник в цепочке вызываемого (request.args.get, request.getParameter)
            // по сегментному совпадению (T10).
            if callee_matches_source(&full_raw, lang) {
                return true;
            }
        }
        // (4) Заражённый ресивер: `tainted_var.strip()`.
        if let Some(func) = callee_full(node) {
            if expr_refs_tainted(&func, tainted, bytes, source_fns) {
                return true;
            }
        }
        // (5) Прочая функция: заражение аргумента проходит насквозь (санитайзеры отсечены).
        if let Some(args) = call_args(node) {
            let mut cur = args.walk();
            for arg in args.named_children(&mut cur) {
                if expr_tainted(&unwrap_arg(arg), tainted, sanitized, bytes, lang, source_fns, sink, depth + 1) {
                    return true;
                }
            }
        }
        return false;
    }

    // Идентификатор / PHP-переменная / Kotlin simple_identifier: заражённая переменная,
    // source-функция, либо суперглобал-источник целиком (`$_GET` — сам по себе недоверен).
    if matches!(kind, "identifier" | "variable_name" | "simple_identifier") {
        return node.utf8_text(bytes).is_ok_and(|t| {
            // T06: если переменная очищена санитайзером, совместимым со стоком — она чиста.
            if var_is_cleared(t, sanitized, sink) {
                return false;
            }
            tainted.contains(t) || source_fns.contains(t) || ident_matches_source(t, lang)
        });
    }

    // Доступ к атрибуту/полю/индексу: квалифицированный ключ может быть заражён напрямую
    // (T05: `self.cmd`), либо текст доступа сегментно совпадает с источником (T10:
    // `request.args`, `r.Form`).
    if matches!(
        kind,
        "attribute"               // python  request.args
            | "member_expression" // js      req.query
            | "subscript"          // python  m['k'] (поле-чувствительный ключ)
            | "subscript_expression"
            | "selector_expression" // go     r.Form
            | "index_expression"
            | "element_reference"          // ruby   params[:id]
            | "field_access"               // java   req.field
            | "member_access_expression"   // c#     Request.QueryString
            | "element_access_expression"  // c#     Request.Form["x"]
            | "field_expression"           // rust   x.field
            | "navigation_expression"      // kotlin call.parameters
            | "scoped_property_access_expression"
            | "property_access_expression"
    ) {
        // T05: квалифицированный путь заражён как ключ (если не очищен совместимым санитайзером).
        if let Some(key) = qualified_path(node, bytes) {
            if tainted.contains(&key) && !var_is_cleared(&key, sanitized, sink) {
                return true;
            }
        }
        if let Ok(t) = node.utf8_text(bytes) {
            if access_matches_source(t, lang) {
                return true;
            }
        }
    }

    // Прочие узлы (конкатенация, f-строка, индексация, доступ с заражённым ресивером):
    // заражены, если заражён хотя бы один ребёнок.
    let mut cur = node.walk();
    for ch in node.named_children(&mut cur) {
        if expr_tainted(&ch, tainted, sanitized, bytes, lang, source_fns, sink, depth + 1) {
            return true;
        }
    }
    false
}

/// T06: переменная очищена санитайзером, совместимым с текущим классом стока. Числовой
/// санитайзер очищает для всех текстовых стоков; контекстный — только для своего класса.
fn var_is_cleared(name: &str, sanitized: &HashMap<String, SanClass>, sink: SinkClass) -> bool {
    match sanitized.get(name) {
        Some(sc) => match sink {
            SinkClass::Other => *sc == SanClass::Numeric,
            _ => sanitizer_clears(*sc, sink),
        },
        None => false,
    }
}

/// Сегментное сопоставление источника (T10): источник совпадает с вызываемым/доступом не
/// произвольной подстрокой, а по границам сегментов `.`/`::`/`->`. Источник с ведущей точкой
/// (`.FormValue`, `.getParameter`) трактуется как «метод/поле»: совпадает, если такой
/// сегмент есть в цепочке. Источник без точки (`getenv`, `os.environ`, `request.args`)
/// должен совпасть как СУФФИКС цепочки сегментов или как точная подцепочка по границам.
fn segment_source_match(text: &str, source: &str) -> bool {
    // Источники со спецсимволами (PHP-суперглобалы `$_GET`, `input(`, `stdin(`, Rust
    // `web::Query`) сегментацией не разложить осмысленно — для них сохраняем подстрочное
    // совпадение с проверкой границы слева (символ перед вхождением не должен быть частью
    // идентификатора), чтобы `myparams.` не ловил `params.`.
    if source.contains('$') || source.contains('(') || source.contains('[') {
        return bounded_substring(text, source);
    }
    // Нормализуем разделители доступа к точке для единого разбиения по сегментам.
    // Каждый сегмент обрезаем по первой открывающей скобке вызова или индекса, чтобы
    // `var("CMD")` переходил в `var`, а `unwrap()` в `unwrap`: иначе скобки аргументов и
    // хвостовая цепочка вызовов (`std::env::var("CMD").unwrap()`) ломали бы посегментное
    // совпадение источника `env::var`.
    let norm = |s: &str| -> Vec<String> {
        s.replace("::", ".")
            .replace("->", ".")
            .split('.')
            .map(|p| {
                let cut = p.find(['(', '[']).unwrap_or(p.len());
                p[..cut].trim()
            })
            .filter(|p| !p.is_empty())
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
    };
    let text_segs = norm(text);
    if source.starts_with('.') {
        // источник-метод/поле: его последний сегмент должен присутствовать в цепочке как
        // отдельный сегмент (`.FormValue` совпадает с `r.FormValue`, но не с `.Bodyguard`).
        let s_segs = norm(source);
        if let Some(last) = s_segs.last() {
            return text_segs.iter().any(|seg| seg == last);
        }
        return false;
    }
    let src_segs = norm(source);
    if src_segs.is_empty() {
        return false;
    }
    if src_segs.len() == 1 {
        // одиночный сегмент (`getenv`, `argv`) — должен совпасть как ЦЕЛЫЙ сегмент,
        // чтобы forgetenv (один сегмент «forgetenv») не матчился с «getenv».
        return text_segs.iter().any(|seg| seg == &src_segs[0]);
    }
    // непрерывное вхождение последовательности сегментов источника в текст по границам.
    text_segs
        .windows(src_segs.len())
        .any(|w| w == src_segs.as_slice())
}

/// Подстрочное совпадение с проверкой левой границы слова (T10): символ перед вхождением
/// не должен быть буквой/цифрой/подчёркиванием, иначе `myparams` поймал бы `params`.
fn bounded_substring(text: &str, needle: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = text[from..].find(needle) {
        let abs = from + pos;
        let ok_left = abs == 0
            || !text[..abs]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if ok_left {
            return true;
        }
        from = abs + 1;
    }
    false
}

/// Источник в цепочке ВЫЗЫВАЕМОГО по сегментам (T10).
fn callee_matches_source(full_raw: &str, lang: &str) -> bool {
    taint_sources(lang)
        .iter()
        .any(|s| segment_source_match(full_raw, s))
}

/// Источник в ИДЕНТИФИКАТОРЕ (одиночное имя) по сегментам (T10). Источник-метод (с точкой)
/// одиночному идентификатору не соответствует; одиночный сегмент-источник — да.
fn ident_matches_source(t: &str, lang: &str) -> bool {
    taint_sources(lang).iter().any(|s| {
        if s.starts_with('.') {
            false
        } else if s.contains('.') || s.contains("::") {
            // составной источник (`request.args`) не может быть одиночным идентификатором,
            // но PHP-суперглобал `$_GET` — целый токен идентификатора-переменной.
            t == *s
        } else {
            t == *s
        }
    })
}

/// Источник в узле ДОСТУПА к полю/атрибуту по сегментам (T10).
fn access_matches_source(t: &str, lang: &str) -> bool {
    taint_sources(lang)
        .iter()
        .any(|s| segment_source_match(t, s))
}

/// T10: префикс вызываемого (всё до последнего сегмента) входит в контролируемый набор.
/// `eval` без префикса (`eval(x)`) и с известным глобалом (`window.eval`) — да; `obj.eval`
/// из чужого namespace — нет. Префиксы сравниваются по последнему сегменту перед leaf.
fn eval_prefix_ok(full: &str, leaf: &str, allowed: &[&str]) -> bool {
    let norm = full.replace("::", ".");
    let prefix = match norm.strip_suffix(leaf) {
        Some(p) => p.trim_end_matches('.'),
        None => return false,
    };
    // последний сегмент префикса (window из window.eval).
    let last = prefix.rsplit('.').next().unwrap_or(prefix);
    allowed.contains(&last)
}

/// T10: голый динамический исполнитель (eval/exec) по leaf с контролем префикса.
fn bare_dynamic_exec(full: &str, leaf: &str, allowed: &[&str]) -> bool {
    matches!(leaf, "eval" | "exec") && eval_prefix_ok(full, leaf, allowed)
}

/// Классификация стока по языку: (правило, важность, что атакуется). None — не сток.
fn classify_sink(
    lang: &str,
    full: &str,
    leaf: &str,
) -> Option<(&'static str, Severity, &'static str)> {
    let cmd = (
        "sast/taint-command-exec",
        Severity::Critical,
        "исполнения команды/кода (CWE-78/94)",
    );
    let sql = ("sast/taint-sql", Severity::High, "SQL-запроса (CWE-89)");
    let path = ("sast/taint-path", Severity::High, "открытия файла (CWE-22)");
    let buffer = (
        "sast/taint-buffer",
        Severity::Critical,
        "небезопасного копирования/формата (переполнение буфера, CWE-120/134)",
    );
    match lang {
        "python" => {
            let subprocess = full.contains("subprocess")
                && matches!(
                    leaf,
                    "run" | "call" | "popen" | "check_output" | "check_call" | "getoutput" | "getstatusoutput"
                );
            // T10: eval/exec по leaf с контролируемым набором префиксов (поймать
            // builtins.eval/__builtins__.exec, но не object.eval из чужого namespace).
            let dyn_exec = bare_dynamic_exec(full, leaf, &["", "builtins", "__builtins__"]);
            // XPath-инъекция (CWE-643): lxml `etree.XPath(...)`/`root.xpath(...)` (leaf
            // xpath покрывает обе формы) и `elementpath.select(...)`. Сток принимает
            // строку XPath-выражения; параметризации в lxml.xpath нет, поэтому ввод в
            // выражении это инъекция. Аргумент-запрос не всегда первый (elementpath.select
            // (root, query)) — проверяем все аргументы (sink_whole_args).
            let xpath = leaf == "xpath" || full.contains("elementpath");
            // LDAP-инъекция (CWE-90): python-ldap `search_s/search_ext_s/search_st` и
            // ldap3 `conn.search(base, filter, …)`. `re.search` исключаем по префиксу.
            let ldap = matches!(leaf, "search" | "search_s" | "search_ext_s" | "search_st")
                && !full.starts_with("re.")
                && !full.starts_with("regex.");
            // Открытый редирект (CWE-601): flask `redirect(...)`, Django
            // `HttpResponseRedirect(...)`, Starlette/FastAPI `RedirectResponse(...)`.
            let redirect = matches!(leaf, "redirect" | "httpresponseredirect" | "redirectresponse");
            // Серверный XSS (CWE-79): рендер недоверенной строки как HTML или построение
            // ответа из неё. `render_template_string` (Jinja-инъекция и XSS), а также
            // `Markup(...)`/`make_response(...)` с заражённым телом. Возврат заражённой
            // строки из обработчика ловит check_response_sink отдельно (это не вызов).
            let xss = matches!(leaf, "render_template_string" | "markup" | "make_response")
                || full == "response";
            if dyn_exec {
                // eval/exec это инъекция КОДА (CWE-94), отдельный класс от команд ОС.
                // Отделён от dangerous-exec намеренно: правило потоковое (verified по
                // taint), а не паттерновое, поэтому не шумит на eval с константой.
                Some((
                    "sast/taint-dynamic-exec",
                    Severity::Critical,
                    "динамического исполнения кода (CWE-94)",
                ))
            } else if full.contains("os.system") || full.contains("os.popen") || subprocess {
                Some(cmd)
            } else if matches!(leaf, "execute" | "executemany" | "executescript") {
                Some(sql)
            } else if matches!(full, "open" | "os.open" | "io.open" | "codecs.open")
                || matches!(
                    leaf,
                    // pathlib.Path: данные в ресивере (p = base / tainted; p.exists()/
                    // p.read_text()), receiver-проверку делает sink_is_dangerous.
                    "read_text" | "read_bytes" | "write_text" | "write_bytes" | "exists"
                        | "is_file" | "is_dir" | "unlink" | "iterdir" | "glob" | "open"
                )
            {
                Some(path)
            } else if xpath {
                Some(("sast/taint-xpath", Severity::High, "XPath-запроса (CWE-643)"))
            } else if ldap {
                Some(("sast/taint-ldap", Severity::High, "LDAP-фильтра (CWE-90)"))
            } else if redirect {
                Some((
                    "sast/taint-open-redirect",
                    Severity::Medium,
                    "редиректа по адресу из ввода (CWE-601)",
                ))
            } else if xss {
                Some(("sast/taint-xss", Severity::High, "HTML-ответа без экранирования (CWE-79)"))
            } else {
                None
            }
        }
        "javascript" | "typescript" => {
            let child_proc = full.contains("child_process")
                && matches!(leaf, "exec" | "execsync" | "spawn" | "spawnsync" | "execfile" | "execfilesync");
            let fs_path = full.contains("fs.")
                && matches!(
                    leaf,
                    "readfile" | "readfilesync" | "createreadstream" | "writefile"
                        | "writefilesync" | "appendfile" | "appendfilesync" | "open" | "opensync"
                );
            // T10: eval/Function по leaf с контролируемым набором глобальных префиксов.
            let dyn_exec = (leaf == "eval"
                && eval_prefix_ok(full, leaf, &["", "window", "globalthis", "self", "global"]))
                || (leaf == "function"
                    && eval_prefix_ok(full, leaf, &["", "window", "globalthis", "self", "global"]));
            if dyn_exec || full.contains("vm.runin") || child_proc {
                Some(cmd) // eval / Function(...) / vm.runInContext / child_process.*
            } else if matches!(leaf, "query" | "execute") {
                Some(sql)
            } else if fs_path || leaf == "sendfile" {
                Some(path)
            } else {
                None
            }
        }
        "go" => {
            if full.contains("exec.command") {
                Some(cmd)
            } else if matches!(leaf, "query" | "exec" | "queryrow" | "querycontext" | "execcontext" | "queryrowcontext") {
                Some(sql)
            } else if full.contains("os.open") || full.contains("os.readfile") || full.contains("os.create") || full.contains("os.readdir") || full.contains("ioutil.read") {
                Some(path)
            } else {
                None
            }
        }
        "java" => {
            // Конструкторы по leaf-имени типа (устойчиво к полной квалификации
            // `new java.io.FileInputStream(...)`): new ProcessBuilder → команда; File* → файл.
            if leaf == "processbuilder" {
                Some(cmd)
            } else if matches!(
                leaf,
                "file" | "fileinputstream" | "fileoutputstream" | "filereader" | "randomaccessfile"
            ) {
                Some(path)
            } else if leaf == "exec" {
                // ailc:ignore[dangerous-exec,command-exec-runtime] — упоминание в комментарии классификатора стоков
                Some(cmd) // Runtime.getRuntime().exec(...)
            } else if matches!(leaf, "executequery" | "executeupdate" | "execute" | "preparestatement") {
                Some(sql) // JDBC (prepareStatement с конкатенацией — тоже инъекция)
            } else if matches!(
                leaf,
                "readallbytes" | "readalllines" | "readstring" | "lines" | "newinputstream"
                    | "newbufferedreader"
            ) {
                Some(path) // java.nio.file.Files.*
            } else {
                None
            }
        }
        "ruby" => {
            let io_path = (full.contains("file.") || full.contains("io."))
                && matches!(leaf, "open" | "read" | "readlines" | "foreach" | "binread");
            if full == "eval"
                || matches!(
                    leaf,
                    "system" | "exec" | "popen" | "popen3" | "spawn" | "capture2" | "capture3"
                )
            {
                Some(cmd)
            } else if matches!(leaf, "execute" | "exec_query") {
                Some(sql)
            } else if full == "open" || io_path {
                Some(path) // Kernel#open / File.read / IO.read
            } else {
                None
            }
        }
        "php" => {
            if matches!(
                leaf,
                "system" | "exec" | "shell_exec" | "passthru" | "popen" | "proc_open"
            ) {
                Some(cmd)
            } else if matches!(leaf, "mysqli_query" | "query" | "pg_query" | "pg_exec") {
                Some(sql)
            } else if matches!(
                leaf,
                "fopen" | "file_get_contents" | "file_put_contents" | "readfile" | "fread"
                    | "fgets" | "opendir" | "scandir" | "simplexml_load_file"
            ) {
                Some(path)
            } else {
                None
            }
        }
        "csharp" => {
            // Конструкторы по leaf-имени типа (устойчиво к полной квалификации
            // `new System.Data.SqlClient.SqlCommand(...)`).
            if matches!(leaf, "process" | "processstartinfo") {
                Some(cmd)
            } else if matches!(
                leaf,
                "sqlcommand" | "mysqlcommand" | "npgsqlcommand" | "sqlitecommand" | "oledbcommand"
            ) {
                Some(sql)
            } else if matches!(leaf, "streamreader" | "streamwriter" | "filestream") {
                Some(path)
            } else if full.contains("process.start") {
                Some(cmd)
            } else if matches!(leaf, "executesqlraw" | "executesqlrawasync" | "fromsqlraw") {
                Some(sql) // EF Core raw SQL
            } else if full.contains("file.")
                && matches!(
                    leaf,
                    "readalltext" | "readallbytes" | "readalllines" | "open" | "openread"
                        | "opentext" | "writealltext" | "writeallbytes"
                )
            {
                Some(path)
            } else {
                None
            }
        }
        "rust" => {
            // Rust использует `::`, поэтому матчим по полному пути вызываемого.
            if full.contains("command::new") {
                Some(cmd)
            } else if full.contains("sqlx::query") || full.contains("sql_query") {
                Some(sql)
            } else if full.contains("file::open") || full.contains("fs::read") || full.contains("fs::write") {
                Some(path)
            } else {
                None
            }
        }
        "kotlin" => {
            // Kotlin без `new`: ProcessBuilder(x)/File(x) — обычные вызовы.
            if leaf == "exec" || leaf == "processbuilder" {
                Some(cmd)
            } else if matches!(leaf, "executequery" | "executeupdate" | "execute" | "preparestatement") {
                Some(sql)
            } else if matches!(
                leaf,
                "file" | "fileinputstream" | "filereader" | "readtext" | "readbytes" | "readlines"
            ) {
                Some(path)
            } else {
                None
            }
        }
        "scala" => {
            if leaf == "exec" || leaf == "process" {
                Some(cmd)
            } else if leaf == "sql"
                || matches!(leaf, "executequery" | "executeupdate" | "execute" | "preparestatement")
            {
                Some(sql) // Anorm SQL(...) / JDBC
            } else if matches!(leaf, "fromfile" | "file" | "fileinputstream") {
                Some(path) // Source.fromFile / new File
            } else {
                None
            }
        }
        "c" | "cpp" => {
            // malloc/calloc/realloc/alloca (заражённый размер) и free (UAF/double-free)
            // обрабатывает check_memory_safety, ЗДЕСЬ их нет — иначе была бы двойная находка.
            let fmt = (
                "sast/taint-format-string",
                Severity::High,
                "форматной строки (CWE-134)",
            );
            if matches!(
                leaf,
                "system" | "popen" | "execl" | "execlp" | "execle" | "execv" | "execvp" | "execvpe"
            ) {
                Some(cmd)
            } else if matches!(leaf, "mysql_query" | "mysql_real_query" | "sqlite3_exec" | "pqexec") {
                Some(sql)
            } else if matches!(leaf, "fopen" | "freopen" | "open" | "open64") {
                Some(path)
            } else if matches!(
                leaf,
                // T08: классические переполнения буфера + n-варианты с заражённой длиной.
                "strcpy" | "strcat" | "sprintf" | "vsprintf" | "stpcpy" | "memcpy" | "memmove"
                    | "strncpy" | "strncat" | "snprintf" | "vsnprintf" | "bcopy" | "wcscpy"
                    | "wcscat"
            ) {
                Some(buffer)
            } else if matches!(leaf, "printf" | "fprintf" | "syslog" | "vprintf" | "vfprintf" | "dprintf" | "err" | "warn") {
                Some(fmt) // T08: форматная строка из недоверенного источника (CWE-134)
            } else {
                None
            }
        }
        "swift" => {
            // Серверный Swift (Vapor) / CLI: команда · SQL (SQLite.swift/Vapor raw) · файл.
            if leaf == "system" || leaf == "popen" || full.contains("process") || leaf == "launch" {
                Some(cmd)
            } else if matches!(leaf, "prepare" | "run" | "scalar" | "execute" | "raw") {
                Some(sql) // SQLite.swift db.run/prepare/scalar · Vapor .raw(SQLQueryString)
            } else if leaf == "contentsoffile" || full.contains("filehandle") {
                Some(path)
            } else {
                None
            }
        }
        "dart" => {
            if full.contains("process.run") || full.contains("process.start") {
                Some(cmd)
            } else if matches!(leaf, "rawquery" | "rawinsert" | "rawupdate" | "rawdelete" | "execute") {
                Some(sql)
            } else if leaf == "file"
                || matches!(leaf, "readasstring" | "readasbytes" | "readaslines" | "open")
            {
                Some(path)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Класс стока для контекстной проверки санитайзера (T06) по идентификатору правила.
fn sink_class_for_rule(rule: &str) -> SinkClass {
    match rule {
        "sast/taint-command-exec" => SinkClass::Command,
        "sast/taint-sql" => SinkClass::Sql,
        "sast/taint-path" => SinkClass::Path,
        // Серверный XSS — сток разметки: HTML-экранирование (html.escape/markupsafe/
        // escape_for_html) снимает заражение, поэтому класс Html.
        "sast/taint-xss" => SinkClass::Html,
        // buffer/format/alloc — контекст размера/копирования: числовой санитайзер тут не
        // снимает риск переполнения, поэтому Size.
        "sast/taint-buffer" | "sast/taint-format-string" | "sast/taint-alloc-size" => {
            SinkClass::Size
        }
        // XPath/LDAP/редирект/код-инъекция: курируемого санитайзера-функции в корпусе нет,
        // числовое приведение всё же безопасно (Other пропускает Numeric), прочее опасно.
        _ => SinkClass::Other,
    }
}

/// Истинно ли, что классифицированный сток `call` получает заражённый аргумент (T09:
/// используется и обратным межпроцедурным проходом). Без записи находки.
fn sink_is_dangerous(
    call: &Node,
    tainted: &HashSet<String>,
    sanitized: &HashMap<String, SanClass>,
    bytes: &[u8],
    lang: &str,
    source_fns: &HashSet<String>,
) -> bool {
    let Some(full_raw) = callee_text(call, bytes) else {
        return false;
    };
    let full = full_raw.to_lowercase();
    let leaf = full.rsplit(['.', ':']).next().unwrap_or(full.as_str());
    let Some((rule, _sev, _what)) = classify_sink(lang, &full, leaf) else {
        return false;
    };
    let Some(args) = call_args(call) else {
        return false;
    };
    let sink = sink_class_for_rule(rule);
    let qpos = sql_query_arg_index(lang, rule, leaf).unwrap_or(0);
    let via_args = if sink_whole_args(rule, lang) {
        expr_tainted(&args, tainted, sanitized, bytes, lang, source_fns, sink, 0)
    } else {
        // SQL/path/format-string/alloc проверяют аргумент-запрос/путь/форматную строку/размер
        // (для Go-SQL — точную позицию qpos); buffer/command идут целиком (sink_whole_args).
        args.named_child(qpos)
            .map(unwrap_arg)
            .is_some_and(|first| expr_tainted(&first, tainted, sanitized, bytes, lang, source_fns, sink, 0))
    };
    if via_args {
        return true;
    }
    // pathlib (CWE-22): у `p.exists()`/`p.read_text()` опасные данные в РЕСИВЕРЕ (p = base /
    // tainted), а не в аргументах. Проверяем заражённость ресивера ТОЛЬКО для path-стока,
    // чтобы не менять поведение командных/SQL-стоков.
    if rule == "sast/taint-path" {
        if let Some(func) = callee_full(call) {
            if let Some(recv) = receiver_of(&func) {
                if expr_refs_tainted(&recv, tainted, bytes, source_fns) {
                    return true;
                }
            }
        }
    }
    false
}

/// Какие аргументы стока проверять целиком (T11). Команда/буфер — все. SQL целиком в
/// php/c/cpp (запрос не первый, bind-параметры в этих API позиционно не отделены).
/// format-string — первый. Go-SQL целиком НЕ проверяем (параметры привязки идут после
/// запроса и не должны давать FP на параметризованном запросе): для него точную позицию
/// строки запроса даёт sql_query_arg_index.
fn sink_whole_args(rule: &str, lang: &str) -> bool {
    matches!(
        rule,
        "sast/taint-command-exec"
            | "sast/taint-buffer"
            | "sast/taint-dynamic-exec"
            // XPath/LDAP: строка-выражение не всегда первый аргумент
            // (elementpath.select(root, query); conn.search(base, filter, …)),
            // поэтому проверяем все аргументы стока.
            | "sast/taint-xpath"
            | "sast/taint-ldap"
            // Серверный XSS: тело ответа может быть любым из аргументов конструктора
            // ответа, проверяем целиком.
            | "sast/taint-xss"
    ) || (rule == "sast/taint-sql" && matches!(lang, "php" | "c" | "cpp"))
}

/// T11: позиция аргумента-СТРОКИ-ЗАПРОСА для SQL-стоков, где запрос не первый. Для Go
/// Context-вариантов (`db.QueryContext(ctx, q, args...)`) запрос на позиции 1; для обычных
/// (`db.Query(q, args...)`) — на позиции 0. None: язык/сток обрабатывается общим правилом
/// (первый аргумент) либо whole_args.
fn sql_query_arg_index(lang: &str, rule: &str, leaf: &str) -> Option<usize> {
    // T08: позиция форматной строки для C/C++ format-string стоков. printf — 0;
    // fprintf/syslog/dprintf/err/warn — 1 (перед форматом идёт поток/приоритет/fd).
    if rule == "sast/taint-format-string" {
        return Some(match leaf {
            "fprintf" | "syslog" | "dprintf" | "vfprintf" => 1,
            _ => 0, // printf / vprintf / err / warn
        });
    }
    if lang == "go" && rule == "sast/taint-sql" {
        return Some(match leaf {
            "querycontext" | "execcontext" | "queryrowcontext" => 1,
            _ => 0, // query / exec / queryrow
        });
    }
    None
}

/// Вызов-сток: классифицируем по имени, проверяем аргументы на заражение, при потоке
/// добавляем находку. T06: санитайзер сверяется с классом стока. T11: для Go-SQL
/// проверяются все аргументы (запрос не первый). T14: эвристический taint-результат
/// помечается verified=false и снабжается evidence-фрагментом узла-стока.
#[allow(clippy::too_many_arguments)]
fn check_taint_sink(
    call: &Node,
    tainted: &HashSet<String>,
    sanitized: &HashMap<String, SanClass>,
    bytes: &[u8],
    rel: &str,
    lang: &str,
    source_fns: &HashSet<String>,
    out: &mut Vec<Finding>,
) {
    let Some(full_raw) = callee_text(call, bytes) else {
        return;
    };
    let full = full_raw.to_lowercase();
    let leaf = full.rsplit(['.', ':']).next().unwrap_or(full.as_str());

    let Some((rule, sev, what)) = classify_sink(lang, &full, leaf) else {
        return;
    };

    let Some(args) = call_args(call) else {
        return;
    };
    let sink = sink_class_for_rule(rule);
    // T11: позиция строки запроса (Go Context-варианты — не первый аргумент).
    let qpos = sql_query_arg_index(lang, rule, leaf).unwrap_or(0);
    let dangerous = if sink_whole_args(rule, lang) {
        expr_tainted(&args, tainted, sanitized, bytes, lang, source_fns, sink, 0)
    } else {
        args.named_child(qpos)
            .map(unwrap_arg)
            .is_some_and(|first| expr_tainted(&first, tainted, sanitized, bytes, lang, source_fns, sink, 0))
    };
    if dangerous {
        let line = call.start_position().row as u32 + 1;
        // T14: taint-находка эвристична (подстрочные источники, грубые санитайзеры, проход
        // насквозь), verified=false до фактической верификации; evidence — фрагмент стока.
        push(
            out,
            rel,
            line,
            rule,
            sev,
            false,
            node_evidence(call, bytes),
            format!(
                "Поток недоверенных данных достигает {what}: пользовательский ввод течёт в `{}(…)`. Валидируйте/параметризуйте на пути от источника к стоку.",
                full_raw.trim()
            ),
        );
    }
}

/// Граница доверия (CWE-501): запись недоверенных данных в серверную сессию
/// (`flask.session[bar] = …`, `session[k] = tainted`). Ключ или значение из запроса
/// попадают в доверенное хранилище без валидации. Форма характерна для Python/Flask, на
/// неё и ограничено, чтобы не флагать обычные присваивания в словари. Сток это сам левый
/// узел-подписка, а не вызов; проверяется в walk_taint до update_taint.
fn check_trust_boundary(
    assign: &Node,
    tainted: &HashSet<String>,
    bytes: &[u8],
    rel: &str,
    lang: &str,
    source_fns: &HashSet<String>,
    out: &mut Vec<Finding>,
) {
    if lang != "python" {
        return;
    }
    let (Some(left), Some(right)) = (
        assign.child_by_field_name("left"),
        assign.child_by_field_name("right"),
    ) else {
        return;
    };
    if left.kind() != "subscript" {
        return;
    }
    // База подписки — session / flask.session / <obj>.session.
    let Some(base) = left.child_by_field_name("value") else {
        return;
    };
    let Some(base_key) = qualified_path(&base, bytes) else {
        return;
    };
    let bl = base_key.to_lowercase();
    if bl != "session" && !bl.ends_with(".session") {
        return;
    }
    // Заражён ключ (идентификатор внутри подписки) либо присваиваемое значение.
    if expr_refs_tainted(&left, tainted, bytes, source_fns)
        || expr_refs_tainted(&right, tainted, bytes, source_fns)
    {
        let line = assign.start_position().row as u32 + 1;
        push(
            out,
            rel,
            line,
            "sast/taint-trust-boundary",
            Severity::Medium,
            false,
            node_evidence(assign, bytes),
            "Недоверенные данные записаны в серверную сессию (CWE-501, нарушение границы доверия). Валидируйте ключ и значение перед сохранением в session.".into(),
        );
    }
}

/// Серверный отражённый XSS (CWE-79): обработчик ВОЗВРАЩАЕТ заражённую строку как тело
/// HTTP-ответа. Сток это сам `return`, а не вызов, поэтому ловится отдельно. Класс стока
/// Html: HTML-экранирование на пути (markupsafe.escape/html.escape/escape_for_html) снимает
/// заражение, поэтому защищённые обработчики не флагуются. Числовое приведение тоже чисто.
fn check_response_sink(
    ret: &Node,
    tainted: &HashSet<String>,
    sanitized: &HashMap<String, SanClass>,
    bytes: &[u8],
    rel: &str,
    lang: &str,
    source_fns: &HashSet<String>,
    out: &mut Vec<Finding>,
) {
    let Some(expr) = ret.named_child(0) else {
        return;
    };
    // Возврат прямого ВЫЗОВА (`return get_input()`, `return jsonify(user)`,
    // `return flask.redirect(url)`) это проброс/сериализация/готовый объект-ответ, а не
    // рендеринг недоверённой строки в тело ответа: иначе любой хелпер, возвращающий
    // данные запроса, ложно считался бы XSS. XSS-вывод строится из локальной строки
    // (идентификатор тела ответа или интерполяция/конкатенация), её и проверяем; готовые
    // строковые ответчики (render_template_string/make_response) ловит классификация стока.
    if is_call_node(lang, expr.kind()) {
        return;
    }
    if expr_tainted(&expr, tainted, sanitized, bytes, lang, source_fns, SinkClass::Html, 0) {
        let line = ret.start_position().row as u32 + 1;
        push(
            out,
            rel,
            line,
            "sast/taint-xss",
            Severity::High,
            false,
            node_evidence(ret, bytes),
            "Заражённые данные возвращаются как тело HTTP-ответа без экранирования (CWE-79, отражённый XSS). Экранируйте вывод (markupsafe.escape) или используйте шаблон с автоэкранированием.".into(),
        );
    }
}

/// T08: модель жизненного цикла памяти C/C++ внутри функции. Отслеживает множество
/// освобождённых указателей `freed`: повторный `free`/`delete` того же указателя —
/// double-free (CWE-415); использование освобождённого указателя в любом вызове до его
/// переназначения — use-after-free (CWE-416). После переназначения (`p = ...`) указатель
/// снимается из freed (это делает update_taint косвенно через имя, но мы явно очищаем тут).
#[allow(clippy::too_many_arguments)]
fn check_memory_safety(
    call: &Node,
    tainted: &HashSet<String>,
    sanitized: &HashMap<String, SanClass>,
    freed: &mut HashSet<String>,
    bytes: &[u8],
    rel: &str,
    lang: &str,
    source_fns: &HashSet<String>,
    out: &mut Vec<Finding>,
) {
    let Some(full_raw) = callee_text(call, bytes) else {
        return;
    };
    let full = full_raw.to_lowercase();
    let leaf = full.rsplit(['.', ':']).next().unwrap_or(full.as_str());

    // Перед обработкой free проверяем use-after-free: ЛЮБОЙ аргумент вызова, ссылающийся
    // на уже освобождённый указатель (и сам вызов не повторный free того же указателя).
    if leaf != "free" {
        if let Some(args) = call_args(call) {
            let mut cur = args.walk();
            for arg in args.named_children(&mut cur) {
                if let Some(name) = inner_ident(&unwrap_arg(arg), bytes) {
                    if freed.contains(&name) {
                        let line = call.start_position().row as u32 + 1;
                        push(
                            out,
                            rel,
                            line,
                            "sast/use-after-free",
                            Severity::Critical,
                            false,
                            node_evidence(call, bytes),
                            format!(
                                "Использование освобождённого указателя `{name}` после free (use-after-free, CWE-416): обнуляйте указатель сразу после освобождения."
                            ),
                        );
                    }
                }
            }
        }
    }

    if leaf == "free" {
        // free(p): double-free, если p уже в freed; иначе помечаем p освобождённым.
        if let Some(args) = call_args(call) {
            if let Some(first) = args.named_child(0) {
                if let Some(name) = inner_ident(&unwrap_arg(first), bytes) {
                    let line = call.start_position().row as u32 + 1;
                    if freed.contains(&name) {
                        push(
                            out,
                            rel,
                            line,
                            "sast/double-free",
                            Severity::Critical,
                            false,
                            node_evidence(call, bytes),
                            format!(
                                "Повторное освобождение указателя `{name}` (double-free, CWE-415): порча кучи; освобождайте ровно один раз и обнуляйте указатель."
                            ),
                        );
                    } else {
                        freed.insert(name);
                    }
                }
            }
        }
        return;
    }

    // C++ delete/delete[] — те же UAF/double-free.
    if matches!(leaf, "delete" | "delete[]") {
        return;
    }

    // T08: malloc/calloc/realloc/alloca с ЗАРАЖЁННЫМ размером — целочисленное переполнение
    // размера выделения (CWE-190). Размер: для malloc/alloca первый аргумент, для calloc
    // оба (n*size), для realloc второй.
    if matches!(leaf, "malloc" | "calloc" | "realloc" | "alloca") {
        if let Some(args) = call_args(call) {
            let tainted_size = match leaf {
                "realloc" => args
                    .named_child(1)
                    .map(unwrap_arg)
                    .is_some_and(|a| expr_tainted(&a, tainted, sanitized, bytes, lang, source_fns, SinkClass::Size, 0)),
                _ => {
                    let mut cur = args.walk();
                    let any_tainted = args.named_children(&mut cur).any(|a| {
                        expr_tainted(&unwrap_arg(a), tainted, sanitized, bytes, lang, source_fns, SinkClass::Size, 0)
                    });
                    any_tainted
                }
            };
            if tainted_size {
                let line = call.start_position().row as u32 + 1;
                push(
                    out,
                    rel,
                    line,
                    "sast/taint-alloc-size",
                    Severity::High,
                    false,
                    node_evidence(call, bytes),
                    format!(
                        "Размер выделения памяти в `{}` зависит от недоверенного ввода (целочисленное переполнение/чрезмерное выделение, CWE-190/789): проверяйте величину перед выделением.",
                        full_raw.trim()
                    ),
                );
            }
        }
    }
}

/// T08: при присваивании-цели в C/C++ снимаем имя цели из множества освобождённых.
/// Извлекаем имя из тех же полей, что и update_taint (left/declarator), и удаляем из freed.
fn clear_freed_on_reassign(assign: &Node, freed: &mut HashSet<String>, bytes: &[u8]) {
    let left = match assign.kind() {
        "init_declarator" => assign.child_by_field_name("declarator"),
        _ => assign.child_by_field_name("left"),
    };
    if let Some(left) = left {
        if let Some(name) = left_name(&left, bytes) {
            freed.remove(&name);
        }
    }
}

/// T09: вызов функции, чей формальный параметр достигает стока (sink-параметр), с
/// ЗАРАЖЁННЫМ фактическим аргументом на этой позиции — порождает находку обратного потока.
#[allow(clippy::too_many_arguments)]
fn check_call_into_sink_param(
    call: &Node,
    tainted: &HashSet<String>,
    sanitized: &HashMap<String, SanClass>,
    bytes: &[u8],
    rel: &str,
    lang: &str,
    inter: &InterProc,
    out: &mut Vec<Finding>,
) {
    let Some(full_raw) = callee_text(call, bytes) else {
        return;
    };
    let full = full_raw.to_lowercase();
    let leaf = full.rsplit(['.', ':']).next().unwrap_or(full.as_str());
    // sink-параметры индексируются по имени функции (leaf или полное имя).
    let Some(params) = inter
        .sink_params
        .get(leaf)
        .or_else(|| inter.sink_params.get(full.as_str()))
    else {
        return;
    };
    let Some(args) = call_args(call) else {
        return;
    };
    let mut cur = args.walk();
    let actual: Vec<Node> = args.named_children(&mut cur).collect();
    for &idx in params {
        if let Some(a) = actual.get(idx) {
            if expr_tainted(&unwrap_arg(*a), tainted, sanitized, bytes, lang, &inter.source_fns, SinkClass::Command, 0) {
                let line = call.start_position().row as u32 + 1;
                push(
                    out,
                    rel,
                    line,
                    "sast/taint-interproc",
                    Severity::High,
                    false,
                    node_evidence(call, bytes),
                    format!(
                        "Недоверенные данные передаются в `{}(…)`: внутри функции этот параметр достигает опасного стока (межпроцедурный поток). Валидируйте ввод до вызова.",
                        full_raw.trim()
                    ),
                );
            }
        }
    }
}

/// Версия для intra-прохода сбора sink-параметров (T09): тот же транзит, но БЕЗ записи
/// находки — только сигнал «параметр течёт в sink-параметр другой функции».
fn call_into_sink_param(
    call: &Node,
    tainted: &HashSet<String>,
    sanitized: &HashMap<String, SanClass>,
    bytes: &[u8],
    lang: &str,
    inter: &InterProc,
) -> bool {
    let Some(full_raw) = callee_text(call, bytes) else {
        return false;
    };
    let full = full_raw.to_lowercase();
    let leaf = full.rsplit(['.', ':']).next().unwrap_or(full.as_str());
    let Some(params) = inter
        .sink_params
        .get(leaf)
        .or_else(|| inter.sink_params.get(full.as_str()))
    else {
        return false;
    };
    let Some(args) = call_args(call) else {
        return false;
    };
    let mut cur = args.walk();
    let actual: Vec<Node> = args.named_children(&mut cur).collect();
    for &idx in params {
        if let Some(a) = actual.get(idx) {
            if expr_tainted(&unwrap_arg(*a), tainted, sanitized, bytes, lang, &inter.source_fns, SinkClass::Command, 0) {
                return true;
            }
        }
    }
    false
}

fn check_pii_log(call: &Node, bytes: &[u8], rel: &str, out: &mut Vec<Finding>) {
    let Some(func) = callee_full(call) else {
        return;
    };
    let Ok(full) = func.utf8_text(bytes) else {
        return;
    };
    if !is_log_callee(&full.to_lowercase()) {
        return;
    }
    let Some(args) = call_args(call) else {
        return;
    };
    let Ok(args_text) = args.utf8_text(bytes) else {
        return;
    };
    // Замаскированное значение — не находка (ровно то, что line-regex не умеет).
    let at = args_text.to_lowercase();
    if at.contains("mask") || at.contains("redact") || at.contains("anonym") || at.contains("hash(")
    {
        return;
    }
    // Идентификаторы в поддереве аргументов: user.passport, snilsNumber, …
    let mut stack = vec![args];
    while let Some(n) = stack.pop() {
        if n.kind().contains("identifier") {
            if let Ok(t) = n.utf8_text(bytes) {
                if has_pii_token(t) {
                    out.push(Finding {
                        rule: "pdn-log-dynamic".into(),
                        severity: Severity::High,
                        message: format!(
                            "ПДн в логах: `{}` логирует поле с персональными данными — маскируй значение (152-ФЗ ст.19; утечка ПДн — штраф до 15 млн, ст.13.11 КоАП)",
                            full.trim()
                        ),
                        location: Some(Location {
                            file: rel.to_string(),
                            line: call.start_position().row as u32 + 1,
                        }),
                        evidence: Some(args_text.trim().chars().take(120).collect()),
                        // T14: эвристика по ПДн-токену — verified=false до фактической проверки,
                        // но evidence заполнен (фрагмент аргументов лог-вызова).
                        verified: false,
                        source: "compliance.ru/pdn-logs-ast".into(),
                    });
                    return; // одна находка на вызов
                }
            }
        }
        let mut cur = n.walk();
        for ch in n.named_children(&mut cur) {
            stack.push(ch);
        }
    }
}

// ───────────────────────────── юнит-тесты дорожки sast-taint ─────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use ailc_contracts::RunInput;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Временный проект с файлами для прогона публичных функций движка.
    fn tmp(files: &[(&str, &str)]) -> Ctx {
        let n = CNT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ailc-sast-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (rel, content) in files {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(p, content).unwrap();
        }
        Ctx::new(dir)
    }

    fn rules(rep: &SastReport) -> Vec<&str> {
        rep.findings.iter().map(|f| f.rule.as_str()).collect()
    }

    // ── T16: именованный аргумент не подменяет значение меткой ──
    #[test]
    fn t16_named_argument_value_not_label() {
        // Kotlin: exec(command = call.parameters["c"]) — значение, а не метка, заражено.
        let ctx = tmp(&[(
            "K.kt",
            concat!(
                "fun vuln(call: ApplicationCall) {\n",
                "    val cmd = call.parameters[\"c\"]\n",
                "    Runtime.getRuntime().exec(command = cmd)\n",
                "}\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(
            rules(&rep).contains(&"sast/taint-command-exec"),
            "значение именованного аргумента должно проверяться: {:?}",
            rules(&rep)
        );
    }

    // ── T07: yaml.full_load/unsafe_load и алиасы как небезопасная десериализация ──
    #[test]
    fn t07_yaml_full_load_detected() {
        let ctx = tmp(&[(
            "a.py",
            concat!(
                "import yaml\n",
                "def v(d):\n",
                "    yaml.full_load(d)\n",
                "def u(d):\n",
                "    yaml.unsafe_load(d)\n",
                "def s(d):\n",
                "    yaml.safe_load(d)\n",
                "def w(d):\n",
                "    yaml.load(d, Loader=yaml.SafeLoader)\n",
            ),
        )]);
        let rep = scan(&ctx, &RunInput::default()).unwrap();
        let de = rep
            .findings
            .iter()
            .filter(|f| f.rule == "sast/unsafe-deserialize")
            .count();
        assert_eq!(
            de, 2,
            "full_load и unsafe_load флагуются; safe_load и SafeLoader — нет: {:?}",
            rules(&rep)
        );
    }

    // ── T06: контекстный санитайзер — basename НЕ снимает заражение для команды ──
    #[test]
    fn t06_basename_does_not_clear_command_sink() {
        let ctx = tmp(&[(
            "a.py",
            concat!(
                "import os\n",
                "def vuln():\n",
                "    c = os.path.basename(request.args.get('c'))\n",
                "    os.system(c)\n",
                "def numeric():\n",
                "    n = int(request.args.get('n'))\n",
                "    os.system(n)\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        let cmd = rep
            .findings
            .iter()
            .filter(|f| f.rule == "sast/taint-command-exec")
            .count();
        assert_eq!(
            cmd, 1,
            "basename (path) не очищает команду — находка; int (numeric) очищает — нет: {:?}",
            rules(&rep)
        );
        assert_eq!(rep.findings[0].location.as_ref().unwrap().line, 4);
    }

    // ── T05: квалифицированный путь self.x хранит заражение ──
    #[test]
    fn t05_qualified_path_field_tracks_taint() {
        let ctx = tmp(&[(
            "a.py",
            concat!(
                "import os\n",
                "class C:\n",
                "    def vuln(self):\n",
                "        self.cmd = request.args.get('c')\n",
                "        os.system(self.cmd)\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(
            rules(&rep).contains(&"sast/taint-command-exec"),
            "поток через self.cmd должен сохраняться: {:?}",
            rules(&rep)
        );
    }

    // ── T05: мутирующий метод append заражает ресивер ──
    #[test]
    fn t05_mutating_append_taints_receiver() {
        let ctx = tmp(&[(
            "a.py",
            concat!(
                "import os\n",
                "def vuln():\n",
                "    parts = []\n",
                "    parts.append(request.args.get('c'))\n",
                "    os.system(parts)\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(
            rules(&rep).contains(&"sast/taint-command-exec"),
            "append(user) заражает ресивер parts: {:?}",
            rules(&rep)
        );
    }

    // ── T11: SQL-инъекция через f-string распознаётся; склейка констант — нет ──
    #[test]
    fn t11_fstring_sql_and_constant_concat() {
        let ctx = tmp(&[(
            "a.py",
            concat!(
                "def vuln(cur):\n",
                "    uid = request.args.get('id')\n",
                "    cur.execute(f\"SELECT * FROM t WHERE id={uid}\")\n",
                "def safe_const(cur):\n",
                "    cur.execute(\"SELECT \" + \"1\")\n",
            ),
        )]);
        let rep = scan(&ctx, &RunInput::default()).unwrap();
        let sql = rep
            .findings
            .iter()
            .filter(|f| f.rule == "sast/sql-injection")
            .count();
        assert_eq!(
            sql, 1,
            "f-string с динамикой — находка; склейка двух констант — нет: {:?}",
            rules(&rep)
        );
    }

    // ── T11: Go Context-вариант проверяет позицию запроса (не первый аргумент) ──
    #[test]
    fn t11_go_querycontext_query_position() {
        let ctx = tmp(&[(
            "h.go",
            concat!(
                "package main\n",
                "func vuln(db *DB, r *Request, ctx Context) {\n",
                "    q := r.FormValue(\"q\")\n",
                "    db.QueryContext(ctx, q)\n",
                "}\n",
                "func safe(db *DB, r *Request, ctx Context) {\n",
                "    db.QueryContext(ctx, \"SELECT 1\", r.FormValue(\"id\"))\n",
                "}\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        let sql = rep.findings.iter().filter(|f| f.rule == "sast/taint-sql").count();
        assert_eq!(
            sql, 1,
            "QueryContext(ctx, q) — находка на позиции запроса; параметризованный (bind после запроса) — нет: {:?}",
            rules(&rep)
        );
    }

    // ── T08: use-after-free и double-free в C ──
    #[test]
    fn t08_use_after_free_and_double_free() {
        let ctx = tmp(&[(
            "m.c",
            concat!(
                "void vuln() {\n",
                "    char* p = malloc(10);\n",
                "    free(p);\n",
                "    strlen(p);\n",   // use-after-free
                "    free(p);\n",    // double-free
                "}\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(rules(&rep).contains(&"sast/use-after-free"), "UAF: {:?}", rules(&rep));
        assert!(rules(&rep).contains(&"sast/double-free"), "double-free: {:?}", rules(&rep));
    }

    // ── T08: malloc с заражённым размером и memcpy ──
    #[test]
    fn t08_tainted_alloc_size_and_memcpy() {
        let ctx = tmp(&[(
            "m.c",
            concat!(
                "void vuln() {\n",
                "    char* n = getenv(\"N\");\n",
                "    char* buf = malloc(n);\n",   // заражённый размер
                "    memcpy(dst, n, 10);\n",     // заражённый источник копирования
                "}\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(rules(&rep).contains(&"sast/taint-alloc-size"), "alloc-size: {:?}", rules(&rep));
        assert!(rules(&rep).contains(&"sast/taint-buffer"), "memcpy buffer: {:?}", rules(&rep));
    }

    // ── T08: format-string из заражённого источника ──
    #[test]
    fn t08_format_string_sink() {
        let ctx = tmp(&[(
            "m.c",
            "void vuln() {\n    char* s = getenv(\"X\");\n    printf(s);\n}\n",
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(
            rules(&rep).contains(&"sast/taint-format-string"),
            "printf(s) с заражённой форматной строкой: {:?}",
            rules(&rep)
        );
    }

    // ── T09: межпроцедурный обратный поток через параметр функции ──
    #[test]
    fn t09_interprocedural_param_to_sink() {
        let ctx = tmp(&[(
            "a.py",
            concat!(
                "import os\n",
                "def run(cmd):\n",
                "    os.system(cmd)\n",
                "def vuln():\n",
                "    run(request.args.get('c'))\n",
                "def safe():\n",
                "    run('ls -la')\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        let ip = rep
            .findings
            .iter()
            .filter(|f| f.rule == "sast/taint-interproc")
            .count();
        assert_eq!(
            ip, 1,
            "run(заражённый) — находка обратного потока; run('ls') — нет: {:?}",
            rules(&rep)
        );
    }

    // ── T10: forgetenv не совпадает с источником getenv (границы сегмента) ──
    #[test]
    fn t10_segment_match_no_false_positive() {
        assert!(segment_source_match("r.FormValue", ".FormValue"));
        assert!(!segment_source_match("r.Bodyguard", ".Body"));
        assert!(segment_source_match("getenv", "getenv"));
        assert!(!segment_source_match("forgetenv", "getenv"));
        assert!(segment_source_match("request.args.get", "request.args"));
        assert!(!segment_source_match("myrequest.argsx", "request.args"));
    }

    // ── T12: переприсваивание в одной ветке не снимает заражение после if ──
    #[test]
    fn t12_branch_join_keeps_taint() {
        let ctx = tmp(&[(
            "a.py",
            concat!(
                "import os\n",
                "def vuln(flag):\n",
                "    cmd = request.args.get('c')\n",
                "    if flag:\n",
                "        cmd = 'safe'\n",
                "    os.system(cmd)\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(
            rules(&rep).contains(&"sast/taint-command-exec"),
            "реассайн только в ветке if не должен гасить заражение (join): {:?}",
            rules(&rep)
        );
    }

    // ── T13: лимит глубины не роняет процесс на глубоко вложенном выражении ──
    #[test]
    fn t13_deep_nesting_terminates() {
        // Глубоко вложенная конкатенация — обход обязан завершиться (без переполнения стека).
        let mut expr = String::from("request.args.get('c')");
        for _ in 0..600 {
            expr = format!("f({expr})");
        }
        let src = format!("import os\ndef v():\n    os.system({expr})\n");
        let ctx = tmp(&[("a.py", src.as_str())]);
        // Сам факт успешного возврата (без паники) — проверка лимита глубины.
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(rep.files >= 1);
    }

    // ── T14: taint-находка verified=false и с заполненным evidence ──
    #[test]
    fn t14_taint_finding_unverified_with_evidence() {
        let ctx = tmp(&[(
            "a.py",
            "import os\ndef v():\n    c = request.args.get('c')\n    os.system(c)\n",
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        let f = rep
            .findings
            .iter()
            .find(|f| f.rule == "sast/taint-command-exec")
            .expect("находка есть");
        assert!(!f.verified, "taint-находка эвристична, verified=false");
        assert!(f.evidence.is_some(), "evidence заполнен фрагментом стока");
        assert!(f.evidence.as_ref().unwrap().contains("os.system"));
    }

    // ── T14: структурная находка scan остаётся verified=true ──
    #[test]
    fn t14_structural_finding_verified_true() {
        // eval/exec выведены в потоковый сток; для структурной верификации берём
        // десериализацию по полному имени (детерминированное правило scan).
        let ctx = tmp(&[("a.py", "import pickle\ndef v(x):\n    pickle.loads(x)\n")]);
        let rep = scan(&ctx, &RunInput::default()).unwrap();
        let f = rep
            .findings
            .iter()
            .find(|f| f.rule == "sast/unsafe-deserialize")
            .expect("находка есть");
        assert!(f.verified, "структурное правило детерминировано, verified=true");
    }

    // ── T15: счётчики пропусков растут на нечитаемом/непарсящемся вводе ──
    #[test]
    fn t15_skip_counters_track_coverage() {
        // .py разбирается; .xyz — исходноподобного нет, источник на python-файле + язык
        // вне taint-профиля считается skipped_lang.
        let ctx = tmp(&[
            ("ok.py", "def v(x):\n    eval(x)\n"),
            ("weird.zig", "pub fn main() void {}\n"),
        ]);
        let rep = scan(&ctx, &RunInput::default()).unwrap();
        assert!(rep.files >= 1, "python-файл разобран");
        assert!(
            rep.skipped_lang >= 1,
            "исходник без AST-грамматики учтён в skipped_lang"
        );
    }

    // ── T10: builtins.eval как сток КОДОВОЙ инъекции (точное равенство снято) ──
    #[test]
    fn t10_builtins_eval_sink() {
        // классификация python eval: точное full=="eval" заменено на leaf-проверку.
        // eval/exec теперь отдельный потоковый сток кодовой инъекции (CWE-94), не команда.
        let cmd = classify_sink("python", "builtins.eval", "eval");
        assert!(cmd.is_some(), "builtins.eval должен классифицироваться как сток");
        assert_eq!(cmd.unwrap().0, "sast/taint-dynamic-exec");
    }

    // ── Новые потоковые стоки web-слоя: XPath/LDAP/редирект/XSS/граница доверия ──
    #[test]
    fn xpath_injection_flow() {
        // lxml etree.XPath(query) с заражённым выражением — XPath-инъекция (CWE-643).
        let ctx = tmp(&[(
            "x.py",
            concat!(
                "import lxml.etree\n",
                "def v():\n",
                "    bar = request.cookies.get('q')\n",
                "    q = '/Employees/Employee[@id=\\'' + bar + '\\']'\n",
                "    lxml.etree.XPath(q)\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(rules(&rep).contains(&"sast/taint-xpath"), "xpath-сток: {:?}", rules(&rep));
    }

    #[test]
    fn xpath_safe_constant_not_flagged() {
        // Ввод перезаписан константой до стока — заражение снято, находки быть не должно.
        let ctx = tmp(&[(
            "x.py",
            concat!(
                "import lxml.etree\n",
                "def v():\n",
                "    bar = request.cookies.get('q')\n",
                "    bar = 'safe'\n",
                "    lxml.etree.XPath(bar)\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(!rules(&rep).contains(&"sast/taint-xpath"), "константа не XPath: {:?}", rules(&rep));
    }

    #[test]
    fn ldap_injection_flow() {
        // ldap3 conn.search(base, filter) с заражённым фильтром — LDAP-инъекция (CWE-90).
        let ctx = tmp(&[(
            "l.py",
            concat!(
                "def v(conn):\n",
                "    bar = request.form.get('u')\n",
                "    flt = '(uid=' + bar + ')'\n",
                "    conn.search(base, flt)\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(rules(&rep).contains(&"sast/taint-ldap"), "ldap-сток: {:?}", rules(&rep));
    }

    #[test]
    fn re_search_is_not_ldap() {
        // re.search(pattern, tainted) НЕ должен считаться LDAP-стоком (исключение по re.).
        let ctx = tmp(&[(
            "r.py",
            concat!(
                "import re\n",
                "def v():\n",
                "    bar = request.args.get('q')\n",
                "    re.search('x', bar)\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(!rules(&rep).contains(&"sast/taint-ldap"), "re.search не LDAP: {:?}", rules(&rep));
    }

    #[test]
    fn open_redirect_flow() {
        // flask.redirect(bar) с заражённым адресом — открытый редирект (CWE-601).
        let ctx = tmp(&[(
            "o.py",
            concat!(
                "import flask\n",
                "def v():\n",
                "    bar = request.cookies.get('next')\n",
                "    return flask.redirect(bar)\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(
            rules(&rep).contains(&"sast/taint-open-redirect"),
            "redirect-сток: {:?}",
            rules(&rep)
        );
    }

    #[test]
    fn server_xss_return_flow() {
        // Возврат заражённой строки как тела ответа — серверный XSS (CWE-79).
        let ctx = tmp(&[(
            "s.py",
            concat!(
                "def v():\n",
                "    bar = request.args.get('q')\n",
                "    return 'hello ' + bar\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(rules(&rep).contains(&"sast/taint-xss"), "xss-сток: {:?}", rules(&rep));
    }

    #[test]
    fn server_xss_escaped_not_flagged() {
        // HTML-экранирование вывода снимает заражение XSS-стока (класс Html).
        let ctx = tmp(&[(
            "s.py",
            concat!(
                "import html\n",
                "def v():\n",
                "    bar = request.args.get('q')\n",
                "    safe = html.escape(bar)\n",
                "    return safe\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(!rules(&rep).contains(&"sast/taint-xss"), "экранированный вывод чист: {:?}", rules(&rep));
    }

    #[test]
    fn trust_boundary_session_write() {
        // Запись недоверенного ключа в flask.session — нарушение границы доверия (CWE-501).
        let ctx = tmp(&[(
            "t.py",
            concat!(
                "import flask\n",
                "def v():\n",
                "    bar = request.cookies.get('k')\n",
                "    flask.session[bar] = '1'\n",
            ),
        )]);
        let rep = scan_taint(&ctx, &RunInput::default()).unwrap();
        assert!(
            rules(&rep).contains(&"sast/taint-trust-boundary"),
            "trust-boundary-сток: {:?}",
            rules(&rep)
        );
    }

    #[test]
    fn dynamic_exec_flow_gated() {
        // eval(bar) с потоком — кодовая инъекция; eval('const') без потока — молчание.
        let vuln = tmp(&[(
            "e.py",
            "def v():\n    bar = request.args.get('q')\n    eval(bar)\n",
        )]);
        let rep = scan_taint(&vuln, &RunInput::default()).unwrap();
        assert!(
            rules(&rep).contains(&"sast/taint-dynamic-exec"),
            "eval с потоком: {:?}",
            rules(&rep)
        );
        let safe = tmp(&[("e.py", "def v():\n    eval('1 + 1')\n")]);
        let rep2 = scan_taint(&safe, &RunInput::default()).unwrap();
        assert!(
            !rules(&rep2).contains(&"sast/taint-dynamic-exec"),
            "eval константы без потока не сток: {:?}",
            rules(&rep2)
        );
    }
}
