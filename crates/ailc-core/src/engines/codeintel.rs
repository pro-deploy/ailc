//! E3 CodeIntel — извлечение символов из исходников.
//!
//! Каскад: AST (tree-sitter, ОСНОВНОЙ слой, 15 языков, вкл. Kotlin/Swift/Dart) →
//! regex (фолбэк при ошибке парсера). AST даёт точные символы и граф вызовов.
//!
//! Один движок питает семейство code.intel (symbols, find_usages, module_card,
//! dependency_graph, cycles) — capability лишь по-разному агрегируют его выход.

use super::walk::{ext_of, walk};
use ailc_contracts::{Ctx, Result, RunInput, Symbol, SymbolKind};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

/// Верхний предел числа возвращаемых ссылок в `references` (T70). Распространённое
/// имя (например `get`) встречается тысячи раз; неограниченный вектор раздувает
/// память и вывод. При достижении предела сбор останавливается, а вызывающий
/// узнаёт об усечении по флагу `ReferenceHits.truncated`.
pub const MAX_REFERENCES: usize = 500;

/// Прочитать исходник устойчиво к кодировке (T68). Возвращает None только при
/// настоящей ошибке ввода-вывода (файл нечитаем), а не при не-UTF-8 содержимом.
///
/// Логика по шагам. Сначала читаем сырые байты через `fs::read`. Затем срезаем
/// ведущую метку порядка байтов (Byte Order Mark, последовательность EF BB BF для
/// UTF-8): символ U+FEFF не является пробельным в Rust, поэтому без среза первая
/// строка с меткой не проходит ни `strip_prefix("import ")`, ни `starts_with`, и
/// первый импорт либо точка входа теряются. Декодируем через `from_utf8_lossy`,
/// который не падает на байтах вне UTF-8 (Windows-1251, Shift-JIS, UTF-16),
/// заменяя их символом замены вместо молчаливого пропуска всего файла. Наконец,
/// нормализуем переводы строк: одиночный возврат каретки (CR) без последующего
/// перевода строки (LF) не разбивается методом `str::lines`, поэтому старый
/// macOS-файл читается как одна строка с неверной нумерацией; приводим CRLF и
/// одиночный CR к LF.
pub(crate) fn read_source(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(decode_source(&bytes))
}

/// Чистое декодирование байтов в нормализованную строку (вынесено для юнит-тестов).
pub(crate) fn decode_source(bytes: &[u8]) -> String {
    // Срез ведущего UTF-8 BOM (EF BB BF), если он есть.
    let without_bom = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let text = String::from_utf8_lossy(without_bom);
    normalize_newlines(&text)
}

/// Привести CRLF и одиночный CR к LF, сохранив число и порядок строк.
fn normalize_newlines(s: &str) -> String {
    if !s.contains('\r') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            // CRLF: пропускаем CR, LF добавит следующая итерация. Одиночный CR
            // (старый macOS) преобразуется в LF.
            if chars.peek() == Some(&'\n') {
                continue;
            }
            out.push('\n');
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Clone)]
struct Pat {
    re: Regex,
    kind: SymbolKind,
}

fn pat(re: &str, kind: SymbolKind) -> Pat {
    Pat {
        re: Regex::new(re).expect("статический паттерн валиден"),
        kind,
    }
}

/// Таблица «расширение → паттерны символов». Группа 1 каждого паттерна = имя символа.
fn table() -> &'static HashMap<&'static str, Vec<Pat>> {
    static T: OnceLock<HashMap<&'static str, Vec<Pat>>> = OnceLock::new();
    T.get_or_init(|| {
        use SymbolKind::*;
        let mut m: HashMap<&'static str, Vec<Pat>> = HashMap::new();

        m.insert(
            "go",
            vec![
                pat(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[\(\[]", Function),
                pat(r"^\s*type\s+([A-Za-z_]\w*)\s", Type),
            ],
        );

        m.insert(
            "rs",
            vec![
                pat(r"^\s*(?:pub\s+(?:\([^)]*\)\s+)?)?(?:async\s+)?fn\s+([A-Za-z_]\w*)", Function),
                pat(r"^\s*(?:pub\s+)?struct\s+([A-Za-z_]\w*)", Type),
                pat(r"^\s*(?:pub\s+)?enum\s+([A-Za-z_]\w*)", Enum),
                pat(r"^\s*(?:pub\s+)?trait\s+([A-Za-z_]\w*)", Trait),
            ],
        );

        m.insert(
            "py",
            vec![
                pat(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)", Function),
                pat(r"^\s*class\s+([A-Za-z_]\w*)", Class),
            ],
        );

        let web = vec![
            pat(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)", Function),
            pat(r"^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)", Class),
            pat(r"^\s*(?:export\s+)?interface\s+([A-Za-z_$][\w$]*)", Interface),
            pat(r"^\s*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\([^)]*\)\s*(?::\s*[^=]+)?=>", Function),
        ];
        for e in ["ts", "tsx", "js", "jsx", "mjs", "cjs"] {
            m.insert(e, web.clone());
        }

        m.insert(
            "java",
            vec![
                pat(r"^\s*(?:public|private|protected)?\s*(?:abstract\s+|final\s+)?(?:class|interface|enum)\s+([A-Za-z_]\w*)", Type),
                pat(r"^\s*(?:public|private|protected)\s+(?:static\s+|final\s+|synchronized\s+)*[\w<>\[\],\s\.]+\s+([A-Za-z_]\w*)\s*\(", Method),
            ],
        );

        let kt = vec![
            pat(r"^\s*(?:public\s+|private\s+|protected\s+|internal\s+)?(?:suspend\s+)?fun\s+([A-Za-z_]\w*)", Function),
            pat(r"^\s*(?:public\s+|private\s+|protected\s+|internal\s+)?(?:data\s+|sealed\s+|abstract\s+|open\s+)?(?:class|interface|object)\s+([A-Za-z_]\w*)", Class),
        ];
        for e in ["kt", "kts"] {
            m.insert(e, kt.clone());
        }

        m.insert(
            "swift",
            vec![
                pat(r"^\s*(?:public\s+|private\s+|internal\s+|fileprivate\s+|open\s+)?(?:static\s+)?func\s+([A-Za-z_]\w*)", Function),
                pat(r"^\s*(?:public\s+|private\s+|internal\s+|open\s+)?(?:final\s+)?(?:class|struct|enum|protocol|extension)\s+([A-Za-z_]\w*)", Type),
            ],
        );

        m.insert(
            "cs",
            vec![pat(
                r"^\s*(?:public|private|protected|internal)?\s*(?:static\s+|abstract\s+|sealed\s+|partial\s+)*(?:class|interface|struct|enum)\s+([A-Za-z_]\w*)",
                Type,
            )],
        );

        // Regex-фолбэк для языков, у которых раньше был ТОЛЬКО AST (теряли символы при
        // сбое парсера). AST остаётся основным слоем; это страховка.
        m.insert(
            "rb",
            vec![
                pat(r"^\s*def\s+(?:self\.)?([A-Za-z_]\w*[!?=]?)", Method),
                pat(r"^\s*class\s+([A-Za-z_]\w*)", Class),
                pat(r"^\s*module\s+([A-Za-z_]\w*)", Type),
            ],
        );
        m.insert(
            "php",
            vec![
                pat(r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+([A-Za-z_]\w*)", Method),
                pat(r"^\s*(?:(?:final|abstract)\s+)*class\s+([A-Za-z_]\w*)", Class),
                pat(r"^\s*interface\s+([A-Za-z_]\w*)", Interface),
                pat(r"^\s*trait\s+([A-Za-z_]\w*)", Trait),
            ],
        );
        let scala = vec![
            pat(r"^\s*(?:override\s+)?def\s+([A-Za-z_]\w*)", Method),
            pat(r"^\s*(?:(?:final|sealed|abstract|case)\s+)*class\s+([A-Za-z_]\w*)", Class),
            pat(r"^\s*(?:case\s+)?object\s+([A-Za-z_]\w*)", Type),
            pat(r"^\s*trait\s+([A-Za-z_]\w*)", Trait),
        ];
        for e in ["scala", "sc"] {
            m.insert(e, scala.clone());
        }
        let cpp = vec![pat(r"^\s*(?:struct|class)\s+([A-Za-z_]\w*)", Type)];
        for e in ["c", "cpp", "cc", "cxx", "h", "hpp", "hh", "hxx"] {
            m.insert(e, cpp.clone());
        }

        m
    })
}

pub(crate) fn lang_for_ext(ext: &str) -> &'static str {
    match ext {
        "go" => "go",
        "rs" => "rust",
        "py" => "python",
        "ts" | "tsx" => "typescript",
        "js" | "jsx" | "mjs" | "cjs" => "javascript",
        "java" => "java",
        "kt" | "kts" => "kotlin",
        "swift" => "swift",
        "cs" => "csharp",
        "c" => "c",
        // `.h` — почти всегда C++-заголовок (классы/шаблоны); C++-грамматика — надмножество
        // C, поэтому и чистые C-заголовки разбирает. Иначе классы в .h теряются/мислейблятся.
        "cpp" | "cc" | "cxx" | "h" | "hpp" | "hh" | "hxx" => "cpp",
        "rb" => "ruby",
        "php" => "php",
        "scala" | "sc" => "scala",
        "dart" => "dart",
        _ => "text",
    }
}

fn is_exported(lang: &str, line: &str, name: &str) -> bool {
    match lang {
        "go" => name.chars().next().is_some_and(|c| c.is_uppercase()),
        "python" => !name.starts_with('_'),
        "rust" => line.contains("pub "),
        "typescript" | "javascript" => line.contains("export "),
        // Java/C#: открыто, если явно public. Kotlin: открыто по умолчанию (кроме
        // private/internal). Swift: открыто только при public/open.
        "java" | "csharp" => line.contains("public "),
        "kotlin" => !line.contains("private ") && !line.contains("internal "),
        "swift" => line.contains("public ") || line.contains("open "),
        // C/C++: символ виден извне, если не помечен static (внутренняя линковка).
        "c" | "cpp" => !line.contains("static "),
        // PHP/Scala: по умолчанию public, закрыт явным private/protected.
        "php" | "scala" => !line.contains("private ") && !line.contains("protected "),
        // Ruby: на уровне строки модификатора нет (public/private — отдельной строкой).
        "ruby" => true,
        // Dart: приватность — подчёркивание в начале имени (как в Python).
        "dart" => !name.starts_with('_'),
        _ => true,
    }
}

pub struct CodeIntelEngine;

impl CodeIntelEngine {
    /// Извлечь символы из дерева (или из `input.target`).
    pub fn symbols(ctx: &Ctx, input: &RunInput) -> Result<Vec<Symbol>> {
        // target валидируется (абсолютный путь / `..` не выводят за корень проекта).
        let base = ctx.base(input)?;
        let root = ctx.root.clone();
        let tbl = table();
        let mut syms: Vec<Symbol> = Vec::new();

        walk(&base, &mut |path| {
            let ext = ext_of(path);
            let lang = lang_for_ext(ext);
            // Исходник, который мы понимаем = есть грамматика (lang != text) ИЛИ regex-паттерны.
            // Языки только с AST (c/cpp/ruby/php/scala) regex-паттернов не имеют — pats пуст.
            if lang == "text" && !tbl.contains_key(ext) {
                return;
            }
            let pats: &[Pat] = tbl.get(ext).map(Vec::as_slice).unwrap_or(&[]);
            let content = match read_source(path) {
                Some(c) => c,
                None => return,
            };
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            // Основной слой: точный AST через tree-sitter (если язык поддержан
            // грамматикой). Иначе — regex-фолбэк ниже (kotlin/swift и прочие).
            if let Some(ts) = ts_symbols(lang, &content, &rel) {
                syms.extend(ts);
                return;
            }

            // Regex-фолбэк построчный, поэтому объявления внутри блочных комментариев
            // или многострочных строковых литералов давали бы ложные символы (T68).
            // Вырезаем блочные комментарии и тела многострочных литералов (заменяя
            // их содержимое пробелами с сохранением переводов строк, чтобы нумерация
            // строк осталась точной), а имена объявлений матчим уже по очищенному
            // тексту.
            let masked = mask_comments_and_strings(lang, &content);
            for (i, line) in masked.lines().enumerate() {
                for p in pats {
                    if let Some(c) = p.re.captures(line) {
                        if let Some(m) = c.get(1) {
                            let name = m.as_str().to_string();
                            let exported = is_exported(lang, line, &name);
                            syms.push(Symbol {
                                name,
                                kind: p.kind,
                                file: rel.clone(),
                                line: (i as u32) + 1,
                                lang: lang.to_string(),
                                exported,
                            });
                        }
                    }
                }
            }
        })?;

        Ok(syms)
    }

    /// Частота идентификаторов по всему дереву — основа dead-code и грубого usage.
    /// Один проход токенизации; используется и dead-code, и другими проверками.
    pub fn identifier_freq(ctx: &Ctx, input: &RunInput) -> Result<HashMap<String, u32>> {
        // target валидируется (абсолютный путь / `..` не выводят за корень проекта).
        let base = ctx.base(input)?;
        let mut freq: HashMap<String, u32> = HashMap::new();
        walk(&base, &mut |path| {
            if lang_for_ext(ext_of(path)) == "text" {
                return; // считаем идентификаторы только в известных языках
            }
            if let Some(content) = read_source(path) {
                count_identifiers(&content, &mut freq);
            }
        })?;
        Ok(freq)
    }

    /// Все строки, где `name` встречается как ОТДЕЛЬНЫЙ идентификатор (impact-анализ).
    ///
    /// Результат усечён до [`MAX_REFERENCES`] записей (T70): распространённое имя даёт
    /// огромный вектор, который раздувает память и вывод. Чтобы вызывающий узнал об
    /// усечении, используйте [`CodeIntelEngine::references_capped`], возвращающий флаг
    /// `truncated`. Этот метод сохранён для обратной совместимости и возвращает только
    /// (уже усечённый) список вхождений.
    pub fn references(
        ctx: &Ctx,
        input: &RunInput,
        name: &str,
    ) -> Result<Vec<(String, u32, String)>> {
        Ok(Self::references_capped(ctx, input, name)?.hits)
    }

    /// Как [`CodeIntelEngine::references`], но сообщает факт усечения и полное число
    /// найденных вхождений. Сбор останавливается, как только достигнут предел
    /// [`MAX_REFERENCES`], поэтому работа на «горячем» имени не деградирует.
    pub fn references_capped(ctx: &Ctx, input: &RunInput, name: &str) -> Result<ReferenceHits> {
        // target валидируется (абсолютный путь / `..` не выводят за корень проекта).
        let base = ctx.base(input)?;
        let root = ctx.root.clone();
        let mut hits: Vec<(String, u32, String)> = Vec::new();
        let mut total: usize = 0;
        walk(&base, &mut |path| {
            if lang_for_ext(ext_of(path)) == "text" {
                return;
            }
            let content = match read_source(path) {
                Some(c) => c,
                None => return,
            };
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            for (i, line) in content.lines().enumerate() {
                if contains_word(line, name) {
                    total += 1;
                    // Копим записи только до предела, но продолжаем считать total,
                    // чтобы честно показать, сколько вхождений всего.
                    if hits.len() < MAX_REFERENCES {
                        hits.push((
                            rel.clone(),
                            (i as u32) + 1,
                            line.trim().chars().take(120).collect(),
                        ));
                    }
                }
            }
        })?;
        let truncated = total > hits.len();
        Ok(ReferenceHits {
            hits,
            total,
            truncated,
        })
    }

    /// Граф зависимостей на уровне модулей (папок-пакетов) по импортам.
    ///
    /// Модуль идентифицируется ПОЛНЫМ относительным путём папки (`services/a/utils`),
    /// поэтому одноимённые папки в разных сервисах (`services/a/utils`,
    /// `services/b/utils`) больше не сливаются в один узел (T65). Импорт резолвится в
    /// модуль по выравненному по сегментам совпадению самого длинного суффикса пути
    /// импорта с реально существующим путём модуля проекта, а не по первой совпавшей
    /// по имени компоненте, поэтому `use serde::core` не даёт ложного ребра на
    /// локальный модуль `core`. Внешние зависимости отсекаются.
    ///
    /// Межсервисный взгляд возвращается отдельно через [`CodeIntelEngine::service_graph`]
    /// (исходящие сетевые вызовы и контейнеры из Dockerfile/compose/k8s), чтобы добавление
    /// было строго аддитивным и не меняло форму [`DepGraph`] (T67).
    pub fn dependency_graph(ctx: &Ctx, input: &RunInput) -> Result<DepGraph> {
        // target валидируется (абсолютный путь / `..` не выводят за корень проекта).
        let base = ctx.base(input)?;
        let root = ctx.root.clone();

        // Проход 1: набор модулей (папок-пакетов) с исходниками, как полные пути.
        let mut modules: BTreeSet<String> = BTreeSet::new();
        walk(&base, &mut |path| {
            if lang_for_ext(ext_of(path)) == "text" {
                return;
            }
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            modules.insert(module_of(&rel));
        })?;
        // Резолвер сопоставляет импорт с известным путём модуля по окну сегментов.
        let resolver = ModuleResolver::new(&modules);

        // Проход 2: рёбра по импортам.
        let mut edges: BTreeSet<(String, String)> = BTreeSet::new();
        walk(&base, &mut |path| {
            let lang = lang_for_ext(ext_of(path));
            if lang == "text" {
                return;
            }
            let content = match read_source(path) {
                Some(c) => c,
                None => return,
            };
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            let from = module_of(&rel);
            for target in import_targets(lang, &content) {
                if let Some(to) = resolver.resolve(&target) {
                    if to != from {
                        edges.insert((from.clone(), to));
                    }
                }
            }
        })?;

        Ok(DepGraph {
            modules: modules.into_iter().collect(),
            edges,
        })
    }

    /// Межсервисный взгляд (T67): ИСХОДЯЩИЕ сетевые вызовы (URL внешних сервисов,
    /// gRPC/Feign/RestTemplate/WebClient/requests/axios/http.Get/HttpClient) и
    /// развёртываемые контейнеры из Dockerfile/compose/k8s. В отличие от прежнего
    /// подхода (контейнерами объявлялись внутренние папки верхнего уровня), здесь
    /// контейнеры берутся из манифестов развёртывания, а связи между сервисами — из
    /// реальных исходящих вызовов, а не только из внутрипроцессных импортов.
    pub fn service_graph(ctx: &Ctx, input: &RunInput) -> Result<ServiceGraph> {
        let base = ctx.base(input)?;
        let root = ctx.root.clone();

        let mut outbound: BTreeSet<OutboundCall> = BTreeSet::new();
        let mut containers: BTreeSet<String> = BTreeSet::new();
        walk(&base, &mut |path| {
            let lang = lang_for_ext(ext_of(path));
            let content = match read_source(path) {
                Some(c) => c,
                None => return,
            };
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            // Контейнеры определяем по манифестам развёртывания, НЕ по папкам (T67).
            for c in containers_in_file(&rel, &content) {
                containers.insert(c);
            }

            if lang == "text" {
                return;
            }
            let from = module_of(&rel);
            for (i, line) in content.lines().enumerate() {
                for kind in outbound_in_line(line) {
                    outbound.insert(OutboundCall {
                        from_module: from.clone(),
                        target: kind.target,
                        protocol: kind.protocol,
                        file: rel.clone(),
                        line: (i as u32) + 1,
                    });
                }
            }
        })?;

        Ok(ServiceGraph {
            outbound: outbound.into_iter().collect(),
            containers: containers.into_iter().collect(),
        })
    }

    /// Сводка по «частям» проекта (папкам-пакетам). Единый источник для
    /// module_card и генерации обзорной документации — без дублирования.
    pub fn module_stats(ctx: &Ctx, input: &RunInput) -> Result<BTreeMap<String, ModuleStat>> {
        let syms = Self::symbols(ctx, input)?;
        let mut m: BTreeMap<String, ModuleStat> = BTreeMap::new();
        for s in &syms {
            let st = m.entry(module_of(&s.file)).or_default();
            st.total += 1;
            st.langs.insert(s.lang.clone());
            if s.exported {
                st.exported += 1;
                if st.top_exports.len() < 5 {
                    st.top_exports.push(format!("{} {}", s.kind, s.name));
                }
            }
        }
        Ok(m)
    }

    /// Карта проекта: по папкам (языки/файлы/строки/символы) + точки входа + итоги.
    /// Аналог project_map — единый «первый взгляд» на незнакомый легаси.
    pub fn project_map(ctx: &Ctx, input: &RunInput) -> Result<ProjectMap> {
        // target валидируется (абсолютный путь / `..` не выводят за корень проекта).
        let base = ctx.base(input)?;
        let root = ctx.root.clone();

        // Символы по папкам (переиспользуем извлечение).
        let syms = Self::symbols(ctx, input)?;
        let mut sym_by_dir: HashMap<String, u32> = HashMap::new();
        for s in &syms {
            *sym_by_dir.entry(dir_of(&s.file)).or_default() += 1;
        }

        let mut dirs: BTreeMap<String, DirStat> = BTreeMap::new();
        let mut entry_points: Vec<String> = Vec::new();
        let mut total_files = 0u32;
        let mut total_lines = 0u32;
        let mut langs: BTreeMap<String, u32> = BTreeMap::new();

        walk(&base, &mut |path| {
            let ext = ext_of(path);
            let lang = lang_for_ext(ext);
            if lang == "text" {
                return;
            }
            let content = match read_source(path) {
                Some(c) => c,
                None => return,
            };
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            let lines = content.lines().count() as u32;
            total_files += 1;
            total_lines += lines;
            *langs.entry(lang.to_string()).or_default() += 1;

            let d = dir_of(&rel);
            let st = dirs.entry(d.clone()).or_default();
            st.files += 1;
            st.lines += lines;
            st.langs.insert(lang.to_string());
            st.symbols = sym_by_dir.get(&d).copied().unwrap_or(st.symbols);

            if is_entry_point(&rel, &content) {
                entry_points.push(rel);
            }
        })?;

        let dirs: Vec<DirStat> = dirs
            .into_iter()
            .map(|(path, mut st)| {
                st.path = path;
                st
            })
            .collect();
        entry_points.sort();

        Ok(ProjectMap {
            dirs,
            entry_points,
            total_files,
            total_lines,
            langs,
        })
    }
}

/// Сводка по одной части проекта.
#[derive(Default)]
pub struct ModuleStat {
    pub total: u32,
    pub exported: u32,
    pub langs: BTreeSet<String>,
    pub top_exports: Vec<String>,
}

/// Статистика по одной папке.
#[derive(Default)]
pub struct DirStat {
    pub path: String,
    pub langs: BTreeSet<String>,
    pub files: u32,
    pub lines: u32,
    pub symbols: u32,
}

/// Карта проекта целиком.
pub struct ProjectMap {
    pub dirs: Vec<DirStat>,
    pub entry_points: Vec<String>,
    pub total_files: u32,
    pub total_lines: u32,
    pub langs: BTreeMap<String, u32>,
}

/// Папка файла (родительский путь) или "." для корня.
fn dir_of(rel: &str) -> String {
    match rel.rsplit_once(['/', '\\']) {
        Some((dir, _)) => dir.to_string(),
        None => ".".to_string(),
    }
}

/// Файл — точка входа (по имени или содержимому).
fn is_entry_point(rel: &str, content: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    // Тест-файл никогда не точка входа (в нём бывают шаблоны "func main(" в строках).
    if lower.ends_with("_test.go")
        || lower.contains("/test")
        || lower.contains("__tests__")
        || lower.contains(".test.")
        || lower.contains(".spec.")
    {
        return false;
    }
    let name = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
    if matches!(
        name,
        "main.go" | "main.rs" | "main.py" | "__main__.py" | "app.py" | "server.py"
            | "index.ts" | "index.js" | "index.tsx" | "main.ts" | "manage.py"
    ) {
        return true;
    }
    // По содержимому — главную функцию ищем В НАЧАЛЕ строки (а не в строковом литерале).
    content.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("func main(")
            || t.starts_with("fn main(")
            || t.starts_with("def main(")
            || t.starts_with("int main(")
            || (t.starts_with("if __name__") && t.contains("__main__"))
    })
}

/// Исходящий сетевой вызов из модуля наружу (URL/gRPC/клиент внешнего сервиса).
/// Основа межсервисного графа (T67): из них строится C4-Container, в отличие от
/// прежнего подхода, где контейнерами объявлялись внутренние папки.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutboundCall {
    /// Модуль-источник (полный путь папки), откуда уходит вызов.
    pub from_module: String,
    /// Цель вызова: хост сервиса, путь URL либо имя удалённого сервиса/клиента.
    pub target: String,
    /// Протокол/транспорт (http, https, grpc, amqp, kafka, nats, sqs и так далее).
    pub protocol: String,
    /// Файл, где найден вызов.
    pub file: String,
    /// Строка, где найден вызов.
    pub line: u32,
}

/// Граф зависимостей модулей. Циклы = SCC размером > 1.
///
/// Узлы — полные относительные пути папок-пакетов (T65). Структура сохранена в прежней
/// форме (только `modules` и `edges`), чтобы существующие вызывающие места и литералы не
/// сломались; межсервисный взгляд (исходящие вызовы и контейнеры) живёт в отдельном
/// аддитивном типе [`ServiceGraph`], возвращаемом [`CodeIntelEngine::service_graph`] (T67).
pub struct DepGraph {
    /// Узлы графа — полные относительные пути папок-пакетов (T65).
    pub modules: Vec<String>,
    /// Рёбра внутрипроцессных зависимостей по импортам (from-путь, to-путь).
    pub edges: BTreeSet<(String, String)>,
}

/// Межсервисный взгляд (T67): исходящие сетевые вызовы и развёртываемые контейнеры.
/// Отдельно от [`DepGraph`], чтобы добавление было строго аддитивным.
#[derive(Debug, Default)]
pub struct ServiceGraph {
    /// Исходящие сетевые вызовы наружу — межсервисные связи.
    pub outbound: Vec<OutboundCall>,
    /// Развёртываемые контейнеры из Dockerfile/compose/k8s, НЕ из папок.
    pub containers: Vec<String>,
}

impl DepGraph {
    /// Сильно связные компоненты размером > 1 — циклические зависимости.
    pub fn cycles(&self) -> Vec<Vec<String>> {
        let idx: HashMap<&str, usize> = self
            .modules
            .iter()
            .enumerate()
            .map(|(i, m)| (m.as_str(), i))
            .collect();
        let n = self.modules.len();
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (a, b) in &self.edges {
            if let (Some(&ia), Some(&ib)) = (idx.get(a.as_str()), idx.get(b.as_str())) {
                adj[ia].push(ib);
            }
        }
        tarjan_scc(&adj)
            .into_iter()
            .filter(|c| c.len() > 1)
            .map(|c| c.into_iter().map(|i| self.modules[i].clone()).collect())
            .collect()
    }

    /// Уверенность находки import-cycle (T65). Резолвер импортов эвристичен (матч по
    /// суффиксу пути), поэтому ребро может быть как точным, так и приблизительным;
    /// сам цикл — структурный факт над этими рёбрами, но достоверность не выше
    /// достоверности самого слабого ребра. Возвращаем Medium как осознанный компромисс
    /// между «жёсткой находкой» и «низкоуверенным шумом».
    pub fn cycle_confidence(&self) -> ailc_contracts::Confidence {
        ailc_contracts::Confidence::Medium
    }
}

/// Tarjan SCC на ЯВНОМ стеке без рекурсии (T69): для патологического графа с длинной
/// цепочкой зависимостей рекурсивный обход переполнял бы системный стек. Здесь кадры
/// эмулируются вектором, поэтому глубина ограничена лишь кучей.
///
/// Каждый кадр хранит вершину и индекс следующего необработанного соседа. Когда все
/// соседи обработаны, выполняется «возврат»: обновляем low родителя и, если вершина
/// корень компоненты (`low[v] == index[v]`), снимаем со стека сильно связную компоненту.
fn tarjan_scc(adj: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let n = adj.len();
    let mut index = 0usize;
    let mut indices = vec![usize::MAX; n];
    let mut low = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut comp_stack: Vec<usize> = Vec::new();
    let mut sccs: Vec<Vec<usize>> = Vec::new();

    // Кадр обхода: (вершина, индекс следующего соседа в adj[вершина]).
    let mut call_stack: Vec<(usize, usize)> = Vec::new();

    for start in 0..n {
        if indices[start] != usize::MAX {
            continue;
        }
        call_stack.push((start, 0));
        while let Some(&(v, next)) = call_stack.last() {
            if next == 0 {
                // Первое посещение вершины: присваиваем index/low, кладём в комп-стек.
                indices[v] = index;
                low[v] = index;
                index += 1;
                comp_stack.push(v);
                on_stack[v] = true;
            }
            if next < adj[v].len() {
                // Берём очередного соседа и продвигаем счётчик кадра.
                let w = adj[v][next];
                call_stack.last_mut().expect("кадр на вершине стека").1 += 1;
                if indices[w] == usize::MAX {
                    // Спускаемся в непосещённого соседа новым кадром (вместо рекурсии).
                    call_stack.push((w, 0));
                } else if on_stack[w] {
                    low[v] = low[v].min(indices[w]);
                }
            } else {
                // Все соседи обработаны: «возврат» из вершины.
                if low[v] == indices[v] {
                    let mut comp = Vec::new();
                    loop {
                        let w = comp_stack.pop().expect("комп-стек Tarjan непуст");
                        on_stack[w] = false;
                        comp.push(w);
                        if w == v {
                            break;
                        }
                    }
                    sccs.push(comp);
                }
                call_stack.pop();
                // Обновляем low родителя значением низа закрытой вершины.
                if let Some(&(parent, _)) = call_stack.last() {
                    low[parent] = low[parent].min(low[v]);
                }
            }
        }
    }
    sccs
}

/// Модуль = ПОЛНЫЙ относительный путь папки-пакета (родитель файла), нормализованный к
/// прямым слэшам (T65). Так одноимённые папки в разных сервисах (`services/a/utils` и
/// `services/b/utils`) остаются разными узлами, а не сливаются по имени. Файлы в корне
/// дерева получают сентинел `(root)`.
pub fn module_of(rel: &str) -> String {
    match rel.rsplit_once(['/', '\\']) {
        Some((dir, _)) if !dir.is_empty() => dir.replace('\\', "/"),
        _ => "(root)".to_string(),
    }
}

/// Резолвер импортов в модули проекта по совпадению непрерывного окна сегментов (T65).
///
/// Каждый путь модуля раскладывается на сегменты. Путь импорта (например
/// `services.a.utils`, `services/a/utils`, `App\Services\A\Utils`) тоже режется на
/// сегменты по любому из разделителей пути или пространства имён. Импорт резолвится в
/// тот модуль, чей путь является самым длинным НЕПРЕРЫВНЫМ окном последовательности
/// сегментов импорта и при этом реально существует среди модулей проекта. Так
/// `use serde::core` не матчится на локальный `app/core` (нет известного пути-окна
/// внутри `serde/core`), а реальная межпакетная связь `from services.a.utils import x`
/// находит именно `services/a/utils`. Резерв по уникальному имени применяется лишь к
/// односегментному импорту, чтобы не давать ложных рёбер на одноимённые папки.
struct ModuleResolver {
    /// Сегментированные пути всех модулей проекта (`["services","a","utils"]`).
    modules: Vec<Vec<String>>,
    /// Быстрая проверка существования пути модуля по нормализованной строке.
    known: HashSet<String>,
}

impl ModuleResolver {
    fn new(modules: &BTreeSet<String>) -> Self {
        let segmented: Vec<Vec<String>> = modules
            .iter()
            .filter(|m| m.as_str() != "(root)")
            .map(|m| m.split('/').map(str::to_string).collect())
            .collect();
        let known: HashSet<String> = segmented.iter().map(|p| p.join("/")).collect();
        Self {
            modules: segmented,
            known,
        }
    }

    /// Сегменты пути импорта по любому разделителю пути/пространства имён.
    fn import_segments(target: &str) -> Vec<String> {
        target
            .split(|c: char| {
                matches!(
                    c,
                    '/' | '.' | ':' | '\\' | ' ' | '{' | '}' | ';' | '"' | '\'' | '<' | '>'
                )
            })
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Найти модуль проекта, чей путь — самое длинное непрерывное вхождение (окно
    /// сегментов) в путь импорта. Так покрываются и префиксные формы (`a::b::C`, где
    /// модуль `a/b` — начало пути перед элементом `C`), и суффиксные/файловые формы
    /// (`../services/b/utils/helper`, где `services/b/utils` — окно внутри пути).
    fn resolve(&self, target: &str) -> Option<String> {
        let segs = Self::import_segments(target);
        if segs.is_empty() {
            return None;
        }
        // Перебираем все непрерывные окна сегментов, предпочитая самое длинное (а при
        // равной длине — самое раннее), чтобы матч был максимально специфичным.
        let mut best: Option<String> = None;
        let mut best_len = 0usize;
        for start in 0..segs.len() {
            for end in (start + 1..=segs.len()).rev() {
                let len = end - start;
                if len <= best_len {
                    break; // более короткие окна с этого старта уже не улучшат результат
                }
                let candidate = segs[start..end].join("/");
                if self.known.contains(&candidate) {
                    best_len = len;
                    best = Some(candidate);
                    break;
                }
            }
        }
        if best.is_some() {
            return best;
        }
        // Резерв только для ОДНОСЕГМЕНТНОГО импорта (голое имя модуля, например
        // `import utils`): совпадение по концевому имени модуля, и ТОЛЬКО если имя
        // уникально среди модулей. Для МНОГОСЕГМЕНТНЫХ путей резерв НЕ применяется,
        // иначе `use serde::core` ложно резолвился бы на локальный `app/core` по
        // совпадению последней компоненты (T65: ровно этого и избегаем).
        if segs.len() == 1 {
            let last = &segs[0];
            let matches: Vec<&Vec<String>> = self
                .modules
                .iter()
                .filter(|p| p.last().map(String::as_str) == Some(last.as_str()))
                .collect();
            if matches.len() == 1 {
                return Some(matches[0].join("/"));
            }
        }
        None
    }
}

/// Извлечь пути импортов из файла (по языку).
fn import_targets(lang: &str, content: &str) -> Vec<String> {
    let mut out = Vec::new();
    match lang {
        "go" => {
            let mut in_block = false;
            for line in content.lines() {
                let t = line.trim();
                if in_block {
                    if t.starts_with(')') {
                        in_block = false;
                    } else if let Some(s) = quoted(t) {
                        out.push(s);
                    }
                } else if t.starts_with("import (") {
                    in_block = true;
                } else if let Some(rest) = t.strip_prefix("import ") {
                    if let Some(s) = quoted(rest) {
                        out.push(s);
                    }
                }
            }
        }
        "rust" => {
            for line in content.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("use ") {
                    out.push(rest.trim_end_matches(';').to_string());
                } else if let Some(rest) = t.strip_prefix("mod ") {
                    out.push(rest.trim_end_matches(';').trim().to_string());
                }
            }
        }
        "python" => {
            for line in content.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("from ") {
                    if let Some(i) = rest.find(" import ") {
                        out.push(rest[..i].trim().to_string());
                    }
                } else if let Some(rest) = t.strip_prefix("import ") {
                    for part in rest.split(',') {
                        if let Some(name) = part.split_whitespace().next() {
                            out.push(name.to_string());
                        }
                    }
                }
            }
        }
        "typescript" | "javascript" => {
            for line in content.lines() {
                let t = line.trim();
                if t.contains("import ") || t.contains("require(") || t.starts_with("export ") {
                    if let Some(s) = quoted_any(t) {
                        out.push(s);
                    }
                }
            }
        }
        "java" | "kotlin" => {
            // import a.b.C;  (Java со `;`, Kotlin без) + `import static a.b.c;`
            for line in content.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("import ") {
                    let rest = rest.strip_prefix("static ").unwrap_or(rest);
                    let path = rest.trim_end_matches(';').trim();
                    if !path.is_empty() {
                        out.push(path.to_string());
                    }
                }
            }
        }
        "swift" => {
            // import Foo  /  import class Foo.Bar
            for line in content.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("import ") {
                    if let Some(name) = rest.split_whitespace().last() {
                        out.push(name.to_string());
                    }
                }
            }
        }
        "csharp" => {
            // using A.B;  /  using X = A.B;  (global using ... тоже)
            for line in content.lines() {
                let t = line.trim();
                let rest = t.strip_prefix("global ").unwrap_or(t);
                if let Some(rest) = rest.strip_prefix("using ") {
                    let path = rest.trim_end_matches(';').trim();
                    let path = path.split('=').next_back().unwrap_or(path).trim();
                    if !path.is_empty() && !path.starts_with('(') {
                        out.push(path.to_string());
                    }
                }
            }
        }
        "php" => {
            // use App\Models\User;  /  use App\X as Y;  /  require 'foo.php';
            for line in content.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("use ") {
                    let path = rest.trim_end_matches(';').trim();
                    let path = path.split(" as ").next().unwrap_or(path).trim();
                    if !path.is_empty() {
                        out.push(path.replace('\\', "/"));
                    }
                } else if (t.starts_with("require") || t.starts_with("include")) && t.contains('(') {
                    if let Some(s) = quoted_any(t) {
                        out.push(s);
                    }
                }
            }
        }
        "ruby" => {
            // require 'foo'  /  require_relative 'bar'
            for line in content.lines() {
                let t = line.trim();
                if t.starts_with("require") {
                    if let Some(s) = quoted_any(t) {
                        out.push(s);
                    }
                }
            }
        }
        "scala" => {
            // import a.b.C  /  import a.b.{C, D}
            for line in content.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("import ") {
                    let path = rest.split('{').next().unwrap_or(rest).trim();
                    if !path.is_empty() {
                        out.push(path.trim_end_matches('.').to_string());
                    }
                }
            }
        }
        "c" | "cpp" => {
            // #include "foo.h"  /  #include <bar>
            for line in content.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("#include") {
                    let rest = rest.trim();
                    let inner = rest
                        .trim_start_matches(['"', '<'])
                        .trim_end_matches(['"', '>']);
                    if !inner.is_empty() {
                        out.push(inner.to_string());
                    }
                }
            }
        }
        "dart" => {
            // import 'package:x/y.dart';  /  import 'src/z.dart';
            for line in content.lines() {
                let t = line.trim();
                if t.starts_with("import ") || t.starts_with("export ") || t.starts_with("part ") {
                    if let Some(s) = quoted_any(t) {
                        out.push(s);
                    }
                }
            }
        }
        _ => {}
    }
    out
}

/// Результат поиска ссылок с учётом усечения (T70).
#[derive(Debug, Clone, Default)]
pub struct ReferenceHits {
    /// Найденные вхождения (файл, строка, обрезанный текст), не более [`MAX_REFERENCES`].
    pub hits: Vec<(String, u32, String)>,
    /// Полное число вхождений (может превышать длину `hits` при усечении).
    pub total: usize,
    /// Признак того, что список усечён до предела.
    pub truncated: bool,
}

/// Один распознанный исходящий сетевой вызов в строке кода (T67).
struct OutboundHit {
    target: String,
    protocol: String,
}

/// Таблица regex для исходящих сетевых вызовов (T67): URL-схемы внешних сервисов и
/// характерные клиенты межсервисного взаимодействия (gRPC/Feign/RestTemplate/WebClient/
/// requests/axios/http.Get/HttpClient). Группа 1 каждого паттерна — цель (хост/путь/имя).
fn outbound_res() -> &'static Vec<(Regex, &'static str)> {
    static R: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    R.get_or_init(|| {
        let mk = |p: &str, proto: &'static str| {
            (
                Regex::new(p).expect("встроенный паттерн outbound валиден"),
                proto,
            )
        };
        vec![
            // Полный URL в строковом литерале: http(s)://host/path.
            mk(r#"(?i)["'`](https?://[^"'`\s]+)["'`]"#, "http"),
            // gRPC/прочие транспорты в литералах (grpc/nats/amqp/kafka/redis).
            mk(
                r#"(?i)["'`]((?:grpc|grpcs|nats|amqp|amqps|kafka)://[^"'`\s]+)["'`]"#,
                "rpc",
            ),
            // Feign-клиент Spring: @FeignClient(name="svc"|url="...").
            mk(
                r#"@FeignClient\s*\([^)]*\b(?:name|value|url)\s*=\s*["']([^"']+)["']"#,
                "feign",
            ),
            // Spring RestTemplate/WebClient: .getForObject("URL"|.uri("URL").
            mk(
                r#"(?i)\b(?:RestTemplate|WebClient)\b[^\n;]*?["'`](https?://[^"'`]+)["'`]"#,
                "http",
            ),
            // Python requests / JS axios / fetch: requests.get("URL"), axios.post("URL"), fetch("URL").
            mk(
                r#"(?i)\b(?:requests|axios|httpx|got|fetch)\b[\.a-z]*\(\s*["'`](https?://[^"'`]+)["'`]"#,
                "http",
            ),
            // Go: http.Get("URL") / http.NewRequest(..., "URL", ...).
            mk(
                r#"(?i)\bhttp\.(?:Get|Post|NewRequest)\b[^\n;]*?["'`](https?://[^"'`]+)["'`]"#,
                "http",
            ),
            // .NET HttpClient: new HttpClient { BaseAddress = new Uri("URL") } или GetAsync("URL").
            mk(
                r#"(?i)\bHttpClient\b[^\n;]*?["'`](https?://[^"'`]+)["'`]"#,
                "http",
            ),
        ]
    })
}

/// Распознать исходящие сетевые вызовы в одной строке (T67).
fn outbound_in_line(line: &str) -> Vec<OutboundHit> {
    let mut out = Vec::new();
    for (re, proto) in outbound_res() {
        if let Some(c) = re.captures(line) {
            if let Some(m) = c.get(1) {
                let raw = m.as_str();
                // Цель нормализуем к схеме+хосту (без креденшелов и хвостов запроса),
                // чтобы один сервис, вызванный по разным путям, не плодил узлы-дубли.
                let target = normalize_outbound_target(raw);
                out.push(OutboundHit {
                    target,
                    protocol: scheme_of(raw).unwrap_or_else(|| (*proto).to_string()),
                });
            }
        }
    }
    out
}

/// Схема URI (`https://...` переходит в `https`); None, если схемы нет.
fn scheme_of(s: &str) -> Option<String> {
    let idx = s.find("://")?;
    let scheme = &s[..idx];
    if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || c == '+') {
        return None;
    }
    Some(scheme.to_ascii_lowercase())
}

/// Нормализовать цель вызова к `схема://хост[:порт]`, отбросив путь, query и креденшелы.
fn normalize_outbound_target(raw: &str) -> String {
    let trimmed: String = raw.chars().take(200).collect();
    match trimmed.find("://") {
        Some(p) => {
            let scheme = &trimmed[..p];
            let rest = &trimmed[p + 3..];
            // Отрезаем путь/запрос; убираем user:pass@ перед хостом.
            let host_part = rest
                .split(['/', '?', '#'])
                .next()
                .unwrap_or(rest);
            let host = host_part.rsplit('@').next().unwrap_or(host_part);
            format!("{scheme}://{host}")
        }
        None => trimmed,
    }
}

/// Контейнеры/сервисы развёртывания, объявленные в манифестах (T67): Dockerfile,
/// docker-compose, Kubernetes. Возвращаем имена сервисов/образов, по которым строится
/// уровень Контейнеры C4, вместо выдачи внутренних папок за развёртываемые единицы.
fn containers_in_file(rel: &str, content: &str) -> Vec<String> {
    let lower = rel.to_ascii_lowercase();
    let file = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
    let mut out = Vec::new();

    // Dockerfile/Containerfile: единица развёртывания = образ из FROM (последний этап).
    if file == "dockerfile" || file == "containerfile" || file.ends_with(".dockerfile") {
        for line in content.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("FROM ").or_else(|| t.strip_prefix("from ")) {
                if let Some(img) = rest.split_whitespace().next() {
                    out.push(format!("image:{img}"));
                }
            }
        }
        return out;
    }

    // docker-compose: ключи под верхним `services:`. Имя сервиса — ключ с отступом в
    // два пробела (одно слово, заканчивается двоеточием) внутри блока services.
    let is_compose = file.starts_with("docker-compose") || file == "compose.yaml" || file == "compose.yml";
    if is_compose {
        let mut in_services = false;
        for line in content.lines() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            let t = line.trim_end();
            if indent == 0 {
                in_services = t.trim_end_matches(':').trim() == "services";
                continue;
            }
            if in_services && indent == 2 {
                let key = t.trim();
                if let Some(name) = key.strip_suffix(':') {
                    if !name.is_empty() && !name.contains(' ') {
                        out.push(format!("service:{name}"));
                    }
                }
            }
        }
        return out;
    }

    // Kubernetes-манифест (yaml с kind: Deployment/StatefulSet/Service и metadata.name).
    if (file.ends_with(".yaml") || file.ends_with(".yml")) && content.contains("kind:") {
        let mut kind: Option<String> = None;
        for line in content.lines() {
            let t = line.trim();
            if let Some(k) = t.strip_prefix("kind:") {
                kind = Some(k.trim().to_string());
            } else if let Some(n) = t.strip_prefix("name:") {
                if matches!(
                    kind.as_deref(),
                    Some("Deployment") | Some("StatefulSet") | Some("DaemonSet") | Some("Service")
                ) {
                    let name = n.trim().trim_matches(['"', '\'']);
                    if !name.is_empty() {
                        out.push(format!("k8s:{name}"));
                    }
                    kind = None; // первое name после kind = metadata.name
                }
            }
        }
    }
    out
}

/// Замаскировать блочные комментарии и многострочные строковые литералы (T68) для
/// построчного regex-фолбэка извлечения символов: содержимое заменяем пробелами,
/// сохраняя переводы строк (нумерация строк остаётся точной), чтобы внутри `/* ... */`
/// или многострочной строки не находились ложные объявления. Точная семантика языков
/// не требуется: цель — убрать самые частые источники ложных символов.
fn mask_comments_and_strings(lang: &str, content: &str) -> String {
    // Параметры по семейству синтаксиса.
    let (block_open, block_close, triple): (&str, &str, Option<&str>) = match lang {
        "python" => ("", "", Some("\"\"\"")), // тройные кавычки как блок (грубо)
        // C-подобные и большинство языков: /* ... */.
        _ => ("/*", "*/", None),
    };
    let bytes = content.as_bytes();
    let mut out = String::with_capacity(content.len());
    let mut i = 0usize;
    let mut in_block = false;
    let mut in_triple = false;
    while i < bytes.len() {
        let rest = &content[i..];
        // Тройные кавычки Python.
        if let Some(tq) = triple {
            if rest.starts_with(tq) {
                in_triple = !in_triple;
                for _ in 0..tq.len() {
                    out.push(' ');
                }
                i += tq.len();
                continue;
            }
        }
        if in_triple {
            let ch = content[i..].chars().next().unwrap();
            out.push(if ch == '\n' { '\n' } else { ' ' });
            i += ch.len_utf8();
            continue;
        }
        if !block_open.is_empty() {
            if in_block {
                if rest.starts_with(block_close) {
                    in_block = false;
                    for _ in 0..block_close.len() {
                        out.push(' ');
                    }
                    i += block_close.len();
                    continue;
                }
                let ch = content[i..].chars().next().unwrap();
                out.push(if ch == '\n' { '\n' } else { ' ' });
                i += ch.len_utf8();
                continue;
            } else if rest.starts_with(block_open) {
                in_block = true;
                for _ in 0..block_open.len() {
                    out.push(' ');
                }
                i += block_open.len();
                continue;
            }
        }
        let ch = content[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn quoted(s: &str) -> Option<String> {
    let start = s.find('"')?;
    let rest = &s[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn quoted_any(s: &str) -> Option<String> {
    quoted(s).or_else(|| {
        let start = s.find('\'')?;
        let rest = &s[start + 1..];
        let end = rest.find('\'')?;
        Some(rest[..end].to_string())
    })
}

// ───────────────────────── tree-sitter тир (feature = "treesitter") ─────────────────────────

/// Точное извлечение символов через AST tree-sitter. None = язык не поддержан
/// грамматикой (вызывающий откатывается на regex-фолбэк).
/// Грамматика tree-sitter по имени языка. None = языка нет (откат на regex).
pub(crate) fn ts_language(lang: &str) -> Option<tree_sitter::Language> {
    Some(match lang {
        "rust" => tree_sitter_rust::LANGUAGE.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        "python" => tree_sitter_python::LANGUAGE.into(),
        "javascript" => tree_sitter_javascript::LANGUAGE.into(),
        "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "java" => tree_sitter_java::LANGUAGE.into(),
        "c" => tree_sitter_c::LANGUAGE.into(),
        "cpp" => tree_sitter_cpp::LANGUAGE.into(),
        "csharp" => tree_sitter_c_sharp::LANGUAGE.into(),
        "ruby" => tree_sitter_ruby::LANGUAGE.into(),
        "php" => tree_sitter_php::LANGUAGE_PHP.into(),
        "scala" => tree_sitter_scala::LANGUAGE.into(),
        "kotlin" => tree_sitter_kotlin_ng::LANGUAGE.into(),
        "swift" => tree_sitter_swift::LANGUAGE.into(),
        "dart" => tree_sitter_dart::LANGUAGE.into(),
        _ => return None,
    })
}

fn ts_symbols(lang: &str, content: &str, rel: &str) -> Option<Vec<Symbol>> {
    use tree_sitter::Parser;

    let language = ts_language(lang)?;
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(content, None)?;
    let lines: Vec<&str> = content.lines().collect();
    let bytes = content.as_bytes();

    let mut syms = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if let Some((kind, name_node)) = def_node(lang, &node) {
            if let Ok(name) = name_node.utf8_text(bytes) {
                let row = node.start_position().row;
                let line = lines.get(row).copied().unwrap_or("");
                syms.push(Symbol {
                    name: name.to_string(),
                    kind,
                    file: rel.to_string(),
                    line: (row as u32) + 1,
                    lang: lang.to_string(),
                    exported: is_exported(lang, line, name),
                });
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    Some(syms)
}

/// Узел-определение для языка: (вид символа, узел с именем).
fn def_node<'a>(
    lang: &str,
    node: &tree_sitter::Node<'a>,
) -> Option<(SymbolKind, tree_sitter::Node<'a>)> {
    use SymbolKind::*;
    let name = || node.child_by_field_name("name");
    let pair = |k: SymbolKind| name().map(|n| (k, n));
    let has_body = || node.child_by_field_name("body").is_some();
    match (lang, node.kind()) {
        ("rust", "function_item") => pair(Function),
        ("rust", "struct_item") => pair(Type),
        ("rust", "enum_item") => pair(Enum),
        ("rust", "trait_item") => pair(Trait),
        ("go", "function_declaration") => pair(Function),
        ("go", "method_declaration") => pair(Method),
        ("go", "type_spec") => pair(Type),
        ("python", "function_definition") => pair(Function),
        ("python", "class_definition") => pair(Class),
        ("javascript" | "typescript", "function_declaration") => pair(Function),
        ("javascript" | "typescript", "class_declaration") => pair(Class),
        ("javascript" | "typescript", "method_definition") => pair(Method),
        ("typescript", "interface_declaration") => pair(Interface),
        ("typescript", "type_alias_declaration") => pair(Type),
        // Java
        ("java", "class_declaration") => pair(Class),
        ("java", "interface_declaration") => pair(Interface),
        ("java", "enum_declaration") => pair(Enum),
        ("java", "record_declaration") => pair(Type),
        ("java", "method_declaration") => pair(Method),
        // C#
        ("csharp", "class_declaration") => pair(Class),
        ("csharp", "interface_declaration") => pair(Interface),
        ("csharp", "struct_declaration") => pair(Type),
        ("csharp", "enum_declaration") => pair(Enum),
        ("csharp", "method_declaration") => pair(Method),
        // C / C++ — имя функции вложено в declarator (указатели/ссылки/квалификация).
        ("c" | "cpp", "function_definition") => c_func_name(node).map(|n| (Function, n)),
        ("c" | "cpp", "struct_specifier") if has_body() => pair(Type),
        ("cpp", "class_specifier") if has_body() => pair(Class),
        // Ruby
        ("ruby", "method" | "singleton_method") => pair(Method),
        ("ruby", "class") => pair(Class),
        ("ruby", "module") => pair(Type),
        // PHP
        ("php", "function_definition") => pair(Function),
        ("php", "method_declaration") => pair(Method),
        ("php", "class_declaration") => pair(Class),
        ("php", "interface_declaration") => pair(Interface),
        // Scala
        ("scala", "function_definition") => pair(Function),
        ("scala", "class_definition") => pair(Class),
        ("scala", "object_definition") => pair(Type),
        ("scala", "trait_definition") => pair(Trait),
        // Kotlin (методы класса — те же function_declaration внутри тела).
        ("kotlin", "function_declaration") => pair(Function),
        ("kotlin", "class_declaration") => pair(Class),
        ("kotlin", "object_declaration") => pair(Type),
        // Swift (class_declaration покрывает class/struct/enum/actor — declaration_kind).
        ("swift", "function_declaration" | "init_declaration") => pair(Function),
        ("swift", "class_declaration") => pair(Class),
        ("swift", "protocol_declaration") => pair(Interface),
        // Dart
        ("dart", "function_signature") => pair(Function),
        ("dart", "class_declaration") => pair(Class),
        ("dart", "mixin_declaration") => pair(Type),
        ("dart", "enum_declaration") => pair(Enum),
        _ => None,
    }
}

/// Имя функции в C/C++: спускаемся по цепочке declarator до идентификатора.
fn c_func_name<'a>(node: &tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let mut d = node.child_by_field_name("declarator")?;
    loop {
        match d.kind() {
            "identifier" | "field_identifier" | "qualified_identifier" | "operator_name"
            | "destructor_name" => return Some(d),
            "function_declarator" | "pointer_declarator" | "parenthesized_declarator"
            | "reference_declarator" => d = d.child_by_field_name("declarator")?,
            _ => return None,
        }
    }
}

// ───────────────────────── Граф вызовов (call graph, AST) ─────────────────────────

/// Граф вызовов: кто кого зовёт на уровне функций. Best-effort через AST: вызовы
/// разрешаются по ИМЕНИ к определённым в проекте функциям; неразрешённые (stdlib,
/// динамика, рефлексия) считаются ЯВНО — не молчим. Только для AST-языков.
///
/// T66: дополнительно фиксируются КВАЛИФИЦИРОВАННЫЕ определения (тип-получатель плюс
/// имя) и набор имён, потенциально вызываемых через диспетчеризацию (реализации
/// трейтов/интерфейсов, переопределения, экспортируемые символы). Это нужно, чтобы не
/// объявлять метод недостижимым лишь потому, что прямого вызова по имени не нашлось:
/// при виртуальной диспетчеризации/колбэке/рефлексии вызов реально существует, но в
/// AST по имени не виден.
pub struct CallGraph {
    /// Имена определённых функций/методов проекта (бэр-имена, для совместимости).
    pub funcs: Vec<String>,
    /// Рёбра (вызывающий → вызываемый), где оба — определённые функции.
    pub edges: BTreeSet<(String, String)>,
    /// Сколько вызовов ушло «вовне» (имя не совпало ни с одним определением).
    pub unresolved: usize,
    /// Всего обнаружено вызовов.
    pub total_calls: usize,
    /// Файлы, разобранные через AST (язык поддержан грамматикой).
    pub files_parsed: usize,
    /// Квалифицированные ключи определений `тип-или-модуль::имя` (T66). Позволяют не
    /// сливать два разных метода с одинаковым именем в один узел.
    pub qualified_defs: BTreeSet<String>,
    /// Имена, определённые БОЛЕЕ ЧЕМ в одном месте (омонимы методов). Для них вывод о
    /// недостижимости по имени недостоверен — исключаем из жёсткого результата.
    pub ambiguous: BTreeSet<String>,
    /// Имена, потенциально достижимые через диспетчеризацию (методы трейтов/интерфейсов,
    /// переопределения, экспортируемые символы): их нельзя считать мёртвыми по AST (T66).
    pub dispatch_exempt: BTreeSet<String>,
}

impl CallGraph {
    /// Функции без входящих рёбер и не являющиеся точкой входа — потенциально
    /// недостижимые. T66: дополнительно исключаются неоднозначные имена (омонимы) и
    /// имена, достижимые через диспетчеризацию, чтобы не выдавать ложный мёртвый код
    /// при трейтах/интерфейсах/виртуальных вызовах/колбэках. Результат этого метода
    /// носит характер ЭВРИСТИКИ НИЗКОЙ ДОСТОВЕРНОСТИ (см. [`CallGraph::reachability_confidence`])
    /// и не должен выноситься жёсткой находкой мёртвого кода.
    pub fn unreachable(&self) -> Vec<String> {
        let called: HashSet<&str> = self.edges.iter().map(|(_, c)| c.as_str()).collect();
        let mut out: Vec<String> = self
            .funcs
            .iter()
            .filter(|f| {
                !called.contains(f.as_str())
                    && !is_entry_name(f)
                    && !self.ambiguous.contains(f.as_str())
                    && !self.dispatch_exempt.contains(f.as_str())
            })
            .cloned()
            .collect();
        out.sort();
        out
    }

    /// Достоверность вывода о недостижимости (T66). Граф строится по имени без полного
    /// разрешения типов, поэтому виртуальная диспетчеризация, колбэки и рефлексия дают
    /// ложноотрицательные рёбра. Это осознанно НИЗКАЯ уверенность: результат —
    /// подсказка, а не детерминированная находка мёртвого кода.
    pub fn reachability_confidence(&self) -> ailc_contracts::Confidence {
        ailc_contracts::Confidence::Low
    }
}

/// Типичные точки входа/каркасные имена — не считаем недостижимыми.
fn is_entry_name(name: &str) -> bool {
    matches!(
        name,
        "main" | "Main" | "init" | "setUp" | "tearDown" | "run" | "handler" | "Handler"
    ) || name.starts_with("Test")
        || name.starts_with("test")
        || name.starts_with("Benchmark")
}

/// Одно собранное определение функции/метода с контекстом (T66).
struct CallDef {
    /// Бэр-имя символа.
    name: String,
    /// Квалификатор: ближайший объемлющий тип/класс/трейт/интерфейс/модуль или "".
    qualifier: String,
    /// Символ потенциально достижим через диспетчеризацию (метод трейта/интерфейса/
    /// абстрактного класса, переопределение, экспортируемый символ).
    dispatch_exempt: bool,
}

impl CodeIntelEngine {
    /// Построить граф вызовов по дереву (или по `input.target`).
    pub fn call_graph(ctx: &Ctx, input: &RunInput) -> Result<CallGraph> {
        // target валидируется (абсолютный путь / `..` не выводят за корень проекта).
        let base = ctx.base(input)?;
        let mut all_defs: Vec<CallDef> = Vec::new();
        let mut raw: Vec<(String, String)> = Vec::new();
        let mut files_parsed = 0usize;

        walk(&base, &mut |path| {
            let lang = lang_for_ext(ext_of(path));
            if ts_language(lang).is_none() {
                return;
            }
            let content = match read_source(path) {
                Some(c) => c,
                None => return,
            };
            if collect_calls(lang, &content, &mut all_defs, &mut raw).is_some() {
                files_parsed += 1;
            }
        })?;

        // Множество бэр-имён определений (для совместимости и резолва рёбер).
        let defs: HashSet<String> = all_defs.iter().map(|d| d.name.clone()).collect();

        // Подсчёт, сколько раз встречается каждое имя: > 1 ведёт к неоднозначности (T66).
        let mut name_count: HashMap<&str, usize> = HashMap::new();
        for d in &all_defs {
            *name_count.entry(d.name.as_str()).or_default() += 1;
        }
        let ambiguous: BTreeSet<String> = name_count
            .iter()
            .filter(|(_, &c)| c > 1)
            .map(|(&n, _)| n.to_string())
            .collect();

        // Квалифицированные ключи и набор диспетчеризуемых имён (T66).
        let mut qualified_defs: BTreeSet<String> = BTreeSet::new();
        let mut dispatch_exempt: BTreeSet<String> = BTreeSet::new();
        for d in &all_defs {
            let key = if d.qualifier.is_empty() {
                d.name.clone()
            } else {
                format!("{}::{}", d.qualifier, d.name)
            };
            qualified_defs.insert(key);
            if d.dispatch_exempt {
                dispatch_exempt.insert(d.name.clone());
            }
        }

        let total_calls = raw.len();
        let mut edges = BTreeSet::new();
        let mut unresolved = 0usize;
        for (caller, callee) in raw {
            if caller != callee && defs.contains(&callee) {
                edges.insert((caller, callee));
            } else if !defs.contains(&callee) {
                unresolved += 1;
            }
        }
        let mut funcs: Vec<String> = defs.into_iter().collect();
        funcs.sort();
        Ok(CallGraph {
            funcs,
            edges,
            unresolved,
            total_calls,
            files_parsed,
            qualified_defs,
            ambiguous,
            dispatch_exempt,
        })
    }
}

/// Узел tree-sitter — это объявление контейнера-квалификатора (класс/трейт/интерфейс/
/// объект/модуль/реализация), внутри которого живут методы. Используется для построения
/// квалифицированного ключа метода (T66).
fn qualifier_node<'a>(lang: &str, node: &tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let is_container = matches!(
        (lang, node.kind()),
        (_, "class_declaration")
            | (_, "class_definition")
            | (_, "class_specifier")
            | (_, "class")
            | (_, "interface_declaration")
            | (_, "trait_declaration")
            | (_, "trait_definition")
            | (_, "trait_item")
            | (_, "impl_item")
            | (_, "struct_item")
            | (_, "enum_item")
            | (_, "object_declaration")
            | (_, "object_definition")
            | (_, "module")
            | (_, "protocol_declaration")
            | (_, "record_declaration")
            | (_, "struct_declaration")
            | (_, "mixin_declaration")
            | (_, "extension")
            | (_, "extension_declaration")
    );
    if !is_container {
        return None;
    }
    Some(*node)
}

/// Признак того, что определение потенциально достижимо через диспетчеризацию (T66) и
/// потому НЕ может объявляться мёртвым по AST: метод внутри трейта/интерфейса/протокола
/// или их реализации (виртуальная/полиморфная диспетчеризация), а также явное
/// переопределение (override). Намеренно НЕ считаем диспетчеризуемым каждый публичный
/// свободный символ: иначе для языков, где публичность по умолчанию (Python/Ruby),
/// недостижимыми не оказался бы почти никто, и анализ потерял бы смысл. Возможный вызов
/// публичного символа из другого пакета или через рефлексию учитывается понижением
/// общей уверенности результата до Low (см. [`CallGraph::reachability_confidence`]),
/// а не индивидуальным исключением каждого публичного символа.
fn is_dispatchable(_lang: &str, qualifier_kind: &str, def_line: &str, _name: &str) -> bool {
    // Метод внутри контракта поведения (трейт/интерфейс/протокол) или реализации.
    let in_contract = matches!(
        qualifier_kind,
        "interface_declaration"
            | "trait_declaration"
            | "trait_definition"
            | "trait_item"
            | "impl_item"
            | "protocol_declaration"
    );
    if in_contract {
        return true;
    }
    // Явное переопределение виртуального метода.
    let t = def_line.trim_start();
    t.contains("override ") || def_line.contains("@Override") || t.starts_with("@Override")
}

/// Собрать определения функций (с контекстом-квалификатором) и пары
/// (вызывающий, вызываемое-имя) из одного файла (T66).
fn collect_calls(
    lang: &str,
    content: &str,
    defs: &mut Vec<CallDef>,
    raw: &mut Vec<(String, String)>,
) -> Option<()> {
    use tree_sitter::Parser;
    let language = ts_language(lang)?;
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(content, None)?;
    let bytes = content.as_bytes();
    let lines: Vec<&str> = content.lines().collect();

    // DFS с контекстом: (узел, имя объемлющей функции, квалификатор, вид квалификатора).
    let mut stack: Vec<(tree_sitter::Node, String, String, String)> =
        vec![(tree.root_node(), "(верх)".into(), String::new(), String::new())];
    while let Some((node, caller, qualifier, qual_kind)) = stack.pop() {
        let mut child_caller = caller.clone();
        let mut child_qualifier = qualifier.clone();
        let mut child_qual_kind = qual_kind.clone();

        // Узел-контейнер обновляет квалификатор для вложенных методов.
        if let Some(qn) = qualifier_node(lang, &node) {
            if let Some(name_node) = qn.child_by_field_name("name") {
                if let Ok(n) = name_node.utf8_text(bytes) {
                    child_qualifier = n.to_string();
                }
            }
            child_qual_kind = node.kind().to_string();
        }

        if let Some((kind, name_node)) = def_node(lang, &node) {
            if matches!(kind, SymbolKind::Function | SymbolKind::Method) {
                if let Ok(n) = name_node.utf8_text(bytes) {
                    let row = node.start_position().row;
                    let def_line = lines.get(row).copied().unwrap_or("");
                    let dispatch = is_dispatchable(lang, &qual_kind, def_line, n);
                    defs.push(CallDef {
                        name: n.to_string(),
                        qualifier: qualifier.clone(),
                        dispatch_exempt: dispatch,
                    });
                    child_caller = n.to_string();
                }
            }
        }
        if is_call_node(lang, node.kind()) {
            if let Some(callee) = callee_name(&node, bytes) {
                raw.push((caller.clone(), callee));
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push((
                child,
                child_caller.clone(),
                child_qualifier.clone(),
                child_qual_kind.clone(),
            ));
        }
    }
    Some(())
}

/// Узел — это вызов функции/метода (по языку).
pub(crate) fn is_call_node(lang: &str, kind: &str) -> bool {
    match lang {
        "java" => kind == "method_invocation",
        "csharp" => kind == "invocation_expression",
        "python" => kind == "call",
        "ruby" => kind == "call" || kind == "method_call",
        "php" => matches!(
            kind,
            "function_call_expression" | "member_call_expression" | "scoped_call_expression"
        ),
        // rust/go/c/cpp/js/ts/scala
        _ => kind == "call_expression",
    }
}

/// Имя вызываемой функции: берём узел-цель вызова и его хвостовой идентификатор
/// (`a.b.c()` → `c`, `pkg::f()` → `f`, `obj.m()` → `m`).
pub(crate) fn callee_name(call: &tree_sitter::Node, bytes: &[u8]) -> Option<String> {
    let target = call
        .child_by_field_name("function")
        .or_else(|| call.child_by_field_name("name"))
        .or_else(|| call.child_by_field_name("method"))
        .or_else(|| call.named_child(0))?;
    trailing_ident(target, bytes)
}

/// Хвостовой идентификатор выражения (правый лист цепочки доступа). T69: обход на
/// ЯВНОМ стеке без рекурсии, чтобы глубоко вложенное выражение не переполняло стек.
///
/// Семантика прежняя: спускаемся по дереву, всегда предпочитая правого потомка, и
/// возвращаем первый встреченный листовой идентификатор. Поскольку рекурсивная версия
/// перебирала именованных детей справа налево и возвращала первый успешный результат,
/// эквивалент на стеке кладёт детей в порядке СЛЕВА НАПРАВО, чтобы правый оказался
/// наверху и обрабатывался первым.
fn trailing_ident(node: tree_sitter::Node, bytes: &[u8]) -> Option<String> {
    let mut stack: Vec<tree_sitter::Node> = vec![node];
    while let Some(n) = stack.pop() {
        if matches!(
            n.kind(),
            "identifier" | "field_identifier" | "property_identifier" | "name" | "simple_identifier"
        ) {
            if let Some(s) = n.utf8_text(bytes).ok().map(String::from) {
                return Some(s);
            }
            continue;
        }
        let mut cursor = n.walk();
        let kids: Vec<tree_sitter::Node> = n.named_children(&mut cursor).collect();
        // Кладём слева направо: правый ребёнок окажется наверху и обработается первым.
        for child in kids {
            stack.push(child);
        }
    }
    None
}

/// Токенизировать содержимое в идентификаторы и накопить частоты.
fn count_identifiers(content: &str, freq: &mut HashMap<String, u32>) {
    let mut cur = String::new();
    for ch in content.chars() {
        if ch == '_' || ch.is_alphanumeric() {
            cur.push(ch);
        } else if !cur.is_empty() {
            flush_ident(&mut cur, freq);
        }
    }
    if !cur.is_empty() {
        flush_ident(&mut cur, freq);
    }
}

fn flush_ident(cur: &mut String, freq: &mut HashMap<String, u32>) {
    if cur.chars().count() >= 2 && !cur.starts_with(|c: char| c.is_numeric()) {
        *freq.entry(cur.clone()).or_default() += 1;
    }
    cur.clear();
}

/// `name` встречается в строке как целый идентификатор (с границами слова).
fn contains_word(line: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let boundary = |c: Option<char>| c.is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
    line.match_indices(name).any(|(idx, _)| {
        let before = line[..idx].chars().last();
        let after = line[idx + name.len()..].chars().next();
        boundary(before) && boundary(after)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_contracts::{Ctx, RunInput};
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Уникальная пустая временная папка для файловых фикстур.
    fn tmp() -> std::path::PathBuf {
        let n = CNT.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("ailc-codeintel-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }

    // ───────────────────────── T68: устойчивое чтение ─────────────────────────

    #[test]
    fn decode_strips_leading_bom() {
        // BOM (EF BB BF) перед import не должен мешать распознаванию импорта.
        let bytes = [&[0xEF, 0xBB, 0xBF][..], b"import foo"].concat();
        let s = decode_source(&bytes);
        assert!(s.starts_with("import foo"), "BOM не срезан: {s:?}");
        assert!(!s.starts_with('\u{FEFF}'));
    }

    #[test]
    fn decode_non_utf8_does_not_drop_file() {
        // Байт 0xFF (вне UTF-8) не должен приводить к пустой/потерянной строке.
        let bytes = b"fn a() {}\nfn b\xFF() {}\n";
        let s = decode_source(bytes);
        assert!(s.contains("fn a()"));
        assert!(s.lines().count() >= 2);
    }

    #[test]
    fn normalize_lone_cr_splits_lines() {
        // Старый macOS: одиночный CR должен давать несколько строк.
        assert_eq!(normalize_newlines("a\rb\rc").lines().count(), 3);
        // CRLF не должен удваивать переводы строк.
        assert_eq!(normalize_newlines("a\r\nb").lines().count(), 2);
        // Чистый LF не меняется.
        assert_eq!(normalize_newlines("a\nb"), "a\nb");
    }

    #[test]
    fn mask_removes_block_comment_decls() {
        // Объявление внутри /* ... */ не должно давать символ; нумерация строк цела.
        let src = "fn real() {}\n/* fn fake() {}\nstruct Fake; */\nfn after() {}\n";
        let masked = mask_comments_and_strings("rust", src);
        assert_eq!(masked.lines().count(), src.lines().count());
        assert!(masked.contains("fn real"));
        assert!(masked.contains("fn after"));
        assert!(!masked.contains("fake"));
        assert!(!masked.contains("Fake"));
    }

    // ───────────────────────── T65: модуль и резолвер ─────────────────────────

    #[test]
    fn module_of_keeps_full_path() {
        assert_eq!(module_of("services/a/utils/x.rs"), "services/a/utils");
        assert_eq!(module_of("services\\b\\utils\\y.go"), "services/b/utils");
        assert_eq!(module_of("main.rs"), "(root)");
    }

    #[test]
    fn resolver_distinguishes_same_named_dirs() {
        let mods: BTreeSet<String> = ["services/a/utils", "services/b/utils", "core"]
            .into_iter()
            .map(String::from)
            .collect();
        let r = ModuleResolver::new(&mods);
        // Цель импорта (как её извлекает import_targets) по полному пути находит именно
        // нужный из двух одноимённых utils.
        assert_eq!(
            r.resolve("services.a.utils"),
            Some("services/a/utils".to_string())
        );
        assert_eq!(
            r.resolve("services/b/utils/helper"),
            Some("services/b/utils".to_string())
        );
    }

    #[test]
    fn resolver_rejects_external_crate_component() {
        // `core` существует как локальный модуль, но `serde::core` не должен матчиться,
        // потому что суффикс `serde/core` не известен, а имя `core` неоднозначно? Нет —
        // оно уникально, поэтому fallback по уникальному концевому имени дал бы ложь.
        // Проверяем, что суффиксный матч имеет приоритет и НЕ срабатывает на serde::core,
        // так как полного существующего суффикса нет, а fallback по уникальному `core`
        // мы намеренно НЕ применяем для многосегментных внешних путей.
        let mods: BTreeSet<String> = ["app/core"].into_iter().map(String::from).collect();
        let r = ModuleResolver::new(&mods);
        // serde::core: суффикс `serde/core` неизвестен, суффикс `core` неизвестен
        // (модуль называется app/core), поэтому ребра нет.
        assert_eq!(r.resolve("serde::core"), None);
        // А реальный импорт app/core резолвится.
        assert_eq!(r.resolve("crate::app::core"), Some("app/core".to_string()));
    }

    // ───────────────────────── T69: Tarjan на стеке ─────────────────────────

    #[test]
    fn tarjan_detects_cycle_iteratively() {
        // 0 -> 1 -> 2 -> 0 образует один SCC размера 3; 3 одиночка.
        let adj = vec![vec![1], vec![2], vec![0], vec![]];
        let sccs = tarjan_scc(&adj);
        let big: Vec<&Vec<usize>> = sccs.iter().filter(|c| c.len() > 1).collect();
        assert_eq!(big.len(), 1);
        assert_eq!(big[0].len(), 3);
    }

    #[test]
    fn tarjan_deep_chain_no_overflow() {
        // Длинная цепочка без рекурсии не должна переполнять стек.
        let n = 50_000usize;
        let mut adj = vec![Vec::new(); n];
        for (i, edges) in adj.iter_mut().enumerate().take(n - 1) {
            edges.push(i + 1);
        }
        let sccs = tarjan_scc(&adj);
        // Все вершины — отдельные SCC (ацикличная цепочка).
        assert_eq!(sccs.len(), n);
    }

    #[test]
    fn dependency_graph_no_false_cycle_across_services() {
        let dir = tmp();
        // Два одноимённых пакета utils в разных сервисах не должны сливаться в цикл.
        write(&dir, "services/a/utils/u.py", "def a_helper():\n    return 1\n");
        write(
            &dir,
            "services/a/main/m.py",
            "from services.a.utils import a_helper\n",
        );
        write(&dir, "services/b/utils/u.py", "def b_helper():\n    return 2\n");
        let ctx = Ctx::new(&dir);
        let g = CodeIntelEngine::dependency_graph(&ctx, &RunInput::default()).unwrap();
        // utils из a и b — РАЗНЫЕ узлы.
        assert!(g.modules.iter().any(|m| m == "services/a/utils"));
        assert!(g.modules.iter().any(|m| m == "services/b/utils"));
        // Никакого цикла быть не должно.
        assert!(g.cycles().is_empty(), "ложный цикл: {:?}", g.cycles());
        let _ = fs::remove_dir_all(&dir);
    }

    // ───────────────────────── T67: outbound и контейнеры ─────────────────────────

    #[test]
    fn outbound_extracts_http_target() {
        let hits = outbound_in_line(r#"    resp = requests.get("https://api.payments.io/charge")"#);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].target, "https://api.payments.io");
        assert_eq!(hits[0].protocol, "https");
    }

    #[test]
    fn outbound_normalizes_credentials_and_path() {
        assert_eq!(
            normalize_outbound_target("https://user:pass@svc.local:8080/v1/x?y=1"),
            "https://svc.local:8080"
        );
    }

    #[test]
    fn containers_from_compose() {
        let yaml = "version: '3'\nservices:\n  api:\n    image: api:latest\n  worker:\n    build: .\n";
        let c = containers_in_file("docker-compose.yml", yaml);
        assert!(c.contains(&"service:api".to_string()));
        assert!(c.contains(&"service:worker".to_string()));
    }

    #[test]
    fn containers_from_dockerfile() {
        let df = "FROM rust:1.79 AS build\nRUN cargo build\nFROM debian:stable\n";
        let c = containers_in_file("Dockerfile", df);
        assert!(c.iter().any(|x| x == "image:debian:stable"));
    }

    #[test]
    fn service_graph_collects_outbound_and_containers() {
        let dir = tmp();
        write(
            &dir,
            "svc/client.go",
            "package svc\nfunc call() { http.Get(\"https://billing.internal/api\") }\n",
        );
        write(&dir, "Dockerfile", "FROM golang:1.22\n");
        let ctx = Ctx::new(&dir);
        let g = CodeIntelEngine::service_graph(&ctx, &RunInput::default()).unwrap();
        assert!(g.outbound.iter().any(|o| o.target.contains("billing.internal")));
        assert!(g.containers.iter().any(|c| c == "image:golang:1.22"));
        let _ = fs::remove_dir_all(&dir);
    }

    // ───────────────────────── T66: квалифицированные вызовы ─────────────────────────

    #[test]
    fn call_graph_does_not_flag_trait_impl_as_dead() {
        let dir = tmp();
        // save определён только как метод трейта/impl и нигде не вызывается по имени:
        // не должен попадать в недостижимые (диспетчеризация).
        write(
            &dir,
            "lib.rs",
            "pub trait Store { fn save(&self); }\n\
             pub struct S;\n\
             impl Store for S { fn save(&self) { helper(); } }\n\
             fn helper() {}\n\
             pub fn entry() { let s = S; }\n",
        );
        let ctx = Ctx::new(&dir);
        let cg = CodeIntelEngine::call_graph(&ctx, &RunInput::default()).unwrap();
        let unreachable = cg.unreachable();
        assert!(
            !unreachable.contains(&"save".to_string()),
            "метод трейта ложно объявлен мёртвым: {unreachable:?}"
        );
        // Уверенность результата — низкая (эвристика, не жёсткая находка).
        assert_eq!(cg.reachability_confidence(), ailc_contracts::Confidence::Low);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn call_graph_ambiguous_name_not_dead() {
        let dir = tmp();
        // Два разных метода `process` (омонимы): неоднозначное имя нельзя объявлять мёртвым.
        write(
            &dir,
            "a.py",
            "class A:\n    def process(self):\n        return 1\n",
        );
        write(
            &dir,
            "b.py",
            "class B:\n    def process(self):\n        return 2\n",
        );
        let ctx = Ctx::new(&dir);
        let cg = CodeIntelEngine::call_graph(&ctx, &RunInput::default()).unwrap();
        assert!(cg.ambiguous.contains("process"));
        assert!(!cg.unreachable().contains(&"process".to_string()));
        let _ = fs::remove_dir_all(&dir);
    }

    // ───────────────────────── T70: лимит ссылок и компиляция паттернов ─────────────────────────

    #[test]
    fn references_are_capped() {
        let dir = tmp();
        // Создаём заведомо больше MAX_REFERENCES вхождений имени `widget`.
        let mut body = String::new();
        for _ in 0..(MAX_REFERENCES + 50) {
            body.push_str("let widget = 1;\n");
        }
        write(&dir, "big.rs", &body);
        let ctx = Ctx::new(&dir);
        let r = CodeIntelEngine::references_capped(&ctx, &RunInput::default(), "widget").unwrap();
        assert_eq!(r.hits.len(), MAX_REFERENCES);
        assert!(r.truncated);
        assert!(r.total > MAX_REFERENCES);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn static_symbol_patterns_compile() {
        // Принудительно компилируем все статические паттерны таблицы символов (T70):
        // опечатка в любом regex упадёт этим тестом, а не паникой MCP-сервера в проде.
        let t = table();
        assert!(t.contains_key("rs"));
        assert!(t.contains_key("go"));
        // Outbound-паттерны тоже компилируем.
        assert!(!outbound_res().is_empty());
    }
}
