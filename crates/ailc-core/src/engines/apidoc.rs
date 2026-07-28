//! Извлечение ОПИСАНИЙ программных элементов (сигнатура, комментарий документации,
//! отношение наследования) для разделов документов, оформляемых по государственным
//! стандартам.
//!
//! Извлечение символов, выполняемое движком CodeIntel, даёт лишь имя, вид, файл,
//! строку, язык и признак доступности элемента извне. Для документа этого
//! недостаточно: раздел «Функции частей программного обеспечения» и раздел
//! «Требования к функциональным характеристикам» требуют изложить, ЧТО делает каждая
//! часть программного обеспечения, а перечень имён на такой вопрос не отвечает.
//! Настоящий модуль добавляет к перечню имён именно описательную часть: объявление
//! элемента одной строкой, относящийся к нему комментарий документации, взятый из
//! исходного текста без домысливания, и отношение наследования (базовые типы и
//! реализуемые интерфейсы).
//!
//! Разбор выполняется исключительно по дереву tree-sitter и исключительно для тех
//! языков, для которых грамматика подключена. Язык без грамматики честно
//! пропускается: приблизительный построчный разбор давал бы правдоподобные, но
//! неверные описания, а неверное описание в документе по стандарту хуже отсутствия
//! описания, поскольку оно не отличимо от достоверного. Подход к разбору полностью
//! повторяет применённый в модуле `codeintel`, а вспомогательные функции выбора
//! грамматики, определения языка по расширению и устойчивого чтения исходного текста
//! переиспользуются оттуда, чтобы разбор не дублировался.

use super::codeintel::{lang_for_ext, read_source, ts_language};
use super::walk::{ext_of, is_test_dir_path, is_test_path, walk};
use ailc_contracts::{Ctx, Result, RunInput};
use std::collections::BTreeMap;

/// Предельная длина сигнатуры в символах.
///
/// Предел необходим по двум причинам. Во-первых, объявление на языке со сложной
/// системой типов (обобщения с ограничениями, длинные списки параметров, атрибуты)
/// занимает сотни символов, и в таблице документа такая строка перестаёт читаться,
/// разрушая вёрстку раздела. Во-вторых, выдача движка попадает в отчёты и в кэш, и
/// неограниченная строка из машинно сгенерированного исходного текста способна
/// раздуть их до непредсказуемого объёма. Величина выбрана так, чтобы типовое
/// объявление помещалось целиком, а усечение происходило только у действительно
/// исключительных случаев; факт усечения виден по завершающему многоточию.
const MAX_SIGNATURE_CHARS: usize = 200;

/// Предельная длина комментария документации в символах. Обоснование то же, что и у
/// предела длины сигнатуры: в разделе документа приводится краткое назначение части
/// программного обеспечения, а не полный текст руководства, который в отдельных
/// проектах занимает десятки килобайт на один элемент.
const MAX_DOC_CHARS: usize = 600;

/// Предельное число строк исходного текста, просматриваемых при сборе комментария
/// документации. Ограничение защищает от вырожденного случая незавершённой конструкции
/// комментария: если у блочного комментария нет открывающей последовательности знаков,
/// а у строки документации языка Python нет закрывающей последовательности кавычек, то
/// просмотр без предела дошёл бы до границы файла и объявил бы описанием произвольный
/// фрагмент кода.
const MAX_DOC_LINES: usize = 60;

/// Предельное число элементов, извлекаемых из ОДНОГО файла.
///
/// Предел нужен потому, что в реальных деревьях встречаются машинно сгенерированные
/// файлы (клиенты протоколов, привязки к схемам данных, наборы констант), содержащие
/// тысячи однотипных объявлений. Такой файл не описывает функции продукта, но при
/// отсутствии предела он один вытеснил бы из документа все прикладные части и
/// многократно увеличил бы объём выдачи. Элементы файла перед усечением упорядочены
/// по строке и имени, поэтому усечение детерминировано и оставляет начало файла, где
/// обычно объявлены основные элементы.
const MAX_ITEMS_PER_FILE: usize = 300;

/// Наименования видов программных элементов на русском языке. Вид пишется словом, а
/// не машинным обозначением, поскольку значение поля переносится в текст документа
/// без дополнительного перевода.
const KIND_FUNCTION: &str = "функция";
const KIND_METHOD: &str = "метод";
const KIND_TYPE: &str = "тип";
const KIND_CLASS: &str = "класс";
/// Трейт языка Rust, протокол языка Swift и типаж языка Scala описывают одно и то же
/// понятие: набор требований к поведению, реализуемый другими типами. В документе они
/// именуются интерфейсом, поскольку иного устоявшегося русского наименования для этого
/// понятия в стандартах нет.
const KIND_INTERFACE: &str = "интерфейс";
const KIND_ENUM: &str = "перечисление";
const KIND_MODULE: &str = "модуль";
const KIND_OBJECT: &str = "объект";

/// Описание одного программного элемента, пригодное для включения в раздел документа.
pub struct ApiItem {
    /// Имя элемента так, как оно записано в исходном тексте.
    pub name: String,
    /// Вид элемента словом на русском языке: функция, метод, тип, класс, интерфейс,
    /// перечисление, модуль, объект.
    pub kind: String,
    /// Путь файла относительно корня проекта.
    pub file: String,
    /// Номер строки объявления, отсчитываемый от единицы.
    pub line: u32,
    /// Объявление элемента одной строкой: текст от начала объявления до начала тела,
    /// приведённый к одиночным пробелам и ограниченный по длине.
    pub signature: String,
    /// Комментарий документации, приведённый к обычному тексту без знаков разметки
    /// комментария. Значение отсутствует, если комментария в исходном тексте нет:
    /// описание не сочиняется.
    pub doc: Option<String>,
    /// Базовые типы и реализуемые интерфейсы в порядке их записи в исходном тексте.
    pub extends: Vec<String>,
    /// Признак доступности элемента извне своей части программного обеспечения.
    pub exported: bool,
}

/// Движок извлечения описаний программных элементов.
pub struct ApiDoc;

impl ApiDoc {
    /// Извлечь описания программных элементов из дерева исходных текстов проекта либо
    /// из подпути, заданного полем `target` входа.
    ///
    /// Файлы тестов исключаются: документ описывает продукт, а не средства его
    /// проверки, и тестовый класс, попавший в раздел о функциях программного
    /// обеспечения, вводит читателя в заблуждение относительно состава продукта.
    /// Результат упорядочен по файлу, затем по строке, затем по имени, поэтому два
    /// прогона на неизменном дереве дают побайтово совпадающую выдачу.
    pub fn extract(ctx: &Ctx, input: &RunInput) -> Result<Vec<ApiItem>> {
        // Подпуть проверяется контекстом: абсолютный путь и переходы к родительскому
        // каталогу не должны выводить обход за корень проекта.
        let base = ctx.base(input)?;
        let root = ctx.root.clone();
        let mut items: Vec<ApiItem> = Vec::new();

        walk(&base, &mut |path| {
            let lang = lang_for_ext(ext_of(path));
            // Язык без подключённой грамматики пропускается честно, без приблизительного
            // разбора: см. пояснение в заголовке модуля.
            if ts_language(lang).is_none() {
                return;
            }
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if is_test_path(&rel) || is_test_dir_path(&rel) {
                return;
            }
            let Some(content) = read_source(path) else {
                return;
            };
            items.extend(items_of_file(lang, &content, &rel));
        })?;

        items.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.line.cmp(&b.line))
                .then(a.name.cmp(&b.name))
        });
        Ok(items)
    }
}

/// Описания программных элементов одного файла. Возвращает пустой вектор, если
/// грамматика недоступна либо разбор не состоялся: отсутствие описаний честнее
/// приблизительных описаний.
fn items_of_file(lang: &str, content: &str, rel: &str) -> Vec<ApiItem> {
    use tree_sitter::Parser;

    let Some(language) = ts_language(lang) else {
        return Vec::new();
    };
    let mut parser = Parser::new();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(content, None) else {
        return Vec::new();
    };

    let bytes = content.as_bytes();
    let lines: Vec<&str> = content.lines().collect();
    // Отношение реализации в языке Rust записывается отдельным блоком `impl Trait for
    // Type`, то есть вне объявления самого типа. Поэтому оно собирается предварительным
    // проходом в отображение «имя типа, перечень реализованных интерфейсов» и
    // присоединяется к описанию типа, когда тот встретится при основном обходе.
    let rust_impls = if lang == "rust" {
        rust_impl_map(&tree.root_node(), bytes)
    } else {
        BTreeMap::new()
    };

    // Обход в глубину с явным стеком, а не рекурсией: глубина дерева чужого исходного
    // текста заранее неизвестна, а переполнение системного стека завершает процесс
    // целиком, тогда как изоляция сбоев в конвейере рассчитана на панику.
    let mut items: Vec<ApiItem> = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if let Some((kind, name_node)) = declaration(lang, &node) {
            if let Ok(name) = name_node.utf8_text(bytes) {
                // Для описания берётся внешний узел объявления: в отдельных грамматиках
                // объявление обёрнуто узлом, который и несёт ключевое слово и к которому
                // относится комментарий документации.
                let outer = outer_node(lang, &node);
                let signature = signature_of(content, &outer);
                let row = outer.start_position().row;
                let body_row = outer
                    .child_by_field_name("body")
                    .map(|b| b.start_position().row);
                let doc = doc_of(lang, &lines, row, body_row);
                let mut extends = extends_of(lang, &node, bytes);
                // Отношение реализации, собранное предварительным проходом, относится
                // именно к ТИПУ, поэтому присоединяется только к описанию типа. Иначе
                // функция, случайно одноимённая типу, получила бы чужое отношение
                // наследования, которого в исходном тексте нет.
                if extends.is_empty() && is_type_kind(kind) {
                    if let Some(traits) = rust_impls.get(name) {
                        extends = traits.clone();
                    }
                }
                items.push(ApiItem {
                    exported: is_exported(lang, &signature, name),
                    name: name.to_string(),
                    kind: kind.to_string(),
                    file: rel.to_string(),
                    line: (row as u32) + 1,
                    signature,
                    doc,
                    extends,
                });
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }

    // Упорядочивание выполняется до усечения по пределу на файл, поэтому усечение
    // детерминировано и не зависит от порядка обхода дерева.
    items.sort_by(|a, b| a.line.cmp(&b.line).then(a.name.cmp(&b.name)));
    items.truncate(MAX_ITEMS_PER_FILE);
    items
}

/// Узел-объявление: вид элемента словом и узел, несущий имя. Перечень видов узлов
/// повторяет перечень, применяемый при извлечении символов движком CodeIntel, чтобы
/// описание и перечень имён относились к одним и тем же элементам.
fn declaration<'a>(
    lang: &str,
    node: &tree_sitter::Node<'a>,
) -> Option<(&'static str, tree_sitter::Node<'a>)> {
    let name = || node.child_by_field_name("name");
    let pair = |k: &'static str| name().map(|n| (k, n));
    let has_body = || node.child_by_field_name("body").is_some();
    match (lang, node.kind()) {
        ("rust", "function_item") => pair(KIND_FUNCTION),
        ("rust", "struct_item") => pair(KIND_TYPE),
        ("rust", "enum_item") => pair(KIND_ENUM),
        ("rust", "trait_item") => pair(KIND_INTERFACE),
        ("go", "function_declaration") => pair(KIND_FUNCTION),
        ("go", "method_declaration") => pair(KIND_METHOD),
        ("go", "type_spec") => pair(KIND_TYPE),
        ("python", "function_definition") => pair(KIND_FUNCTION),
        ("python", "class_definition") => pair(KIND_CLASS),
        ("javascript" | "typescript", "function_declaration") => pair(KIND_FUNCTION),
        ("javascript" | "typescript", "class_declaration") => pair(KIND_CLASS),
        ("javascript" | "typescript", "method_definition") => pair(KIND_METHOD),
        ("typescript", "interface_declaration") => pair(KIND_INTERFACE),
        ("typescript", "type_alias_declaration") => pair(KIND_TYPE),
        ("typescript", "enum_declaration") => pair(KIND_ENUM),
        ("java", "class_declaration") => pair(KIND_CLASS),
        ("java", "interface_declaration") => pair(KIND_INTERFACE),
        ("java", "enum_declaration") => pair(KIND_ENUM),
        ("java", "record_declaration") => pair(KIND_TYPE),
        ("java", "method_declaration") => pair(KIND_METHOD),
        ("csharp", "class_declaration") => pair(KIND_CLASS),
        ("csharp", "interface_declaration") => pair(KIND_INTERFACE),
        ("csharp", "struct_declaration") => pair(KIND_TYPE),
        ("csharp", "enum_declaration") => pair(KIND_ENUM),
        ("csharp", "method_declaration") => pair(KIND_METHOD),
        // Имя функции в языках C и C++ вложено в цепочку описателей, поэтому
        // извлекается отдельным спуском по этой цепочке.
        ("c" | "cpp", "function_definition") => c_func_name(node).map(|n| (KIND_FUNCTION, n)),
        ("c" | "cpp", "struct_specifier") if has_body() => pair(KIND_TYPE),
        ("cpp", "class_specifier") if has_body() => pair(KIND_CLASS),
        ("ruby", "method" | "singleton_method") => pair(KIND_METHOD),
        ("ruby", "class") => pair(KIND_CLASS),
        ("ruby", "module") => pair(KIND_MODULE),
        ("php", "function_definition") => pair(KIND_FUNCTION),
        ("php", "method_declaration") => pair(KIND_METHOD),
        ("php", "class_declaration") => pair(KIND_CLASS),
        ("php", "interface_declaration") => pair(KIND_INTERFACE),
        ("php", "trait_declaration") => pair(KIND_INTERFACE),
        ("scala", "function_definition") => pair(KIND_FUNCTION),
        ("scala", "class_definition") => pair(KIND_CLASS),
        ("scala", "object_definition") => pair(KIND_OBJECT),
        ("scala", "trait_definition") => pair(KIND_INTERFACE),
        ("kotlin", "function_declaration") => pair(KIND_FUNCTION),
        ("kotlin", "class_declaration") => pair(KIND_CLASS),
        ("kotlin", "object_declaration") => pair(KIND_OBJECT),
        ("swift", "function_declaration" | "init_declaration") => pair(KIND_FUNCTION),
        ("swift", "class_declaration") => pair(KIND_CLASS),
        ("swift", "protocol_declaration") => pair(KIND_INTERFACE),
        ("dart", "function_signature") => pair(KIND_FUNCTION),
        ("dart", "class_declaration") => pair(KIND_CLASS),
        ("dart", "mixin_declaration") => pair(KIND_TYPE),
        ("dart", "enum_declaration") => pair(KIND_ENUM),
        _ => None,
    }
}

/// Вид элемента обозначает тип данных, а не подпрограмму. Отношение наследования
/// осмысленно лишь для таких видов.
fn is_type_kind(kind: &str) -> bool {
    kind == KIND_TYPE
        || kind == KIND_CLASS
        || kind == KIND_INTERFACE
        || kind == KIND_ENUM
        || kind == KIND_OBJECT
}

/// Внешний узел объявления, от которого берутся сигнатура, номер строки и поиск
/// комментария документации.
///
/// В грамматике языка Go объявление типа состоит из узла `type_declaration` с ключевым
/// словом и вложенного узла `type_spec` с именем и телом. Комментарий документации по
/// соглашению языка располагается перед ключевым словом, а не перед именем, поэтому для
/// объявления типа берётся именно внешний узел; иначе сигнатура лишилась бы ключевого
/// слова, а комментарий не был бы найден. Для прочих языков внешним узлом является сам
/// узел объявления.
fn outer_node<'a>(lang: &str, node: &tree_sitter::Node<'a>) -> tree_sitter::Node<'a> {
    if lang == "go" && node.kind() == "type_spec" {
        if let Some(parent) = node.parent().filter(|p| p.kind() == "type_declaration") {
            return parent;
        }
    }
    *node
}

/// Имя функции в языках C и C++: спуск по цепочке описателей до идентификатора.
/// Повторяет разбор, применяемый при извлечении символов, поскольку без него имя
/// функции с указателем или квалификацией не определяется.
fn c_func_name<'a>(node: &tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let mut d = node.child_by_field_name("declarator")?;
    loop {
        match d.kind() {
            "identifier"
            | "field_identifier"
            | "qualified_identifier"
            | "operator_name"
            | "destructor_name" => return Some(d),
            "function_declarator"
            | "pointer_declarator"
            | "parenthesized_declarator"
            | "reference_declarator" => d = d.child_by_field_name("declarator")?,
            _ => return None,
        }
    }
}

/// Сигнатура объявления одной строкой.
///
/// Границей объявления служит начало тела: в языках с фигурными скобками оно совпадает
/// с открывающей фигурной скобкой, а в языках с блоком по отступу отсекает тело столь
/// же точно. Если тела у объявления нет, границей становится первая открывающая
/// фигурная скобка либо конец строки, смотря что встретится раньше. Определять границу
/// поиском фигурной скобки и при наличии тела нельзя: в языках семейства JavaScript
/// фигурная скобка встречается уже в списке параметров при их деструктурировании, и
/// сигнатура обрывалась бы на первом же параметре.
///
/// Пробельные последовательности схлопываются в одиночный пробел, поэтому объявление,
/// записанное в исходном тексте на нескольких строках, остаётся читаемым в таблице
/// документа. Длина ограничена величиной [`MAX_SIGNATURE_CHARS`].
fn signature_of(content: &str, node: &tree_sitter::Node) -> String {
    let start = node.start_byte();
    let raw: &str = match node.child_by_field_name("body") {
        Some(body) if body.start_byte() > start => content.get(start..body.start_byte()),
        _ => {
            let full = content.get(start..node.end_byte()).unwrap_or("");
            let cut = [full.find('{'), full.find('\n')]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(full.len());
            full.get(..cut)
        }
    }
    .unwrap_or("");

    let collapsed = raw.split_whitespace().collect::<Vec<&str>>().join(" ");
    // Завершающие знаки, отделяющие объявление от тела (двоеточие блока по отступу,
    // знак присваивания перед выражением-телом, открывающая скобка), к объявлению не
    // относятся и в документе выглядят обрывом строки.
    truncate_chars(
        collapsed.trim_end_matches([':', '=', '{', ' ']),
        MAX_SIGNATURE_CHARS,
    )
}

/// Усечь строку до заданного числа символов, обозначив усечение многоточием. Счёт
/// ведётся по символам, а не по байтам, чтобы усечение не разрубило многобайтовый
/// символ и не породило некорректную строку.
fn truncate_chars(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        return s.to_string();
    }
    let mut out: String = s.chars().take(limit).collect();
    out.push('…');
    out
}

/// Комментарий документации, относящийся к объявлению.
///
/// Просмотр идёт вверх от строки объявления и собирает строки вида `///` и `//!`,
/// блочный комментарий `/** ... */`, а для языков Python и Ruby строки, начинающиеся со
/// знака решётки. Для языка Go собирается обычный комментарий `//`, поскольку именно он
/// по соглашению самого языка и является комментарием документации, и его исключение
/// оставило бы весь код на этом языке без описаний. Строки атрибутов и аннотаций
/// (`#[...]` в языке Rust, `@...` в языках Java и Python, `[...]` в языке C#) не
/// прерывают просмотр и в описание не входят, так как они располагаются между
/// комментарием и объявлением. Первая пустая строка либо строка кода просмотр
/// прекращает: описанием считается только то, что записано непосредственно перед
/// объявлением.
///
/// Для языка Python дополнительно читается строка документации в тройных кавычках,
/// расположенная первой в теле объявления, если комментария перед объявлением нет.
///
/// Если ничего не найдено, возвращается отсутствие значения. Описание не сочиняется ни
/// при каких условиях: выдуманное назначение части программного обеспечения в документе
/// по стандарту является прямой дезинформацией читателя.
fn doc_of(lang: &str, lines: &[&str], decl_row: usize, body_row: Option<usize>) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut idx = decl_row;
    // Признак того, что найден конец блочного комментария и идёт поиск его начала.
    let mut in_block = false;
    while idx > 0 && parts.len() < MAX_DOC_LINES {
        idx -= 1;
        let t = lines.get(idx).copied().unwrap_or("").trim();
        if in_block {
            parts.push(strip_markers(t));
            if t.starts_with("/*") {
                break;
            }
            continue;
        }
        if t.is_empty() {
            break;
        }
        if is_attribute_line(t) {
            continue;
        }
        if t.ends_with("*/") {
            parts.push(strip_markers(t));
            // Однострочная запись `/** ... */` уже содержит и начало, и конец блока.
            if !t.starts_with("/*") {
                in_block = true;
            }
            continue;
        }
        if t.starts_with("///") || t.starts_with("//!") {
            parts.push(strip_markers(t));
            continue;
        }
        if lang == "go" && t.starts_with("//") {
            parts.push(strip_markers(t));
            continue;
        }
        // Знак «шебанг» в первой строке файла является указанием интерпретатора, а не
        // описанием, и в документ попасть не должен.
        if matches!(lang, "python" | "ruby") && t.starts_with('#') && !t.starts_with("#!") {
            parts.push(strip_markers(t));
            continue;
        }
        break;
    }

    parts.reverse();
    let joined = parts.join(" ");
    let text = joined.split_whitespace().collect::<Vec<&str>>().join(" ");
    if !text.is_empty() {
        return Some(truncate_chars(&text, MAX_DOC_CHARS));
    }
    match (lang, body_row) {
        ("python", Some(row)) => python_docstring(lines, row),
        _ => None,
    }
}

/// Строка является атрибутом либо аннотацией, а не кодом и не комментарием.
fn is_attribute_line(t: &str) -> bool {
    t.starts_with("#[") || t.starts_with('@') || (t.starts_with('[') && t.ends_with(']'))
}

/// Снять знаки разметки комментария, оставив обычный текст.
fn strip_markers(line: &str) -> String {
    let mut t = line.trim();
    if let Some(rest) = t.strip_suffix("*/") {
        t = rest.trim_end();
    }
    // Порядок перебора значим: более длинный знак разметки проверяется раньше своего
    // префикса, иначе `///` было бы снято как `//` и в тексте остался бы лишний знак.
    for marker in ["///", "//!", "/**", "/*", "//", "*", "#"] {
        if let Some(rest) = t.strip_prefix(marker) {
            t = rest.trim_start();
            break;
        }
    }
    t.trim().to_string()
}

/// Строка документации языка Python, расположенная первой в теле объявления.
/// Возвращает отсутствие значения, если первым в теле стоит не литерал в тройных
/// кавычках: сочинять описание по коду тела недопустимо.
fn python_docstring(lines: &[&str], from_row: usize) -> Option<String> {
    let mut i = from_row;
    while i < lines.len() && lines[i].trim().is_empty() {
        i += 1;
    }
    let first = lines.get(i)?.trim();
    // Литерал может быть записан как тройными двойными, так и тройными одинарными
    // кавычками; обе формы равноправны в языке.
    let (quote, head) = if let Some(rest) = first.strip_prefix("\"\"\"") {
        ("\"\"\"", rest)
    } else if let Some(rest) = first.strip_prefix("'''") {
        ("'''", rest)
    } else {
        return None;
    };

    let mut parts: Vec<String> = Vec::new();
    if let Some(end) = head.find(quote) {
        let text = head.get(..end).unwrap_or("").trim().to_string();
        return non_empty(text);
    }
    parts.push(head.trim().to_string());
    i += 1;
    let mut scanned = 0usize;
    while i < lines.len() && scanned < MAX_DOC_LINES {
        let t = lines[i].trim();
        if let Some(end) = t.find(quote) {
            parts.push(t.get(..end).unwrap_or("").trim().to_string());
            break;
        }
        parts.push(t.to_string());
        i += 1;
        scanned += 1;
    }
    let joined = parts.join(" ");
    let text = joined.split_whitespace().collect::<Vec<&str>>().join(" ");
    non_empty(text).map(|s| truncate_chars(&s, MAX_DOC_CHARS))
}

/// Непустая строка либо отсутствие значения. Пустой результат означает, что описания
/// нет, и такое положение обозначается именно отсутствием значения, а не пустой
/// строкой, которую читатель принял бы за пустое описание.
fn non_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Виды узлов дерева разбора, которыми грамматики выражают отношение наследования:
/// базовый класс, перечень реализуемых интерфейсов, список базовых типов. Сопоставление
/// ведётся по вхождению подстроки в имя узла, поскольку каждая грамматика именует такой
/// узел по-своему (`superclass` и `super_interfaces` в языке Java, `base_list` в языке
/// C#, `class_heritage` и `extends_type_clause` в языке TypeScript, `base_clause` и
/// `class_interface_clause` в языке PHP, `delegation_specifier` в языке Kotlin,
/// `inheritance_specifier` в языке Swift), а перечислять их поимённо для пятнадцати
/// языков означало бы завести таблицу, устаревающую с первым обновлением любой
/// грамматики.
const HERITAGE_KINDS: &[&str] = &[
    "super",
    "extends",
    "implements",
    "heritage",
    "base_list",
    "base_clause",
    "interface_clause",
    "inheritance",
    "delegation_specifier",
];

/// Виды узлов, текст которых является готовым именем типа и внутрь которых спускаться
/// не следует: квалифицированное имя должно попасть в описание целиком, а не распасться
/// на отдельные составляющие.
const TYPE_NAME_KINDS: &[&str] = &[
    "type_identifier",
    "identifier",
    "simple_identifier",
    "constant",
    "scoped_type_identifier",
    "nested_type_identifier",
    "qualified_type",
    "qualified_name",
    "dotted_name",
    "attribute",
];

/// Отношение наследования для объявления: базовые типы и реализуемые интерфейсы.
///
/// Берётся только то, что даёт дерево разбора. Ничего не достраивается: если в дереве
/// отношения нет, значит в исходном тексте его нет либо грамматика его не выражает, и в
/// обоих случаях выдумывать связь недопустимо.
fn extends_of(lang: &str, node: &tree_sitter::Node, bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match lang {
        // В языке Python базовые классы записываются в скобках после имени класса и
        // представлены полем `superclasses` со списком аргументов.
        "python" => {
            if let Some(list) = node.child_by_field_name("superclasses") {
                collect_type_names(&list, bytes, &mut out);
            }
        }
        // В языке Go отношение выражается встроенными полями структуры: полем без
        // имени, у которого задан только тип.
        "go" => collect_go_embedded(node, bytes, &mut out),
        _ => {
            // Поля с общепринятыми именами проверяются первыми, поскольку они дают
            // однозначный ответ там, где грамматика их объявляет.
            for field in ["superclass", "interfaces", "supertypes"] {
                if let Some(n) = node.child_by_field_name(field) {
                    collect_type_names(&n, bytes, &mut out);
                }
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                let kind = child.kind();
                if HERITAGE_KINDS.iter().any(|k| kind.contains(k)) {
                    collect_type_names(&child, bytes, &mut out);
                }
            }
        }
    }
    dedup_keep_order(out)
}

/// Встроенные поля структуры языка Go: поле, у которого задан тип, но не задано имя,
/// означает включение другого типа в состав данной структуры.
fn collect_go_embedded(node: &tree_sitter::Node, bytes: &[u8], out: &mut Vec<String>) {
    let Some(ty) = node.child_by_field_name("type") else {
        return;
    };
    if ty.kind() != "struct_type" {
        return;
    }
    let mut list_cursor = ty.walk();
    for list in ty.named_children(&mut list_cursor) {
        if list.kind() != "field_declaration_list" {
            continue;
        }
        let mut field_cursor = list.walk();
        for field in list.named_children(&mut field_cursor) {
            if field.kind() != "field_declaration" || field.child_by_field_name("name").is_some() {
                continue;
            }
            if let Some(t) = field.child_by_field_name("type") {
                if let Ok(text) = t.utf8_text(bytes) {
                    let name = text.trim();
                    if !name.is_empty() {
                        out.push(name.to_string());
                    }
                }
            }
        }
    }
}

/// Собрать имена типов из поддерева, выражающего отношение наследования.
///
/// Обход выполняется явным стеком, дети укладываются в обратном порядке, поэтому имена
/// собираются в порядке их записи в исходном тексте. Списки параметров и аргументов
/// обобщённых типов пропускаются: в отношении наследования существен базовый тип, а его
/// параметризация лишь удлиняет строку документа. Именованный аргумент вызова
/// пропускается, поскольку в языке Python указание метакласса записывается в том же
/// списке, что и базовые классы, но базовым классом не является.
fn collect_type_names(root: &tree_sitter::Node, bytes: &[u8], out: &mut Vec<String>) {
    let mut stack = vec![*root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if kind.contains("type_arguments")
            || kind.contains("type_argument_list")
            || kind.contains("type_parameters")
            || kind == "keyword_argument"
            || kind == "comment"
        {
            continue;
        }
        if node.id() != root.id() && TYPE_NAME_KINDS.contains(&kind) {
            if let Ok(text) = node.utf8_text(bytes) {
                let name = text.trim();
                if !name.is_empty() {
                    out.push(name.to_string());
                }
            }
            continue;
        }
        // Дочерние узлы укладываются в стек в обратном порядке, поэтому извлекаются из
        // него слева направо и имена собираются в порядке их записи в исходном тексте.
        for i in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(i) {
                stack.push(child);
            }
        }
    }
}

/// Убрать повторы, сохранив порядок первого появления. Повтор возникает, когда один и
/// тот же тип извлечён и через поле объявления, и через просмотр дочерних узлов.
fn dedup_keep_order(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

/// Признак доступности элемента извне своей части программного обеспечения.
///
/// Правила совпадают с применяемыми при извлечении символов, однако проверяются по
/// нормализованной сигнатуре, а не по одной физической строке исходного текста: при
/// объявлении, записанном на нескольких строках, модификатор доступа может оказаться не
/// на той строке, где записано имя, и проверка по строке дала бы неверный ответ.
fn is_exported(lang: &str, signature: &str, name: &str) -> bool {
    match lang {
        "go" => name.chars().next().is_some_and(|c| c.is_uppercase()),
        "python" | "dart" => !name.starts_with('_'),
        "rust" => signature.contains("pub "),
        "typescript" | "javascript" => signature.contains("export "),
        "java" | "csharp" => signature.contains("public "),
        "kotlin" => !signature.contains("private ") && !signature.contains("internal "),
        "swift" => signature.contains("public ") || signature.contains("open "),
        "c" | "cpp" => !signature.contains("static "),
        "php" | "scala" => !signature.contains("private ") && !signature.contains("protected "),
        // В языке Ruby модификатор доступа записывается отдельной строкой и в самом
        // объявлении не виден, поэтому элемент считается доступным.
        "ruby" => true,
        _ => true,
    }
}

/// Отображение «имя типа, перечень реализованных им интерфейсов» для языка Rust.
///
/// Отношение реализации записывается блоком `impl Trait for Type`, то есть отдельно от
/// объявления самого типа, поэтому собирается предварительным проходом по всему дереву
/// файла. Блоки собственных методов (`impl Type`, без указания интерфейса) отношением
/// наследования не являются и пропускаются.
fn rust_impl_map(root: &tree_sitter::Node, bytes: &[u8]) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut stack = vec![*root];
    while let Some(node) = stack.pop() {
        if node.kind() == "impl_item" {
            if let (Some(tr), Some(ty)) = (
                node.child_by_field_name("trait"),
                node.child_by_field_name("type"),
            ) {
                let mut trait_names: Vec<String> = Vec::new();
                collect_type_names_inclusive(&tr, bytes, &mut trait_names);
                let mut type_names: Vec<String> = Vec::new();
                collect_type_names_inclusive(&ty, bytes, &mut type_names);
                if let (Some(trait_name), Some(type_name)) =
                    (trait_names.first(), type_names.first())
                {
                    let entry = map.entry(type_name.clone()).or_default();
                    if !entry.contains(trait_name) {
                        entry.push(trait_name.clone());
                    }
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    for names in map.values_mut() {
        names.sort();
    }
    map
}

/// Как [`collect_type_names`], но узел-корень тоже рассматривается как возможное имя
/// типа. Это требуется там, где корнем передаётся уже сам тип (поля `trait` и `type`
/// блока реализации в языке Rust), а не охватывающее его предложение наследования.
fn collect_type_names_inclusive(root: &tree_sitter::Node, bytes: &[u8], out: &mut Vec<String>) {
    if TYPE_NAME_KINDS.contains(&root.kind()) {
        if let Ok(text) = root.utf8_text(bytes) {
            let name = text.trim();
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
        return;
    }
    collect_type_names(root, bytes, out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Счётчик для образования неповторяющихся имён временных каталогов: тесты
    /// выполняются параллельно, и общий каталог приводил бы к взаимному влиянию.
    static СЧЁТЧИК: AtomicU32 = AtomicU32::new(0);

    /// Создать пустой временный каталог под файловую фикстуру.
    fn временный_каталог() -> PathBuf {
        let n = СЧЁТЧИК.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ailc-apidoc-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn записать(dir: &Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }

    fn извлечь(dir: &Path) -> Vec<ApiItem> {
        ApiDoc::extract(&Ctx::new(dir), &RunInput::default()).unwrap()
    }

    fn найти<'a>(items: &'a [ApiItem], name: &str) -> &'a ApiItem {
        items
            .iter()
            .find(|i| i.name == name)
            .unwrap_or_else(|| panic!("элемент «{name}» не найден в выдаче"))
    }

    /// Сигнатура обязана содержать список параметров и возвращаемый тип: раздел
    /// документа о функциональных характеристиках описывает функцию по тому, что она
    /// принимает и что возвращает, и одного имени для этого недостаточно.
    #[test]
    fn сигнатура_извлекается_вместе_с_параметрами() {
        let dir = временный_каталог();
        записать(
            &dir,
            "src/lib.rs",
            "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
        );
        let items = извлечь(&dir);
        let item = найти(&items, "add");
        assert_eq!(item.kind, "функция");
        assert!(
            item.signature.contains("a: i32") && item.signature.contains("b: i32"),
            "список параметров обязан войти в сигнатуру: «{}»",
            item.signature
        );
        assert!(
            item.signature.contains("-> i32"),
            "возвращаемый тип обязан войти в сигнатуру: «{}»",
            item.signature
        );
        assert!(
            !item.signature.contains('{'),
            "тело функции в сигнатуру входить не должно: «{}»",
            item.signature
        );
        assert!(item.exported, "функция объявлена доступной извне");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Комментарий документации, записанный непосредственно перед объявлением, обязан
    /// попасть в описание и лишиться знаков разметки комментария, поскольку в документе
    /// приводится обычный текст, а не фрагмент исходного текста.
    #[test]
    fn комментарий_документации_над_функцией_попадает_в_поле_doc() {
        let dir = временный_каталог();
        записать(
            &dir,
            "src/lib.rs",
            "/// Сложить два числа и вернуть сумму.\n\
             /// Переполнение не проверяется.\n\
             #[inline]\n\
             pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
        );
        let items = извлечь(&dir);
        let doc = найти(&items, "add")
            .doc
            .clone()
            .expect("комментарий документации обязан быть извлечён");
        assert_eq!(
            doc, "Сложить два числа и вернуть сумму. Переполнение не проверяется.",
            "строки склеиваются в связный текст, знаки разметки снимаются"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Строка документации языка Python, записанная первой в теле объявления, также
    /// является комментарием документации и обязана извлекаться.
    #[test]
    fn строка_документации_python_извлекается_из_тела() {
        let dir = временный_каталог();
        записать(
            &dir,
            "src/service.py",
            "def compute(value):\n    \"\"\"Вычислить показатель по значению.\"\"\"\n    return value\n",
        );
        let items = извлечь(&dir);
        assert_eq!(
            найти(&items, "compute").doc.as_deref(),
            Some("Вычислить показатель по значению.")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Отсутствие комментария обязано выражаться отсутствием значения. Сочинённое
    /// описание в документе по стандарту неотличимо от достоверного и потому опаснее
    /// пропуска.
    #[test]
    fn функция_без_комментария_даёт_none() {
        let dir = временный_каталог();
        записать(
            &dir,
            "src/lib.rs",
            "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
        );
        let items = извлечь(&dir);
        assert!(
            найти(&items, "add").doc.is_none(),
            "описание не сочиняется при отсутствии комментария"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Отношение наследования обязано извлекаться из дерева разбора. Проверяются языки
    /// Python (базовые классы в скобках), Java (ключевые слова extends и implements) и
    /// Rust (блок реализации интерфейса для типа).
    #[test]
    fn отношение_наследования_извлекается() {
        let dir = временный_каталог();
        записать(
            &dir,
            "src/model.py",
            "class Derived(Base, Mixin):\n    pass\n",
        );
        записать(
            &dir,
            "src/Child.java",
            "public class Child extends Base implements Runnable {\n    public void run() {}\n}\n",
        );
        записать(
            &dir,
            "src/lib.rs",
            "pub struct Report;\n\nimpl Display for Report {\n    fn show(&self) {}\n}\n",
        );
        let items = извлечь(&dir);

        let питон = &найти(&items, "Derived").extends;
        assert!(
            питон.contains(&"Base".to_string()) && питон.contains(&"Mixin".to_string()),
            "базовые классы языка Python обязаны извлекаться: {питон:?}"
        );

        let ява = &найти(&items, "Child").extends;
        assert!(
            ява.contains(&"Base".to_string()) && ява.contains(&"Runnable".to_string()),
            "базовый класс и реализуемый интерфейс языка Java обязаны извлекаться: {ява:?}"
        );

        assert_eq!(
            найти(&items, "Report").extends,
            vec!["Display".to_string()],
            "блок реализации интерфейса относится к типу, для которого он записан"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Тестовые файлы в выдачу не попадают: документ описывает продукт, а не средства
    /// его проверки.
    #[test]
    fn тестовые_файлы_не_попадают_в_выдачу() {
        let dir = временный_каталог();
        записать(&dir, "src/lib.rs", "pub fn production() -> u8 { 1 }\n");
        записать(&dir, "src/handler_test.go", "func TestHandler() {}\n");
        записать(
            &dir,
            "tests/integration.rs",
            "pub fn checked() -> u8 { 2 }\n",
        );
        записать(
            &dir,
            "src/__tests__/helper.py",
            "def prepare():\n    pass\n",
        );
        let items = извлечь(&dir);
        assert!(
            items.iter().any(|i| i.name == "production"),
            "прикладной элемент обязан остаться в выдаче"
        );
        assert!(
            items
                .iter()
                .all(|i| !i.file.contains("test") && !i.file.contains("__tests__")),
            "ни один тестовый файл не попал в выдачу: {:?}",
            items.iter().map(|i| &i.file).collect::<Vec<_>>()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Выдача обязана быть детерминированной: два прогона на неизменном дереве дают
    /// совпадающий результат в совпадающем порядке. Без этого свойства документ,
    /// перегенерированный без изменения кода, отличался бы от предыдущего, и
    /// сопоставление редакций стало бы невозможным.
    #[test]
    fn выдача_детерминирована() {
        let dir = временный_каталог();
        записать(&dir, "src/b.rs", "pub fn beta() {}\npub fn alpha() {}\n");
        записать(&dir, "src/a.rs", "pub fn gamma() {}\n");
        записать(&dir, "src/service.py", "class Service:\n    pass\n");

        let ключи = |items: &[ApiItem]| -> Vec<String> {
            items
                .iter()
                .map(|i| format!("{}:{}:{}", i.file, i.line, i.name))
                .collect()
        };
        let первый = ключи(&извлечь(&dir));
        let второй = ключи(&извлечь(&dir));
        assert_eq!(первый, второй, "повторный прогон даёт ту же выдачу");
        let mut упорядоченный = первый.clone();
        упорядоченный.sort();
        assert_eq!(
            первый, упорядоченный,
            "выдача упорядочена по файлу, затем по строке, затем по имени"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
