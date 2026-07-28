//! Извлечение интерфейса командной строки и конфигурационных параметров проекта.
//!
//! Это НЕ находки (не проблемы), а ФАКТЫ о продукте, требуемые документами по
//! государственным стандартам. Руководство пользователя обязано содержать раздел
//! «Описание операций», то есть перечень команд и ключей, которыми человек управляет
//! программой; описание видов обеспечения и условий эксплуатации обязано содержать
//! перечень настраиваемых параметров. Модель проекта до сих пор знала маршруты
//! протокола передачи гипертекста, переменные окружения, внешние сервисы и модели
//! данных (см. модуль `surface`), но не знала ни командного интерфейса, ни состава
//! конфигурации, поэтому соответствующие разделы документов приходилось заполнять
//! домыслом вместо факта.
//!
//! Устройство модуля намеренно повторяет модуль `surface`: таблицы регулярных
//! выражений, собираемые один раз через `OnceLock`, отсев тестовых файлов, маскирование
//! комментариев перед сопоставлением, гашение встроенных тестовых модулей языка Rust и
//! детерминированный порядок выдачи. Единообразие важно потому, что оба модуля питают
//! одни и те же генераторы документов, и различие в поведении выглядело бы для читателя
//! документа необъяснимым.

use super::scan::SOURCE_CODE;
use super::walk::{blank_rust_test_modules, ext_of, is_test_path, walk};
use ailc_contracts::{Ctx, Result, RunInput};
use regex::Regex;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::OnceLock;

/// Один извлечённый факт командного интерфейса или конфигурации: его значение и место,
/// где он объявлен, чтобы из документа можно было перейти к исходному тексту.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliItem {
    pub value: String,
    pub file: String,
    pub line: u32,
}

/// Командный интерфейс проекта и состав его конфигурации.
#[derive(Debug, Default)]
pub struct CliSurface {
    /// Подкоманды приложения (значение элемента есть имя подкоманды).
    pub commands: Vec<CliItem>,
    /// Ключи и параметры командной строки (значение элемента есть длинное написание
    /// ключа с двумя дефисами).
    pub flags: Vec<CliItem>,
    /// Конфигурационные параметры, объявленные в файлах настроек (значение элемента
    /// есть ИМЯ параметра, но никогда не его значение).
    pub config: Vec<CliItem>,
}

impl CliSurface {
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty() && self.flags.is_empty() && self.config.is_empty()
    }
}

// ───────────────────────── Маскирование комментариев ─────────────────────────

/// Синтаксис комментариев и строковых литералов, достаточный для языков, на которых
/// пишутся программы с командным интерфейсом.
///
/// Модуль `surface` содержит более полный маскировщик, однако он объявлен там приватным,
/// а расширение его области видимости означало бы правку чужого модуля, что настоящей
/// задачей не предусмотрено. Кроме того, здесь достаточно упрощённого варианта: набор
/// языков, в которых встречаются рассматриваемые библиотеки построения командного
/// интерфейса, заметно уже общего набора языков, поддерживаемых модулем `surface`.
/// Поэтому ниже приведён минимальный самостоятельный вариант, повторяющий подход
/// оригинала: содержимое комментариев заменяется пробелами, строковые литералы
/// сохраняются, нумерация строк не смещается.
struct CommentStyle {
    /// Строчный комментарий `//` и блочный `/* … */`.
    slashes: bool,
    /// Строчный комментарий `#` до конца строки.
    hash: bool,
    /// Одиночная кавычка открывает строку. Для языков Rust и Go признак выключен
    /// намеренно: там одиночная кавычка обозначает метку времени жизни и руническую
    /// константу, и принятие её за строку проглотило бы остаток строки вместе с фактами.
    single_quote: bool,
    /// Обратная кавычка открывает строку (шаблонная строка языка JavaScript, сырая
    /// строка языка Go).
    backtick: bool,
    /// Тройные кавычки языка Python как документирующая строка.
    py_triple: bool,
}

fn comment_style(ext: &str) -> CommentStyle {
    CommentStyle {
        slashes: matches!(
            ext,
            "rs" | "go"
                | "js"
                | "jsx"
                | "mjs"
                | "cjs"
                | "ts"
                | "tsx"
                | "java"
                | "kt"
                | "kts"
                | "cs"
                | "swift"
                | "dart"
                | "scala"
                | "php"
        ),
        hash: matches!(
            ext,
            "py" | "rb" | "sh" | "bash" | "zsh" | "yaml" | "yml" | "toml" | "properties" | "php"
        ),
        single_quote: matches!(
            ext,
            "py" | "rb"
                | "js"
                | "jsx"
                | "mjs"
                | "cjs"
                | "ts"
                | "tsx"
                | "php"
                | "sh"
                | "bash"
                | "zsh"
                | "dart"
                | "yaml"
                | "yml"
                | "toml"
                | "properties"
        ),
        backtick: matches!(ext, "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "go"),
        py_triple: ext == "py",
    }
}

/// Заменить содержимое комментариев пробелами, СОХРАНИВ строковые литералы.
///
/// Строки сохраняются намеренно: имя подкоманды и написание ключа живут именно в
/// строковом литерале, поэтому их маскирование уничтожило бы сам предмет извлечения.
/// Комментарии же являются массовым источником ложных фактов, поскольку в них живут
/// примеры употребления, синтаксически неотличимые от настоящего объявления команды.
/// Именно так в документы попадали несуществующие возможности продукта.
///
/// Отслеживание строк обязательно и по обратной причине: последовательность `//` внутри
/// адреса вида `https://host` не должна приниматься за начало комментария.
///
/// Нумерация строк сохраняется: содержимое заменяется пробелами, переводы строк остаются
/// на местах, поэтому указанная в документе строка соответствует исходному тексту.
fn mask_comments(ext: &str, content: &str) -> String {
    let st = comment_style(ext);
    if !st.slashes && !st.hash {
        // Языку нечего маскировать (например форматы обмена данными без комментариев).
        return content.to_string();
    }
    let cs: Vec<char> = content.chars().collect();
    let mut out = String::with_capacity(content.len());
    let mut i = 0usize;
    while i < cs.len() {
        let c = cs[i];

        // Документирующая строка языка Python маскируется как комментарий: на практике
        // это проза с примерами употребления, а не объявление командного интерфейса.
        if st.py_triple
            && (c == '"' || c == '\'')
            && cs.get(i + 1) == Some(&c)
            && cs.get(i + 2) == Some(&c)
        {
            out.push_str("   ");
            i += 3;
            while i < cs.len() {
                if cs[i] == c && cs.get(i + 1) == Some(&c) && cs.get(i + 2) == Some(&c) {
                    out.push_str("   ");
                    i += 3;
                    break;
                }
                out.push(if cs[i] == '\n' { '\n' } else { ' ' });
                i += 1;
            }
            continue;
        }

        // Строчный комментарий: остаток строки гасится, перевод строки сохраняется.
        if (st.slashes && c == '/' && cs.get(i + 1) == Some(&'/')) || (st.hash && c == '#') {
            while i < cs.len() && cs[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }

        // Блочный комментарий. Незакрытый блок поглощает остаток файла, что консервативно
        // и безопасно: лучше недосчитаться факта, чем приписать продукту вымышленный.
        if st.slashes && c == '/' && cs.get(i + 1) == Some(&'*') {
            out.push_str("  ");
            i += 2;
            while i < cs.len() {
                if cs[i] == '*' && cs.get(i + 1) == Some(&'/') {
                    out.push_str("  ");
                    i += 2;
                    break;
                }
                out.push(if cs[i] == '\n' { '\n' } else { ' ' });
                i += 1;
            }
            continue;
        }

        // Строковый литерал: содержимое сохраняется дословно.
        if c == '"' || (st.single_quote && c == '\'') || (st.backtick && c == '`') {
            let delim = c;
            out.push(c);
            i += 1;
            while i < cs.len() {
                let ch = cs[i];
                // Обратная косая черта уводит следующий символ из-под разбора.
                if ch == '\\' && delim != '`' {
                    out.push(ch);
                    i += 1;
                    if let Some(next) = cs.get(i) {
                        out.push(*next);
                        i += 1;
                    }
                    continue;
                }
                out.push(ch);
                i += 1;
                if ch == delim {
                    break;
                }
                // Незакрытая однострочная строка сбрасывается на переводе строки, поэтому
                // ошибка разбора одной строки не распространяется на остаток файла.
                if ch == '\n' && delim != '`' {
                    break;
                }
            }
            continue;
        }

        out.push(c);
        i += 1;
    }
    out
}

// ───────────────────────── Таблица правил командного интерфейса ─────────────────────────

/// Какого рода факт даёт правило.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Подкоманда приложения.
    Command,
    /// Ключ (параметр) командной строки.
    Flag,
}

/// Правило распознавания элемента командного интерфейса. Значение всегда берётся из
/// первой группы захвата, что избавляет таблицу от лишнего поля и делает правила
/// единообразными.
struct CliRe {
    re: Regex,
    kind: Kind,
    /// Расширения файлов, к которым применимо правило. Ограничение обязательно: одна и
    /// та же последовательность символов в другом языке означает совсем иное, и без
    /// привязки к языку таблица давала бы вымышленные команды.
    exts: &'static [&'static str],
}

fn cli_res() -> &'static Vec<CliRe> {
    static R: OnceLock<Vec<CliRe>> = OnceLock::new();
    R.get_or_init(|| {
        // Невалидный встроенный паттерн исключает СВОЁ правило и не завершает процесс:
        // сервер живёт одним процессом на весь сеанс работы среды разработки, поэтому цена
        // аварийного завершения несоизмерима с ценой пропуска одного правила (см. модуль
        // `crate::re`). Полнота набора закреплена тестом
        // `таблица_встроенных_паттернов_собирается_целиком`.
        let mk = |p: &str, kind: Kind, exts: &'static [&'static str]| {
            crate::re::compile(p).map(|re| CliRe { re, kind, exts })
        };
        const RS: &[&str] = &["rs"];
        const PY: &[&str] = &["py"];
        const GO: &[&str] = &["go"];
        const JS: &[&str] = &["js", "jsx", "mjs", "cjs", "ts", "tsx"];
        const JVM: &[&str] = &["java", "kt", "kts"];
        vec![
            // ── Rust, библиотека clap, строительный вид ──
            // Подкоманда объявляется вложенным построителем: .subcommand(Command::new("имя")).
            mk(
                r#"\.subcommand\s*\(\s*(?:clap::)?Command::new\s*\(\s*"([^"]+)""#,
                Kind::Command,
                RS,
            ),
            // Историческое написание той же библиотеки: SubCommand::with_name("имя").
            mk(
                r#"SubCommand::with_name\s*\(\s*"([^"]+)""#,
                Kind::Command,
                RS,
            ),
            // Ключ строительного вида: .arg(Arg::new("имя")).long("имя").
            mk(r#"\.long\s*\(\s*"([^"]+)""#, Kind::Flag, RS),
            // ── Rust, библиотека clap, объявительный вид ──
            // Имя команды задаётся атрибутом: #[command(name = "имя")].
            mk(
                r#"#\[(?:clap::)?command\s*\([^)]*?name\s*=\s*"([^"]+)""#,
                Kind::Command,
                RS,
            ),
            // Длинное написание ключа задаётся атрибутом: #[arg(long = "имя", short = 'и')].
            mk(
                r#"#\[(?:arg|clap)\s*\([^)]*?\blong\s*=\s*"([^"]+)""#,
                Kind::Flag,
                RS,
            ),
            // ── Python, модуль argparse ──
            // Подкоманда: subparsers.add_parser("имя").
            mk(r#"add_parser\s*\(\s*["']([^"']+)["']"#, Kind::Command, PY),
            // Ключ: parser.add_argument("-и", "--имя"). Длинное написание может стоять не
            // первым доводом, поэтому оно ищется в пределах вызова до закрывающей скобки.
            mk(
                r#"add_argument\s*\([^)]*?["'](--[A-Za-z][^"']*)["']"#,
                Kind::Flag,
                PY,
            ),
            // ── Python, библиотека click ──
            // Команда и группа команд: @click.command("имя") либо @click.group("имя").
            mk(
                r#"@click\.(?:command|group)\s*\(\s*["']([^"'\s]+)["']"#,
                Kind::Command,
                PY,
            ),
            // Ключ: @click.option("--имя", "-и", help="…").
            mk(
                r#"@click\.(?:option|argument)\s*\([^)]*?["'](--[A-Za-z][^"']*)["']"#,
                Kind::Flag,
                PY,
            ),
            // ── Go, библиотека cobra ──
            // Команда объявляется полем Use структуры &cobra.Command{Use: "имя [ключи]"};
            // поле нередко стоит на отдельной строке, поэтому правило построчное.
            mk(r#"^\s*Use:\s*"([^"]+)""#, Kind::Command, GO),
            // Ключ с привязкой к переменной: Flags().StringVar(&имяПеременной, "имя", …)
            // либо PersistentFlags().BoolVarP(&…, "имя", "и", …).
            mk(
                r#"(?:Persistent)?Flags\(\)\.\w+VarP?\(\s*[^,]+,\s*"([A-Za-z][^"]*)""#,
                Kind::Flag,
                GO,
            ),
            // Ключ с возвратом значения: Flags().String("имя", значение, "пояснение").
            mk(
                r#"(?:Persistent)?Flags\(\)\.[A-Z]\w*P?\(\s*"([A-Za-z][^"]*)""#,
                Kind::Flag,
                GO,
            ),
            // ── Node.js, библиотеки commander и yargs ──
            // Команда: .command("имя <довод>").
            mk(r#"\.command\s*\(\s*["'`]([^"'`]+)["'`]"#, Kind::Command, JS),
            // Ключ: .option("-и, --имя <значение>", "пояснение").
            mk(
                r#"\.option\s*\(\s*["'`][^"'`]*?(--[A-Za-z][\w.-]*)"#,
                Kind::Flag,
                JS,
            ),
            // ── Java и Kotlin, библиотека picocli ──
            // Команда: @Command(name = "имя", description = "…").
            mk(
                r#"@Command\s*\([^)]*?name\s*=\s*"([^"]+)""#,
                Kind::Command,
                JVM,
            ),
            // Ключ: @Option(names = {"-и", "--имя"}).
            mk(r#"@Option\s*\([^)]*?"(--[A-Za-z][^"]*)""#, Kind::Flag, JVM),
        ]
        .into_iter()
        .flatten()
        .collect()
    })
}

/// Привести распознанное имя подкоманды к каноническому виду либо отвергнуть его.
///
/// Библиотеки допускают запись имени вместе с описанием доводов (например `add [ключи]`
/// в поле Use библиотеки cobra либо `serve <порт>` в библиотеке yargs), поэтому берётся
/// первое слово. Отвергается всё, что заведомо не является именем команды: пустая строка,
/// написание, начинающееся с дефиса (это ключ, а не команда), а также строки с символами
/// пути и подстановки, которые обыкновенно означают шаблон, а не имя.
fn normalize_command(raw: &str) -> Option<String> {
    let first = raw.split_whitespace().next()?;
    if first.is_empty() || first.starts_with('-') {
        return None;
    }
    let head = first.chars().next()?;
    if !(head.is_alphanumeric() || head == '_') {
        return None;
    }
    if first
        .chars()
        .any(|c| matches!(c, '/' | '\\' | '{' | '}' | '$' | '%' | '<' | '>'))
    {
        return None;
    }
    Some(first.chars().take(80).collect())
}

/// Привести распознанный ключ к длинному написанию с двумя дефисами либо отвергнуть его.
///
/// На вход поступают три разные записи: полное длинное написание (`--имя`), перечисление
/// написаний одной строкой (`-и, --имя <значение>`) и голое имя без дефисов, как его
/// задают библиотеки clap и cobra. Первые две приводятся к длинному написанию отсечением
/// всего, что следует за именем, третья дополняется двумя дефисами. Одиночное короткое
/// написание (`-и`) отвергается: раздел «Описание операций» перечисляет ключи по их
/// длинному, то есть самодокументирующему написанию.
fn normalize_flag(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let body = match raw.find("--") {
        Some(p) => &raw[p + 2..],
        None if raw.starts_with('-') => return None,
        None => raw,
    };
    let name: String = body
        .chars()
        .take_while(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(80)
        .collect();
    let head = name.chars().next()?;
    if !(head.is_alphanumeric() || head == '_') {
        return None;
    }
    Some(format!("--{name}"))
}

// ───────────────────────── Конфигурационные параметры ─────────────────────────

/// Формат файла настроек. Разбор ведётся по формату, а не по расширению, поскольку одно
/// и то же расширение (например `.yml`) встречается у файлов разных экосистем.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConfigFormat {
    Yaml,
    Toml,
    Json,
    /// Формат «имя равно значение»: файл `application.properties` и образец окружения
    /// `.env.example`.
    Properties,
}

/// Имена файлов настроек, которые просматриваются в корне проекта и в каталоге `config`.
/// Перечень закрытый и намеренно короткий: подстановка по образцу имени приводила бы к
/// разбору произвольных файлов данных, чьи ключи конфигурационными параметрами не
/// являются.
const CONFIG_FILES: &[&str] = &[
    "config.yaml",
    "config.yml",
    "config.toml",
    "config.json",
    "settings.yaml",
    "settings.toml",
    "application.properties",
    "application.yml",
    "appsettings.json",
    ".env.example",
];

fn config_format(name: &str) -> Option<ConfigFormat> {
    match name.to_ascii_lowercase().as_str() {
        "config.yaml" | "config.yml" | "settings.yaml" | "application.yml" => {
            Some(ConfigFormat::Yaml)
        }
        "config.toml" | "settings.toml" => Some(ConfigFormat::Toml),
        "config.json" | "appsettings.json" => Some(ConfigFormat::Json),
        "application.properties" | ".env.example" => Some(ConfigFormat::Properties),
        _ => None,
    }
}

fn yaml_key_re() -> Option<&'static Regex> {
    static R: OnceLock<Option<Regex>> = OnceLock::new();
    R.get_or_init(|| crate::re::compile(r"^([A-Za-z_][A-Za-z0-9_.-]*)\s*:"))
        .as_ref()
}

fn toml_key_re() -> Option<&'static Regex> {
    static R: OnceLock<Option<Regex>> = OnceLock::new();
    R.get_or_init(|| crate::re::compile(r"^([A-Za-z_][A-Za-z0-9_.-]*)\s*="))
        .as_ref()
}

fn toml_section_re() -> Option<&'static Regex> {
    static R: OnceLock<Option<Regex>> = OnceLock::new();
    R.get_or_init(|| crate::re::compile(r"^\[\[?\s*([A-Za-z_][A-Za-z0-9_.-]*)"))
        .as_ref()
}

fn prop_key_re() -> Option<&'static Regex> {
    static R: OnceLock<Option<Regex>> = OnceLock::new();
    R.get_or_init(|| crate::re::compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*[=:]"))
        .as_ref()
}

/// Имена ключей ВЕРХНЕГО уровня файла обмена данными в формате JSON вместе с номером
/// строки, на которой они объявлены.
///
/// Разбор ведётся посимвольно с учётом глубины вложенности и строковых литералов, потому
/// что построчное сопоставление не отличило бы ключ верхнего уровня от одноимённого ключа
/// вложенного объекта, а перечень параметров, в котором вложенное выдано за верхнее,
/// вводит читателя документа в заблуждение.
fn json_top_keys(content: &str) -> Vec<(String, u32)> {
    let cs: Vec<char> = content.chars().collect();
    let mut out: Vec<(String, u32)> = Vec::new();
    let mut depth: i32 = 0;
    let mut line: u32 = 1;
    let mut i = 0usize;
    while i < cs.len() {
        match cs[i] {
            '\n' => {
                line += 1;
                i += 1;
            }
            '{' | '[' => {
                depth += 1;
                i += 1;
            }
            '}' | ']' => {
                depth -= 1;
                i += 1;
            }
            '"' => {
                let start_line = line;
                let mut buf = String::new();
                i += 1;
                while i < cs.len() {
                    let ch = cs[i];
                    if ch == '\\' {
                        if let Some(next) = cs.get(i + 1) {
                            buf.push(*next);
                        }
                        i += 2;
                        continue;
                    }
                    if ch == '"' {
                        i += 1;
                        break;
                    }
                    if ch == '\n' {
                        line += 1;
                    }
                    buf.push(ch);
                    i += 1;
                }
                // Ключом строка является лишь тогда, когда за нею следует двоеточие;
                // иначе это значение, которое в выдачу не попадает.
                let mut j = i;
                while j < cs.len() && cs[j].is_whitespace() {
                    j += 1;
                }
                if depth == 1 && cs.get(j) == Some(&':') && !buf.is_empty() {
                    out.push((buf, start_line));
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// Имена конфигурационных параметров вместе с номерами строк.
///
/// Извлекаются ИСКЛЮЧИТЕЛЬНО имена параметров, но никогда их значения. Соображение здесь
/// не стилистическое, а связанное с защитой сведений: значением параметра сплошь и рядом
/// оказывается пароль базы данных, ключ доступа к платёжной системе или иной секрет, а
/// извлечённые факты попадают в порождаемые документы, которые хранятся в хранилище
/// исходного текста и передаются заказчику. Попадание значения в такой документ было бы
/// утечкой, притом утечкой тем более опасной, что незаметной для автора. Имя параметра,
/// напротив, секретом не является и как раз и требуется разделами о видах обеспечения и
/// об условиях эксплуатации.
///
/// Для вложенных структур достаточно первого уровня: документ описывает состав настроек,
/// а не их полное дерево.
fn config_names(fmt: ConfigFormat, content: &str) -> Vec<(String, u32)> {
    let mut out: Vec<(String, u32)> = Vec::new();
    match fmt {
        ConfigFormat::Json => out.extend(json_top_keys(content)),
        ConfigFormat::Yaml => {
            let masked = mask_comments("yaml", content);
            if let Some(re) = yaml_key_re() {
                for (i, line) in masked.lines().enumerate() {
                    // Ключ верхнего уровня записан без отступа; отступ означает вложенность.
                    if line.starts_with(char::is_whitespace) {
                        continue;
                    }
                    if let Some(c) = re.captures(line) {
                        if let Some(m) = c.get(1) {
                            out.push((m.as_str().to_string(), (i as u32) + 1));
                        }
                    }
                }
            }
        }
        ConfigFormat::Toml => {
            let masked = mask_comments("toml", content);
            let mut in_section = false;
            for (i, line) in masked.lines().enumerate() {
                let ln = (i as u32) + 1;
                if let Some(c) = toml_section_re().and_then(|re| re.captures(line)) {
                    in_section = true;
                    if let Some(m) = c.get(1) {
                        out.push((m.as_str().to_string(), ln));
                    }
                    continue;
                }
                // Ключ засчитывается только до первого заголовка таблицы: далее он
                // принадлежит таблице и первым уровнем уже не является.
                if in_section {
                    continue;
                }
                if let Some(c) = toml_key_re().and_then(|re| re.captures(line)) {
                    if let Some(m) = c.get(1) {
                        out.push((m.as_str().to_string(), ln));
                    }
                }
            }
        }
        ConfigFormat::Properties => {
            let masked = mask_comments("properties", content);
            if let Some(re) = prop_key_re() {
                for (i, line) in masked.lines().enumerate() {
                    if let Some(c) = re.captures(line) {
                        if let Some(m) = c.get(1) {
                            out.push((m.as_str().to_string(), (i as u32) + 1));
                        }
                    }
                }
            }
        }
    }
    out
}

// ───────────────────────── Извлечение ─────────────────────────

/// Извлечь командный интерфейс и конфигурационные параметры проекта (либо подпути,
/// указанного в `input.target`).
pub fn extract(ctx: &Ctx, input: &RunInput) -> Result<CliSurface> {
    let base = ctx.base(input)?;
    let root = ctx.root.clone();
    let mut s = CliSurface::default();
    // Ключ включает вид факта, значение, файл и строку, поэтому одно и то же объявление,
    // распознанное сразу несколькими правилами, попадает в выдачу единожды.
    let mut seen: BTreeSet<(u8, String, String, u32)> = BTreeSet::new();

    walk(&base, &mut |path| {
        let ext = ext_of(path);
        // Командный интерфейс объявляется только в исходном тексте программы. Прочие файлы
        // (проза документации, данные) не рассматриваются: пример команды в руководстве
        // синтаксически неотличим от её объявления, а порождённая документация, будучи
        // просканированной, вернула бы собственные строки обратно в модель проекта.
        if !SOURCE_CODE.contains(&ext) {
            return;
        }
        let content = match super::codeintel::read_source(path) {
            Some(c) => c,
            None => return,
        };
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        // Тестовые файлы описывают проверки, а не продукт: команда, придуманная фикстурой,
        // в руководстве пользователя значиться не должна.
        if is_test_path(&rel) {
            return;
        }

        let masked = mask_comments(ext, &content);
        let mut lines: Vec<&str> = masked.lines().collect();
        // Язык Rust держит тесты ВНУТРИ исходного файла, поэтому отсев по имени файла их не
        // видит и придуманные фикстурами команды попадали бы в документ наравне с
        // настоящими. Модули под `#[cfg(test)]` гасятся с сохранением нумерации строк.
        if ext == "rs" {
            blank_rust_test_modules(&mut lines);
        }

        for (i, line) in lines.iter().copied().enumerate() {
            let ln = (i as u32) + 1;
            for rule in cli_res() {
                if !rule.exts.contains(&ext) {
                    continue;
                }
                let Some(c) = rule.re.captures(line) else {
                    continue;
                };
                let Some(raw) = c.get(1).map(|m| m.as_str()) else {
                    continue;
                };
                let (cat, value, bucket) = match rule.kind {
                    Kind::Command => match normalize_command(raw) {
                        Some(v) => (0u8, v, &mut s.commands),
                        None => continue,
                    },
                    Kind::Flag => match normalize_flag(raw) {
                        Some(v) => (1u8, v, &mut s.flags),
                        None => continue,
                    },
                };
                if seen.insert((cat, value.clone(), rel.clone(), ln)) {
                    bucket.push(CliItem {
                        value,
                        file: rel.clone(),
                        line: ln,
                    });
                }
            }
        }
    })?;

    // Файлы настроек читаются по закрытому перечню имён в корне проекта и в каталоге
    // `config`, а не через общий обход дерева. Причина в том, что образец окружения
    // `.env.example` является скрытым файлом, а общий обход скрытые файлы намеренно
    // отбрасывает; кроме того, прямое обращение к известным путям детерминировано само по
    // себе и не зависит от порядка файловой системы.
    for dir in [base.clone(), base.join("config")] {
        for name in CONFIG_FILES {
            let path = dir.join(name);
            if !path.is_file() {
                continue;
            }
            let Some(fmt) = config_format(name) else {
                continue;
            };
            let rel = rel_path(&path, &root);
            if is_test_path(&rel) {
                continue;
            }
            let Some(content) = super::codeintel::read_source(&path) else {
                continue;
            };
            for (value, ln) in config_names(fmt, &content) {
                if seen.insert((2, value.clone(), rel.clone(), ln)) {
                    s.config.push(CliItem {
                        value,
                        file: rel.clone(),
                        line: ln,
                    });
                }
            }
        }
    }

    // Детерминированный порядок обязателен: обход файловой системы сам по себе порядка не
    // задаёт, а неупорядоченная выдача сделала бы повторное порождение документов
    // неидемпотентным, то есть один и тот же исходный текст всякий раз объявлялся бы
    // изменённым.
    sort_items(&mut s.commands);
    sort_items(&mut s.flags);
    sort_items(&mut s.config);
    Ok(s)
}

/// Путь файла относительно корня проекта в виде строки. Разделитель приводится к прямой
/// косой черте, чтобы выдача на Windows и на Unix совпадала посимвольно.
fn rel_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn sort_items(v: &mut [CliItem]) {
    v.sort_by(|a, b| {
        (a.file.as_str(), a.line, a.value.as_str()).cmp(&(
            b.file.as_str(),
            b.line,
            b.value.as_str(),
        ))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_testkit::TempTree;

    fn surface(dir: &Path) -> CliSurface {
        let ctx = Ctx::new(dir);
        extract(&ctx, &RunInput::default()).unwrap()
    }

    fn command_values(dir: &Path) -> Vec<String> {
        surface(dir).commands.into_iter().map(|i| i.value).collect()
    }

    fn flag_values(dir: &Path) -> Vec<String> {
        surface(dir).flags.into_iter().map(|i| i.value).collect()
    }

    fn config_values(dir: &Path) -> Vec<String> {
        surface(dir).config.into_iter().map(|i| i.value).collect()
    }

    /// Строительный и объявительный виды библиотеки clap дают подкоманду и длинный ключ.
    #[test]
    fn подкоманда_clap_извлекается() {
        let t = TempTree::new("cli");
        t.write(
            "src/main.rs",
            "fn build() -> Command {\n\
             \x20   Command::new(\"ailc\").subcommand(Command::new(\"doctor\"))\n\
             }\n\
             #[command(name = \"plan\")]\n\
             struct Plan {\n\
             \x20   #[arg(long = \"strict\", short = 's')]\n\
             \x20   strict: bool,\n\
             }\n",
        );
        let commands = command_values(t.path());
        let flags = flag_values(t.path());
        assert!(
            commands.contains(&"doctor".to_string()),
            "подкоманда строительного вида обязана извлекаться: {commands:?}"
        );
        assert!(
            commands.contains(&"plan".to_string()),
            "имя команды из атрибута обязано извлекаться: {commands:?}"
        );
        assert!(
            flags.contains(&"--strict".to_string()),
            "длинный ключ из атрибута обязан извлекаться: {flags:?}"
        );
    }

    /// Модуль argparse задаёт ключ строкой довода, причём длинное написание может стоять
    /// не первым, что и проверяется.
    #[test]
    fn длинный_ключ_argparse_извлекается() {
        let t = TempTree::new("cli");
        t.write(
            "src/cli.py",
            "parser.add_argument(\"-v\", \"--verbose\", action=\"store_true\")\n\
             sub = parser.add_subparsers()\n\
             sub.add_parser(\"report\")\n",
        );
        let flags = flag_values(t.path());
        let commands = command_values(t.path());
        assert!(
            flags.contains(&"--verbose".to_string()),
            "длинное написание ключа обязано извлекаться: {flags:?}"
        );
        assert!(
            commands.contains(&"report".to_string()),
            "подкоманда argparse обязана извлекаться: {commands:?}"
        );
    }

    /// Библиотека cobra задаёт имя команды полем Use, зачастую вместе с описанием доводов;
    /// в перечень операций попадает именно имя, без описания доводов.
    #[test]
    fn подкоманда_cobra_извлекается() {
        let t = TempTree::new("cli");
        t.write(
            "cmd/add.go",
            "var addCmd = &cobra.Command{\n\
             \tUse:   \"add [flags]\",\n\
             \tShort: \"добавить запись\",\n\
             }\n\
             func init() {\n\
             \taddCmd.Flags().StringVar(&output, \"output\", \"\", \"путь к файлу\")\n\
             }\n",
        );
        let commands = command_values(t.path());
        let flags = flag_values(t.path());
        assert!(
            commands.contains(&"add".to_string()),
            "имя команды обязано извлекаться без описания доводов: {commands:?}"
        );
        assert!(
            flags.contains(&"--output".to_string()),
            "ключ обязан приводиться к длинному написанию: {flags:?}"
        );
    }

    /// Значение параметра не является фактом для документа: оно сплошь и рядом содержит
    /// секрет, и его попадание в порождаемый документ было бы утечкой. Проверяется, что в
    /// выдаче есть имя параметра и нет ни одной части его значения.
    #[test]
    fn конфигурационный_параметр_извлекается_по_имени_а_значение_нет() {
        let t = TempTree::new("cli");
        t.write(
            "config/config.yaml",
            "database_url: postgres://пользователь:секретный-пароль@host/db\n\
             timeout: 30\n\
             server:\n\
             \x20 port: 8080\n",
        );
        let config = config_values(t.path());
        assert!(
            config.contains(&"database_url".to_string()),
            "имя параметра обязано извлекаться: {config:?}"
        );
        assert!(
            config.contains(&"server".to_string()),
            "имя параметра верхнего уровня обязано извлекаться: {config:?}"
        );
        assert!(
            !config.iter().any(|v| v.contains("секретный-пароль")),
            "значение параметра в выдачу попадать не должно: {config:?}"
        );
        assert!(
            !config.iter().any(|v| v.contains("postgres")),
            "значение параметра в выдачу попадать не должно: {config:?}"
        );
        assert!(
            !config.contains(&"port".to_string()),
            "вложенный ключ первым уровнем не является: {config:?}"
        );
    }

    /// Пример употребления в комментарии неотличим по написанию от настоящего объявления,
    /// поэтому комментарии маскируются: иначе руководство пользователя описывало бы
    /// несуществующие ключи, взятые из пояснений к коду.
    #[test]
    fn пример_ключа_в_комментарии_фактом_не_становится() {
        let t = TempTree::new("cli");
        t.write(
            "src/cli.py",
            "# пример употребления: parser.add_argument(\"--from-comment\")\n\
             parser.add_argument(\"--real\")\n",
        );
        let flags = flag_values(t.path());
        assert!(
            flags.contains(&"--real".to_string()),
            "настоящий ключ обязан извлекаться: {flags:?}"
        );
        assert!(
            !flags.iter().any(|f| f.contains("from-comment")),
            "пример из комментария ключом продукта не является: {flags:?}"
        );
    }

    /// Тестовые файлы описывают проверки, а не продукт. Проверяется как отсев по имени
    /// файла (язык Go), так и гашение встроенного тестового модуля (язык Rust).
    #[test]
    fn тестовые_файлы_пропускаются() {
        let t = TempTree::new("cli");
        t.write(
            "cmd/root_test.go",
            "var c = &cobra.Command{\n\tUse: \"fixture\",\n}\n",
        );
        t.write(
            "cmd/root.go",
            "var c = &cobra.Command{\n\tUse: \"serve\",\n}\n",
        );
        t.write(
            "src/lib.rs",
            "pub fn build() -> Command {\n\
             \x20   Command::new(\"app\").subcommand(Command::new(\"prod\"))\n\
             }\n\
             #[cfg(test)]\n\
             mod tests {\n\
             \x20   #[test]\n\
             \x20   fn t() {\n\
             \x20       let _ = Command::new(\"app\").subcommand(Command::new(\"embedded\"));\n\
             \x20   }\n\
             }\n",
        );
        let commands = command_values(t.path());
        assert!(
            commands.contains(&"serve".to_string()),
            "команда продукта обязана извлекаться: {commands:?}"
        );
        assert!(
            commands.contains(&"prod".to_string()),
            "команда продукта обязана извлекаться: {commands:?}"
        );
        assert!(
            !commands.contains(&"fixture".to_string()),
            "команда из тестового файла продуктом не является: {commands:?}"
        );
        assert!(
            !commands.contains(&"embedded".to_string()),
            "команда из встроенного тестового модуля продуктом не является: {commands:?}"
        );
    }

    /// Повторное извлечение обязано давать в точности ту же выдачу в том же порядке,
    /// иначе повторное порождение документов было бы неидемпотентным и один и тот же
    /// исходный текст всякий раз объявлялся бы изменённым.
    #[test]
    fn выдача_детерминирована() {
        let t = TempTree::new("cli");
        t.write("cmd/b.go", "var c = &cobra.Command{\n\tUse: \"beta\",\n}\n");
        t.write(
            "cmd/a.go",
            "var c = &cobra.Command{\n\tUse: \"alpha\",\n}\n",
        );
        t.write(
            "src/cli.py",
            "parser.add_argument(\"--zeta\")\nparser.add_argument(\"--alpha\")\n",
        );
        t.write(
            "config.toml",
            "name = \"проект\"\n\n[server]\nport = 8080\n",
        );

        let first = surface(t.path());
        let second = surface(t.path());
        assert_eq!(
            first.commands, second.commands,
            "перечень команд воспроизводим"
        );
        assert_eq!(first.flags, second.flags, "перечень ключей воспроизводим");
        assert_eq!(
            first.config, second.config,
            "перечень параметров воспроизводим"
        );

        let ordered = |v: &[CliItem]| {
            let mut c = v.to_vec();
            sort_items(&mut c);
            c
        };
        assert_eq!(first.commands, ordered(&first.commands));
        assert_eq!(first.flags, ordered(&first.flags));
        assert_eq!(first.config, ordered(&first.config));
        assert!(
            !first.is_empty(),
            "проверка порядка имеет смысл лишь на непустой выдаче"
        );
    }

    /// Компиляция паттерна более не завершает процесс, поэтому опечатка в литерале молча
    /// уменьшила бы таблицу правил. Тест делает такую деградацию видимой в непрерывной
    /// интеграции, а не в работе пользователя.
    #[test]
    fn таблица_встроенных_паттернов_собирается_целиком() {
        assert_eq!(
            cli_res().len(),
            16,
            "собрано правил командного интерфейса: {}",
            cli_res().len()
        );
        assert!(yaml_key_re().is_some(), "паттерн ключа YAML собран");
        assert!(toml_key_re().is_some(), "паттерн ключа TOML собран");
        assert!(toml_section_re().is_some(), "паттерн таблицы TOML собран");
        assert!(prop_key_re().is_some(), "паттерн ключа свойств собран");
    }
}
