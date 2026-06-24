//! Семейство quality.ui/* — детерминированные эвристики доступности (accessibility,
//! сокращённо a11y) и адаптивной разметки.
//!
//! Назначение. Соседняя дорожка проверок (`verify/mobile`, `verify/desktop`) только
//! собирает и прогоняет тесты стека, но НЕ анализирует интерфейс. Здесь добавляется
//! недостающий слой: разметка, стили и нативный код экранов проверяются на типовые
//! барьеры доступности и на отсутствие адаптивных настроек. Это эвристики поверх
//! текста файлов, а не полноценный аудит с рендерингом, поэтому правила
//! формулируются строго и сообщают только то, что действительно проверено.
//!
//! Почему не таблица правил поверх `ScanEngine`. Большинство проверок этого слоя по
//! своей природе суть «тег присутствует, но обязательный атрибут отсутствует» и «во
//! всём файле нет нужной директивы». Оба класса требуют отрицания (lookahead в
//! терминах регулярных выражений), которого крейт `regex` версии 1 не поддерживает.
//! Поэтому анализ выполнен явной логикой по полному тексту каждого файла: это даёт
//! и корректность без отрицательного просмотра, и устойчивость к переносу тега на
//! несколько строк, типичному для JSX и для XML-макетов платформы Android. Обход
//! дерева и инвариант «нет молчаливых пропусков» переиспользуются из общего модуля
//! обхода (`walk`), новой логики обхода здесь не вводится.
//!
//! Достоверность. Каждое сообщение несёт ПРОВЕРЕННУЮ ссылку на критерий WCAG (Web
//! Content Accessibility Guidelines, Руководство по доступности веб-контента, версия
//! 2.1) с номером критерия успеха и уровнем соответствия в скобках, чтобы человек мог
//! открыть первоисточник и убедиться в основании находки. Каждое правило обязано
//! иметь явный класс достоверности в `contracts::rule_confidence` (список новых
//! идентификаторов и желаемых классов вынесен для классификации соседней дорожкой).
//!
//! Границы охвата (важно для честности вердикта). Проверяется только то, что
//! детерминированно видно в исходном тексте: отсутствие обязательных атрибутов, явно
//! заданные значения свойств, наличие или отсутствие директив адаптивности. НЕ
//! проверяются: фактический контраст после применения каскада и тем, вычисленные
//! размеры элементов после раскладки, порядок обхода с клавиатуры, корректность
//! ролей ARIA по дереву доступности. Эти классы требуют рендеринга и в охват
//! эвристик не входят, поэтому их отсутствие здесь не утверждается как «всё хорошо».

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Finding, Location, Result,
    RunInput, Severity, Tier,
};
use ailc_core::engines::walk::{is_test_path, walk_stats, WalkStats};
use ailc_core::registry::Registry;
use ailc_core::Capability;
use regex::Regex;
use std::fs;
use std::sync::OnceLock;

/// Единая JSON-схема входа для проверок «по проекту» (тот же контракт, что у прочих
/// сканеров: необязательный подпуть target).
const TARGET_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;

/// Предельная длина одной физической строки, после которой содержимое считается вне
/// охвата по той же причине, что и в `ScanEngine`: минифицированные бандлы дают и
/// медленный разбор, и поток ложных подстрок. Совпадает с порогом движка сканирования.
const MAX_LINE_LEN: usize = 2_000;

/// Расширения файлов разметки гипертекста и компонентов, в которых встречается
/// разметка HTML-подобного вида: чистый HTML и его шаблоны, компоненты React
/// (JSX и TSX), одно-файловые компоненты Vue, Svelte и Astro. По ним работают
/// правила атрибутов разметки (alt, программная подпись поля, интерактив на
/// неинтерактивном теге) и правило области просмотра.
const MARKUP_EXTS: &[&str] = &["html", "htm", "xhtml", "jsx", "tsx", "vue", "svelte", "astro"];

/// Расширения файлов каскадных таблиц стилей и их препроцессоров. По ним работают
/// правила, опирающиеся на текст объявлений: предпочитаемая цветовая схема, видимость
/// фокуса, единицы размеров целей нажатия в вебе.
const STYLE_EXTS: &[&str] = &["css", "scss", "sass", "less", "styl"];

/// Разметка XML-макетов платформы Android (каталог res/layout): по ней проверяется
/// размер целей нажатия и наличие описания содержимого у изображений и кнопок-иконок.
const ANDROID_XML_EXTS: &[&str] = &["xml"];

/// Исходники iOS на языках Swift и Objective-C: по ним проверяются нативные цели
/// нажатия и явное отключение доступности элемента.
const IOS_EXTS: &[&str] = &["swift", "m", "mm"];

/// Исходники каркаса Flutter на языке Dart: по ним проверяется наличие семантической
/// подписи у виджета изображения.
const FLUTTER_EXTS: &[&str] = &["dart"];

/// Расширение файла в нижнем регистре (без точки). Пустая строка, если расширения нет.
fn file_ext(path: &std::path::Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Скомпилировать (один раз, лениво) регулярное выражение открывающего тега с
/// перечисленными через альтернацию именами. Шаблон: «<», имя из набора, граница
/// слова, далее любые символы кроме «>» (атрибуты, в том числе разнесённые по
/// строкам), затем «>». Флаг s позволяет точке покрывать перенос строки внутри тега,
/// поэтому правило корректно ловит и однострочный, и многострочный тег. Отрицательный
/// просмотр не используется (его нет в крейте regex версии 1): отсутствие атрибутов
/// проверяется явной логикой по тексту найденного тега.
fn tag_re(cell: &'static OnceLock<Regex>, names_alt: &str) -> &'static Regex {
    cell.get_or_init(|| {
        let pat = format!(r"(?is)<(?:{names_alt})\b[^>]*>");
        Regex::new(&pat).expect("встроенный паттерн тега невалиден")
    })
}

/// Найти все вхождения открывающего тега данным скомпилированным выражением и вернуть
/// для каждого пару (полный текст тега, байтовое смещение начала).
fn find_tags<'a>(text: &'a str, re: &Regex) -> Vec<(&'a str, usize)> {
    re.find_iter(text).map(|m| (m.as_str(), m.start())).collect()
}

/// Ленивые регулярные выражения тегов по семействам имён (по одному статическому
/// слоту на каждое выражение, без общего кеша и без утечки в куче).
fn re_img() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    tag_re(&C, "img|image")
}
fn re_field() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    tag_re(&C, "input|textarea|select")
}
fn re_box() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    tag_re(&C, "div|span")
}
fn re_html() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    tag_re(&C, "html")
}
fn re_meta() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    tag_re(&C, "meta")
}
fn re_android_image() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    tag_re(&C, "ImageView|ImageButton")
}

/// Номер строки (с единицы), на которой начинается байтовое смещение в тексте.
fn line_of_offset(content: &str, byte_off: usize) -> u32 {
    let upto = byte_off.min(content.len());
    (content[..upto].bytes().filter(|&b| b == b'\n').count() as u32) + 1
}

/// Доказательство для находки: первая строка фрагмента, обрезанная до 120 символов.
fn evidence_of(fragment: &str) -> String {
    fragment
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .chars()
        .take(120)
        .collect()
}

/// Регистронезависимая проверка вхождения подстроки.
fn contains_ci(haystack: &str, needle_lower: &str) -> bool {
    haystack.to_ascii_lowercase().contains(needle_lower)
}

/// Присутствует ли в тексте тега атрибут как ЦЕЛОЕ имя (а не как хвост другого имени).
/// `tag_lower` это текст тега в нижнем регистре, `attr` имя атрибута в нижнем регистре.
/// Имя атрибута считается присутствующим, если перед ним граница (начало строки,
/// пробельный символ или открывающая угловая скобка), а сразу за ним идёт знак
/// равенства, пробельный символ либо конец тега. Это отсекает ложные совпадения вида
/// `data-testid` для искомого `id` или `aria-labelledby` для искомого `title`.
fn has_attr(tag_lower: &str, attr: &str) -> bool {
    let bytes = tag_lower.as_bytes();
    let alen = attr.len();
    let mut from = 0usize;
    while let Some(rel) = tag_lower[from..].find(attr) {
        let pos = from + rel;
        // Граница слева: начало, пробел или «<».
        let left_ok = pos == 0
            || {
                let c = bytes[pos - 1];
                c == b'<' || c == b'/' || c.is_ascii_whitespace()
            };
        // Граница справа: «=», пробел, «>», «/» или конец.
        let after = pos + alen;
        let right_ok = after >= bytes.len() || {
            let c = bytes[after];
            c == b'=' || c == b'>' || c == b'/' || c.is_ascii_whitespace()
        };
        if left_ok && right_ok {
            return true;
        }
        from = pos + alen;
    }
    false
}

/// Описание одного правила слоя: идентификатор, важность, сообщение со ссылкой WCAG.
struct UiRule {
    id: &'static str,
    severity: Severity,
    message: &'static str,
}

/// Контракт анализатора одной capability: по полному тексту файла и его расширению
/// эмитировать находки (каждая заземлена на номер строки). Разные capability
/// подставляют разные анализаторы поверх общего обхода.
type Analyzer = fn(content: &str, ext: &str, rel: &str, out: &mut CapabilityOutput, source: &str);

/// Общая capability слоя: манифест плюс анализатор. Один обход дерева, инвариант
/// «нет молчаливых пропусков» как в `ScanEngine`, разные анализаторы для разных
/// проверок. Тест-файлы и фикстуры пропускаются (как и в сканерах безопасности).
struct UiCapability {
    manifest: CapabilityManifest,
    analyze: Analyzer,
    /// Расширения, которые этот анализатор вообще читает (предотбор файлов).
    exts: &'static [&'static str],
}

impl UiCapability {
    fn new(
        id: &'static str,
        when_to_use: &'static str,
        exts: &'static [&'static str],
        analyze: Analyzer,
    ) -> Self {
        Self {
            manifest: CapabilityManifest {
                id,
                family: Family::Quality,
                engine: EngineKind::Scan,
                when_to_use,
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
            analyze,
            exts,
        }
    }
}

impl Capability for UiCapability {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let base = ctx.base(input)?;
        let mut out = CapabilityOutput::default();
        let mut files_scanned: u64 = 0;
        let mut long_lines_skipped: u64 = 0;
        let mut skips = WalkStats::default();
        let root = ctx.root.clone();
        let source = self.manifest.id;
        let analyze = self.analyze;
        let exts = self.exts;

        walk_stats(
            &base,
            &mut |path| {
                let ext = file_ext(path);
                if !exts.contains(&ext.as_str()) {
                    return;
                }
                let rel = path
                    .strip_prefix(&root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string();
                // Тест-файлы и фикстуры не анализируем (как и сканеры безопасности).
                if is_test_path(&rel) {
                    return;
                }
                let content = match fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                // Сверхдлинная строка (минифицированный бандл) вне охвата: честно
                // учитываем и не запускаем по такому файлу разбор разметки.
                if content.lines().any(|l| l.len() > MAX_LINE_LEN) {
                    long_lines_skipped += 1;
                    return;
                }
                files_scanned += 1;
                analyze(&content, &ext, &rel, &mut out, source);
            },
            &mut skips,
        )?;

        // Инвариант «нет молчаливых пропусков»: ноль подходящих файлов это не успех,
        // а явная причина пропуска.
        if files_scanned == 0 {
            out.skipped = Some(format!(
                "{source}: не найдено подходящих файлов разметки/стилей по указанному пути"
            ));
        }
        out.metrics.push(("files_scanned".into(), files_scanned as f64));
        out.metrics
            .push(("files_out_of_scope".into(), skips.total() as f64));
        out.metrics
            .push(("long_lines_out_of_scope".into(), long_lines_skipped as f64));
        out.metrics
            .push((format!("{source}_findings"), out.findings.len() as f64));
        let long_note = if long_lines_skipped > 0 {
            format!(", {long_lines_skipped} файлов со сверхдлинными строками вне охвата")
        } else {
            String::new()
        };
        out.summary = format!(
            "{source}: {files_scanned} файлов, {} находок{}{}",
            out.findings.len(),
            skips.note(),
            long_note
        );
        Ok(out)
    }
}

/// Добавить находку, заземлённую на конкретную строку файла. `verified` истинно, как
/// и у прочих детерминированных сканеров: находка привязана к file:line и потому
/// учитывается гейтом, а уровень уверенности задаётся отдельной картой достоверности
/// по идентификатору правила (`contracts::rule_confidence`).
fn emit(
    out: &mut CapabilityOutput,
    rule: &UiRule,
    rel: &str,
    line: u32,
    evidence: String,
    source: &str,
) {
    out.findings.push(Finding {
        rule: rule.id.to_string(),
        severity: rule.severity,
        message: rule.message.to_string(),
        location: Some(Location {
            file: rel.to_string(),
            line,
        }),
        evidence: Some(evidence),
        verified: true,
        source: source.to_string(),
    });
}

// ───────────────────────── quality.ui/a11y-markup ─────────────────────────

const IMG_NO_ALT: UiRule = UiRule {
    id: "ui-img-without-alt",
    severity: Severity::Medium,
    message: "Изображение без текстовой альтернативы (атрибут alt). Нарушает WCAG 2.1, критерий успеха 1.1.1 «Нетекстовый контент» (уровень A). Добавьте alt с описанием смысла изображения; для декоративных изображений задайте пустое alt=\"\".",
};

const INPUT_NO_LABEL: UiRule = UiRule {
    id: "ui-input-without-label",
    severity: Severity::Medium,
    message: "Поле ввода без программной подписи (нет aria-label, aria-labelledby, привязки через id к label или title). Нарушает WCAG 2.1, критерии успеха 1.3.1 «Информация и взаимосвязи» и 4.1.2 «Имя, роль, значение» (уровень A). Свяжите поле с подписью через for/id или задайте aria-label.",
};

const CLICKABLE_NONSEMANTIC: UiRule = UiRule {
    id: "ui-clickable-nonsemantic",
    severity: Severity::Medium,
    message: "Интерактив на неинтерактивном теге (div/span с onClick без role и без обработчика клавиатуры). Нарушает WCAG 2.1, критерии успеха 2.1.1 «Клавиатура» и 4.1.2 «Имя, роль, значение» (уровень A). Используйте button/a либо задайте role и onKeyDown для управления с клавиатуры.",
};

/// Анализатор барьеров доступности в разметке. Для каждого открывающего тега
/// проверяет наличие обязательных атрибутов явной логикой по тексту тега (без
/// отрицательного просмотра в регулярном выражении).
/// JSX/HTML: тег, начинающийся с заглавной буквы, это React-компонент (например shadcn
/// <Input>/<Select>, Next.js <Image>), а не DOM-элемент. Доступность WCAG относится к
/// итоговому HTML, а подпись компонента задаётся его композицией (<Label htmlFor>,
/// FormField) и из текста тега не видна, поэтому проверять её на теге компонента нельзя:
/// это давало массовые ложные срабатывания на shadcn/Radix/MUI. Веб-анализатор a11y
/// работает только по строчным DOM-элементам; Android XML (легитимный PascalCase) идёт
/// отдельным путём и сюда не попадает.
fn is_dom_element(tag: &str) -> bool {
    tag.trim_start_matches('<')
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase())
}

fn analyze_a11y_markup(content: &str, _ext: &str, rel: &str, out: &mut CapabilityOutput, source: &str) {
    // Изображение без alt. Атрибут alt с пустым значением считается корректным
    // приёмом для декоративных изображений и находку снимает (наличие имени alt
    // достаточно). Проверяем имя атрибута как целое слово, чтобы не спутать с хвостом
    // другого имени.
    for (tag, off) in find_tags(content, re_img()) {
        if !is_dom_element(tag) {
            continue; // React-компонент (<Image> и т.п.), не DOM-элемент
        }
        let lower = tag.to_ascii_lowercase();
        if !has_attr(&lower, "alt") {
            let line = line_of_offset(content, off);
            emit(out, &IMG_NO_ALT, rel, line, evidence_of(tag), source);
        }
    }

    // Поле ввода без программной подписи. Поля типов hidden/submit/button/reset/image
    // подписи не требуют и исключаются. Наличие любого из признаков подписи
    // (aria-label, aria-labelledby, id для внешнего label, title) снимает находку.
    for (tag, off) in find_tags(content, re_field()) {
        if !is_dom_element(tag) {
            continue; // React-компонент (<Input>/<Select>/<Textarea> shadcn), не DOM-поле
        }
        let lower = tag.to_ascii_lowercase();
        // Тип, не требующий подписи через label.
        let exempt_type = ["hidden", "submit", "button", "reset", "image"]
            .iter()
            .any(|t| {
                lower.contains(&format!("type=\"{t}\""))
                    || lower.contains(&format!("type='{t}'"))
                    || lower.contains(&format!("type={t}"))
            });
        if exempt_type {
            continue;
        }
        let has_label = has_attr(&lower, "aria-label")
            || has_attr(&lower, "aria-labelledby")
            || has_attr(&lower, "id")
            || has_attr(&lower, "title");
        if !has_label {
            let line = line_of_offset(content, off);
            emit(out, &INPUT_NO_LABEL, rel, line, evidence_of(tag), source);
        }
    }

    // Интерактив на неинтерактивном теге: div/span с обработчиком клика, но без role
    // и без клавиатурного обработчика (onKeyDown/onKeyPress/onKeyUp).
    for (tag, off) in find_tags(content, re_box()) {
        if !is_dom_element(tag) {
            continue; // React-компонент, не DOM div/span
        }
        let lower = tag.to_ascii_lowercase();
        if !has_attr(&lower, "onclick") {
            continue;
        }
        let has_role = has_attr(&lower, "role");
        let has_keyboard = has_attr(&lower, "onkeydown")
            || has_attr(&lower, "onkeypress")
            || has_attr(&lower, "onkeyup");
        if !has_role && !has_keyboard {
            let line = line_of_offset(content, off);
            emit(out, &CLICKABLE_NONSEMANTIC, rel, line, evidence_of(tag), source);
        }
    }
}

// ───────────────────────── quality.ui/responsive ─────────────────────────

const VIEWPORT_MISSING: UiRule = UiRule {
    id: "ui-viewport-missing",
    severity: Severity::Medium,
    message: "Корневой HTML без метатега области просмотра (viewport): на мобильных устройствах страница будет масштабироваться как десктопная и станет нечитаемой. Связано с WCAG 2.1, критерий успеха 1.4.10 «Адаптация» (уровень AA). Добавьте <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">.",
};

const VIEWPORT_ZOOM_BLOCKED: UiRule = UiRule {
    id: "ui-viewport-zoom-blocked",
    severity: Severity::Medium,
    message: "Масштабирование страницы заблокировано (user-scalable=no или maximum-scale=1 в метатеге viewport). Нарушает WCAG 2.1, критерии успеха 1.4.4 «Изменение размера текста» и 1.4.10 «Адаптация» (уровень AA). Уберите запрет масштабирования, чтобы пользователь мог увеличивать содержимое.",
};

/// Анализатор адаптивности веб-страницы. Признак корневого документа это наличие тега
/// html: только для него осмысленно требовать метатег области просмотра (фрагменты
/// компонентов корневого документа не образуют). Блокировка масштабирования
/// проверяется по содержимому метатега viewport, где бы он ни встретился.
fn analyze_responsive(content: &str, _ext: &str, rel: &str, out: &mut CapabilityOutput, source: &str) {
    // Метатеги собираем один раз: используются и для признака наличия viewport, и для
    // проверки блокировки масштабирования.
    let metas = find_tags(content, re_meta());

    // Корневой документ без метатега области просмотра. Признак корня: открывающий
    // тег <html. Метатег viewport ищем по совокупности «meta» и подстроки «viewport».
    let html_tags = find_tags(content, re_html());
    if let Some((_, html_off)) = html_tags.first() {
        let has_viewport = metas.iter().any(|(tag, _)| tag.to_ascii_lowercase().contains("viewport"));
        if !has_viewport {
            // Заземляем на строку тега html (точка, с которой человек начнёт правку).
            let line = line_of_offset(content, *html_off);
            emit(out, &VIEWPORT_MISSING, rel, line, "<html> без метатега viewport".to_string(), source);
        }
    }

    // Блокировка масштабирования: разбираем каждый метатег viewport и смотрим его
    // содержимое на user-scalable=no/0 или maximum-scale=1.
    for &(tag, off) in &metas {
        let t = tag.to_ascii_lowercase();
        if !t.contains("viewport") {
            continue;
        }
        let blocks_zoom = t.contains("user-scalable=no")
            || t.contains("user-scalable =no")
            || t.contains("user-scalable= no")
            || t.contains("user-scalable = no")
            || t.contains("user-scalable=0")
            || maximum_scale_is_one(&t);
        if blocks_zoom {
            let line = line_of_offset(content, off);
            emit(out, &VIEWPORT_ZOOM_BLOCKED, rel, line, evidence_of(tag), source);
        }
    }
}

/// Содержит ли строка тега ограничение maximum-scale равным единице (1 или 1.0…).
/// Разбор без числовых сравнений регулярного выражения: ищем подстроку и проверяем,
/// что значение это «1» (возможно с дробной частью из нулей).
fn maximum_scale_is_one(tag_lower: &str) -> bool {
    let needle = "maximum-scale";
    let Some(pos) = tag_lower.find(needle) else {
        return false;
    };
    let rest = &tag_lower[pos + needle.len()..];
    // Пропустить пробелы, знак равенства и снова пробелы.
    let val: String = rest
        .trim_start()
        .strip_prefix('=')
        .unwrap_or(rest)
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    // «1», «1.», «1.0», «1.00» это единица; «1.5», «10» это не единица.
    if val.is_empty() {
        return false;
    }
    let mut parts = val.splitn(2, '.');
    let int_part = parts.next().unwrap_or("");
    let frac_part = parts.next().unwrap_or("");
    int_part == "1" && frac_part.chars().all(|c| c == '0')
}

// ───────────────────────── quality.ui/dark-theme ─────────────────────────

const NO_PREFERS_COLOR_SCHEME: UiRule = UiRule {
    id: "ui-no-prefers-color-scheme",
    severity: Severity::Low,
    message: "Цвета фона и текста заданы явными значениями, но во всём файле нет медиазапроса prefers-color-scheme (тёмная тема не поддержана). Связано с WCAG 2.1, критерий успеха 1.4.8 «Визуальное представление» (уровень AAA). Добавьте блок @media (prefers-color-scheme: dark) с альтернативной палитрой.",
};

/// Регулярное выражение явного цветового объявления: свойство background,
/// background-color или color со значением в форме шестнадцатеричного цвета. Без
/// отрицательного просмотра; «во всём файле нет prefers-color-scheme» проверяется
/// отдельной строковой проверкой по полному тексту.
fn explicit_color_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:background(?:-color)?|color)\s*:\s*#[0-9a-f]{3,8}\b")
            .expect("встроенный паттерн цветового объявления невалиден")
    })
}

/// Анализатор поддержки тёмной темы. Если файл стилей задаёт фон или цвет текста
/// явным шестнадцатеричным значением, но во всём файле нет ни одного медиазапроса
/// prefers-color-scheme, эмитируется одна находка на строку первого такого
/// объявления (не по объявлению на строку, чтобы не зашумлять отчёт).
fn analyze_dark_theme(content: &str, _ext: &str, rel: &str, out: &mut CapabilityOutput, source: &str) {
    if contains_ci(content, "prefers-color-scheme") {
        return;
    }
    if let Some(m) = explicit_color_re().find(content) {
        let line = line_of_offset(content, m.start());
        let frag = m.as_str().to_string();
        emit(out, &NO_PREFERS_COLOR_SCHEME, rel, line, frag, source);
    }
}

// ───────────────────────── quality.ui/focus-visible ─────────────────────────

const FOCUS_OUTLINE_REMOVED: UiRule = UiRule {
    id: "ui-focus-outline-removed",
    severity: Severity::Medium,
    message: "Контур фокуса убран (outline: none/0), а видимый фокус нигде в файле не восстановлен (нет :focus-visible или :focus). Нарушает WCAG 2.1, критерий успеха 2.4.7 «Видимый фокус» (уровень AA). Сохраните видимый индикатор фокуса, например через :focus-visible.",
};

/// Регулярное выражение снятия контура фокуса: outline со значением none или нулём
/// (с необязательной единицей px). Чистый положительный паттерн.
fn outline_removed_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\boutline\s*:\s*(?:none|0(?:px)?)\b")
            .expect("встроенный паттерн снятия контура невалиден")
    })
}

/// Анализатор видимости фокуса. Если стиль убирает контур фокуса, но во всём файле
/// нет селектора :focus (включая :focus-visible), видимый фокус не восстановлен, и
/// эмитируется находка на строку снятия контура.
fn analyze_focus_visible(content: &str, _ext: &str, rel: &str, out: &mut CapabilityOutput, source: &str) {
    if contains_ci(content, ":focus") {
        // Любой селектор :focus или :focus-visible в файле снимает находку: видимый
        // фокус где-то восстановлен.
        return;
    }
    if let Some(m) = outline_removed_re().find(content) {
        let line = line_of_offset(content, m.start());
        let frag = m.as_str().to_string();
        emit(out, &FOCUS_OUTLINE_REMOVED, rel, line, frag, source);
    }
}

// ───────────────────────── quality.ui/touch-target ─────────────────────────

const TOUCH_SMALL_WEB: UiRule = UiRule {
    id: "ui-touch-target-small-web",
    severity: Severity::Low,
    message: "Явный размер элемента меньше 44px: цель нажатия может быть слишком мелкой для пальца. Связано с WCAG 2.1, критерии успеха 2.5.5 «Размер цели» (уровень AAA) и 2.5.8 «Минимальный размер цели» (уровень AA). Делайте интерактивные цели не меньше 44 на 44 пикселя.",
};

const TOUCH_SMALL_ANDROID: UiRule = UiRule {
    id: "ui-touch-target-small-android",
    severity: Severity::Low,
    message: "Размер элемента нажатия меньше 48dp: цель нажатия ниже рекомендации Android по доступности. Связано с WCAG 2.1, критерий успеха 2.5.5 «Размер цели» (уровень AAA). Делайте цели нажатия не меньше 48 на 48 независимых пикселей (dp).",
};

const TOUCH_SMALL_IOS: UiRule = UiRule {
    id: "ui-touch-target-small-ios",
    severity: Severity::Low,
    message: "Явный размер кадра меньше 44pt: цель нажатия ниже минимума доступности iOS. Связано с WCAG 2.1, критерий успеха 2.5.5 «Размер цели» (уровень AAA). Делайте цели нажатия не меньше 44 на 44 пунктов (pt).",
};

/// Регулярное выражение размера в вебе: свойство width/height/min-width/min-height со
/// значением в пикселях. Значение захватывается группой 1 для числового сравнения в
/// коде (диапазон проверяется явно, без зависимости от форм числа в регулярке).
fn web_size_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:min-)?(?:width|height)\s*:\s*([0-9]+(?:\.[0-9]+)?)px\b")
            .expect("встроенный паттерн размера в вебе невалиден")
    })
}

/// Регулярное выражение размера Android: атрибут layout_width/layout_height со
/// значением в независимых пикселях (dp). Значение в группе 1.
fn android_size_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)android:(?:layout_)?(?:width|height)\s*=\s*["']([0-9]+(?:\.[0-9]+)?)dp["']"#)
            .expect("встроенный паттерн размера Android невалиден")
    })
}

/// Регулярное выражение размера iOS: width/height со значением в пунктах в
/// конструкции кадра (CGSize/CGRect/frame). Значение в группе 1.
fn ios_size_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:width|height)\s*:\s*([0-9]+(?:\.[0-9]+)?)\b")
            .expect("встроенный паттерн размера iOS невалиден")
    })
}

/// Анализатор размеров целей нажатия. Минимумы взяты из рекомендаций платформ и
/// критериев WCAG: 44 пикселя/пункта для веба и iOS, 48 независимых пикселей для
/// Android. Значение порога не считается нарушением (строго меньше порога).
fn analyze_touch_target(content: &str, ext: &str, rel: &str, out: &mut CapabilityOutput, source: &str) {
    if STYLE_EXTS.contains(&ext) {
        for caps in web_size_re().captures_iter(content) {
            let whole = caps.get(0).expect("группа 0 всегда присутствует");
            let val: f64 = caps[1].parse().unwrap_or(f64::MAX);
            if val > 0.0 && val < 44.0 {
                let line = line_of_offset(content, whole.start());
                emit(out, &TOUCH_SMALL_WEB, rel, line, whole.as_str().to_string(), source);
            }
        }
    } else if ANDROID_XML_EXTS.contains(&ext) {
        for caps in android_size_re().captures_iter(content) {
            let whole = caps.get(0).expect("группа 0 всегда присутствует");
            let val: f64 = caps[1].parse().unwrap_or(f64::MAX);
            if val > 0.0 && val < 48.0 {
                let line = line_of_offset(content, whole.start());
                emit(out, &TOUCH_SMALL_ANDROID, rel, line, whole.as_str().to_string(), source);
            }
        }
    } else if IOS_EXTS.contains(&ext) {
        // Для iOS требуем контекст кадра в той же строке, чтобы не ловить любые
        // width/height из произвольной геометрии: рядом должно быть CGSize/CGRect/frame.
        for caps in ios_size_re().captures_iter(content) {
            let whole = caps.get(0).expect("группа 0 всегда присутствует");
            let line_start = content[..whole.start()].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let line_end = content[whole.start()..]
                .find('\n')
                .map(|i| whole.start() + i)
                .unwrap_or(content.len());
            let line_text = &content[line_start..line_end];
            let lt = line_text.to_ascii_lowercase();
            if !(lt.contains("cgsize") || lt.contains("cgrect") || lt.contains("frame")) {
                continue;
            }
            let val: f64 = caps[1].parse().unwrap_or(f64::MAX);
            if val > 0.0 && val < 44.0 {
                let line = line_of_offset(content, whole.start());
                emit(out, &TOUCH_SMALL_IOS, rel, line, line_text.trim().chars().take(120).collect(), source);
            }
        }
    }
}

// ───────────────────────── quality.ui/native-a11y ─────────────────────────

const ANDROID_IMAGE_NO_DESC: UiRule = UiRule {
    id: "ui-android-image-no-contentdescription",
    severity: Severity::Medium,
    message: "Изображение или иконка Android без contentDescription: программа чтения с экрана не сможет его озвучить. Связано с WCAG 2.1, критерий успеха 1.1.1 «Нетекстовый контент» (уровень A). Задайте android:contentDescription, а для декоративных элементов importantForAccessibility=\"no\".",
};

const FLUTTER_IMAGE_NO_SEMANTICS: UiRule = UiRule {
    id: "ui-flutter-image-no-semantics",
    severity: Severity::Medium,
    message: "Виджет Image во Flutter без семантической подписи (нет semanticLabel и обёртки Semantics). Связано с WCAG 2.1, критерий успеха 1.1.1 «Нетекстовый контент» (уровень A). Передайте semanticLabel или оберните в Semantics(label: ...); для декоративных задайте excludeFromSemantics: true.",
};

const IOS_A11Y_DISABLED: UiRule = UiRule {
    id: "ui-ios-accessibility-disabled",
    severity: Severity::Medium,
    message: "Доступность элемента iOS отключена (isAccessibilityElement = false): элемент станет невидим для VoiceOver. Связано с WCAG 2.1, критерий успеха 4.1.2 «Имя, роль, значение» (уровень A). Не отключайте доступность у значимых элементов; задавайте accessibilityLabel.",
};

/// Регулярное выражение явного отключения доступности iOS: isAccessibilityElement,
/// присвоенный false (Swift) или NO (Objective-C).
fn ios_a11y_off_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)isAccessibilityElement\s*=\s*(?:false|NO)\b")
            .expect("встроенный паттерн отключения доступности iOS невалиден")
    })
}

/// Регулярное выражение вызова конструктора виджета Image во Flutter, включая
/// именованные конструкторы (Image.asset/Image.network/Image.file/Image.memory) и их
/// аргументы в скобках. Поскольку крейт regex не балансирует скобки, захватываем до
/// конца строки или до закрывающей скобки верхнего уровня эвристически: берём от
/// имени Image до ближайшей закрывающей скобки на той же или соседних строках через
/// оконный разбор в анализаторе, а здесь только находим начало вызова.
fn flutter_image_start_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\bImage\s*(?:\.\s*(?:asset|network|file|memory))?\s*\(")
            .expect("встроенный паттерн вызова Image невалиден")
    })
}

/// Анализатор нативной доступности. Для Android разбирает теги изображений XML-макета
/// и требует contentDescription. Для Flutter находит вызов конструктора Image и в
/// окне его аргументов требует semanticLabel либо обёртку Semantics, либо явное
/// исключение из дерева доступности. Для iOS ловит явное отключение доступности.
fn analyze_native_a11y(content: &str, ext: &str, rel: &str, out: &mut CapabilityOutput, source: &str) {
    if ANDROID_XML_EXTS.contains(&ext) {
        for (tag, off) in find_tags(content, re_android_image()) {
            let lower = tag.to_ascii_lowercase();
            // Описание содержимого задаётся либо contentDescription, либо явным
            // исключением из дерева доступности (importantForAccessibility=no).
            // Имя атрибута проверяем как целое слово (учитывая префикс android:).
            let has_desc = has_attr(&lower, "android:contentdescription")
                || lower.contains("importantforaccessibility=\"no\"")
                || lower.contains("importantforaccessibility='no'");
            if !has_desc {
                let line = line_of_offset(content, off);
                emit(out, &ANDROID_IMAGE_NO_DESC, rel, line, evidence_of(tag), source);
            }
        }
    } else if FLUTTER_EXTS.contains(&ext) {
        for m in flutter_image_start_re().find_iter(content) {
            // Окно аргументов: от начала вызова до конца сбалансированной скобки или,
            // если баланс не сошёлся в разумных пределах, до 600 символов вперёд. Этого
            // достаточно, чтобы увидеть именованные аргументы конструктора Image.
            let start = m.start();
            let window_end = balanced_paren_end(content, m.end() - 1).unwrap_or((start + 600).min(content.len()));
            let window = &content[start..window_end];
            let lower = window.to_ascii_lowercase();
            let has_semantics = lower.contains("semanticlabel")
                || lower.contains("excludefromsemantics");
            // Обёртка Semantics(label: ...) вокруг Image: ищем слово Semantics в
            // небольшом окне ПЕРЕД вызовом Image (родительский виджет идёт раньше).
            let before_start = start.saturating_sub(200);
            let before = content[before_start..start].to_ascii_lowercase();
            let wrapped = before.contains("semantics(");
            if !has_semantics && !wrapped {
                let line = line_of_offset(content, start);
                emit(out, &FLUTTER_IMAGE_NO_SEMANTICS, rel, line, evidence_of(window), source);
            }
        }
    } else if IOS_EXTS.contains(&ext) {
        for m in ios_a11y_off_re().find_iter(content) {
            let line = line_of_offset(content, m.start());
            emit(out, &IOS_A11Y_DISABLED, rel, line, m.as_str().to_string(), source);
        }
    }
}

/// Найти позицию закрывающей скобки, парной открывающей по смещению `open_idx`.
/// Возвращает индекс символа ПОСЛЕ закрывающей скобки. Если баланс не сошёлся в
/// пределах текста, возвращает None. Учитывает только круглые скобки (для окна
/// аргументов конструктора этого достаточно; строковые литералы со скобками внутри
/// дадут чуть большее окно, что безопасно для проверки наличия подстроки).
fn balanced_paren_end(content: &str, open_idx: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    if bytes.get(open_idx) != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    let mut i = open_idx;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

// ───────────────────────── регистрация ─────────────────────────

/// Регистрирует семейство quality.ui/* (детерминированные эвристики доступности и
/// адаптивности). Каждая capability это общий обход поверх своего анализатора.
pub fn register(reg: &mut Registry) {
    reg.register(Box::new(UiCapability::new(
        "quality.ui/a11y-markup",
        "Барьеры доступности в разметке (HTML/JSX/TSX/Vue/Svelte): изображение без текстовой альтернативы (alt), поле ввода без программной подписи (label/aria-label/aria-labelledby), интерактив на неинтерактивном теге (div/span с onClick) без роли и клавиатурного обработчика.",
        MARKUP_EXTS,
        analyze_a11y_markup,
    )));
    reg.register(Box::new(UiCapability::new(
        "quality.ui/responsive",
        "Адаптивность веб-страницы: корневой HTML без метатега области просмотра (viewport) и блокировка масштабирования (user-scalable=no либо maximum-scale=1), мешающая увеличению страницы.",
        MARKUP_EXTS,
        analyze_responsive,
    )));
    reg.register(Box::new(UiCapability::new(
        "quality.ui/dark-theme",
        "Поддержка предпочитаемой цветовой схемы (тёмная тема): файл стилей задаёт фон и цвет текста явными значениями, но во всём файле нет медиазапроса prefers-color-scheme.",
        STYLE_EXTS,
        analyze_dark_theme,
    )));
    reg.register(Box::new(UiCapability::new(
        "quality.ui/focus-visible",
        "Видимость фокуса клавиатуры: стиль убирает контур фокуса (outline: none/0), но во всём файле нет восстановления видимого фокуса через :focus-visible или :focus.",
        STYLE_EXTS,
        analyze_focus_visible,
    )));
    // Размер целей нажатия охватывает три источника (веб-стили, XML-макеты Android,
    // исходники iOS), поэтому читает объединённый набор расширений и ветвится по
    // расширению внутри анализатора.
    reg.register(Box::new(UiCapability::new(
        "quality.ui/touch-target",
        "Размер цели нажатия меньше минимума доступности: для веба явные width/height меньше 44px, для Android android:layout_height/width меньше 48dp, для iOS размер кадра кнопки меньше 44pt.",
        TOUCH_EXTS,
        analyze_touch_target,
    )));
    reg.register(Box::new(UiCapability::new(
        "quality.ui/native-a11y",
        "Доступность нативного мобильного интерфейса: изображение/иконка в XML-макете Android без contentDescription, виджет Image во Flutter без semanticLabel и обёртки Semantics, элемент iOS с отключённой доступностью (isAccessibilityElement=false).",
        NATIVE_A11Y_EXTS,
        analyze_native_a11y,
    )));
}

/// Объединённый набор расширений для правила размеров целей нажатия (веб-стили плюс
/// XML-макеты Android плюс исходники iOS).
const TOUCH_EXTS: &[&str] = &[
    "css", "scss", "sass", "less", "styl", // веб-стили
    "xml", // макеты Android
    "swift", "m", "mm", // исходники iOS
];

/// Объединённый набор расширений для правил нативной доступности (XML-макеты Android
/// плюс Dart для Flutter плюс исходники iOS).
const NATIVE_A11Y_EXTS: &[&str] = &[
    "xml", // макеты Android
    "dart", // Flutter
    "swift", "m", "mm", // исходники iOS
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Уникальная пустая временная папка для файловых фикстур (без внешних зависимостей).
    fn tmp() -> PathBuf {
        let n = CNT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ailc-uiux-{}-{}", std::process::id(), n));
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

    /// Прогнать анализатор capability с данным идентификатором по корню. Берём
    /// конкретный анализатор через построение той же capability, что и в register.
    fn run_analyzer(
        analyze: Analyzer,
        exts: &'static [&'static str],
        root: &Path,
    ) -> CapabilityOutput {
        let cap = UiCapability::new("test/ui", "тест", exts, analyze);
        cap.run(&Ctx::new(root), &RunInput::default()).unwrap()
    }

    /// Сколько находок данного правила в выводе.
    fn count_rule(out: &CapabilityOutput, rule: &str) -> usize {
        out.findings.iter().filter(|f| f.rule == rule).count()
    }

    /// Истинно, если правило сработало хотя бы раз.
    fn has_rule(out: &CapabilityOutput, rule: &str) -> bool {
        count_rule(out, rule) > 0
    }

    // ───────────────────────── вспомогательные функции разбора ─────────────────────────

    #[test]
    fn find_tags_ловит_однострочный_и_многострочный_тег() {
        let html = "<img src=\"a\">\n<img\n  src=\"b\"\n  alt=\"b\"\n>\n";
        let tags = find_tags(html, re_img());
        assert_eq!(tags.len(), 2, "оба тега img должны найтись, в т.ч. многострочный");
    }

    #[test]
    fn line_of_offset_честный_номер_строки() {
        let t = "a\nb\nc";
        assert_eq!(line_of_offset(t, 0), 1);
        assert_eq!(line_of_offset(t, 2), 2);
        assert_eq!(line_of_offset(t, 4), 3);
    }

    #[test]
    fn maximum_scale_распознаёт_единицу_и_не_путает_с_другими() {
        assert!(maximum_scale_is_one("maximum-scale=1"));
        assert!(maximum_scale_is_one("maximum-scale = 1.0"));
        assert!(maximum_scale_is_one("maximum-scale=1.00"));
        assert!(!maximum_scale_is_one("maximum-scale=1.5"));
        assert!(!maximum_scale_is_one("maximum-scale=10"));
        assert!(!maximum_scale_is_one("maximum-scale=2"));
        assert!(!maximum_scale_is_one("initial-scale=1"));
    }

    #[test]
    fn balanced_paren_end_находит_парную_скобку() {
        let s = "Image.asset('a', semanticLabel: f(x))rest";
        let open = s.find('(').unwrap();
        let end = balanced_paren_end(s, open).unwrap();
        assert_eq!(&s[end..], "rest", "окно завершается на парной закрывающей скобке");
    }

    // ───────────────────────── a11y-markup: alt у изображения ─────────────────────────

    #[test]
    fn img_без_alt_срабатывает() {
        let dir = tmp();
        write(&dir, "page.html", "<div><img src=\"logo.png\"></div>\n");
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-img-without-alt"), 1, "img без alt должен сработать");
        assert_eq!(out.findings[0].location.as_ref().unwrap().line, 1, "честная строка");
    }

    #[test]
    fn a11y_только_dom_элементы_не_react_компоненты() {
        // Строчное имя это DOM-элемент (его a11y проверяем), заглавное это React-компонент
        // (shadcn <Input>/<Select>, Next.js <Image>): его подпись задаётся композицией и из
        // тега не видна, проверять нельзя. Это убирает массовые ложные срабатывания.
        let dir = tmp();
        write(
            &dir,
            "form.tsx",
            "<input type=\"text\" />\n<Input value={x} />\n<Select onValueChange={f} />\n<Image src={s} />\n",
        );
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(
            count_rule(&out, "ui-input-without-label"),
            1,
            "находка только на строчном <input>, а не на компонентах <Input>/<Select>"
        );
        assert_eq!(
            count_rule(&out, "ui-img-without-alt"),
            0,
            "Next.js <Image> это компонент, не DOM <img>, alt не проверяем"
        );
        assert_eq!(
            out.findings[0].location.as_ref().unwrap().line,
            1,
            "находка именно на строчном <input> (строка 1)"
        );
    }

    #[test]
    fn img_с_alt_не_срабатывает() {
        let dir = tmp();
        write(&dir, "page.html", "<img src=\"logo.png\" alt=\"логотип компании\">\n");
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-img-without-alt"), 0, "img с alt не должен срабатывать");
    }

    #[test]
    fn img_с_пустым_alt_декоративный_не_срабатывает() {
        let dir = tmp();
        write(&dir, "page.html", "<img src=\"bg.png\" alt=\"\">\n");
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-img-without-alt"), 0, "пустой alt валиден для декора");
    }

    #[test]
    fn img_jsx_не_путается_с_соседним_тегом() {
        let dir = tmp();
        write(
            &dir,
            "Card.tsx",
            "<><img src=\"a.png\" alt=\"первая\" /><img src=\"b.png\" /></>\n",
        );
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-img-without-alt"), 1, "ровно второй img без alt");
    }

    #[test]
    fn img_многострочный_без_alt_срабатывает() {
        // Тег разнесён на несколько строк, alt отсутствует: должно сработать.
        let dir = tmp();
        write(&dir, "page.html", "<img\n  src=\"logo.png\"\n  width=\"40\"\n>\n");
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-img-without-alt"), 1, "многострочный img без alt");
    }

    // ───────────────────────── a11y-markup: подпись поля ввода ─────────────────────────

    #[test]
    fn input_без_подписи_срабатывает() {
        let dir = tmp();
        write(&dir, "form.html", "<form><input type=\"text\" name=\"q\"></form>\n");
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-input-without-label"), 1, "поле без подписи срабатывает");
    }

    #[test]
    fn input_с_aria_label_не_срабатывает() {
        let dir = tmp();
        write(&dir, "form.html", "<input type=\"text\" aria-label=\"поиск\">\n");
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-input-without-label"), 0, "aria-label снимает находку");
    }

    #[test]
    fn input_с_id_для_внешнего_label_не_срабатывает() {
        let dir = tmp();
        write(&dir, "form.html", "<label for=\"q\">Поиск</label><input id=\"q\" type=\"text\">\n");
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-input-without-label"), 0, "id допускает внешний label");
    }

    #[test]
    fn input_тип_кнопка_не_срабатывает() {
        let dir = tmp();
        write(&dir, "form.html", "<input type=\"submit\" value=\"Отправить\">\n");
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-input-without-label"), 0, "кнопка не требует label");
    }

    #[test]
    fn input_скрытый_не_срабатывает() {
        let dir = tmp();
        write(&dir, "form.html", "<input type=\"hidden\" name=\"csrf\" value=\"x\">\n");
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-input-without-label"), 0, "скрытое поле не требует label");
    }

    // ───────────────────────── a11y-markup: интерактив на неинтерактивном теге ─────────────────────────

    #[test]
    fn div_onclick_без_роли_срабатывает() {
        let dir = tmp();
        write(&dir, "App.jsx", "<div onClick={open}>Открыть</div>\n");
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-clickable-nonsemantic"), 1, "div+onClick без role");
    }

    #[test]
    fn div_onclick_с_ролью_и_клавиатурой_не_срабатывает() {
        let dir = tmp();
        write(
            &dir,
            "App.jsx",
            "<div role=\"button\" tabIndex={0} onClick={open} onKeyDown={open}>Открыть</div>\n",
        );
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-clickable-nonsemantic"), 0, "role и onKeyDown снимают");
    }

    #[test]
    fn кнопка_с_onclick_не_срабатывает() {
        let dir = tmp();
        write(&dir, "App.jsx", "<button onClick={open}>Открыть</button>\n");
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-clickable-nonsemantic"), 0, "button не неинтерактивен");
    }

    // ───────────────────────── responsive: viewport ─────────────────────────

    #[test]
    fn html_без_viewport_срабатывает() {
        let dir = tmp();
        write(&dir, "index.html", "<html><head><title>Т</title></head><body></body></html>\n");
        let out = run_analyzer(analyze_responsive, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-viewport-missing"), 1, "корневой html без viewport");
    }

    #[test]
    fn html_с_viewport_не_срабатывает() {
        let dir = tmp();
        write(
            &dir,
            "index.html",
            "<html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head></html>\n",
        );
        let out = run_analyzer(analyze_responsive, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-viewport-missing"), 0, "viewport присутствует");
    }

    #[test]
    fn фрагмент_без_html_не_требует_viewport() {
        // Компонент без корневого тега html не образует документ, требовать viewport
        // от него нельзя, иначе массовое ложное срабатывание на каждом компоненте.
        let dir = tmp();
        write(&dir, "Card.tsx", "export const Card = () => <div>карточка</div>;\n");
        let out = run_analyzer(analyze_responsive, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-viewport-missing"), 0, "фрагмент не документ");
    }

    #[test]
    fn viewport_user_scalable_no_срабатывает() {
        let dir = tmp();
        write(
            &dir,
            "index.html",
            "<html><meta name=\"viewport\" content=\"width=device-width, user-scalable=no\"></html>\n",
        );
        let out = run_analyzer(analyze_responsive, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-viewport-zoom-blocked"), 1, "user-scalable=no срабатывает");
    }

    #[test]
    fn viewport_maximum_scale_1_срабатывает() {
        let dir = tmp();
        write(
            &dir,
            "index.html",
            "<html><meta name=\"viewport\" content=\"width=device-width, maximum-scale=1.0\"></html>\n",
        );
        let out = run_analyzer(analyze_responsive, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-viewport-zoom-blocked"), 1, "maximum-scale=1 срабатывает");
    }

    #[test]
    fn viewport_initial_scale_1_не_срабатывает() {
        // initial-scale=1 это норма и не должна путаться с maximum-scale=1.
        let dir = tmp();
        write(
            &dir,
            "index.html",
            "<html><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></html>\n",
        );
        let out = run_analyzer(analyze_responsive, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-viewport-zoom-blocked"), 0, "initial-scale=1 это норма");
    }

    // ───────────────────────── dark-theme ─────────────────────────

    #[test]
    fn явные_цвета_без_prefers_color_scheme_срабатывают() {
        let dir = tmp();
        write(&dir, "theme.css", "body { background: #ffffff; color: #111111; }\n");
        let out = run_analyzer(analyze_dark_theme, STYLE_EXTS, &dir);
        assert!(has_rule(&out, "ui-no-prefers-color-scheme"), "явные цвета без тёмной темы");
    }

    #[test]
    fn явные_цвета_с_prefers_color_scheme_не_срабатывают() {
        let dir = tmp();
        write(
            &dir,
            "theme.css",
            "body { background: #fff; color: #111; }\n@media (prefers-color-scheme: dark) { body { background: #000; } }\n",
        );
        let out = run_analyzer(analyze_dark_theme, STYLE_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-no-prefers-color-scheme"), 0, "prefers-color-scheme снимает");
    }

    #[test]
    fn стиль_без_явных_цветов_не_срабатывает() {
        let dir = tmp();
        write(&dir, "layout.css", ".row { display: flex; gap: 8px; }\n");
        let out = run_analyzer(analyze_dark_theme, STYLE_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-no-prefers-color-scheme"), 0, "нет явных цветов");
    }

    #[test]
    fn dark_theme_одна_находка_на_файл() {
        // Несколько цветовых объявлений в файле дают одну находку, а не по одной на
        // каждое объявление: правило про отсутствие тёмной темы в файле, а не про цвет.
        let dir = tmp();
        write(
            &dir,
            "t.css",
            "a { color: #111; }\nb { color: #222; }\nc { background: #333; }\n",
        );
        let out = run_analyzer(analyze_dark_theme, STYLE_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-no-prefers-color-scheme"), 1, "одна находка на файл");
    }

    // ───────────────────────── focus-visible ─────────────────────────

    #[test]
    fn outline_none_без_focus_срабатывает() {
        let dir = tmp();
        write(&dir, "buttons.css", "button { outline: none; }\n");
        let out = run_analyzer(analyze_focus_visible, STYLE_EXTS, &dir);
        assert!(has_rule(&out, "ui-focus-outline-removed"), "outline:none без :focus");
    }

    #[test]
    fn outline_none_с_focus_visible_не_срабатывает() {
        let dir = tmp();
        write(
            &dir,
            "buttons.css",
            "button { outline: none; }\nbutton:focus-visible { outline: 2px solid #0a84ff; }\n",
        );
        let out = run_analyzer(analyze_focus_visible, STYLE_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-focus-outline-removed"), 0, ":focus-visible восстанавливает");
    }

    #[test]
    fn стиль_без_снятия_контура_не_срабатывает() {
        let dir = tmp();
        write(&dir, "buttons.css", "button { color: #111; padding: 8px; }\n");
        let out = run_analyzer(analyze_focus_visible, STYLE_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-focus-outline-removed"), 0, "контур не снят");
    }

    // ───────────────────────── touch-target ─────────────────────────

    #[test]
    fn web_маленькая_кнопка_срабатывает() {
        let dir = tmp();
        write(&dir, "btn.css", ".icon { width: 24px; height: 24px; }\n");
        let out = run_analyzer(analyze_touch_target, TOUCH_EXTS, &dir);
        assert!(has_rule(&out, "ui-touch-target-small-web"), "24px ниже минимума");
    }

    #[test]
    fn web_достаточная_кнопка_не_срабатывает() {
        let dir = tmp();
        write(&dir, "btn.css", ".icon { width: 48px; height: 48px; }\n");
        let out = run_analyzer(analyze_touch_target, TOUCH_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-touch-target-small-web"), 0, "48px достаточно");
    }

    #[test]
    fn web_граница_44px_не_срабатывает() {
        let dir = tmp();
        write(&dir, "btn.css", ".icon { width: 44px; }\n");
        let out = run_analyzer(analyze_touch_target, TOUCH_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-touch-target-small-web"), 0, "44px это порог");
    }

    #[test]
    fn android_маленькая_цель_срабатывает() {
        let dir = tmp();
        write(
            &dir,
            "res/layout/main.xml",
            "<Button android:layout_width=\"32dp\" android:layout_height=\"32dp\" />\n",
        );
        let out = run_analyzer(analyze_touch_target, TOUCH_EXTS, &dir);
        assert!(has_rule(&out, "ui-touch-target-small-android"), "32dp ниже 48dp");
    }

    #[test]
    fn android_достаточная_цель_не_срабатывает() {
        let dir = tmp();
        write(
            &dir,
            "res/layout/main.xml",
            "<Button android:layout_width=\"48dp\" android:layout_height=\"48dp\" />\n",
        );
        let out = run_analyzer(analyze_touch_target, TOUCH_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-touch-target-small-android"), 0, "48dp достаточно");
    }

    #[test]
    fn ios_маленький_кадр_срабатывает() {
        let dir = tmp();
        write(
            &dir,
            "View.swift",
            "let frame = CGRect(x: 0, y: 0, width: 20, height: 20)\n",
        );
        let out = run_analyzer(analyze_touch_target, TOUCH_EXTS, &dir);
        assert!(has_rule(&out, "ui-touch-target-small-ios"), "кадр 20pt ниже минимума");
    }

    #[test]
    fn ios_размер_вне_контекста_кадра_не_срабатывает() {
        // width/height без CGSize/CGRect/frame в строке это не размер цели нажатия.
        let dir = tmp();
        write(&dir, "Model.swift", "let width: Int = 10\n");
        let out = run_analyzer(analyze_touch_target, TOUCH_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-touch-target-small-ios"), 0, "не контекст кадра");
    }

    // ───────────────────────── native-a11y ─────────────────────────

    #[test]
    fn android_image_без_contentdescription_срабатывает() {
        let dir = tmp();
        write(
            &dir,
            "res/layout/row.xml",
            "<ImageView\n    android:layout_width=\"48dp\"\n    android:layout_height=\"48dp\"\n    android:src=\"@drawable/ic\" />\n",
        );
        let out = run_analyzer(analyze_native_a11y, NATIVE_A11Y_EXTS, &dir);
        assert!(has_rule(&out, "ui-android-image-no-contentdescription"), "нет contentDescription");
    }

    #[test]
    fn android_image_с_contentdescription_не_срабатывает() {
        let dir = tmp();
        write(
            &dir,
            "res/layout/row.xml",
            "<ImageView\n    android:layout_width=\"48dp\"\n    android:contentDescription=\"@string/avatar\"\n    android:src=\"@drawable/ic\" />\n",
        );
        let out = run_analyzer(analyze_native_a11y, NATIVE_A11Y_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-android-image-no-contentdescription"), 0, "есть описание");
    }

    #[test]
    fn android_image_декоративный_не_срабатывает() {
        // Явное исключение из дерева доступности это осознанный выбор для декора.
        let dir = tmp();
        write(
            &dir,
            "res/layout/row.xml",
            "<ImageView android:src=\"@drawable/bg\" android:importantForAccessibility=\"no\" />\n",
        );
        let out = run_analyzer(analyze_native_a11y, NATIVE_A11Y_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-android-image-no-contentdescription"), 0, "декор исключён");
    }

    #[test]
    fn flutter_image_без_semantics_срабатывает() {
        let dir = tmp();
        write(&dir, "lib/card.dart", "Widget build() => Image.asset('assets/logo.png');\n");
        let out = run_analyzer(analyze_native_a11y, NATIVE_A11Y_EXTS, &dir);
        assert!(has_rule(&out, "ui-flutter-image-no-semantics"), "Image.asset без semanticLabel");
    }

    #[test]
    fn flutter_image_с_semantic_label_не_срабатывает() {
        let dir = tmp();
        write(
            &dir,
            "lib/card.dart",
            "Widget build() => Image.asset('assets/logo.png', semanticLabel: 'логотип');\n",
        );
        let out = run_analyzer(analyze_native_a11y, NATIVE_A11Y_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-flutter-image-no-semantics"), 0, "semanticLabel снимает");
    }

    #[test]
    fn flutter_image_в_обёртке_semantics_не_срабатывает() {
        let dir = tmp();
        write(
            &dir,
            "lib/card.dart",
            "Widget build() => Semantics(label: 'логотип', child: Image.asset('a.png'));\n",
        );
        let out = run_analyzer(analyze_native_a11y, NATIVE_A11Y_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-flutter-image-no-semantics"), 0, "обёртка Semantics снимает");
    }

    #[test]
    fn flutter_image_excludefromsemantics_не_срабатывает() {
        let dir = tmp();
        write(
            &dir,
            "lib/card.dart",
            "Widget build() => Image.asset('assets/bg.png', excludeFromSemantics: true);\n",
        );
        let out = run_analyzer(analyze_native_a11y, NATIVE_A11Y_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-flutter-image-no-semantics"), 0, "excludeFromSemantics снимает");
    }

    #[test]
    fn ios_accessibility_disabled_срабатывает() {
        let dir = tmp();
        write(&dir, "View.swift", "button.isAccessibilityElement = false\n");
        let out = run_analyzer(analyze_native_a11y, NATIVE_A11Y_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-ios-accessibility-disabled"), 1, "отключение доступности");
    }

    #[test]
    fn ios_accessibility_enabled_не_срабатывает() {
        let dir = tmp();
        write(&dir, "View.swift", "button.isAccessibilityElement = true\n");
        let out = run_analyzer(analyze_native_a11y, NATIVE_A11Y_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-ios-accessibility-disabled"), 0, "доступность включена");
    }

    // ───────────────────────── инвариант пропуска и тест-файлы ─────────────────────────

    #[test]
    fn пустой_корень_даёт_явный_пропуск() {
        let dir = tmp();
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert!(out.skipped.is_some(), "ноль файлов это явный пропуск, не успех");
    }

    #[test]
    fn тест_файлы_не_анализируются() {
        // Фикстура с заведомым нарушением в тест-файле не должна давать находку.
        let dir = tmp();
        write(&dir, "Button.test.tsx", "<img src=\"x.png\">\n");
        let out = run_analyzer(analyze_a11y_markup, MARKUP_EXTS, &dir);
        assert_eq!(count_rule(&out, "ui-img-without-alt"), 0, "тест-файлы вне охвата");
    }

    // ───────────────────────── полнота перечня идентификаторов правил ─────────────────────────

    #[test]
    fn перечень_идентификаторов_правил_полон_и_уникален() {
        // Все идентификаторы правил этого слоя собраны в одном перечне. Он служит
        // источником истины для классификации достоверности (соседняя дорожка вносит
        // эти идентификаторы в contracts::rule_confidence; желаемые классы перечислены
        // в api_changes). Тест защищает от случайного дубликата идентификатора и
        // фиксирует ровно тот набор, который заявлен оркестратору.
        let ids = [
            IMG_NO_ALT.id,
            INPUT_NO_LABEL.id,
            CLICKABLE_NONSEMANTIC.id,
            VIEWPORT_MISSING.id,
            VIEWPORT_ZOOM_BLOCKED.id,
            NO_PREFERS_COLOR_SCHEME.id,
            FOCUS_OUTLINE_REMOVED.id,
            TOUCH_SMALL_WEB.id,
            TOUCH_SMALL_ANDROID.id,
            TOUCH_SMALL_IOS.id,
            ANDROID_IMAGE_NO_DESC.id,
            FLUTTER_IMAGE_NO_SEMANTICS.id,
            IOS_A11Y_DISABLED.id,
        ];
        let unique: std::collections::HashSet<&str> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len(), "идентификаторы правил должны быть уникальны");
        assert_eq!(ids.len(), 13, "слой объявляет ровно 13 правил");
        // Все идентификаторы в едином пространстве имён quality.ui/* по префиксу ui-.
        assert!(ids.iter().all(|id| id.starts_with("ui-")), "единый префикс ui-");
    }
}
