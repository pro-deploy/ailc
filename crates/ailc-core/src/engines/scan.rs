//! E1 ScanEngine: обойти дерево файлов один раз, применить таблицу правил,
//! собрать `Finding[]` + метрики.
//!
//! Это тот самый движок, который в ailc был переизобретён в ~35 файлах. Здесь он
//! один. Разные capability (security.scan, quality.check, owasp, pii, …) дают ему
//! РАЗНЫЕ таблицы правил, и это даёт ноль дублирования логики обхода, матча, эмита.
//!
//! Кроме построчного матча движок умеет МНОГОСТРОЧНЫЙ режим (целый файл или
//! скользящее окно из нескольких строк) для классов потока данных и секретов,
//! разорванных переносом строки или конкатенацией строковых литералов. Режим
//! выбирается самим матчером (см. [`Matcher`]), поэтому таблицы построчных правил
//! остаются без изменений: новые варианты добавлены аддитивно.

use super::walk::{is_test_path, walk_stats, WalkStats};
use ailc_contracts::{CapabilityOutput, Ctx, Finding, Location, Result, RunInput, Severity};
use regex::Regex;
use std::fs;

/// Предельная длина одной физической строки, после которой она считается
/// вне охвата. Минифицированные бандлы (один JS-файл в десятки тысяч символов на
/// строке) дают и катастрофически медленный regex, и сплошной поток ложных
/// срабатываний по случайным подстрокам. Такую строку движок пропускает и
/// помечает как out-of-scope, честно сообщая человеку об ограничении охвата.
pub const MAX_LINE_LEN: usize = 2_000;

/// Сколько физических строк объединяет скользящее окно по умолчанию, если правило
/// не задало собственный размер. Двух-трёх строк достаточно, чтобы поймать сток и
/// источник, разнесённые переносом аргумента форматтером, не раздувая ложные связи.
pub const DEFAULT_WINDOW: usize = 3;

/// Как правило решает, сработала ли строка (или фрагмент из нескольких строк).
///
/// Один движок переиспользуется всеми сканерами (secret/owasp/pii/iac/…), поэтому
/// и набор способов матча живёт здесь, а не в каждой capability. Строгие regex суть
/// дефолт: они описывают РЕАЛЬНУЮ форму артефакта (AKIA+16, PEM-заголовок), а не
/// случайное вхождение слова, поэтому не ловят сами строки определений правил.
///
/// Варианты делятся по ОБЛАСТИ матча. Построчные (`Regex`, `Entropy`, `Predicate`)
/// применяются к одной физической строке. Многострочные (`MultiLineRegex`,
/// `WindowRegex`, `MultiLineEntropy`) применяются к целому файлу или скользящему
/// окну строк, что ловит секрет/сток, разорванный переносом или конкатенацией.
pub enum Matcher {
    /// Регекс матчит строку как есть (реальная форма ключа или токена).
    Regex(Regex),
    /// Регекс выделяет «значение» (capture-группа 1), и оно засчитывается секретом
    /// только если его энтропия Шеннона не ниже `min_entropy_bits`, что отсекает обычные
    /// слова-плейсхолдеры (`password = "changeme"`) от реальных случайных секретов.
    Entropy {
        re: Regex,
        min_entropy_bits: f64,
    },
    /// Произвольный предикат, для правил, которым regex избыточен (smell-эвристики).
    Predicate(fn(&str) -> bool),
    /// Регекс по ВСЕМУ файлу сразу (флаг `(?s)` для переноса). Применяется к двум
    /// представлениям: к исходному тексту и к тексту со склеенными соседними
    /// строковыми литералами, поэтому ловит PEM-ключ, разнесённый по строкам, и
    /// секрет, собранный конкатенацией. Каждое совпадение даёт находку с номером
    /// строки начала совпадения.
    MultiLineRegex(Regex),
    /// Регекс по скользящему окну из `window` физических строк (склеенных через
    /// `\n`). Для правил потока данных (SSRF, open-redirect, path-traversal, SSTI),
    /// где сток и источник могут оказаться на соседних строках из-за переноса
    /// аргумента форматтером. `window` ограничивает зону связывания, чтобы не
    /// порождать ложные связи между далёкими строками.
    WindowRegex {
        re: Regex,
        window: usize,
    },
    /// Энтропийный вариант по всему файлу: regex с `(?s)` выделяет значение
    /// (capture-группа 1), а порог энтропии решает, секрет это или плейсхолдер.
    /// Применяется и к склеенным конкатенациям, поэтому ловит секрет, собранный из
    /// нескольких литералов.
    MultiLineEntropy {
        re: Regex,
        min_entropy_bits: f64,
    },
}

impl Matcher {
    /// Скомпилировать строгий regex. Паттерны суть статические литералы, выверенные при
    /// сборке; `expect` тут уместен (и не ловится smell-правилом `panic-path`).
    pub fn regex(pattern: &str) -> Self {
        Matcher::Regex(Regex::new(pattern).expect("встроенный паттерн правила невалиден"))
    }

    /// Regex + порог энтропии на capture-группе 1.
    pub fn entropy(pattern: &str, min_entropy_bits: f64) -> Self {
        Matcher::Entropy {
            re: Regex::new(pattern).expect("встроенный паттерн правила невалиден"),
            min_entropy_bits,
        }
    }

    /// Многострочный regex по всему файлу. Паттерн обычно начинается с `(?s)`, чтобы
    /// точка покрывала перенос строки (PEM-ключ, разнесённый конкатенацией).
    pub fn multiline_regex(pattern: &str) -> Self {
        Matcher::MultiLineRegex(Regex::new(pattern).expect("встроенный паттерн правила невалиден"))
    }

    /// Скользящее окно из `window` строк. При `window` равном нулю используется
    /// [`DEFAULT_WINDOW`], чтобы правило никогда не выродилось в построчный матч.
    pub fn window_regex(pattern: &str, window: usize) -> Self {
        Matcher::WindowRegex {
            re: Regex::new(pattern).expect("встроенный паттерн правила невалиден"),
            window: if window == 0 { DEFAULT_WINDOW } else { window },
        }
    }

    /// Многострочный энтропийный матчер по всему файлу: regex с `(?s)` выделяет
    /// значение (группа 1), порог энтропии отсекает плейсхолдеры.
    pub fn multiline_entropy(pattern: &str, min_entropy_bits: f64) -> Self {
        Matcher::MultiLineEntropy {
            re: Regex::new(pattern).expect("встроенный паттерн правила невалиден"),
            min_entropy_bits,
        }
    }

    /// Истина для матчеров, работающих не по одной строке, а по фрагменту из
    /// нескольких строк (весь файл или окно). Движок для них идёт другим путём.
    pub fn is_multiline(&self) -> bool {
        matches!(
            self,
            Matcher::MultiLineRegex(_)
                | Matcher::WindowRegex { .. }
                | Matcher::MultiLineEntropy { .. }
        )
    }

    /// Достоверна ли находка СТРУКТУРНО (точная сигнатура артефакта/энтропийный
    /// фильтр) или это ЭВРИСТИКА (произвольный предикат, грубая близость стока и
    /// источника в пределах окна). Это РАЗМЕРНОСТЬ УВЕРЕННОСТИ детектора, а НЕ флаг
    /// `verified`.
    ///
    /// Важно различать два независимых понятия этого движка. Поле `verified` у
    /// находки означает «заземлена на конкретный file:line и потому учитывается
    /// гейтом» (анти-гейминг): любая детерминированная находка сканера ему
    /// удовлетворяет, поэтому `verified` остаётся истинным для всех правил, иначе
    /// гейт молча отбросит реальные находки (см. gate.rs: ветка `!f.verified`).
    /// Уверенность же (структурная сигнатура против эвристики) выражается ОТДЕЛЬНОЙ
    /// системой `Confidence` в контрактах (карта по идентификатору правила,
    /// `Finding::confidence`/`is_signal`), которая направляет низкоуверенные находки
    /// в советы, не теряя их. Метод оставлен публичным как точное, языко-независимое
    /// определение структурности правила для этой карты и для будущего состязательного
    /// прохода верификации.
    pub fn is_structural(&self) -> bool {
        match self {
            // Точная форма артефакта или энтропийный фильтр: структурный сигнал.
            Matcher::Regex(_)
            | Matcher::Entropy { .. }
            | Matcher::MultiLineRegex(_)
            | Matcher::MultiLineEntropy { .. } => true,
            // Произвольный предикат и оконная близость: эвристика, не доказательство.
            Matcher::Predicate(_) | Matcher::WindowRegex { .. } => false,
        }
    }

    pub fn is_match(&self, line: &str) -> bool {
        match self {
            Matcher::Regex(re) => re.is_match(line),
            Matcher::Entropy {
                re,
                min_entropy_bits,
            } => re
                .captures(line)
                .and_then(|c| c.get(1))
                .is_some_and(|m| shannon_entropy_bits(m.as_str()) >= *min_entropy_bits),
            Matcher::Predicate(f) => f(line),
            // Многострочные матчеры по одной строке не вызываются (движок ведёт их
            // отдельным путём), но для полноты применяем тот же критерий к строке.
            Matcher::MultiLineRegex(re) => re.is_match(line),
            Matcher::WindowRegex { re, .. } => re.is_match(line),
            Matcher::MultiLineEntropy {
                re,
                min_entropy_bits,
            } => re
                .captures(line)
                .and_then(|c| c.get(1))
                .is_some_and(|m| shannon_entropy_bits(m.as_str()) >= *min_entropy_bits),
        }
    }
}

/// Энтропия Шеннона строки в битах на символ. Случайные токены дают примерно от 3.5 до 5,
/// обычные слова и плейсхолдеры дают заметно меньше.
fn shannon_entropy_bits(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    for ch in s.chars() {
        *counts.entry(ch).or_default() += 1;
    }
    let len = s.chars().count() as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Одно правило сканера: какие расширения, как матчить строку, что эмитить.
pub struct Rule {
    pub id: &'static str,
    pub severity: Severity,
    /// Пустой список = применять к любым текстовым файлам.
    pub exts: &'static [&'static str],
    pub matcher: Matcher,
    pub message: &'static str,
}

/// Регекс границы между двумя соседними строковыми литералами: закрывающая кавычка,
/// далее пробелы и переводы строки, необязательный знак `+`, снова пробелы и переводы
/// строки, и открывающая кавычка ТОГО ЖЕ ТИПА. Крейт `regex` не поддерживает обратные
/// ссылки, поэтому одинаковость кавычек обеспечивается двумя явными ветками альтернации:
/// первая для двойных кавычек, вторая для одинарных. Разнотипная склейка `"..."` и
/// `'...'` не матчится ни одной веткой. Перенос строки внутри границы допускается,
/// поэтому склейка ловит конкатенацию, разорванную на несколько физических строк.
fn joiner_re() -> &'static Regex {
    use std::sync::OnceLock;
    static JOINER: OnceLock<Regex> = OnceLock::new();
    JOINER.get_or_init(|| {
        Regex::new(r#""[ \t\r\n]*\+?[ \t\r\n]*"|'[ \t\r\n]*\+?[ \t\r\n]*'"#)
            .expect("встроенный паттерн склейки литералов невалиден")
    })
}

/// Склеить соседние конкатенируемые строковые литералы в одну строку (см.
/// [`joiner_re`]). Тонкая обёртка над [`JoinedText::build`] для случаев, когда нужен
/// только результирующий текст без карты смещений (например, в юнит-тестах).
/// Используется тестами склейки и подключается к секрет-правилам в Волне 3, когда
/// таблица секретов в lib.rs получит правила со scope File.
#[allow(dead_code)]
fn join_concatenated_literals(content: &str) -> String {
    JoinedText::build(content).text
}

/// Текст со склеенными литералами плюс карта обратного перевода смещений в исходный
/// текст. Склейка только УДАЛЯЕТ символы (границу между литералами), поэтому каждому
/// смещению в склеенном тексте однозначно соответствует смещение в исходном, и номер
/// строки находки остаётся ЧЕСТНЫМ (указывает на реальную строку файла), даже когда
/// конкатенация была разорвана переносом строки.
struct JoinedText {
    /// Склеенный текст.
    text: String,
    /// Точки переноса: пары (смещение в склеенном тексте, смещение в исходном) в
    /// возрастающем порядке. Между двумя соседними точками отображение линейно со
    /// сдвигом, поэтому перевод смещения сводится к поиску ближайшей точки слева.
    map: Vec<(usize, usize)>,
}

impl JoinedText {
    /// Построить склеенный текст и карту смещений ОДНИМ проходом. Этого достаточно
    /// даже для цепочек из трёх и более кусков: границы между соседними литералами не
    /// перекрываются (каждая забирает закрывающую кавычку левого и открывающую правого
    /// литерала, а это разные кавычки), поэтому `find_iter` за один проход находит и
    /// удаляет их все, схлопывая `"a"+"b"+"c"` в `"abc"`. Один проход исключает и
    /// сложную композицию карт, и риск рассинхронизации смещений.
    fn build(content: &str) -> Self {
        let re = joiner_re();
        let mut text = String::with_capacity(content.len());
        // Точки переноса: (смещение в склеенном тексте, смещение в исходном). Старт
        // тождественен, чтобы перевод любого смещения до первой границы был точным.
        let mut map: Vec<(usize, usize)> = vec![(0, 0)];
        let mut cur = 0usize;
        for m in re.find_iter(content) {
            // Скопировать кусок до границы и записать точку переноса: позиция конца
            // скопированного в склеенном тексте отображается в позицию начала границы
            // в исходном; удалённая граница [m.start(), m.end()) пропускается.
            text.push_str(&content[cur..m.start()]);
            map.push((text.len(), m.start()));
            cur = m.end();
        }
        text.push_str(&content[cur..]);
        Self { text, map }
    }

    /// Перевести смещение в склеенном тексте в смещение в исходном тексте.
    fn to_source(&self, joined_off: usize) -> usize {
        translate(&self.map, joined_off)
    }
}

/// Перевести смещение через карту переносов: между точками карты отображение
/// линейно (одинаковый сдвиг), поэтому к найденной слева точке прибавляем смещение
/// от неё. Карта всегда непуста и начинается с (0, 0).
fn translate(map: &[(usize, usize)], off: usize) -> usize {
    // Ближайшая точка с from_off <= off.
    let mut base = (0usize, 0usize);
    for &(from_off, to_off) in map {
        if from_off <= off {
            base = (from_off, to_off);
        } else {
            break;
        }
    }
    base.1 + (off - base.0)
}

/// Номер строки (с единицы), на которой начинается байтовое смещение `byte_off` в
/// тексте `content`. Нужен, чтобы многострочное совпадение указывало человеку на
/// строку начала артефакта, а не на абстрактный «весь файл».
fn line_of_offset(content: &str, byte_off: usize) -> u32 {
    let upto = byte_off.min(content.len());
    (content[..upto].bytes().filter(|&b| b == b'\n').count() as u32) + 1
}

/// Строки (с единицы, включительно), занятые встроенными тестами Rust:
/// `#[cfg(test)] mod ... { ... }` и `#[cfg(test)] fn ...`. В Rust тесты живут ВНУТРИ
/// исходного файла, а не в отдельном, поэтому путь-ориентированный `is_test_path` их не
/// видит. Без этого тестовые фикстуры (строки с `os.system`, `http://10.0.0.1` и т.п.) и
/// `unwrap`/`panic` в тестах давали ложные срабатывания. Конец блока определяем по отбивке
/// rustfmt: первая последующая строка с той же колонкой, начинающаяся с `}`. Это покрывает
/// идиоматичный отформатированный код; редкие неформатированные случаи могут не попасть.
fn cfg_test_line_ranges(content: &str) -> Vec<(u32, u32)> {
    let lines: Vec<&str> = content.lines().collect();
    let indent = |s: &str| s.len() - s.trim_start().len();
    let is_decl = |t: &str| {
        t.starts_with("mod ")
            || t.starts_with("pub mod ")
            || t.starts_with("fn ")
            || t.starts_with("pub fn ")
            || t.starts_with("async fn ")
            || t.starts_with("pub async fn ")
            || t.starts_with("pub(crate) fn ")
    };
    let mut ranges = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        if lines[i].trim_start().starts_with("#[cfg(test)]") {
            // Объявление mod/fn в пределах нескольких строк после атрибута (между ними
            // могут стоять другие атрибуты, например #[tokio::test]).
            let mut j = i + 1;
            while j < lines.len() && j <= i + 4 && !is_decl(lines[j].trim_start()) {
                j += 1;
            }
            if j < lines.len() && is_decl(lines[j].trim_start()) {
                let decl_indent = indent(lines[j]);
                let mut end = lines.len() - 1;
                let mut k = j + 1;
                while k < lines.len() {
                    let l = lines[k];
                    if !l.trim().is_empty()
                        && indent(l) == decl_indent
                        && l.trim_start().starts_with('}')
                    {
                        end = k;
                        break;
                    }
                    k += 1;
                }
                ranges.push(((i as u32) + 1, (end as u32) + 1));
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    ranges
}

pub struct ScanEngine;

impl ScanEngine {
    pub fn run(
        ctx: &Ctx,
        input: &RunInput,
        rules: &[Rule],
        source_id: &str,
        skip_tests: bool,
    ) -> Result<CapabilityOutput> {
        // target валидируется (абсолютный путь / `..` не выводят за корень проекта).
        let base = ctx.base(input)?;

        let mut out = CapabilityOutput::default();
        let mut files_scanned: u64 = 0;
        // Сколько физических строк пропущено как вне охвата (минифицированные/
        // сверхдлинные). Считаем отдельно от файловых пропусков walk_stats, чтобы
        // инвариант «нет молчаливых пропусков» покрывал и построчный отсев.
        let mut long_lines_skipped: u64 = 0;
        let mut skips = WalkStats::default();
        let root = ctx.root.clone();

        walk_stats(
            &base,
            &mut |path| {
                let ext = file_ext(path);
                let rel = path
                    .strip_prefix(&root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string();
                // Тест-файлы/фикстуры не сканируем (фейк-секреты, фикстуры-уязвимости).
                if skip_tests && is_test_path(&rel) {
                    return;
                }
                // Бинарь/нечитаемое: пропуск конкретного файла (не всего capability).
                let content = match fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                files_scanned += 1;

                // Предотбор применимых по расширению правил ОДИН раз на файл: цикл
                // по строкам не должен повторять проверку расширения на каждой строке.
                // Пустой список расширений = правило применимо к любому тексту.
                let applicable: Vec<&Rule> = rules
                    .iter()
                    .filter(|r| r.exts.is_empty() || r.exts.contains(&ext.as_str()))
                    .collect();
                if applicable.is_empty() {
                    return;
                }

                // Многострочные правила выделяем заранее: они идут по целому файлу/
                // окну, а не по строке, и для них готовится склеенный вид литералов
                // вместе с картой смещений (чтобы номер строки оставался честным).
                let has_multiline = applicable.iter().any(|r| r.matcher.is_multiline());
                let joined = if has_multiline {
                    Some(JoinedText::build(&content))
                } else {
                    None
                };

                // Индекс начала находок этого файла: после проходов отсечём те, что
                // попали во встроенные тестовые модули Rust (см. cfg_test_line_ranges).
                let file_start = out.findings.len();

                // ── Построчный проход ──────────────────────────────────────────
                for (i, line) in content.lines().enumerate() {
                    // Минифицированные/сверхдлинные строки вне охвата: и медленный
                    // regex, и поток ложных подстрок. Пропускаем с явным учётом.
                    if line.len() > MAX_LINE_LEN {
                        long_lines_skipped += 1;
                        continue;
                    }
                    for rule in &applicable {
                        if rule.matcher.is_multiline() {
                            continue; // многострочные обрабатываются отдельным проходом
                        }
                        if rule.matcher.is_match(line) {
                            out.findings.push(Finding {
                                rule: rule.id.to_string(),
                                severity: rule.severity,
                                message: rule.message.to_string(),
                                location: Some(Location {
                                    file: rel.clone(),
                                    line: (i as u32) + 1,
                                }),
                                evidence: Some(line.trim().chars().take(120).collect()),
                                // verified = «заземлено на file:line», а не «структурно
                                // достоверно»: оба понятия разведены (см. T14 и
                                // Matcher::is_structural). Детерминированная находка
                                // заземлена, поэтому учитывается гейтом; уровень
                                // уверенности (структура против эвристики) отражает
                                // отдельная система Confidence по идентификатору правила.
                                verified: true,
                                source: source_id.to_string(),
                            });
                        }
                    }
                }

                // ── Многострочный проход ───────────────────────────────────────
                if let Some(joined) = joined.as_ref() {
                    // `&rule` распаковывает &&Rule из Vec<&Rule> в &Rule для вызова.
                    for &rule in &applicable {
                        if !rule.matcher.is_multiline() {
                            continue;
                        }
                        Self::scan_multiline(rule, &content, joined, &rel, source_id, &mut out);
                    }
                }

                // Встроенные тесты Rust: отсекаем находки этого файла, попавшие в
                // `#[cfg(test)]`-модули/функции (фикстуры и unwrap в тестах — не дефекты).
                // Только при skip_tests и только для .rs, чтобы не трогать прочие языки.
                if skip_tests && ext == "rs" && out.findings.len() > file_start {
                    let regions = cfg_test_line_ranges(&content);
                    if !regions.is_empty() {
                        let file_findings = out.findings.split_off(file_start);
                        out.findings.extend(file_findings.into_iter().filter(|f| {
                            f.location.as_ref().map_or(true, |l| {
                                !regions.iter().any(|&(a, b)| l.line >= a && l.line <= b)
                            })
                        }));
                    }
                }
            },
            &mut skips,
        )?;

        // Инвариант «нет молчаливых пропусков»: 0 файлов = нечего проверять, честно
        // сообщаем причину, а не выдаём «0 находок» как успех.
        if files_scanned == 0 {
            out.skipped = Some(format!(
                "{source_id}: не найдено файлов для сканирования по указанному пути"
            ));
        }
        out.metrics.push(("files_scanned".into(), files_scanned as f64));
        // Тот же инвариант для частичного охвата: скрытое/служебное/блобы не
        // сканируются осознанно, но количество пропущенного видно человеку.
        out.metrics
            .push(("files_out_of_scope".into(), skips.total() as f64));
        // Сверхдлинные строки тоже честно учитываем как частичный охват.
        out.metrics
            .push(("long_lines_out_of_scope".into(), long_lines_skipped as f64));
        out.metrics
            .push((format!("{source_id}_findings"), out.findings.len() as f64));
        let long_note = if long_lines_skipped > 0 {
            format!(", {long_lines_skipped} сверхдлинных строк вне охвата")
        } else {
            String::new()
        };
        out.summary = format!(
            "{source_id}: {files_scanned} файлов, {} находок{}{}",
            out.findings.len(),
            skips.note(),
            long_note
        );
        Ok(out)
    }

    /// Применить многострочный матчер к файлу. Для regex/entropy сканирует и исходный
    /// текст, и текст со склеенными литералами; смещение в склеенном тексте переводит
    /// обратно в исходный (карта [`JoinedText`]), поэтому номер строки находки всегда
    /// указывает на реальную строку файла. Дедуплицирует находки по номеру строки в
    /// пределах одного правила и файла, чтобы одно совпадение в двух представлениях не
    /// дало дубль. Для оконных правил режет файл на скользящие окна строк.
    fn scan_multiline(
        rule: &Rule,
        raw: &str,
        joined: &JoinedText,
        rel: &str,
        source_id: &str,
        out: &mut CapabilityOutput,
    ) {
        // Строки, на которых это правило уже сработало в этом файле: гарантия одной
        // находки на строку (исходный и склеенный вид часто совпадают по позиции).
        let mut seen_lines: std::collections::HashSet<u32> = std::collections::HashSet::new();

        match &rule.matcher {
            Matcher::MultiLineRegex(re) => {
                // (текст для матча, нужно ли переводить смещение в исходный текст).
                for (text, is_joined) in [(raw, false), (joined.text.as_str(), true)] {
                    for m in re.find_iter(text) {
                        // Номер строки честно считаем по ИСХОДНОМУ тексту.
                        let src_off = if is_joined {
                            joined.to_source(m.start())
                        } else {
                            m.start()
                        };
                        let line = line_of_offset(raw, src_off);
                        if seen_lines.insert(line) {
                            out.findings.push(make_finding(
                                rule,
                                rel,
                                line,
                                multiline_evidence(text, m.start(), m.end()),
                                source_id,
                            ));
                        }
                    }
                }
            }
            Matcher::MultiLineEntropy {
                re,
                min_entropy_bits,
            } => {
                for (text, is_joined) in [(raw, false), (joined.text.as_str(), true)] {
                    for caps in re.captures_iter(text) {
                        let Some(val) = caps.get(1) else { continue };
                        if shannon_entropy_bits(val.as_str()) < *min_entropy_bits {
                            continue;
                        }
                        let whole = caps.get(0).expect("группа 0 всегда присутствует");
                        let src_off = if is_joined {
                            joined.to_source(whole.start())
                        } else {
                            whole.start()
                        };
                        let line = line_of_offset(raw, src_off);
                        if seen_lines.insert(line) {
                            out.findings.push(make_finding(
                                rule,
                                rel,
                                line,
                                multiline_evidence(text, whole.start(), whole.end()),
                                source_id,
                            ));
                        }
                    }
                }
            }
            Matcher::WindowRegex { re, window } => {
                let lines: Vec<&str> = raw.lines().collect();
                let w = (*window).max(1);
                // Скользящее окно: каждая стартовая строка задаёт фрагмент из w строк
                // (или до конца файла). Окна перекрываются, поэтому одно и то же
                // связывание стока и источника попадёт в несколько соседних окон;
                // чтобы не дублировать находку, её приписываем строке НАЧАЛА самого
                // совпадения внутри окна (а не строке начала окна) и дедуплицируем
                // по этой строке через seen_lines.
                for start in 0..lines.len() {
                    let end = (start + w).min(lines.len());
                    let chunk = lines[start..end].join("\n");
                    if chunk.len() > MAX_LINE_LEN.saturating_mul(w) {
                        continue; // окно из минифицированных строк, вне охвата
                    }
                    if let Some(m) = re.find(&chunk) {
                        // Строка начала совпадения = строка начала окна плюс число
                        // переносов до начала совпадения внутри фрагмента.
                        let inner = chunk[..m.start()].bytes().filter(|&b| b == b'\n').count();
                        let line = (start + inner) as u32 + 1;
                        if seen_lines.insert(line) {
                            out.findings.push(make_finding(
                                rule,
                                rel,
                                line,
                                Some(window_evidence(&chunk)),
                                source_id,
                            ));
                        }
                    }
                }
            }
            // Построчные матчеры сюда не попадают (отфильтрованы is_multiline).
            Matcher::Regex(_) | Matcher::Entropy { .. } | Matcher::Predicate(_) => {}
        }
    }
}

/// Собрать находку многострочного правила. `verified` означает заземление на
/// конкретный file:line (та же семантика, что у построчного прохода), поэтому
/// истинно для любой детерминированной находки и учитывается гейтом. Уровень
/// уверенности (структурная сигнатура против оконной эвристики) задаётся отдельной
/// системой Confidence по идентификатору правила, см. [`Matcher::is_structural`].
fn make_finding(
    rule: &Rule,
    rel: &str,
    line: u32,
    evidence: Option<String>,
    source_id: &str,
) -> Finding {
    Finding {
        rule: rule.id.to_string(),
        severity: rule.severity,
        message: rule.message.to_string(),
        location: Some(Location {
            file: rel.to_string(),
            line,
        }),
        evidence,
        verified: true,
        source: source_id.to_string(),
    }
}

/// Доказательство для многострочного совпадения: фрагмент текста совпадения,
/// переносы строк заменены пробелом, длина ограничена ~120 символами, чтобы отчёт
/// оставался читаемым и не тащил весь PEM-блок.
fn multiline_evidence(text: &str, start: usize, end: usize) -> Option<String> {
    let slice = text.get(start..end.min(text.len()))?;
    let flat: String = slice
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    Some(flat.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(120).collect())
}

/// Доказательство для оконного совпадения: само окно строк, склеенное через
/// разделитель ` | `, чтобы человек видел, какие именно соседние строки связались.
fn window_evidence(chunk: &str) -> String {
    chunk
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" | ")
        .chars()
        .take(160)
        .collect()
}

/// Расширения исходного кода, для правил, которым нет смысла бегать по докам и прозе
/// (это убирает ложные срабатывания на .md/.txt).
pub const SOURCE_CODE: &[&str] = &[
    "go", "rs", "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "java", "kt", "kts", "swift", "cs",
    "c", "cc", "cpp", "h", "hpp", "rb", "php", "scala", "dart", "clj", "ex", "exs",
];

/// Расширение файла в нижнем регистре; файлы Dockerfile/Containerfile дают "dockerfile".
fn file_ext(path: &std::path::Path) -> String {
    let raw = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !raw.is_empty() {
        return raw;
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name == "dockerfile" || name == "containerfile" {
        return "dockerfile".to_string();
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── cfg_test_line_ranges: встроенные тесты Rust ───────────────────────

    #[test]
    fn cfg_test_ranges_покрывают_встроенный_модуль_не_прод() {
        let src = "fn prod() {\n    let x = foo().unwrap();\n}\n\
                   #[cfg(test)]\n\
                   mod tests {\n    \
                   fn t() {\n        let y = bar().unwrap();\n    }\n}\n\
                   fn after() {}\n";
        let r = cfg_test_line_ranges(src);
        assert_eq!(r.len(), 1, "ровно один тестовый регион: {r:?}");
        let (a, b) = r[0];
        // Атрибут на строке 4, mod на 5, закрывающая } на 9.
        assert_eq!((a, b), (4, 9), "регион охватывает весь #[cfg(test)] mod");
        let in_region = |ln: u32| r.iter().any(|&(s, e)| ln >= s && ln <= e);
        assert!(!in_region(2), "unwrap в прод-функции (строка 2) НЕ в тестовом регионе");
        assert!(in_region(7), "unwrap внутри теста (строка 7) в тестовом регионе");
    }

    // ── join_concatenated_literals ────────────────────────────────────────

    #[test]
    fn join_literals_склеивает_плюс_конкатенацию() {
        // Секрет, разорванный конкатенацией с `+`, должен читаться как единый литерал.
        let src = r#"let k = "AKIA" + "IOSFODNN7" + "EXAMPLE";"#;
        let joined = join_concatenated_literals(src);
        assert!(
            joined.contains("AKIAIOSFODNN7EXAMPLE"),
            "ожидалась склейка кусков, получено: {joined}"
        );
    }

    #[test]
    fn join_literals_склеивает_неявную_конкатенацию() {
        // Python/C неявная конкатенация без `+` тоже должна склеиваться.
        let src = "x = \"abc\" \"def\" \"ghi\"";
        let joined = join_concatenated_literals(src);
        assert!(joined.contains("abcdefghi"), "получено: {joined}");
    }

    #[test]
    fn join_literals_склеивает_через_перенос_строки() {
        // Конкатенация, разорванная переносом физической строки.
        let src = "url = \"https://host/\" +\n      \"secret-path\"";
        let joined = join_concatenated_literals(src);
        assert!(joined.contains("https://host/secret-path"), "получено: {joined}");
    }

    #[test]
    fn join_literals_не_склеивает_разнотипные_кавычки() {
        // "..." и '...' рядом: это не один литерал, склеивать нельзя.
        let src = "x = \"abc\" + 'def'";
        let joined = join_concatenated_literals(src);
        assert_eq!(joined, src, "разнотипные кавычки не должны склеиваться");
    }

    #[test]
    fn join_literals_возвращает_исходник_когда_склеивать_нечего() {
        let src = "let plain = compute(a, b);";
        assert_eq!(join_concatenated_literals(src), src);
    }

    // ── shannon_entropy_bits ──────────────────────────────────────────────

    #[test]
    fn энтропия_случайной_строки_выше_порога() {
        assert!(shannon_entropy_bits("a8Kd9Lm2Qx7Zp1Rv") >= 3.5);
    }

    #[test]
    fn энтропия_плейсхолдера_ниже_порога() {
        assert!(shannon_entropy_bits("changeme") < 3.5);
    }

    // ── line_of_offset ────────────────────────────────────────────────────

    #[test]
    fn номер_строки_по_смещению() {
        let text = "line1\nline2\nline3";
        assert_eq!(line_of_offset(text, 0), 1);
        assert_eq!(line_of_offset(text, 6), 2); // начало line2
        assert_eq!(line_of_offset(text, 12), 3); // начало line3
    }

    #[test]
    fn номер_строки_не_паникует_за_границей() {
        let text = "abc";
        assert_eq!(line_of_offset(text, 999), 1);
    }

    // ── Matcher: классификация области и структурности ────────────────────

    #[test]
    fn построчные_матчеры_не_многострочные() {
        assert!(!Matcher::regex("x").is_multiline());
        assert!(!Matcher::entropy(r#"="([^"]+)""#, 3.0).is_multiline());
        assert!(!Matcher::Predicate(|l| l.contains("y")).is_multiline());
    }

    #[test]
    fn многострочные_матчеры_помечены() {
        assert!(Matcher::multiline_regex("(?s)x").is_multiline());
        assert!(Matcher::window_regex("x", 3).is_multiline());
        assert!(Matcher::multiline_entropy(r#"(?s)="([^"]+)""#, 3.0).is_multiline());
    }

    #[test]
    fn окно_ноль_подменяется_дефолтом() {
        match Matcher::window_regex("x", 0) {
            Matcher::WindowRegex { window, .. } => assert_eq!(window, DEFAULT_WINDOW),
            _ => panic!("ожидался WindowRegex"),
        }
    }

    #[test]
    fn структурность_различает_сигнатуру_и_эвристику() {
        // Точная форма и энтропия дают структурный сигнал.
        assert!(Matcher::regex("x").is_structural());
        assert!(Matcher::entropy(r#"="([^"]+)""#, 3.0).is_structural());
        assert!(Matcher::multiline_regex("(?s)x").is_structural());
        assert!(Matcher::multiline_entropy(r#"(?s)="([^"]+)""#, 3.0).is_structural());
        // Предикат и оконная близость дают эвристику.
        assert!(!Matcher::Predicate(|l| l.contains("z")).is_structural());
        assert!(!Matcher::window_regex("x", 2).is_structural());
    }

    // ── ScanEngine::scan_multiline: поведение на синтетике ────────────────

    fn empty_out() -> CapabilityOutput {
        CapabilityOutput::default()
    }

    #[test]
    fn multiline_regex_ловит_pem_разнесённый_по_строкам() {
        // PEM-заголовок и тело на разных строках: построчное правило поймало бы лишь
        // заголовок, многострочное ловит весь блок и указывает на строку начала.
        let rule = Rule {
            id: "private-key-ml",
            severity: Severity::Critical,
            exts: &[],
            matcher: Matcher::multiline_regex(
                r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            ),
            message: "PEM-ключ",
        };
        let raw = "header\n-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----\n";
        let joined = JoinedText::build(raw);
        let mut out = empty_out();
        ScanEngine::scan_multiline(&rule, raw, &joined, "k.pem", "test", &mut out);
        assert_eq!(out.findings.len(), 1, "ожидалась ровно одна находка");
        let f = &out.findings[0];
        assert_eq!(f.location.as_ref().unwrap().line, 2, "строка начала PEM-блока");
        assert!(f.verified, "находка заземлена на file:line, значит verified");
        assert!(f.evidence.as_ref().unwrap().contains("BEGIN RSA PRIVATE KEY"));
    }

    #[test]
    fn multiline_entropy_ловит_секрет_собранный_конкатенацией() {
        // Секрет, разорванный конкатенацией: построчно значение слишком короткое,
        // после склейки литералов многострочный энтропийный матчер его ловит.
        let rule = Rule {
            id: "generic-secret-ml",
            severity: Severity::High,
            exts: &[],
            matcher: Matcher::multiline_entropy(
                r#"(?is)\b(?:secret|token|api[_-]?key)\b\s*[:=]\s*["']([^"'\s]{12,})["']"#,
                3.5,
            ),
            message: "секрет",
        };
        let raw = "secret = \"a8Kd9L\" + \"m2Qx7Zp1Rv\"";
        let joined = JoinedText::build(raw);
        let mut out = empty_out();
        ScanEngine::scan_multiline(&rule, raw, &joined, "c.py", "test", &mut out);
        assert_eq!(out.findings.len(), 1, "склеенный секрет должен сработать");
        assert!(out.findings[0].verified, "находка заземлена на file:line, значит verified");
        // Структурность энтропийного матчера выражается отдельно (для системы Confidence).
        assert!(rule.matcher.is_structural(), "энтропия даёт структурный сигнал");
    }

    #[test]
    fn multiline_entropy_отсекает_плейсхолдер_низкой_энтропии() {
        let rule = Rule {
            id: "generic-secret-ml",
            severity: Severity::High,
            exts: &[],
            matcher: Matcher::multiline_entropy(
                r#"(?is)\b(?:secret|token)\b\s*[:=]\s*["']([^"'\s]{6,})["']"#,
                3.5,
            ),
            message: "секрет",
        };
        let raw = "secret = \"changeme\"";
        let joined = JoinedText::build(raw);
        let mut out = empty_out();
        ScanEngine::scan_multiline(&rule, raw, &joined, "c.py", "test", &mut out);
        assert!(out.findings.is_empty(), "плейсхолдер не должен считаться секретом");
    }

    #[test]
    fn window_regex_связывает_источник_и_сток_на_соседних_строках() {
        // Источник на одной строке, сток на следующей: построчное правило бы оба
        // условия на одной строке не нашло, оконное связывает их.
        let rule = Rule {
            id: "ssrf-window",
            severity: Severity::High,
            exts: &[],
            // Требуем и недоверенный источник, и http-вызов в одном окне.
            matcher: Matcher::window_regex(r"(?s)request\.args.*requests\.get", 3),
            message: "SSRF",
        };
        let raw = "url = request.args.get('u')\nresp = requests.get(url)\n";
        let joined = JoinedText::build(raw);
        let mut out = empty_out();
        ScanEngine::scan_multiline(&rule, raw, &joined, "v.py", "test", &mut out);
        assert_eq!(out.findings.len(), 1, "оконное связывание должно сработать");
        let f = &out.findings[0];
        assert_eq!(f.location.as_ref().unwrap().line, 1, "строка начала совпадения в окне");
        // Находка заземлена на file:line, значит verified (учитывается гейтом); её
        // эвристическая природа выражается ОТДЕЛЬНО через is_structural()/Confidence.
        assert!(f.verified, "находка заземлена на file:line, значит verified");
        assert!(!rule.matcher.is_structural(), "оконная близость есть эвристика");
        assert!(f.evidence.as_ref().unwrap().contains("requests.get"));
    }

    #[test]
    fn window_regex_не_связывает_далёкие_строки() {
        // Источник и сток разнесены дальше размера окна, связи быть не должно.
        let rule = Rule {
            id: "ssrf-window",
            severity: Severity::High,
            exts: &[],
            matcher: Matcher::window_regex(r"(?s)request\.args.*requests\.get", 2),
            message: "SSRF",
        };
        let raw = "url = request.args.get('u')\nx = 1\ny = 2\nresp = requests.get(url)\n";
        let joined = JoinedText::build(raw);
        let mut out = empty_out();
        ScanEngine::scan_multiline(&rule, raw, &joined, "v.py", "test", &mut out);
        assert!(out.findings.is_empty(), "окно из 2 строк не должно перекрыть разрыв в 3");
    }

    #[test]
    fn joinedtext_переводит_смещение_в_исходную_строку() {
        // Конкатенация, разорванная переносом: склейка убирает перенос, но карта
        // смещений возвращает ЧЕСТНЫЙ исходный байтовый офсет, поэтому номер строки
        // указывает на реальную строку файла, а не на сдвинутую в склеенном виде.
        let raw = "line1\nx = \"abc\" +\n    \"def\"\nline4";
        let jt = JoinedText::build(raw);
        assert!(jt.text.contains("abcdef"), "склейка через перенос: {}", jt.text);
        // Найдём «abcdef» в склеенном тексте и переведём его начало в исходный офсет.
        let joined_off = jt.text.find("abcdef").expect("склеенное значение присутствует");
        let src_off = jt.to_source(joined_off);
        // В исходнике «abc» начинается на строке 2 (после открывающей кавычки).
        assert_eq!(line_of_offset(raw, src_off), 2, "честная исходная строка начала");
    }

    #[test]
    fn multiline_entropy_честная_строка_при_переносе_конкатенации() {
        // Секрет собран конкатенацией, разорванной переносом строки. Находка должна
        // указывать на строку, где секрет начинается в ИСХОДНОМ файле.
        let rule = Rule {
            id: "generic-secret-ml",
            severity: Severity::High,
            exts: &[],
            matcher: Matcher::multiline_entropy(
                r#"(?is)\b(?:secret|token)\b\s*[:=]\s*["']([^"'\s]{12,})["']"#,
                3.5,
            ),
            message: "секрет",
        };
        // secret и первый кусок на строке 2, второй кусок переносом на строку 3.
        let raw = "header\nsecret = \"a8Kd9L\" +\n    \"m2Qx7Zp1Rv\"\nfooter";
        let joined = JoinedText::build(raw);
        let mut out = empty_out();
        ScanEngine::scan_multiline(&rule, raw, &joined, "c.py", "test", &mut out);
        assert_eq!(out.findings.len(), 1, "склеенный через перенос секрет должен сработать");
        assert_eq!(
            out.findings[0].location.as_ref().unwrap().line,
            2,
            "строка начала секрета в исходном файле"
        );
    }

    #[test]
    fn multiline_не_дублирует_находку_по_двум_представлениям() {
        // Если совпадение присутствует и в исходном, и в склеенном тексте на той же
        // строке, дедупликация по строке должна оставить ровно одну находку.
        let rule = Rule {
            id: "marker",
            severity: Severity::Low,
            exts: &[],
            matcher: Matcher::multiline_regex(r"MARKER-[0-9]+"),
            message: "маркер",
        };
        let raw = "first\nMARKER-42 here\nlast";
        let joined = JoinedText::build(raw);
        let mut out = empty_out();
        ScanEngine::scan_multiline(&rule, raw, &joined, "f.txt", "test", &mut out);
        assert_eq!(out.findings.len(), 1, "одно совпадение даёт одну находку");
    }
}
