//! Verify Supervisor — состязательная проверка находок (verify-максимализм).
//!
//! Принцип: каждую находку пытаемся ОПРОВЕРГНУТЬ. Выжившие = подтверждённые (идут в
//! балл/блокировку). Опровергнутые отсеиваются. Для детерминированных находок это
//! убирает классические ложные (секрет/PII в КОММЕНТАРИИ или со значением-ПЛЕЙСХОЛДЕРОМ
//! — ровно то, на чём шумят наивные сканеры). Когда добавится LLM-источник находок,
//! сюда встанут N независимых скептиков (loop-until-dry) — интерфейс тот же.
//!
//! Два инварианта безопасности, заложенные здесь явно.
//!
//! Первый (см. T01): эвристики опровержения секрета (плейсхолдер, повтор и ряд цифр,
//! определение шаблона поиска) применяются НЕ ко всей физической строке кода, а только
//! к ЗАХВАЧЕННОМУ значению секрета. Прежняя реализация опровергала реальный ключ, если в
//! той же строке встречалась подстрока «example», восходящий ряд из шести цифр или
//! предикат вида `.contains("…")`. Теперь значение секрета извлекается из строки по
//! канонической форме правила (та же форма, что у сканера), и эвристики смотрят строго на
//! него. Дополнительно для строгих токенов известной формы (AWS Access Key, ключи
//! LLM-провайдеров, токены GitHub/GitLab/Slack, ключи Stripe/SendGrid, npm, Azure, Google,
//! PEM-ключ) опровержение по плейсхолдеру и по «определению шаблона» НЕ применяется вовсе:
//! сама форма токена самодостаточна и доказывает подлинность.
//!
//! Второй (см. T51): семейство `security.ai/*` и любые security-критичные правила
//! ИСКЛЮЧЕНЫ из гашения эвристикой «определение шаблона поиска». Иначе атакующий, дописав
//! к опасной строке (например `eval(response)`) безобидный хвост вроде `s.contains("x")`,
//! скрыл бы реальную находку от собственного гейта ailc. Кроме того, перед возвратом
//! подтверждённых находок их текстовые поля НЕЙТРАЛИЗУЮТСЯ (удаление управляющих символов,
//! ограничение длины), чтобы verify не пропускал инъекцию дальше в промпты LLM.

use ailc_contracts::{rule_confidence, Ctx, Finding, RuleConfidence};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::sync::OnceLock;

pub struct Verifier;

impl Verifier {
    /// Возвращает (подтверждённые, опровергнутые-с-причиной).
    ///
    /// Подтверждённые находки перед возвратом проходят нейтрализацию текстовых полей
    /// (`sanitize_finding`): это страховка инварианта «verify не пропускает инъекцию
    /// дальше в промпты» (см. T51). Опровергнутые в балл/блокировку не идут, поэтому их
    /// поля не санируются: они нужны лишь для журнала причин и не попадают в LLM.
    pub fn verify(ctx: &Ctx, findings: Vec<Finding>) -> (Vec<Finding>, Vec<(Finding, String)>) {
        let mut cache: HashMap<String, Vec<String>> = HashMap::new();
        let mut confirmed = Vec::new();
        let mut refuted = Vec::new();
        for mut f in findings {
            match refute(ctx, &mut cache, &f) {
                Some(reason) => refuted.push((f, reason)),
                None => {
                    sanitize_finding(&mut f);
                    confirmed.push(f);
                }
            }
        }
        (confirmed, refuted)
    }
}

/// Попытка опровергнуть находку. None = опровергнуть не удалось (находка подтверждена).
fn refute(ctx: &Ctx, cache: &mut HashMap<String, Vec<String>>, f: &Finding) -> Option<String> {
    let loc = f.location.as_ref()?;
    let lines = cache
        .entry(loc.file.clone())
        .or_insert_with(|| read_lines(ctx, &loc.file));
    let line = lines.get((loc.line as usize).saturating_sub(1))?;

    // (0) Inline-подавление: `ailc:ignore` или `ailc:ignore[rule,…]` в самой строке
    // или в строке НАД ней. Маркер — подстрока, поэтому работает в комментарии ЛЮБОГО из
    // 15 языков (// # -- /* <!-- ' ; %), без знания синтаксиса. Аналог `// nosemgrep`.
    let prev = (loc.line as usize)
        .checked_sub(2)
        .and_then(|i| lines.get(i));
    if ignore_hit(line, &f.rule) || prev.is_some_and(|p| ignore_hit(p, &f.rule)) {
        return Some("подавлено inline-комментарием (ailc:ignore)".to_string());
    }

    // XXE по умолчанию (xxe-parser-default) это эвристика по факту создания XML-парсера.
    // Если файл показывает защиту парсера (defusedxml, resolve_entities=False,
    // disallow-doctype-decl, FEATURE_SECURE_PROCESSING), сущности не разворачиваются и
    // находка ложна. Опровергаем, чтобы щадить уже защищённый код; на неподготовленных
    // парсерах (как в разобранном кейсе lxml.etree.parse без defusedxml) находка остаётся.
    if f.rule == "xxe-parser-default" {
        let hardened = lines.iter().any(|l| {
            let lc = l.to_ascii_lowercase();
            lc.contains("import defusedxml")
                || lc.contains("from defusedxml")
                || lc.replace(' ', "").contains("resolve_entities=false")
                || lc.contains("disallow-doctype-decl")
                || lc.contains("feature_secure_processing")
        });
        if hardened {
            return Some(
                "XML-парсер в файле защищён (defusedxml/resolve_entities=False/secure-processing)"
                    .to_string(),
            );
        }
    }

    let security = f.source.contains("security") || f.source.contains("pii");
    // Строгие токены известной формы: их форма самодостаточна и доказывает подлинность,
    // поэтому к ним НЕ применяются ни «определение шаблона поиска», ни плейсхолдер, ни ряд
    // цифр (см. T01). Реальный AKIA/ghp_/glpat-/sk- ключ не должен опровергаться лишь
    // потому, что в той же строке оказалась подстрока «example» или предикат `.contains`.
    let strict_token = is_strict_token_rule(&f.rule);

    // (1) Строка САМА — определение шаблона поиска (сканер/WAF/линтер находит свой
    // ruleset). Сигнатуры, которых по сути не бывает в живом уязвимом коде. Ложное
    // для ЛЮБОГО семейства (security и quality). Общий случай, не «по имени проекта».
    //
    // ВАЖНО (T51): эту эвристику НЕ применяем к строгим токенам (форма самодостаточна) и к
    // security-критичным правилам/источникам `security.ai/*`. Иначе атакующий, дописав к
    // опасной строке безобидный хвост `s.contains("x")`, погасил бы реальную находку
    // `security.ai/insecure-output` от собственного гейта ailc.
    // Исключение security.ai из этой эвристики СНИМАЕТСЯ, если строка — БЕЗОШИБОЧНАЯ
    // конструкция правила (литерал регулярного выражения с regex-мета или вызов
    // Regex/Matcher-конструктора). Реальный эксплуатируемый LLM-вызов не бывает строкой
    // `r"(?i)…"`/`Regex::new(…)`, поэтому атакующий не сможет так замаскировать находку, а
    // самосовпадение детектора на собственном ruleset (ai_security.rs) гасится.
    if !strict_token
        && looks_like_pattern_def(line)
        && (!is_security_critical(f) || is_unmistakable_rule_def(line))
    {
        return Some("определение шаблона поиска (правило сканера, не живой вызов)".to_string());
    }

    // Смелы «присутствие кода» (panic/unwrap, проглоченная ошибка, заглушки и пустые
    // блоки): в КОММЕНТАРИИ их находка ложна — код не исполняется. debt-marker сюда НЕ
    // входит: TODO/FIXME штатно живут в комментариях, это и есть их законная цель.
    let code_presence = matches!(
        f.rule.as_str(),
        "panic-path"
            | "swallowed-error"
            | "unimplemented-stub"
            | "empty-catch"
            | "empty-except"
            | "empty-function"
    );

    // (2) В комментарии — ложное для security/PII и для смелов-присутствия-кода.
    let t = line.trim_start();
    let is_comment = t.starts_with("//")
        || t.starts_with('#')
        || t.starts_with('*')
        || t.starts_with("/*")
        || t.starts_with("<!--");
    if (security || code_presence) && is_comment {
        return Some("в комментарии (не исполняемый код)".to_string());
    }

    // (3) Плейсхолдер-значение — только security/PII и только НЕ для строгих токенов.
    if !security || strict_token {
        return None;
    }

    // Эвристики плейсхолдера применяем СТРОГО к захваченному значению секрета, а не ко
    // всей физической строке (см. T01). Значение извлекаем по канонической форме правила;
    // если форма правила неизвестна (нестрогие правила без явной capture-формы), берём
    // эвристический «значение-подобный» фрагмент строки, чтобы не сравнивать с именами
    // переменных и ключевыми словами вокруг присваивания.
    let value = secret_value_in(&f.rule, line)
        .or_else(|| heuristic_value(line))
        .unwrap_or_else(|| line.clone());

    let lower = value.to_lowercase();
    const PLACEHOLDERS: &[&str] = &[
        "changeme", "change-me", "change me", "your_", "your-", "<your", "example",
        "placeholder", "todo", "dummy", "fake", "sample", "xxxxxxxx", "смени", "замени",
        "вставь", "измени",
    ];
    for p in PLACEHOLDERS {
        if lower.contains(p) {
            return Some(format!("значение-плейсхолдер («{p}»)"));
        }
    }
    // Числовые плейсхолдеры: длинный повтор одной цифры (000000…) или восходящий ряд
    // (123456…) — заглушки, а не реальные случайные значения. Порог восходящего ряда и
    // повтора привязан к ДОЛЕ длины значения (см. T01): шесть подряд в коротком значении
    // из восьми символов это явная заглушка, а в длинном ключе из сорока символов случайный
    // короткий ряд может встретиться и не должен опровергать реальный секрет.
    if has_numeric_placeholder(&value) {
        return Some("числовой плейсхолдер (повтор/ряд цифр)".to_string());
    }
    None
}

/// Строгие токены известной формы, для которых опровержение по плейсхолдеру/ряду цифр и по
/// «определению шаблона» НЕ применяется вовсе: сама форма токена доказывает подлинность
/// (см. T01). Список совпадает с правилами сканера, имеющими жёсткую сигнатуру токена.
fn is_strict_token_rule(rule: &str) -> bool {
    const STRICT: &[&str] = &[
        "aws-access-key",
        "llm-api-key",
        "github-token",
        "stripe-key",
        "gitlab-token",
        "slack-token",
        "sendgrid-key",
        "npm-token",
        "azure-account-key",
        "google-api-key",
        "private-key",
    ];
    STRICT.contains(&rule)
}

/// Security-критична ли находка для целей T51: её НЕ должна гасить строковая эвристика
/// «определение шаблона поиска». Критичны всё семейство `security.ai/*` (LLM-цепочки:
/// небезопасный вывод модели, склейка недоверенного в промпт) и любое правило точной
/// достоверности (`Precise`) из security-источника (секреты, taint/AST-SAST), потому что
/// именно такие находки атакующий мог бы замаскировать дописанным безобидным предикатом.
fn is_security_critical(f: &Finding) -> bool {
    if f.source.starts_with("security.ai") {
        return true;
    }
    let security = f.source.contains("security") || f.source.contains("pii");
    security && matches!(rule_confidence(&f.rule), Some(RuleConfidence::Precise))
}

/// Извлечь ЗАХВАЧЕННОЕ значение секрета из строки по канонической форме правила. Формы
/// здесь те же, что у сканера (`ailc-capabilities::secret_scan`); они продублированы
/// локально намеренно, потому что слой `ailc-core` не зависит от `ailc-capabilities`
/// (зависимость направлена в обратную сторону), а значение секрета нужно ровно для того,
/// чтобы эвристики опровержения смотрели на него, а не на всю строку. Возвращает значение
/// для проверки плейсхолдера: для правил с capture-группой это содержимое группы 1
/// (например, литерал значения у `generic-secret`/`aws-secret-key`), иначе весь матч
/// (сам токен). `None`, если форма правила неизвестна или не совпала.
fn secret_value_in(rule: &str, line: &str) -> Option<String> {
    let (_, re, group) = secret_forms().iter().find(|(id, _, _)| *id == rule)?;
    let caps = re.captures(line)?;
    let m = caps.get(*group).or_else(|| caps.get(0))?;
    Some(m.as_str().to_string())
}

/// Канонические формы секрет-правил: (id, regex, индекс интересующей группы). Индекс 0
/// означает «весь матч» (токен целиком), индекс 1 означает «захваченное значение литерала»
/// (для правил, где сам токен заключён в кавычки и не имеет жёсткой формы). Скомпилировано
/// один раз (`OnceLock`); паттерны статичны и выверены, поэтому `expect` уместен.
#[allow(clippy::type_complexity)]
fn secret_forms() -> &'static [(&'static str, Regex, usize)] {
    static FORMS: OnceLock<Vec<(&'static str, Regex, usize)>> = OnceLock::new();
    FORMS.get_or_init(|| {
        let r = |p: &str| Regex::new(p).expect("встроенная форма секрет-правила невалидна");
        vec![
            // Строгие токены (для них опровержение по значению и так не применяется, но
            // форма нужна, чтобы при необходимости извлечь сам токен как значение).
            ("aws-access-key", r(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
            ("github-token", r(r"\bgh[pousr]_[0-9A-Za-z]{36}\b"), 0),
            ("stripe-key", r(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"), 0),
            ("google-api-key", r(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0),
            ("gitlab-token", r(r"\bglpat-[0-9A-Za-z_\-]{20,}"), 0),
            ("slack-token", r(r"\bxox[abposr]-[0-9A-Za-z\-]{10,}\b"), 0),
            (
                "sendgrid-key",
                r(r"\bSG\.[0-9A-Za-z_\-]{16,}\.[0-9A-Za-z_\-]{16,}\b"),
                0,
            ),
            ("npm-token", r(r"\bnpm_[0-9A-Za-z]{36}\b"), 0),
            ("azure-account-key", r(r"(?i)AccountKey=([0-9A-Za-z+/=]{40,})"), 1),
            (
                "llm-api-key",
                r(r"\bsk-[A-Za-z0-9_\-]{20,}\b|\bhf_[A-Za-z0-9]{30,}\b"),
                0,
            ),
            ("private-key", r(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), 0),
            ("twilio-sid", r(r"\bAC[0-9a-f]{32}\b"), 0),
            (
                "jwt",
                r(r"\beyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}\b"),
                0,
            ),
            // Нестрогие правила: значение в кавычках, интересует именно литерал (группа 1).
            (
                "generic-secret",
                r(r#"(?i)\b(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth[_-]?token|token)\b\s*[:=]\s*["']([^"'\s]{12,})["']"#),
                1,
            ),
            (
                "aws-secret-key",
                r(r#"(?i)\baws.{0,20}["']([0-9A-Za-z/+]{40})["']"#),
                1,
            ),
        ]
    })
}

/// Эвристический «значение-подобный» фрагмент строки для секрет-правил без известной
/// canonical-формы: содержимое первого строкового литерала в кавычках, иначе хвост после
/// первого `=`/`:` без кавычек. Нужен, чтобы плейсхолдер искался в значении, а не в имени
/// переменной или ключевом слове присваивания. `None`, если ни то ни другое не найдено.
fn heuristic_value(line: &str) -> Option<String> {
    static QUOTED: OnceLock<Regex> = OnceLock::new();
    let quoted = QUOTED.get_or_init(|| {
        Regex::new(r#"["']([^"']{1,200})["']"#).expect("паттерн строкового литерала невалиден")
    });
    if let Some(c) = quoted.captures(line) {
        if let Some(m) = c.get(1) {
            return Some(m.as_str().to_string());
        }
    }
    // Некавыченное присваивание KEY=VALUE / KEY: VALUE.
    let idx = line.find(['=', ':'])?;
    let rhs = line[idx + 1..].trim();
    if rhs.is_empty() {
        None
    } else {
        Some(rhs.to_string())
    }
}

/// Числовой плейсхолдер в ЗНАЧЕНИИ: длинный повтор одной цифры (000000…) или восходящий
/// ряд (123456…). Порог привязан к ДОЛЕ длины значения, но не ниже шести: для короткого
/// значения хватит и шести подряд (явная заглушка), а в длинном случайном ключе короткий
/// ряд из шести встречается естественно и не должен опровергать реальный секрет. Доля
/// взята как половина длины значения, потому что заглушка обычно состоит из ряда/повтора
/// целиком, а в настоящем ключе доля монотонного участка мала.
fn has_numeric_placeholder(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 6 {
        return false;
    }
    // Порог: минимум шесть, и не меньше половины длины значения. Так короткое значение
    // ловится по абсолютному порогу, а длинный ключ требует, чтобы монотонный участок
    // занимал не менее половины его длины (что для случайного токена практически
    // невозможно), и поэтому реальный длинный секрет не опровергается случайным рядом.
    let threshold = chars.len().div_ceil(2).max(6);
    let (mut repeat, mut ascending) = (1usize, 1usize);
    for w in chars.windows(2) {
        let (a, b) = (w[0], w[1]);
        if a.is_ascii_digit() && b == a {
            repeat += 1;
        } else {
            repeat = 1;
        }
        if a.is_ascii_digit() && b.is_ascii_digit() && (b as u8) == (a as u8) + 1 {
            ascending += 1;
        } else {
            ascending = 1;
        }
        if repeat >= threshold || ascending >= threshold {
            return true;
        }
    }
    false
}

/// Похожа ли строка на ОПРЕДЕЛЕНИЕ паттерна (а не на живой уязвимый код):
/// inline-флаги/группы regex, вызовы-конструкторы правил, булева цепочка
/// `.contains("…")` (тело предиката-детектора).
/// БЕЗОШИБОЧНАЯ конструкция определения правила: литерал регулярного выражения с
/// regex-мета или вызов конструктора Regex/Matcher. Уже строка такого вида не бывает
/// живым эксплуатируемым вызовом, поэтому опровержение для security.ai тут безопасно.
fn is_unmistakable_rule_def(line: &str) -> bool {
    const REGEX_META: &[&str] = &["(?i)", "(?m)", "(?s)", "(?x)", "(?is)", "(?:"];
    const RULE_CTORS: &[&str] = &[
        "Matcher::regex(",
        "Matcher::window_regex(",
        "Matcher::Predicate(",
        "Regex::new(",
        "regexp.MustCompile(",
        "re.compile(",
    ];
    REGEX_META.iter().any(|m| line.contains(m)) || RULE_CTORS.iter().any(|c| line.contains(c))
}

fn looks_like_pattern_def(line: &str) -> bool {
    // Строка-правило конституции ailc (FORBID/REQUIRE <подстрока>) — это шаблон для
    // поиска, а не живой секрет/вызов. Иначе сканер находит секреты в собственных правилах.
    let t = line.trim_start();
    if t.starts_with("FORBID ") || t.starts_with("REQUIRE ") {
        return true;
    }
    const REGEX_META: &[&str] = &["(?i)", "(?m)", "(?s)", "(?x)", "(?:"];
    const RULE_CTORS: &[&str] = &[
        "Matcher::regex(",
        "Matcher::Predicate(",
        "Regex::new(",
        "regexp.MustCompile(",
        "re.compile(",
    ];
    if REGEX_META.iter().any(|m| line.contains(m)) || RULE_CTORS.iter().any(|c| line.contains(c)) {
        return true;
    }
    // Строковые предикаты-поиска с литералом (.contains/.ends_with/.starts_with/.find)
    // — это матчинг подстрок (определение правила/парсинг), а не живой уязвимый вызов.
    const STR_PRED: &[&str] = &[
        ".contains(\"",
        ".ends_with(\"",
        ".starts_with(\"",
        ".find(\"",
    ];
    STR_PRED.iter().any(|p| line.contains(p))
}

/// Есть ли в строке маркер подавления для этого правила. Голый `ailc:ignore` гасит
/// любое правило; `ailc:ignore[a,b]` — только перечисленные. Язык-независимо (подстрока).
fn ignore_hit(line: &str, rule: &str) -> bool {
    const MARK: &str = "ailc:ignore";
    let Some(i) = line.find(MARK) else {
        return false;
    };
    let rest = &line[i + MARK.len()..];
    if let Some(stripped) = rest.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return stripped[..end].split(',').map(str::trim).any(|r| r == rule);
        }
    }
    true // голый маркер — подавить любое правило в этой точке
}

/// Максимальная длина текстового поля находки после нейтрализации. Длинные поля и так
/// бесполезны человеку, а в промпте LLM раздувают контекст и облегчают инъекцию, поэтому
/// поле обрезается с явной отметкой усечения.
const MAX_FIELD_LEN: usize = 300;

/// Нейтрализовать находку перед любой передачей в LLM (см. T51): очистить текстовые поля
/// `message`, `rule`, `evidence` и `location.file` от управляющих символов и ограничить
/// длину. Управляющие символы (включая `\r`/`\n`) удаляются, потому что именно ими
/// инъекция переносит строку и подменяет роль в промпте; форма самой находки (file:line,
/// severity, source) при этом не меняется, поэтому гейт и отчёт остаются корректными.
fn sanitize_finding(f: &mut Finding) {
    f.rule = sanitize_text(&f.rule);
    f.message = sanitize_text(&f.message);
    if let Some(ev) = f.evidence.as_ref() {
        f.evidence = Some(sanitize_text(ev));
    }
    if let Some(loc) = f.location.as_mut() {
        loc.file = sanitize_text(&loc.file);
    }
}

/// Удалить управляющие символы (в том числе переводы строк и табуляции, схлопнутые в
/// пробел) и ограничить длину. Печатаемые символы Unicode сохраняются как есть.
fn sanitize_text(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    // Схлопываем образовавшиеся пробелы, чтобы убрать следы вырезанных переводов строк.
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > MAX_FIELD_LEN {
        let mut out: String = collapsed.chars().take(MAX_FIELD_LEN).collect();
        out.push('…');
        out
    } else {
        collapsed
    }
}

fn read_lines(ctx: &Ctx, rel: &str) -> Vec<String> {
    fs::read_to_string(ctx.root.join(rel))
        .map(|c| c.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_contracts::{Location, Severity};
    use std::fs as stdfs;

    /// Записать файл во временный корень и вернуть Ctx, указывающий на него, вместе с
    /// дескриптором временного каталога (его нужно удерживать в области видимости теста,
    /// потому что каталог удаляется при разрушении дескриптора). Каждый вызов создаёт
    /// отдельный каталог с уникальным именем, поэтому параллельные тесты не мешают друг
    /// другу.
    fn ctx_with(file: &str, content: &str) -> (Ctx, tempdir_like::Dir) {
        let dir = tempdir_like::Dir::new();
        let path = dir.path().join(file);
        if let Some(parent) = path.parent() {
            stdfs::create_dir_all(parent).expect("создание каталога теста");
        }
        stdfs::write(&path, content).expect("запись файла теста");
        (Ctx::new(dir.path().to_path_buf()), dir)
    }

    /// Минимальный временный каталог без внешних зависимостей: создаётся в системном
    /// temp с уникальным именем и удаляется в Drop. Достаточно для файловых тестов
    /// верификатора, не тянет крейт tempfile в граф зависимостей слоя.
    mod tempdir_like {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        pub struct Dir(PathBuf);

        impl Dir {
            #[allow(clippy::new_without_default)]
            pub fn new() -> Self {
                let n = COUNTER.fetch_add(1, Ordering::Relaxed);
                let pid = std::process::id();
                let p = std::env::temp_dir().join(format!("ailc-verify-{pid}-{n}"));
                std::fs::create_dir_all(&p).expect("создание временного каталога");
                Dir(p)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn secret_finding(rule: &str, file: &str, line: u32, message: &str) -> Finding {
        Finding::new(
            rule,
            Severity::Critical,
            message,
            Some(Location {
                file: file.to_string(),
                line,
            }),
            Some("evidence".to_string()),
            true,
            "security.scan/secret",
        )
    }

    fn xxe_finding(file: &str, line: u32) -> Finding {
        Finding::new(
            "xxe-parser-default",
            Severity::High,
            "XXE",
            Some(Location {
                file: file.to_string(),
                line,
            }),
            Some("etree.parse".to_string()),
            true,
            "security.scan/web",
        )
    }

    #[test]
    fn xxe_опровергается_при_защите_парсера_иначе_остаётся() {
        // Защищённый файл (defusedxml): находка xxe-parser-default опровергается.
        let (ctx, _d) = ctx_with(
            "docx.py",
            "from defusedxml.lxml import parse\nroot = parse(str(xml_file)).getroot()\n",
        );
        let (confirmed, refuted) = Verifier::verify(&ctx, vec![xxe_finding("docx.py", 2)]);
        assert!(
            confirmed.is_empty() && refuted.len() == 1,
            "защищённый парсер не должен оставаться находкой"
        );

        // Незащищённый файл (lxml.etree.parse без defusedxml): находка ОСТАЁТСЯ.
        let (ctx2, _d2) = ctx_with(
            "raw.py",
            "import lxml.etree\nroot = lxml.etree.parse(str(xml_file)).getroot()\n",
        );
        let (confirmed2, _r2) = Verifier::verify(&ctx2, vec![xxe_finding("raw.py", 2)]);
        assert_eq!(confirmed2.len(), 1, "незащищённый парсер обязан остаться находкой");
    }

    // ── T01: эвристики применяются к ЗНАЧЕНИЮ, а не ко всей строке ──────────

    #[test]
    fn verifier_strict_token_не_опровергается_словом_example_в_строке() {
        // Реальный AWS Access Key в файле с примером в имени переменной: прежняя
        // реализация опровергала бы его из-за подстроки «example» в строке.
        let line = r#"let example_key = "AKIAIOSFODNN7EXAMPLE";"#;
        let (ctx, _d) = ctx_with("src/aws.rs", line);
        let f = secret_finding("aws-access-key", "src/aws.rs", 1, "AWS Access Key");
        assert!(
            refute(&ctx, &mut HashMap::new(), &f).is_none(),
            "строгий токен не должен опровергаться подстрокой example в строке"
        );
    }

    #[test]
    fn verifier_strict_token_не_опровергается_pattern_def_хвостом() {
        // Атакующий дописал к строке с реальным ключом GitHub предикат `.contains("x")`,
        // чтобы looks_like_pattern_def погасил находку. Строгий токен это не опровергает.
        let line = r#"let t = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"; if s.contains("x") {}"#;
        let (ctx, _d) = ctx_with("src/gh.rs", line);
        let f = secret_finding("github-token", "src/gh.rs", 1, "GitHub token");
        assert!(
            refute(&ctx, &mut HashMap::new(), &f).is_none(),
            "строгий токен не гасится дописанным .contains(\"…\")"
        );
    }

    #[test]
    fn verifier_generic_secret_опровергается_плейсхолдером_в_значении() {
        // Плейсхолдер именно в ЗНАЧЕНИИ нестрогого правила: законно опровергается.
        let line = r#"password = "changeme1234""#;
        let (ctx, _d) = ctx_with("conf.py", line);
        let f = secret_finding("generic-secret", "conf.py", 1, "secret");
        let reason = refute(&ctx, &mut HashMap::new(), &f);
        assert!(
            reason.is_some_and(|r| r.contains("плейсхолдер")),
            "плейсхолдер в значении нестрогого секрета должен опровергать"
        );
    }

    #[test]
    fn verifier_generic_secret_не_опровергается_словом_example_в_имени() {
        // «example» в ИМЕНИ переменной, но значение — реальный высокоэнтропийный секрет.
        // Эвристика смотрит на значение, поэтому находка выживает.
        let line = r#"example_token = "a8Kd9Lm2Qx7Zp1Rv5Tn""#;
        let (ctx, _d) = ctx_with("conf.py", line);
        let f = secret_finding("generic-secret", "conf.py", 1, "secret");
        assert!(
            refute(&ctx, &mut HashMap::new(), &f).is_none(),
            "слово example в имени переменной не должно опровергать реальное значение"
        );
    }

    #[test]
    fn verifier_короткий_числовой_ряд_в_значении_опровергает() {
        // Короткое значение-заглушка из восходящего ряда цифр опровергается.
        let line = r#"secret = "tok123456abc""#;
        let (ctx, _d) = ctx_with("conf.py", line);
        let f = secret_finding("generic-secret", "conf.py", 1, "secret");
        let reason = refute(&ctx, &mut HashMap::new(), &f);
        assert!(
            reason.is_some_and(|r| r.contains("цифр")),
            "короткий восходящий ряд цифр в значении это заглушка"
        );
    }

    #[test]
    fn verifier_длинный_ключ_со_случайным_рядом_не_опровергается() {
        // В длинном строгом токене случайно встречается короткий ряд 123456: строгий
        // токен это не опровергает, и даже без строгости порог-доля не сработал бы.
        let line = r#"let k = "AKIA123456ABCDEFGHIJ";"#; // 16 символов после AKIA
        let (ctx, _d) = ctx_with("src/aws.rs", line);
        let f = secret_finding("aws-access-key", "src/aws.rs", 1, "AWS Access Key");
        assert!(
            refute(&ctx, &mut HashMap::new(), &f).is_none(),
            "случайный короткий ряд в длинном строгом токене не должен опровергать"
        );
    }

    // ── T51: security.ai/* и security-критичные не гасятся pattern-def ──────

    #[test]
    fn verifier_security_ai_не_гасится_дописанным_contains() {
        // security.ai/insecure-output: eval над выводом модели + дописанный безобидный
        // хвост .contains("x"). looks_like_pattern_def НЕ должен погасить эту находку.
        let line = r#"eval(response); if s.contains("x") {}"#;
        let (ctx, _d) = ctx_with("agent.py", line);
        let f = Finding::new(
            "llm-output-exec",
            Severity::High,
            "eval над выводом модели",
            Some(Location {
                file: "agent.py".to_string(),
                line: 1,
            }),
            Some("ev".to_string()),
            true,
            "security.ai/insecure-output",
        );
        assert!(
            refute(&ctx, &mut HashMap::new(), &f).is_none(),
            "security.ai находка не должна гаситься дописанным .contains"
        );
    }

    #[test]
    fn verifier_обычное_правило_pattern_def_всё_ещё_гасится() {
        // Регресс-защита: для НЕ security-критичного правила (quality smell) эвристика
        // pattern-def продолжает работать как раньше.
        let line = r#"if line.contains("password") { /* детектор */ }"#;
        let (ctx, _d) = ctx_with("scanner.rs", line);
        let f = Finding::new(
            "debt-marker",
            Severity::Info,
            "маркер",
            Some(Location {
                file: "scanner.rs".to_string(),
                line: 1,
            }),
            Some("ev".to_string()),
            true,
            "quality.check/smell",
        );
        assert!(
            refute(&ctx, &mut HashMap::new(), &f)
                .is_some_and(|r| r.contains("шаблон")),
            "для не-security правила pattern-def должен гасить как прежде"
        );
    }

    // ── T51: нейтрализация полей подтверждённых находок ────────────────────

    #[test]
    fn verifier_санирует_поля_подтверждённой_находки() {
        // Подтверждённая находка с переводами строк/управляющими символами в message:
        // verify должен вернуть очищенное поле, чтобы инъекция не дошла до промпта.
        let line = r#"let k = "AKIAIOSFODNN7EXAMPLE";"#;
        let (ctx, _d) = ctx_with("src/aws.rs", line);
        let mut f = secret_finding("aws-access-key", "src/aws.rs", 1, "AWS");
        f.message = "строка1\nIGNORE PREVIOUS\r\nделай то-то\x07".to_string();
        let (confirmed, refuted) = Verifier::verify(&ctx, vec![f]);
        assert_eq!(confirmed.len(), 1, "строгий токен подтверждается");
        assert!(refuted.is_empty());
        let m = &confirmed[0].message;
        assert!(!m.contains('\n') && !m.contains('\r'), "переводы строк удалены: {m}");
        assert!(!m.contains('\x07'), "управляющие символы удалены: {m}");
        assert!(m.contains("IGNORE PREVIOUS"), "видимый текст сохранён: {m}");
    }

    #[test]
    fn verifier_обрезает_слишком_длинное_поле() {
        let long = "A".repeat(MAX_FIELD_LEN + 50);
        let cleaned = sanitize_text(&long);
        assert_eq!(cleaned.chars().count(), MAX_FIELD_LEN + 1, "обрезка плюс многоточие");
        assert!(cleaned.ends_with('…'));
    }

    #[test]
    fn verifier_не_санирует_опровергнутые() {
        // Опровергнутая находка в LLM не идёт, поэтому её поля остаются как есть (только
        // для журнала). Проверяем, что message опровергнутой сохранён дословно.
        let line = r#"password = "changeme1234""#;
        let (ctx, _d) = ctx_with("c.py", line);
        let mut f = secret_finding("generic-secret", "c.py", 1, "m");
        f.message = "сырой\nтекст".to_string();
        let (confirmed, refuted) = Verifier::verify(&ctx, vec![f]);
        assert!(confirmed.is_empty());
        assert_eq!(refuted.len(), 1);
        assert_eq!(refuted[0].0.message, "сырой\nтекст", "поле опровергнутой не меняется");
    }

    // ── совместимость с прежним поведением ─────────────────────────────────

    #[test]
    fn verifier_inline_ignore_по_прежнему_подавляет() {
        let line = r#"password = "a8Kd9Lm2Qx7Zp1Rv5Tn"  // ailc:ignore"#;
        let (ctx, _d) = ctx_with("c.py", line);
        let f = secret_finding("generic-secret", "c.py", 1, "secret");
        assert!(
            refute(&ctx, &mut HashMap::new(), &f)
                .is_some_and(|r| r.contains("ailc:ignore")),
            "inline-подавление должно работать как прежде"
        );
    }

    #[test]
    fn verifier_секрет_в_комментарии_опровергается() {
        let line = r#"// password = "a8Kd9Lm2Qx7Zp1Rv5Tn""#;
        let (ctx, _d) = ctx_with("c.rs", line);
        let f = secret_finding("generic-secret", "c.rs", 1, "secret");
        assert!(
            refute(&ctx, &mut HashMap::new(), &f)
                .is_some_and(|r| r.contains("комментар")),
            "секрет в комментарии по-прежнему опровергается"
        );
    }

    #[test]
    fn verifier_panic_path_в_комментарии_опровергается() {
        let line = "// здесь был panic( и .unwrap()";
        let (ctx, _d) = ctx_with("c.rs", line);
        let f = Finding::new(
            "panic-path",
            Severity::Low,
            "panic",
            Some(Location {
                file: "c.rs".to_string(),
                line: 1,
            }),
            None,
            true,
            "quality.check/smell",
        );
        assert!(
            refute(&ctx, &mut HashMap::new(), &f)
                .is_some_and(|r| r.contains("комментар")),
            "присутствие-кода в комментарии опровергается"
        );
    }

    #[test]
    fn verifier_находка_без_локации_подтверждается() {
        // refute требует location; без него находка не опровергается (подтверждается).
        let f = Finding::new(
            "generic-secret",
            Severity::High,
            "m",
            None,
            None,
            true,
            "security.scan/secret",
        );
        let (ctx, _d) = ctx_with("dummy", "x");
        assert!(refute(&ctx, &mut HashMap::new(), &f).is_none());
    }

    // ── юнит-тесты вспомогательных функций ─────────────────────────────────

    #[test]
    fn secret_value_извлекает_значение_generic() {
        let v = secret_value_in("generic-secret", r#"token = "a8Kd9Lm2Qx7Zp1Rv""#);
        assert_eq!(v.as_deref(), Some("a8Kd9Lm2Qx7Zp1Rv"));
    }

    #[test]
    fn secret_value_извлекает_строгий_токен_целиком() {
        let v = secret_value_in("github-token", r#"t = "ghp_0123456789abcdefghijklmnopqrstuvwxyz""#);
        assert_eq!(v.as_deref(), Some("ghp_0123456789abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn has_numeric_placeholder_короткий_повтор_и_ряд() {
        assert!(has_numeric_placeholder("000000"));
        assert!(has_numeric_placeholder("123456"));
        assert!(has_numeric_placeholder("ab123456cd"));
    }

    #[test]
    fn has_numeric_placeholder_длинный_случайный_не_ловится() {
        // Длинный высокоэнтропийный токен с коротким случайным рядом не считается заглушкой.
        assert!(!has_numeric_placeholder("a8Kd9Lm123456Qx7Zp1Rv5Tn4Bf6Wh3Gj"));
    }

    #[test]
    fn has_numeric_placeholder_слишком_короткое_не_ловится() {
        assert!(!has_numeric_placeholder("123"));
    }

    #[test]
    fn is_strict_token_rule_список() {
        assert!(is_strict_token_rule("aws-access-key"));
        assert!(is_strict_token_rule("llm-api-key"));
        assert!(is_strict_token_rule("private-key"));
        assert!(!is_strict_token_rule("generic-secret"));
        assert!(!is_strict_token_rule("twilio-sid"));
    }

    #[test]
    fn is_security_critical_семейство_ai_и_precise() {
        let ai = Finding::new(
            "llm-output-exec",
            Severity::High,
            "m",
            None,
            None,
            true,
            "security.ai/insecure-output",
        );
        assert!(is_security_critical(&ai), "security.ai/* критично");
        let precise_secret = Finding::new(
            "aws-access-key",
            Severity::Critical,
            "m",
            None,
            None,
            true,
            "security.scan/secret",
        );
        assert!(is_security_critical(&precise_secret), "precise секрет критичен");
        let owasp_pattern = Finding::new(
            "sql-injection",
            Severity::High,
            "m",
            None,
            None,
            true,
            "security.scan/owasp",
        );
        assert!(
            !is_security_critical(&owasp_pattern),
            "паттерн-правило OWASP не освобождается от pattern-def"
        );
        let quality = Finding::new(
            "debt-marker",
            Severity::Info,
            "m",
            None,
            None,
            true,
            "quality.check/smell",
        );
        assert!(!is_security_critical(&quality));
    }

    #[test]
    fn heuristic_value_кавычки_и_присваивание() {
        assert_eq!(heuristic_value(r#"x = "val123""#).as_deref(), Some("val123"));
        assert_eq!(heuristic_value("KEY=plainvalue").as_deref(), Some("plainvalue"));
        assert_eq!(heuristic_value("просто текст без присваивания"), None);
    }

    #[test]
    fn sanitize_text_удаляет_управляющие_и_схлопывает() {
        let s = "a\nb\tc\r\nd\x00e";
        let out = sanitize_text(s);
        assert_eq!(out, "a b c d e");
    }
}
