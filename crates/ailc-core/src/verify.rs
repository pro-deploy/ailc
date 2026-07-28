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

use ailc_contracts::{Ctx, Finding};
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
        // Самообучение на проекте: правила, хронически опровергаемые ИМЕННО ЗДЕСЬ,
        // теряют голос (понижение до Low с видимой пометкой), security-критичные
        // исключены. Статистика копится в .ailc/verify-memory и обновляется каждым
        // прогоном; это храповик видимости, а не выключатель.
        learn_and_downgrade(ctx, &mut confirmed, &refuted);
        (confirmed, refuted)
    }
}

/// Порог наблюдений, после которого статистика правила считается представительной.
const LEARN_MIN_OBSERVATIONS: u64 = 20;
/// Доля опровергнутых, начиная с которой правило считается шумным на этом проекте.
const LEARN_REFUTE_RATIO: f64 = 0.8;

/// Применить накопленное знание (понизить хронически шумные правила) и дописать
/// статистику текущего прогона. Работает только внутри инициализированного проекта
/// (есть `.ailc/`); ошибки ввода-вывода глотаются: обучение — побочный эффект.
fn learn_and_downgrade(ctx: &Ctx, confirmed: &mut [Finding], refuted: &[(Finding, String)]) {
    if (confirmed.is_empty() && refuted.is_empty()) || !ctx.root.join(".ailc").is_dir() {
        return;
    }
    let path = ctx.root.join(".ailc/verify-memory/rules.tsv");
    // Файловая блокировка на цикл «прочитал, изменил, записал». Без неё два параллельных
    // процесса (например, MCP-сервер и ручной запуск в CI) читали бы одну и ту же версию
    // статистики и последний записавший затирал бы обновления первого. Блокировка простая:
    // атомарное создание lock-файла (`create_new`) с ожиданием и таймаутом; протухший
    // lock-файл упавшего процесса снимается по возрасту. Если замок получить не удалось,
    // понижение по прошлой статистике всё равно применяется, а ЗАПИСЬ пропускается: лучше
    // потерять одно наблюдение своего прогона, чем затереть чужие.
    let _ = fs::create_dir_all(ctx.root.join(".ailc/verify-memory"));
    let lock = acquire_file_lock(&ctx.root.join(".ailc/verify-memory/rules.tsv.lock"));
    // rule -> (опровергнуто, подтверждено)
    let mut stats: HashMap<String, (u64, u64)> = HashMap::new();
    if let Ok(text) = fs::read_to_string(&path) {
        for l in text.lines() {
            let mut it = l.split('\t');
            if let (Some(rule), Some(r), Some(c)) = (it.next(), it.next(), it.next()) {
                if let (Ok(r), Ok(c)) = (r.parse(), c.parse()) {
                    stats.insert(rule.to_string(), (r, c));
                }
            }
        }
    }

    // Сначала знание по ПРОШЛЫМ прогонам, затем учёт текущего (текущий прогон не должен
    // сам себя понижать).
    for f in confirmed.iter_mut() {
        if is_security_critical(f) {
            continue;
        }
        if let Some((r, c)) = stats.get(&f.rule) {
            let total = r + c;
            if total >= LEARN_MIN_OBSERVATIONS
                && (*r as f64) / (total as f64) >= LEARN_REFUTE_RATIO
                && f.severity > ailc_contracts::Severity::Low
            {
                f.severity = ailc_contracts::Severity::Low;
                f.message.push_str(&format!(
                    " [правило часто шумит на этом проекте: опровергнуто {r} из {total}]"
                ));
            }
        }
    }
    // СЧЁТ ВЕДЁТСЯ ПО МЕСТАМ, А НЕ ПО ЭКЗЕМПЛЯРАМ находок.
    //
    // Прежде считался каждый экземпляр, и это ломало смысл порога наблюдений: один файл с
    // двадцатью пятью опровергнутыми совпадениями одного правила пересекал порог в двадцать
    // наблюдений за ОДИН прогон и понижал правило навсегда. «Правило хронически шумит на
    // этом проекте» это утверждение о РАЗНЫХ местах кода, а не о числе строк в одном файле,
    // поэтому за наблюдение принимается уникальная точка (файл и строка), а находки без
    // локации не учитываются вовсе: их нельзя отличить друг от друга.
    //
    // Подавленное маркером `ailc:ignore` в статистику НЕ идёт: это решение человека скрыть
    // находку, а не свидетельство её ложности. Иначе подавление одного места работало бы как
    // рычаг понижения правила во всём проекте.
    let mut seen: std::collections::HashSet<(String, String, u32)> =
        std::collections::HashSet::new();
    let mut site = |f: &Finding| -> bool {
        match f.location.as_ref() {
            Some(l) => seen.insert((f.rule.clone(), l.file.clone(), l.line)),
            None => false,
        }
    };
    for f in confirmed.iter() {
        if site(f) {
            stats.entry(f.rule.clone()).or_default().1 += 1;
        }
    }
    for (f, reason) in refuted {
        if !is_inline_suppression(reason) && site(f) {
            stats.entry(f.rule.clone()).or_default().0 += 1;
        }
    }

    let mut rows: Vec<(String, (u64, u64))> = stats.into_iter().collect();
    rows.sort();
    let mut body = String::from("# правило\tопровергнуто\tподтверждено (самообучение verify)\n");
    for (rule, (r, c)) in rows {
        body.push_str(&format!("{rule}\t{r}\t{c}\n"));
    }
    if lock.is_some() {
        let _ = crate::engines::store::Store::write(ctx, "verify-memory", "rules.tsv", &body);
    }
}

/// Захваченный lock-файл: удаляется при выходе из области видимости, снимая блокировку.
struct FileLock(std::path::PathBuf);

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Сколько всего ждать захвата блокировки, прежде чем отказаться от записи.
const LOCK_WAIT_TOTAL: std::time::Duration = std::time::Duration::from_secs(1);
/// Шаг ожидания между попытками захвата.
const LOCK_WAIT_STEP: std::time::Duration = std::time::Duration::from_millis(20);
/// Возраст lock-файла, после которого он считается протухшим (упавший процесс) и снимается.
const LOCK_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

/// Захватить простую файловую блокировку: атомарно создать lock-файл (`create_new`).
/// Занятый замок ждём с шагом `LOCK_WAIT_STEP` до `LOCK_WAIT_TOTAL`; lock-файл старше
/// `LOCK_STALE_AFTER` признаётся оставленным упавшим процессом и удаляется. `None`
/// означает, что замок получить не удалось (вызывающий пропускает запись).
fn acquire_file_lock(path: &std::path::Path) -> Option<FileLock> {
    let deadline = std::time::Instant::now() + LOCK_WAIT_TOTAL;
    loop {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(_) => return Some(FileLock(path.to_path_buf())),
            Err(_) => {
                // Протухший замок упавшего процесса снимаем по возрасту, иначе обучение
                // остановилось бы навсегда.
                let stale = fs::metadata(path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > LOCK_STALE_AFTER);
                if stale {
                    let _ = fs::remove_file(path);
                    continue;
                }
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(LOCK_WAIT_STEP);
            }
        }
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
    if ignore_hit(line, f) || prev.is_some_and(|p| ignore_hit(p, f)) {
        return Some(SUPPRESSION_REASON.to_string());
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

    // Семейства, для которых находка на строке-комментарии заведомо ложна: строка не
    // исполняется, поэтому ни утечки, ни нарушения в ней произойти не может.
    //
    // Семейство `compliance.ru` включено сюда по двум сходящимся основаниям. Во-первых, все
    // девять его правил (`pdn-in-logs`, `pdn-in-logs-multiline`, `pdn-logs-ast`,
    // `foreign-db-host`, `foreign-region`, `foreign-tracker`, `pre-checked-consent`,
    // `gost-crypto`, `foreign-crypto-primitive`) опознают КОНСТРУКЦИИ КОДА и настроек, а не
    // наличие требуемого текста в документации, поэтому комментарий для них не может быть
    // законным местом находки. Во-вторых, ниже по тексту список `value_bearing` уже
    // перечисляет `compliance.ru`, но условие `!security` не пускало туда управление, то
    // есть замысел автора и фактическое поведение расходились. Обнаружено запуском: правило
    // `pdn-in-logs` срабатывало на строке пояснительного комментария в
    // `crates/ailc-core/src/engines/sast.rs`, приводившей пример неправильного вызова
    // логгера, и эта находка проходила в блокирующее множество вердикта.
    let security = f.source.contains("security")
        || f.source.contains("pii")
        || f.source.contains("compliance.ru");
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

    // (3) Плейсхолдер-значение. Применимо ТОЛЬКО к находкам о ЗАШИТЫХ ЗНАЧЕНИЯХ (секреты и
    // персональные данные) и только НЕ для строгих токенов.
    //
    // Ограничение по источнику существенно. Вопрос «не заглушка ли это значение» осмыслен
    // ровно там, где находка утверждает наличие настоящего секрета или настоящих
    // персональных данных. Для правила об опасном вызове (`dangerous-exec`, `sql-injection`,
    // `xss-sink`) он бессмыслен: дефект там в способе вызова, а не в подлинности какой-либо
    // строки рядом. Прежде ограничения не было, и в паре с откатом на всю строку (см. ниже)
    // это давало обход гейта одним словом: проверялось запуском, что `os.system(u)  # example`
    // и `os.system(u)  # dummy` дают НОЛЬ находок вместо двух.
    let value_bearing = f.source.contains("security.scan/secret")
        || f.source.contains("pii")
        || f.source.contains("compliance.ru");
    if !security || strict_token || !value_bearing {
        return None;
    }
    // Есть класс правил, где дефектом является САМА ПОСТОЯННОСТЬ значения, а не его
    // подлинность: вектор инициализации, соль, зашитый криптоматериал. Для них
    // «похоже на заглушку» не опровержение, а подтверждение: именно заглушки вроде
    // `0123456789abcdef` и попадают в такой код чаще всего, и они уязвимы ровно потому,
    // что постоянны. Опровергать их по виду значения значило бы гасить настоящую находку.
    if is_constant_is_defect_rule(&f.rule) {
        return None;
    }

    // Эвристики плейсхолдера применяем СТРОГО к захваченному значению секрета, а не ко
    // всей физической строке (см. T01). Значение извлекаем по канонической форме правила;
    // если форма правила неизвестна (нестрогие правила без явной capture-формы), берём
    // эвристический «значение-подобный» фрагмент строки, чтобы не сравнивать с именами
    // переменных и ключевыми словами вокруг присваивания.
    //
    // ЕСЛИ ЗНАЧЕНИЕ ИЗВЛЕЧЬ НЕ УДАЛОСЬ, находка НЕ опровергается. Прежде здесь стоял откат на
    // всю физическую строку, и он полностью обесценивал заявленное ограничение: сравнивать
    // было не с чем, поэтому проверялась вся строка, включая комментарий. Достаточно было
    // одного слова из перечня ниже в любом месте строки, чтобы находка исчезла. Отсутствие
    // значения означает «судить не о чем», а не «можно судить обо всём».
    let value = secret_value_in(&f.rule, line).or_else(|| heuristic_value(line))?;

    let lower = value.to_lowercase();
    const PLACEHOLDERS: &[&str] = &[
        "changeme",
        "change-me",
        "change me",
        "your_",
        "your-",
        "<your",
        "example",
        "placeholder",
        "todo",
        "dummy",
        "fake",
        "sample",
        "xxxxxxxx",
        "смени",
        "замени",
        "вставь",
        "измени",
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

/// Правила, для которых дефектом является постоянство значения, а не его подлинность.
/// К ним эвристики плейсхолдера не применяются: заглушка на месте случайного значения
/// это и есть уязвимость (постоянный вектор инициализации, статическая соль, зашитый
/// криптоматериал), а не признак ложного срабатывания.
fn is_constant_is_defect_rule(rule: &str) -> bool {
    const CONSTANT_IS_DEFECT: &[&str] = &["static-iv", "hardcoded-crypto-material"];
    CONSTANT_IS_DEFECT.contains(&rule)
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
/// «определение шаблона поиска», и её не понижает самообучение.
///
/// Критично ЛЮБОЕ находке из security-источника (включая семейство `security.ai/*`), а не
/// только правило точной достоверности. Прежнее условие требовало
/// `rule_confidence == Precise`, и это было дырой, а не строгостью: достоверность правил
/// OWASP и web/api (`sql-injection`, `dangerous-exec`, `xss-sink`, `ssrf`,
/// `path-traversal`) объявлена `Pattern`, поэтому под защиту они НЕ попадали. Практическое
/// следствие проверялось запуском: дописанный к уязвимой строке безобидный хвостовой
/// комментарий вида `# см. matcher .contains("rm")` снимал находки `sql-injection` и
/// `dangerous-exec`, и они подавались человеку как «ложные, опровергнутые верификатором».
/// То есть проверяемая сторона гасила находки о себе. Ровно эту атаку T51 и закрывает,
/// поэтому условие по достоверности снято: класс уверенности правила говорит о точности
/// сигнала, а не о том, можно ли доверять окружающему тексту.
///
/// Самосовпадение детектора на собственном наборе правил остаётся погашенным, но уже не
/// этой эвристикой, а узкой и однозначной `is_unmistakable_rule_def`: литерал регулярного
/// выражения либо вызов конструктора правила. Живой эксплуатируемый вызов такой строкой не
/// бывает, а безобидным комментарием её не подделать.
fn is_security_critical(f: &Finding) -> bool {
    f.source.contains("security") || f.source.contains("pii")
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
/// один раз (`OnceLock`). Несобравшийся литерал исключает СВОЮ форму, а не завершает
/// процесс: опровержение по значению для этого правила просто не применяется.
#[allow(clippy::type_complexity)]
fn secret_forms() -> &'static [(&'static str, Regex, usize)] {
    static FORMS: OnceLock<Vec<(&'static str, Regex, usize)>> = OnceLock::new();
    FORMS.get_or_init(|| {
        let r = crate::re::compile;
        let forms: Vec<(&'static str, Option<Regex>, usize)> = vec![
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
        ];
        // Форма, чей литерал не собрался, из таблицы исключается: опровержение по
        // значению для этого правила просто не применяется, процесс продолжает работу.
        forms
            .into_iter()
            .filter_map(|(id, re, group)| re.map(|re| (id, re, group)))
            .collect()
    })
}

/// Эвристический «значение-подобный» фрагмент строки для секрет-правил без известной
/// canonical-формы: содержимое первого строкового литерала в кавычках, иначе хвост после
/// первого `=`/`:` без кавычек. Нужен, чтобы плейсхолдер искался в значении, а не в имени
/// переменной или ключевом слове присваивания. `None`, если ни то ни другое не найдено.
fn heuristic_value(line: &str) -> Option<String> {
    static QUOTED: OnceLock<Option<Regex>> = OnceLock::new();
    let quoted = QUOTED
        .get_or_init(|| crate::re::compile(r#"["']([^"']{1,200})["']"#))
        .as_ref();
    if let Some(c) = quoted.and_then(|re| re.captures(line)) {
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

/// Inline-флаги и группы регулярного выражения. Единая таблица: прежде эти же токены были
/// продублированы двумя локальными массивами в соседних функциях, и массивы РАСХОДИЛИСЬ
/// (в одном был `(?is)`, в другом нет), из-за чего судьба security-находки зависела от
/// того, в какой из двух почти одинаковых списков попал токен в её строке.
const REGEX_META: &[&str] = &["(?i)", "(?m)", "(?s)", "(?x)", "(?is)", "(?:"];

/// Вызовы-конструкторы правил: строка с таким вызовом объявляет шаблон поиска.
const RULE_CTORS: &[&str] = &[
    "Matcher::regex(",
    "Matcher::window_regex(",
    "Matcher::Predicate(",
    "Regex::new(",
    "regexp.MustCompile(",
    "re.compile(",
];

/// Стоит ли мета-символ регулярного выражения ВНУТРИ строкового литерала.
///
/// Требование «внутри литерала» принципиально. Прежняя проверка искала `(?i)` в любом месте
/// строки, поэтому безобидный хвостовой комментарий `# (?i) шаблон`, дописанный к живой
/// SQL-инъекции, выглядел как «безошибочное определение правила» и гасил находку. Это
/// проверялось запуском. Настоящее определение шаблона всегда несёт мета-символ в литерале
/// (`r"(?i)…"`, `"(?:…)"`), а комментарий на естественном языке — нет.
///
/// Разбор кавычек упрощённый (учитывается экранирование обратной косой чертой, но не
/// вложенные виды литералов разных языков) и это осознанно: задача не разобрать язык, а
/// отсечь текст вне литерала. Ошибка в сторону «не внутри литерала» безопасна, потому что
/// ведёт к сохранению находки, а не к её сокрытию.
fn regex_meta_in_literal(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = quote {
            // Внутри литерала: сначала ищем мета-символ, затем обрабатываем закрытие.
            if REGEX_META
                .iter()
                .any(|m| line.get(i..).is_some_and(|t| t.starts_with(m)))
            {
                return true;
            }
            if c == b'\\' {
                i += 2; // экранированный символ литерала не закрывает его
                continue;
            }
            if c == q {
                quote = None;
            }
        } else if c == b'r'
            && {
                let prev = if i == 0 { b' ' } else { bytes[i - 1] };
                !(prev.is_ascii_alphanumeric() || prev == b'_')
            }
            && crate::engines::scan::raw_string_len(bytes, i).is_some()
        {
            // Сырой строковый литерал: ищем мета-символ во всей его внутренности, не давая
            // внутренней кавычке (класс `["']`) закрыть литерал преждевременно.
            let len = crate::engines::scan::raw_string_len(bytes, i).unwrap();
            let mut hashes = 0usize;
            while bytes.get(i + 1 + hashes) == Some(&b'#') {
                hashes += 1;
            }
            let inner_start = i + 1 + hashes + 1;
            let inner_end = (i + len).saturating_sub(1 + hashes);
            for p in inner_start..inner_end {
                if REGEX_META
                    .iter()
                    .any(|m| line.get(p..).is_some_and(|t| t.starts_with(m)))
                {
                    return true;
                }
            }
            i += len;
            continue;
        } else if c == b'"' {
            quote = Some(c);
        } else if c == b'\'' {
            // Апостроф открывает литерал лишь когда это символьный литерал; время жизни
            // Rust (`&'a`, `'static`) и апостроф прозы литерала не открывают, иначе остаток
            // строки ошибочно считался бы содержимым литерала.
            if let Some(len) = crate::engines::scan::char_literal_len(bytes, i) {
                i += len;
                continue;
            }
        }
        i += 1;
    }
    false
}

/// Кодовая часть строки: всё до начала КОНЕЧНОГО комментария, стоящего вне строкового
/// литерала. Нужна затем, чтобы признаки «определения шаблона поиска» искались в КОДЕ, а не
/// в дописанном к коду тексте на естественном языке. Именно это различает два внешне похожих
/// случая: тело предиката-детектора `|l| l.contains("eval(")` (настоящее определение
/// правила, находку следует опровергнуть) и живой уязвимый вызов с безобидным хвостом
/// `os.system(cmd)  # см. matcher .contains("rm")` (находку следует сохранить).
///
/// Направление ошибки выбрано осознанно: при сомнении считаем текст комментарием и отрезаем
/// БОЛЬШЕ. Лишнее отсечение оставляет находку в отчёте (безопасно), недостаточное отсечение
/// позволило бы погасить настоящую находку припиской (опасно).
fn code_part_of(line: &str) -> &str {
    let b = line.as_bytes();
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if let Some(q) = quote {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        // Сырой строковый литерал Rust перескакивается ЦЕЛИКОМ: маркеры комментария и
        // кавычки внутри него кодом не являются (см. `raw_string_len`). Признак действителен,
        // лишь когда `r` не продолжает идентификатор (`str`, `expr`).
        let prev_c = if i == 0 { b' ' } else { b[i - 1] };
        if c == b'r' && !(prev_c.is_ascii_alphanumeric() || prev_c == b'_') {
            if let Some(len) = crate::engines::scan::raw_string_len(b, i) {
                i += len;
                continue;
            }
        }
        if c == b'"' {
            quote = Some(c);
            i += 1;
            continue;
        }
        if c == b'\'' {
            // См. `char_literal_len`: время жизни Rust литерала не открывает.
            if let Some(len) = crate::engines::scan::char_literal_len(b, i) {
                i += len;
            } else {
                i += 1;
            }
            continue;
        }
        let prev = if i == 0 { b' ' } else { b[i - 1] };
        let next = b.get(i + 1).copied().unwrap_or(b' ');
        // `//` — комментарий, кроме схемы URL (`https://`).
        if c == b'/' && next == b'/' && prev != b':' {
            return &line[..i];
        }
        // `/*` и `<!--` — начало блочного комментария.
        if (c == b'/' && next == b'*') || (c == b'<' && line[i..].starts_with("<!--")) {
            return &line[..i];
        }
        // `#` — комментарий, кроме сырого строкового литерала Rust (`r#"…"#`), где решётка
        // примыкает к `r` или к кавычке.
        if c == b'#' && next != b'"' && prev != b'r' && prev != b'"' && prev != b'#' {
            return &line[..i];
        }
        // `--` — комментарий SQL/Lua/Ada: требуем пробел перед парой, чтобы не спутать с
        // оператором декремента `a--b`.
        if c == b'-' && next == b'-' && (i == 0 || prev.is_ascii_whitespace()) {
            return &line[..i];
        }
        i += 1;
    }
    line
}

/// Имена СТРОКОВЫХ ПРЕДИКАТОВ разных языков: проверка вхождения подстроки. Список описывает
/// семантику («сравнить строку с образцом»), а не набор правил ailc, поэтому он устойчив и не
/// требует синхронизации с реестром.
const STR_PREDICATES: &[&str] = &[
    "contains",
    "includes",
    "starts_with",
    "startswith",
    "ends_with",
    "endswith",
    "find",
    "matches",
    "test",
    "search",
    "indexof",
    "hasprefix",
    "hassuffix",
    "eq_ignore_ascii_case",
];

/// Заменить содержимое строковых литералов пробелами, сохранив длину. Нужно, чтобы отличать
/// код от ДАННЫХ: опасная конструкция внутри литерала это образец для поиска, а не вызов.
fn blank_literals(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        // Сырой строковый литерал Rust (`r#"…"#`) разбирается ЦЕЛИКОМ: его содержимое может
        // включать двойную кавычку (класс символов `["']` в регулярном выражении), и наивный
        // разбор закрывал бы литерал на ней раньше времени, обнажая хвост как код. Признак
        // сырого литерала действителен, лишь когда `r` не продолжает идентификатор.
        let prev_ident = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        if c == b'r' && !prev_ident {
            if let Some(len) = crate::engines::scan::raw_string_len(b, i) {
                // Открывающие `r#"` и закрывающие `"#` сохраняем, внутренность зануляем,
                // сохраняя длину: разбор идёт по этому же результату, наружу позиции не
                // отображаются.
                let mut hashes = 0usize;
                while b.get(i + 1 + hashes) == Some(&b'#') {
                    hashes += 1;
                }
                let open = 1 + hashes + 1; // r + решётки + "
                let close = 1 + hashes; // " + решётки
                for k in 0..len {
                    if k < open || k >= len.saturating_sub(close) {
                        out.push(b[i + k]);
                    } else {
                        out.push(b' ');
                    }
                }
                i += len;
                continue;
            }
        }
        // Символьный литерал / время жизни: `char_literal_len` отличает `'x'` от `'a`.
        if c == b'\'' {
            if let Some(len) = crate::engines::scan::char_literal_len(b, i) {
                for k in 0..len {
                    if k == 0 || k == len - 1 {
                        out.push(b[i + k]);
                    } else {
                        out.push(b' ');
                    }
                }
                i += len;
                continue;
            }
            out.push(c);
            i += 1;
            continue;
        }
        // Обычный строковый литерал в двойных кавычках.
        if c == b'"' {
            out.push(c);
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    out.push(b' ');
                    if i + 1 < b.len() {
                        out.push(b' ');
                    }
                    i += 2;
                    continue;
                }
                if b[i] == b'"' {
                    out.push(b'"');
                    i += 1;
                    break;
                }
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Является ли строка ОПРЕДЕЛЕНИЕМ СОПОСТАВИТЕЛЯ: она содержит строковый литерал, в её
/// кодовой части есть ХОТЯ БЫ ОДИН вызов строкового предиката, и при этом НЕТ ни одного
/// иного вызова. То есть опасная конструкция присутствует только как ДАННЫЕ (образец для
/// поиска), а строка занимается сравнением строк, а не исполнением.
///
/// Это точный признак законного самосовпадения детектора на собственном наборе правил.
/// Опознаёт: `l.contains("os.system(")`, `|| f.ends_with("objectinputstream")`. НЕ опознаёт и
/// тем сохраняет находку: `os.system("rm -rf " + user)` вместе с любой припиской в
/// комментарии, потому что `system` строковым предикатом не является.
///
/// Требование хотя бы одного предиката существенно. Без него условие выполнялось ВХОЛОСТУЮ
/// на строке вообще без вызовов, то есть на присваивании литеральной константы вида
/// `const iv = "0123456789abcdef"`, а это ровно те находки (зашитый вектор инициализации,
/// криптоматериал), где постоянство значения и ЕСТЬ дефект. Контролируемый корпус поймал
/// это как пять пропущенных настоящих уязвимостей.
///
/// Самосовпадение на ТЕКСТЕ СООБЩЕНИЯ правила (строка вида `message: "… alg=none …"`) этим
/// признаком сознательно не покрывается: там нет ни предиката, ни исполнения, и отличить её
/// от присваивания уязвимой константы по форме нельзя. Такие точки помечаются именованным
/// маркером `ailc:ignore[<правило>]`, что оставляет решение видимым в ревизии.
fn is_matcher_definition(line: &str) -> bool {
    let code = code_part_of(line);
    if !code.contains('"') && !code.contains('\'') {
        return false; // без литерала-образца это не определение сопоставителя
    }
    let blanked = blank_literals(code);
    let b = blanked.as_bytes();
    let mut predicates = 0usize;
    // Каждый вызов вида `ИМЯ(` обязан быть строковым предикатом, и хотя бы один обязан быть.
    for (i, _) in blanked.match_indices('(') {
        let mut start = i;
        while start > 0 {
            let c = b[start - 1];
            if c.is_ascii_alphanumeric() || c == b'_' {
                start -= 1;
            } else {
                break;
            }
        }
        if start == i {
            continue; // группирующая скобка без имени
        }
        let name = blanked[start..i].to_ascii_lowercase();
        if !STR_PREDICATES.contains(&name.as_str()) {
            return false; // настоящий вызов: это живой код, а не образец
        }
        predicates += 1;
    }
    predicates > 0
}

/// Все ли вызовы в кодовой части строки (после гашения литералов) являются законными
/// вызовами конструкции правила: строковыми предикатами либо конструкторами шаблона
/// (`Regex::new`, `re.compile`, `Matcher::regex` и подобными). Строка без единого «живого»
/// вызова тоже проходит (присваивание литерала-шаблона вида `pat = "(?:a|b)"`).
///
/// Проверка закрывает обход T51: прежде безобидный строковый литерал с regex-мета в любом
/// месте кодовой части строки (например `os.system(cmd); x = "(?i)"`) делал всю строку
/// «безошибочным определением правила» и гасил security-находку о живом вызове рядом.
/// Теперь наличие любого постороннего вызова (в примере: `system(`) означает живой код, и
/// опровержение не применяется: опасная конструкция обязана находиться ВНУТРИ литерала, а
/// не просто соседствовать с литералом, содержащим мета-символ.
fn only_rule_construction_calls(code: &str) -> bool {
    // Имена вызовов-конструкторов шаблона (последний сегмент из RULE_CTORS в нижнем
    // регистре): `Regex::new(` даёт `new`, `re.compile(` даёт `compile` и так далее.
    const CTOR_NAMES: &[&str] = &[
        "regex",
        "window_regex",
        "predicate",
        "new",
        "mustcompile",
        "compile",
    ];
    let blanked = blank_literals(code);
    let b = blanked.as_bytes();
    for (i, _) in blanked.match_indices('(') {
        let mut start = i;
        while start > 0 {
            let c = b[start - 1];
            if c.is_ascii_alphanumeric() || c == b'_' {
                start -= 1;
            } else {
                break;
            }
        }
        if start == i {
            continue; // группирующая скобка без имени
        }
        let name = blanked[start..i].to_ascii_lowercase();
        // `pub(crate)`, `pub(super)`, `pub(in …)` это модификатор видимости Rust, а не вызов.
        // Определение правила в реестре ailc обычно объявлено как `pub(crate) const RE_… =
        // r"…"`, и без этого исключения сама решётка видимости выдавала бы строку за живой код,
        // из-за чего самосовпадение детектора на собственном наборе правил (например
        // `cors-reflect-origin` на константе `CORS_REFLECT_ORIGIN_RE`) проходило в отчёт.
        // Пропуск безопасен: настоящий опасный вызов на строке сохраняет собственное имя
        // (`system`, `exec`), которое здесь по-прежнему отвергается.
        if name == "pub" {
            continue;
        }
        if !STR_PREDICATES.contains(&name.as_str()) && !CTOR_NAMES.contains(&name.as_str()) {
            return false; // посторонний вызов: это живой код, а не определение правила
        }
    }
    true
}

/// БЕЗОШИБОЧНАЯ конструкция определения правила: литерал регулярного выражения с regex-мета,
/// вызов конструктора Regex/Matcher либо определение сопоставителя, где опасная конструкция
/// присутствует лишь как данные, причём всё это В КОДОВОЙ ЧАСТИ строки. Строка такого вида
/// не бывает живым эксплуатируемым вызовом, поэтому опровержение security-находки здесь
/// безопасно: это единственная лазейка, оставленная для гашения самосовпадения детектора на
/// собственном наборе правил (см. `is_security_critical`).
///
/// Дополнительное требование (закрытие обхода T51): помимо самого признака (конструктор
/// правила либо мета-символ в литерале) в кодовой части строки не должно быть ни одного
/// постороннего вызова. Иначе строка вида `os.system(cmd); x = "(?i)"` считалась бы
/// определением правила из-за безобидного литерала с мета-символом, хотя опасная
/// конструкция стоит в живом коде, а не внутри литерала.
fn is_unmistakable_rule_def(line: &str) -> bool {
    let code = code_part_of(line);
    // Конструктор правила ищем в кодовой части с погашенными литералами: имя конструктора
    // внутри строкового литерала (`s = "Regex::new("`) определением правила не является.
    let blanked = blank_literals(code);
    ((RULE_CTORS.iter().any(|c| blanked.contains(c)) || regex_meta_in_literal(code))
        && only_rule_construction_calls(code))
        || is_matcher_definition(line)
}

/// Похожа ли строка на ОПРЕДЕЛЕНИЕ паттерна (а не на живой уязвимый код): литерал regex,
/// вызов-конструктор правила, булева цепочка `.contains("…")` (тело предиката-детектора).
fn looks_like_pattern_def(line: &str) -> bool {
    // Строка-правило конституции ailc (FORBID/REQUIRE <подстрока>) — это шаблон для
    // поиска, а не живой секрет/вызов. Иначе сканер находит секреты в собственных правилах.
    let t = line.trim_start();
    if t.starts_with("FORBID ") || t.starts_with("REQUIRE ") {
        return true;
    }
    if is_unmistakable_rule_def(line) {
        return true;
    }
    // Строковые предикаты-поиска с литералом (.contains/.ends_with/.starts_with/.find)
    // — это матчинг подстрок (определение правила/парсинг), а не живой уязвимый вызов.
    // Ищем ТОЛЬКО в кодовой части: тот же предикат, дописанный в комментарий к живому
    // уязвимому вызову, определением правила не является (см. `code_part_of`).
    const STR_PRED: &[&str] = &[
        ".contains(\"",
        ".ends_with(\"",
        ".starts_with(\"",
        ".find(\"",
    ];
    let code = code_part_of(line);
    STR_PRED.iter().any(|p| code.contains(p))
}

/// Причина опровержения для подавленной inline-маркером находки. Единая константа, чтобы
/// подавление можно было отличить от настоящего опровержения ложного срабатывания
/// программно (см. `is_inline_suppression`), а не сравнением вольного текста.
pub const SUPPRESSION_REASON: &str = "подавлено inline-комментарием (ailc:ignore)";

/// Является ли причина опровержения ПОДАВЛЕНИЕМ, а не опровержением ложной находки.
/// Различие принципиально для отчётности: подавление это решение человека скрыть
/// настоящую находку, а опровержение это вывод инструмента о её ложности. Складывать их в
/// один счётчик «ложные срабатывания, опровергнутые верификатором» значит выдавать первое
/// за второе, поэтому потребители отчёта считают их раздельно.
#[must_use]
pub fn is_inline_suppression(reason: &str) -> bool {
    reason.starts_with(SUPPRESSION_REASON)
}

/// Решение о inline-подавлении находки маркером `ailc:ignore` в строке.
///
/// ПОЛИТИКА (ужесточена намеренно). Прежняя реализация принимала ГОЛЫЙ маркер как
/// разрешение погасить ЛЮБОЕ правило без потолка по важности. Это делало гейт
/// необязательным для проверяемой стороны: проверялось запуском, что три комментария
/// `# ailc:ignore` снимают все пять находок в файле, включая зашитый ключ доступа AWS, и
/// все оси безопасности показывают «находок: 0». Инструмент, у которого проверяемый код
/// отменяет вердикт о себе одной строкой комментария, гарантии не даёт.
///
/// Действующая политика:
///
/// 1. Находка семейства безопасности подавляется только ИМЕНОВАННЫМ маркером
///    `ailc:ignore[<правило>]`. Требование назвать правило превращает подавление из
///    бланкетного в узкое и осознанное: маркер гасит ровно названное правило и не
///    распространяется на другие находки в этой же точке, в том числе будущие. В отличие от
///    голого маркера, названное правило видно в разнице ревизий и обсуждаемо на код-ревью.
/// 2. Прочие находки (качество, стиль, спека) подавляются и голым маркером: цена ошибки
///    здесь несопоставима, а трение обесценило бы механизм.
///
/// Полный запрет подавления для важности `High` и выше рассматривался и ОТКЛОНЁН. Он ломает
/// законный и необходимый случай: сканер находит собственный набор правил, где опасная
/// конструкция стоит внутри строкового литерала (текст сообщения правила, тело
/// предиката-детектора). Такие точки в этом репозитории и помечены именованными маркерами.
/// Запрет вынуждал бы либо держать заведомо ложные блокеры вечно, либо отключать правило
/// целиком, что строго хуже узкого именованного подавления.
///
/// Существенное дополнение к обеим ветвям: подавление УЧИТЫВАЕТСЯ ОТДЕЛЬНО от опровержения
/// ложных находок (см. `is_inline_suppression`) и попадает в отчёт своим счётчиком. Молчаливым
/// подавление быть не должно, иначе оно неотличимо от чистого результата.
fn ignore_hit(line: &str, f: &Finding) -> bool {
    const MARK: &str = "ailc:ignore";
    // Берём ПОСЛЕДНЕЕ вхождение: маркер, случайно попавший в строковый литерал в начале
    // строки, не должен заслонять настоящий маркер в хвостовом комментарии.
    let Some(i) = line.rfind(MARK) else {
        return false;
    };
    // Маркер действует ТОЛЬКО в комментарии. Прежде он был подстрокой без проверки
    // контекста, поэтому срабатывал и внутри строкового литерала, и на строке-не-комментарии
    // (например `let s = "ailc:ignore";`), то есть данные программы отменяли вердикт о ней.
    // Кодовая часть строки вычисляется `code_part_of` (понимает //, #, /* и <!--, -- с
    // учётом строковых литералов); маркер законен, лишь когда стоит ПОСЛЕ неё, то есть в
    // комментарии. Дополнительно поддержан комментарий, начинающийся с `;` (ассемблер,
    // INI, Lisp) и строка-продолжение блочного комментария, начинающаяся с `*`: для них
    // вся строка является комментарием.
    let trimmed = line.trim_start();
    let whole_line_comment = trimmed.starts_with(';') || trimmed.starts_with('*');
    if !whole_line_comment && i < code_part_of(line).len() {
        return false;
    }
    let rest = &line[i + MARK.len()..];
    if let Some(stripped) = rest.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return stripped[..end]
                .split(',')
                .map(str::trim)
                .any(|r| r == f.rule);
        }
    }
    // Голый маркер: разрешён только для не-security находок (2); для security нужен
    // именованный маркер (1).
    !is_security_critical(f)
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
        assert_eq!(
            confirmed2.len(),
            1,
            "незащищённый парсер обязан остаться находкой"
        );
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

    /// РЕГРЕССИЯ. Строка-определение правила безопасности, чей образец задан СЫРЫМ строковым
    /// литералом Rust с внутренней двойной кавычкой (класс символов `['"]`) и группой
    /// `ИМЯ(?:…)`, обязана опознаваться как определение шаблона и опровергать самосовпадение
    /// детектора. До исправления наивный разбор кавычек закрывал сырой литерал на внутренней
    /// кавычке, хвост образца выглядел кодом, конструкция `CURLOPT_SSL_VERIFY(?:PEER|HOST)`
    /// принималась за посторонний вызов, и находка `tls-verify-off` высокой важности проходила
    /// в блокирующее множество прямо на исходном тексте самого инструмента.
    #[test]
    fn verifier_сырой_литерал_правила_с_кавычкой_внутри_опровергается() {
        let line = concat!(
            "            matcher: Matcher::regex(r#\"(?i)InsecureSkipVerify\\s*[:=]\\s*true|",
            "NODE_TLS_REJECT_UNAUTHORIZED\\s*[:=]\\s*['\"]?0|",
            "CURLOPT_SSL_VERIFY(?:PEER|HOST)\\s*,\\s*(?:0|false)\"#),"
        );
        let (ctx, _d) = ctx_with("owasp.rs", line);
        let f = Finding::new(
            "tls-verify-off",
            Severity::High,
            "Проверка TLS-сертификата отключена",
            Some(Location {
                file: "owasp.rs".to_string(),
                line: 1,
            }),
            Some("ev".to_string()),
            true,
            "security.scan/owasp",
        );
        assert!(
            refute(&ctx, &mut HashMap::new(), &f).is_some_and(|r| r.contains("шаблон")),
            "самосовпадение на сыром литерале правила опровергается как определение шаблона"
        );
    }

    /// Обратная сторона: живой опасный вызов с теми же скобками группировки внутри СЫРОГО
    /// литерала, но БЕЗ признаков определения правила (нет конструктора и предиката, есть
    /// посторонний исполняемый вызов), опровергаться не должен. Иначе исправление разбора
    /// сырых строк превратилось бы в лазейку для гашения настоящих находок.
    #[test]
    fn verifier_живой_вызов_с_сырым_литералом_не_опровергается() {
        let line = r####"subprocess.run(r#"sh -c "rm -rf ""# + user, shell=True)"####;
        let (ctx, _d) = ctx_with("app.py", line);
        let f = Finding::new(
            "shell-injection",
            Severity::High,
            "запуск через оболочку",
            Some(Location {
                file: "app.py".to_string(),
                line: 1,
            }),
            Some("ev".to_string()),
            true,
            "security.scan/owasp",
        );
        assert!(
            refute(&ctx, &mut HashMap::new(), &f).is_none(),
            "живой вызов с сырым литералом остаётся находкой"
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
            refute(&ctx, &mut HashMap::new(), &f).is_some_and(|r| r.contains("шаблон")),
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
        assert!(
            !m.contains('\n') && !m.contains('\r'),
            "переводы строк удалены: {m}"
        );
        assert!(!m.contains('\x07'), "управляющие символы удалены: {m}");
        assert!(m.contains("IGNORE PREVIOUS"), "видимый текст сохранён: {m}");
    }

    #[test]
    fn verifier_обрезает_слишком_длинное_поле() {
        let long = "A".repeat(MAX_FIELD_LEN + 50);
        let cleaned = sanitize_text(&long);
        assert_eq!(
            cleaned.chars().count(),
            MAX_FIELD_LEN + 1,
            "обрезка плюс многоточие"
        );
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
        assert_eq!(
            refuted[0].0.message, "сырой\nтекст",
            "поле опровергнутой не меняется"
        );
    }

    // ── совместимость с прежним поведением ─────────────────────────────────

    /// Подавление находки КАЧЕСТВА голым маркером остаётся: цена ошибки здесь невелика, а
    /// трение обесценило бы механизм.
    #[test]
    fn inline_ignore_подавляет_находку_качества() {
        let line = "let _ = x.unwrap();  // ailc:ignore";
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
            refute(&ctx, &mut HashMap::new(), &f).is_some_and(|r| is_inline_suppression(&r)),
            "находка качества подавляется голым маркером"
        );
    }

    /// РЕГРЕССИЯ. Маркер подавления действует только в КОММЕНТАРИИ: маркер внутри
    /// строкового литерала на строке-не-комментарии (данные программы) вердикт не отменяет.
    #[test]
    fn ignore_маркер_в_строковом_литерале_не_подавляет() {
        let mk = |line: &str| {
            let (ctx, d) = ctx_with("c.rs", line);
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
            let r = refute(&ctx, &mut HashMap::new(), &f);
            (r.as_deref().is_some_and(is_inline_suppression), d)
        };
        // Маркер в строковом литерале живого кода: НЕ подавляет.
        let (lit, _d1) = mk(r#"let s = "ailc:ignore"; x.unwrap();"#);
        assert!(!lit, "маркер внутри строкового литерала не действует");
        // Маркер в комментариях разных синтаксисов: подавляет.
        for line in [
            "x.unwrap(); // ailc:ignore",
            "x.unwrap()  # ailc:ignore",
            "x.unwrap(); /* ailc:ignore */",
            "SELECT 1; -- ailc:ignore",
            "; ailc:ignore",
        ] {
            let (ok, _d) = mk(line);
            assert!(ok, "маркер в комментарии обязан подавлять: {line}");
        }
    }

    /// РЕГРЕССИЯ на главную дыру подавления. Прежде голый `ailc:ignore` гасил ЛЮБОЕ правило
    /// без потолка важности: проверялось запуском, что три таких комментария снимают все
    /// пять находок в файле, включая зашитый ключ доступа AWS, и все оси безопасности
    /// показывают «находок: 0». Теперь для находки безопасности требуется ИМЕНОВАННЫЙ
    /// маркер, а голый её не гасит.
    #[test]
    fn security_находка_требует_именованного_маркера() {
        let mk = |line: &str| {
            let (ctx, d) = ctx_with("c.py", line);
            let f = secret_finding("generic-secret", "c.py", 1, "secret");
            let r = refute(&ctx, &mut HashMap::new(), &f);
            (r.as_deref().is_some_and(is_inline_suppression), d)
        };
        let (bare, _d1) = mk(r#"key = "a8Kd9Lm2Qx7Zp1Rv5Tn"  # ailc:ignore"#);
        assert!(!bare, "голый маркер не гасит находку безопасности");
        let (other, _d2) = mk(r#"key = "a8Kd9Lm2Qx7Zp1Rv5Tn"  # ailc:ignore[другое-правило]"#);
        assert!(!other, "маркер с ЧУЖИМ правилом не подавляет");
        let (named, _d3) = mk(r#"key = "a8Kd9Lm2Qx7Zp1Rv5Tn"  # ailc:ignore[generic-secret]"#);
        assert!(
            named,
            "именованный маркер подавляет: узкое осознанное решение, видимое в ревизии"
        );
    }

    /// РЕГРЕССИЯ. Слово-заглушка в комментарии не имеет права снимать находку безопасности.
    /// Эвристики плейсхолдера объявлены применимыми к ЗНАЧЕНИЮ секрета, но при неудаче
    /// извлечения стоял откат на всю физическую строку, а для не-секретных правил значение не
    /// извлекается никогда. Итог проверялся запуском: `os.system(u)  # example` и та же строка
    /// с «dummy» давали НОЛЬ находок вместо двух, то есть гейт обходился одним словом.
    #[test]
    fn слово_заглушка_в_комментарии_не_снимает_находку_вызова() {
        for tail in [
            "# example",
            "# dummy",
            "# TODO",
            "# sample",
            "# fake",
            "# changeme",
        ] {
            let line = format!("    os.system(u)  {tail}");
            let (ctx, _d) = ctx_with("a.py", &line);
            let f = Finding::new(
                "dangerous-exec",
                Severity::High,
                "опасный вызов",
                Some(Location {
                    file: "a.py".to_string(),
                    line: 1,
                }),
                None,
                true,
                "security.scan/owasp",
            );
            assert!(
                refute(&ctx, &mut HashMap::new(), &f).is_none(),
                "находка о вызове не опровергается словом «{tail}» в комментарии"
            );
        }
    }

    /// РЕГРЕССИЯ. Находка семейства «Комплаенс РФ» на строке, которая целиком является
    /// комментарием, обязана опровергаться так же, как находка безопасности: комментарий не
    /// исполняется, поэтому персональные данные в журнал из него не попадут. До исправления
    /// признак «комментарий» распространялся только на источники со словами `security` и
    /// `pii`, и правило `pdn-in-logs` срабатывало на пояснительном комментарии в исходном
    /// тексте самого инструмента, а находка проходила в блокирующее множество вердикта.
    #[test]
    fn находка_комплаенса_в_комментарии_опровергается() {
        let line = r#"/// вызов `logger.info("passport=%s", user.passport)` находки не давал"#;
        let (ctx, _d) = ctx_with("a.rs", line);
        let f = Finding::new(
            "pdn-in-logs",
            Severity::Low,
            "ПДн в логах",
            Some(Location {
                file: "a.rs".to_string(),
                line: 1,
            }),
            None,
            true,
            "compliance.ru/pdn-logs",
        );
        let r = refute(&ctx, &mut HashMap::new(), &f);
        assert!(
            r.as_deref().is_some_and(|x| x.contains("комментарии")),
            "находка комплаенса на строке-комментарии опровергается: {r:?}"
        );
    }

    /// Обратная сторона предыдущего теста: живой вызов логгера комментарием не является и
    /// опровергаться не должен, иначе исправление превратилось бы в глушение всего семейства.
    #[test]
    fn живой_вызов_логгера_с_пдн_не_опровергается() {
        let (ctx, _d) = ctx_with("a.py", r#"    logger.info("passport=%s", user.passport)"#);
        let f = Finding::new(
            "pdn-in-logs",
            Severity::Low,
            "ПДн в логах",
            Some(Location {
                file: "a.py".to_string(),
                line: 1,
            }),
            None,
            true,
            "compliance.ru/pdn-logs",
        );
        assert!(
            refute(&ctx, &mut HashMap::new(), &f).is_none(),
            "живой вызов логгера с персональными данными остаётся находкой"
        );
    }

    /// Обратная сторона: для находки о ЗАШИТОМ ЗНАЧЕНИИ опровержение по заглушке остаётся.
    /// Именно там вопрос «не заглушка ли это» осмыслен.
    #[test]
    fn заглушка_в_значении_секрета_по_прежнему_опровергается() {
        let (ctx, _d) = ctx_with("a.py", r#"password = "your_password_here""#);
        let f = secret_finding("generic-secret", "a.py", 1, "секрет");
        let r = refute(&ctx, &mut HashMap::new(), &f);
        assert!(
            r.as_deref().is_some_and(|x| x.contains("плейсхолдер")),
            "значение-заглушка опровергается: {r:?}"
        );
    }

    /// Настоящий секрет не опровергается: иначе опровержение заглушек само стало бы дырой.
    #[test]
    fn настоящий_секрет_не_опровергается_как_заглушка() {
        let (ctx, _d) = ctx_with("a.py", r#"password = "a8Kd9Lm2Qx7Zp1Rv5Tn""#);
        let f = secret_finding("generic-secret", "a.py", 1, "секрет");
        assert!(refute(&ctx, &mut HashMap::new(), &f).is_none());
    }

    /// Подавление обязано быть отличимо от опровержения ложной находки: первое это решение
    /// человека скрыть настоящую находку, второе это вывод инструмента о её ложности.
    #[test]
    fn подавление_отличимо_от_опровержения() {
        assert!(is_inline_suppression(SUPPRESSION_REASON));
        assert!(!is_inline_suppression(
            "определение шаблона поиска (правило сканера, не живой вызов)"
        ));
    }

    /// РЕГРЕССИЯ: мета-символ регулярного выражения в КОММЕНТАРИИ не является определением
    /// правила. Прежде `(?i)` в любом месте строки считался безошибочным признаком, поэтому
    /// хвостовой комментарий `# (?i) шаблон` гасил живую SQL-инъекцию.
    #[test]
    fn regex_мета_вне_литерала_не_считается_определением_правила() {
        assert!(
            !regex_meta_in_literal("conn.execute(q + user)  # (?i) шаблон"),
            "мета в комментарии не в литерале"
        );
        assert!(
            regex_meta_in_literal(r#"let re = Regex::new(r"(?i)os\.system")"#),
            "мета в литерале регулярного выражения"
        );
        assert!(
            regex_meta_in_literal(r#"pat = "(?:a|b)""#),
            "незахватывающая группа в литерале"
        );
        assert!(
            !is_unmistakable_rule_def("os.system(cmd)  // (?i)"),
            "живой вызов с мета в комментарии не является определением правила"
        );
        // РЕГРЕССИЯ (обход T51): безобидный литерал с regex-мета В КОДОВОЙ ЧАСТИ строки не
        // делает всю строку определением правила, если рядом стоит живой вызов. Прежде
        // строка вида `os.system(cmd); x = "(?i)"` гасила security-находку о вызове.
        assert!(
            !is_unmistakable_rule_def(r#"os.system(cmd); x = "(?i)""#),
            "литерал с мета-символом рядом с живым вызовом не является определением правила"
        );
        assert!(
            !is_unmistakable_rule_def(r#"eval(response); pat = "(?:a|b)""#),
            "живой eval не маскируется соседним литералом-шаблоном"
        );
        // Имя конструктора правила ВНУТРИ строкового литерала тоже не признак.
        assert!(
            !is_unmistakable_rule_def(r#"os.system(cmd); s = "Regex::new(""#),
            "имя конструктора в литерале не делает строку определением правила"
        );
        // Настоящее определение (только конструктор, без посторонних вызовов) осталось.
        assert!(is_unmistakable_rule_def(
            r#"let re = Regex::new(r"(?i)os\.system");"#
        ));
        assert!(
            is_unmistakable_rule_def("Matcher::Predicate(|l| l.contains(\"x\"))"),
            "вызов конструктора правила остаётся признаком определения"
        );
    }

    /// Определение сопоставителя отличается от живого кода тем, что опасная конструкция в нём
    /// присутствует как ДАННЫЕ, а исполняются только строковые предикаты.
    #[test]
    fn определение_сопоставителя_отличается_от_живого_вызова() {
        // Тело предиката-детектора: опасное только внутри литерала.
        assert!(is_matcher_definition(r#"|l| l.contains("os.system(")"#));
        assert!(is_matcher_definition(
            r#"|| f.ends_with("objectinputstream");"#
        ));
        assert!(is_matcher_definition(r#"l.contains("yaml.load(")"#));

        // Живой вызов: `system`/`execute` строковыми предикатами не являются.
        assert!(!is_matcher_definition(r#"os.system("rm -rf " + user)"#));
        assert!(!is_matcher_definition(
            r#"conn.execute("SELECT " + user + "'")"#
        ));
        // Тот же живой вызов с припиской в комментарии: приписка не спасает.
        assert!(!is_matcher_definition(
            r#"os.system("rm -rf " + user)  # см. matcher .contains("rm")"#
        ));

        // РЕГРЕССИЯ: строка вообще без вызовов не является определением сопоставителя.
        // Иначе присваивание литеральной константы (зашитый вектор инициализации, ключ)
        // опровергалось бы вхолостую; контролируемый корпус поймал это как пять пропущенных
        // настоящих уязвимостей.
        assert!(!is_matcher_definition(r#"const iv = "0123456789abcdef";"#));
        assert!(!is_matcher_definition(r#"key = "AKIAIOSFODNN7EXAMPLE""#));
        // Без литерала-образца тоже нет: сравнивать не с чем.
        assert!(!is_matcher_definition("l.contains(other)"));
    }

    /// Отсечение комментария: признаки определения правила ищутся в коде, а не в приписке.
    #[test]
    fn кодовая_часть_строки_отсекает_комментарий() {
        assert_eq!(code_part_of("os.system(x)  # хвост"), "os.system(x)  ");
        assert_eq!(code_part_of("let a = 1; // хвост"), "let a = 1; ");
        assert_eq!(code_part_of("s = 1 -- хвост"), "s = 1 ");
        // Решётка внутри сырого строкового литерала Rust не является комментарием.
        assert_eq!(
            code_part_of(r##"let re = Regex::new(r#"(?i)x"#);"##),
            r##"let re = Regex::new(r#"(?i)x"#);"##
        );
        // Двойная косая черта в схеме URL внутри литерала не является комментарием.
        assert_eq!(
            code_part_of(r#"let u = "https://example.com";"#),
            r#"let u = "https://example.com";"#
        );
        // Символ комментария ВНУТРИ литерала не отсекается.
        assert_eq!(code_part_of(r#"let s = "a # b";"#), r#"let s = "a # b";"#);
    }

    #[test]
    fn verifier_секрет_в_комментарии_опровергается() {
        let line = r#"// password = "a8Kd9Lm2Qx7Zp1Rv5Tn""#;
        let (ctx, _d) = ctx_with("c.rs", line);
        let f = secret_finding("generic-secret", "c.rs", 1, "secret");
        assert!(
            refute(&ctx, &mut HashMap::new(), &f).is_some_and(|r| r.contains("комментар")),
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
            refute(&ctx, &mut HashMap::new(), &f).is_some_and(|r| r.contains("комментар")),
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
        let v = secret_value_in(
            "github-token",
            r#"t = "ghp_0123456789abcdefghijklmnopqrstuvwxyz""#,
        );
        assert_eq!(
            v.as_deref(),
            Some("ghp_0123456789abcdefghijklmnopqrstuvwxyz")
        );
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
        assert!(!has_numeric_placeholder(
            "a8Kd9Lm123456Qx7Zp1Rv5Tn4Bf6Wh3Gj"
        ));
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
    fn is_security_critical_любой_security_источник() {
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
        assert!(
            is_security_critical(&precise_secret),
            "precise секрет критичен"
        );
        // Регрессия на закрытую дыру: прежде критичность требовала достоверности
        // `Precise`, поэтому правила OWASP (объявлены `Pattern`) под защиту НЕ попадали, и
        // дописанный к уязвимой строке комментарий с `.contains("…")` гасил живую
        // SQL-инъекцию. Класс уверенности говорит о точности сигнала, а не о том, можно ли
        // доверять окружающему тексту, поэтому критично ЛЮБОЕ security-правило.
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
            is_security_critical(&owasp_pattern),
            "паттерн-правило OWASP тоже защищено от гашения строковой эвристикой"
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
        assert_eq!(
            heuristic_value(r#"x = "val123""#).as_deref(),
            Some("val123")
        );
        assert_eq!(
            heuristic_value("KEY=plainvalue").as_deref(),
            Some("plainvalue")
        );
        assert_eq!(heuristic_value("просто текст без присваивания"), None);
    }

    #[test]
    fn sanitize_text_удаляет_управляющие_и_схлопывает() {
        let s = "a\nb\tc\r\nd\x00e";
        let out = sanitize_text(s);
        assert_eq!(out, "a b c d e");
    }

    #[test]
    fn самообучение_понижает_хронически_шумное_правило() {
        let (ctx, _d) = ctx_with("src/main.rs", "fn main() { let x = compute(); }\n");
        stdfs::create_dir_all(ctx.root.join(".ailc/verify-memory")).unwrap();
        // Прошлая история проекта: правило опровергалось 24 раза из 25 (шумит).
        stdfs::write(
            ctx.root.join(".ailc/verify-memory/rules.tsv"),
            "smell-noisy\t24\t1\n",
        )
        .unwrap();
        let f = Finding {
            rule: "smell-noisy".into(),
            severity: Severity::Medium,
            message: "запах кода".into(),
            location: Some(Location {
                file: "src/main.rs".into(),
                line: 1,
            }),
            evidence: None,
            verified: true,
            source: "quality.check/smell".into(),
        };
        let (confirmed, _refuted) = Verifier::verify(&ctx, vec![f]);
        assert_eq!(
            confirmed.len(),
            1,
            "находка подтверждается, а не скрывается"
        );
        assert_eq!(
            confirmed[0].severity,
            Severity::Low,
            "но теряет голос до Low"
        );
        assert!(
            confirmed[0].message.contains("часто шумит"),
            "понижение видно в сообщении: {}",
            confirmed[0].message
        );
        // Статистика обновилась текущим прогоном (подтверждено стало 2).
        let tsv = stdfs::read_to_string(ctx.root.join(".ailc/verify-memory/rules.tsv")).unwrap();
        assert!(tsv.contains("smell-noisy\t24\t2"), "tsv: {tsv}");
    }

    /// РЕГРЕССИЯ. Наблюдения считаются по МЕСТАМ, а не по экземплярам находок. Прежде счёт
    /// шёл по экземплярам, поэтому один файл с числом опровергнутых совпадений выше порога
    /// пересекал порог за ОДИН прогон и понижал правило по всему проекту навсегда. Здесь
    /// двадцать пять опровержений одного правила приходятся на ОДНО место, значит наблюдение
    /// ровно одно.
    #[test]
    fn самообучение_считает_места_а_не_экземпляры() {
        let (ctx, _d) = ctx_with("src/main.rs", "// password = \"a8Kd9Lm2Qx7Zp1Rv5\"\n");
        stdfs::create_dir_all(ctx.root.join(".ailc/verify-memory")).unwrap();
        // Двадцать пять экземпляров находки в ОДНОЙ точке (файл и строка совпадают).
        let mk = || Finding {
            rule: "generic-secret".into(),
            severity: Severity::Critical,
            message: "секрет".into(),
            location: Some(Location {
                file: "src/main.rs".into(),
                line: 1,
            }),
            evidence: None,
            verified: true,
            source: "security.scan/secret".into(),
        };
        let findings: Vec<Finding> = (0..25).map(|_| mk()).collect();
        let _ = Verifier::verify(&ctx, findings);
        let tsv = stdfs::read_to_string(ctx.root.join(".ailc/verify-memory/rules.tsv")).unwrap();
        assert!(
            tsv.contains("generic-secret\t1\t0"),
            "одно место это одно наблюдение, а не двадцать пять; tsv: {tsv}"
        );
    }

    /// Подавление маркером в статистику самообучения не идёт: это решение человека скрыть
    /// находку, а не свидетельство её ложности. Иначе подавление одного места работало бы
    /// рычагом понижения правила во всём проекте.
    #[test]
    fn подавленное_маркером_не_учится() {
        let (ctx, _d) = ctx_with("a.rs", "let _ = x.unwrap(); // ailc:ignore");
        stdfs::create_dir_all(ctx.root.join(".ailc/verify-memory")).unwrap();
        let f = Finding {
            rule: "panic-path".into(),
            severity: Severity::Low,
            message: "panic".into(),
            location: Some(Location {
                file: "a.rs".into(),
                line: 1,
            }),
            evidence: None,
            verified: true,
            source: "quality.check/smell".into(),
        };
        let (_c, refuted) = Verifier::verify(&ctx, vec![f]);
        assert_eq!(refuted.len(), 1, "находка подавлена");
        let tsv = stdfs::read_to_string(ctx.root.join(".ailc/verify-memory/rules.tsv"))
            .unwrap_or_default();
        assert!(
            !tsv.contains("panic-path\t1"),
            "подавление не идёт в счётчик опровержений; tsv: {tsv}"
        );
    }

    #[test]
    fn самообучение_не_трогает_security_критичное_и_малую_выборку() {
        let (ctx, _d) = ctx_with("src/agent.py", "eval(response)\n");
        stdfs::create_dir_all(ctx.root.join(".ailc/verify-memory")).unwrap();
        // Даже «шумная» история не понижает security.ai (T51-инвариант сохраняется)…
        stdfs::write(
            ctx.root.join(".ailc/verify-memory/rules.tsv"),
            "ai-insecure-output\t24\t1\nsmell-rare\t3\t1\n",
        )
        .unwrap();
        let ai = Finding {
            rule: "ai-insecure-output".into(),
            severity: Severity::High,
            message: "вывод модели исполняется".into(),
            location: Some(Location {
                file: "src/agent.py".into(),
                line: 1,
            }),
            evidence: None,
            verified: true,
            source: "security.ai/insecure-output".into(),
        };
        // …а правило с малой выборкой (4 наблюдения) не считается изученным.
        let rare = Finding {
            rule: "smell-rare".into(),
            severity: Severity::Medium,
            message: "редкий запах".into(),
            location: Some(Location {
                file: "src/agent.py".into(),
                line: 1,
            }),
            evidence: None,
            verified: true,
            source: "quality.check/smell".into(),
        };
        let (confirmed, _) = Verifier::verify(&ctx, vec![ai, rare]);
        let sev: std::collections::HashMap<_, _> = confirmed
            .iter()
            .map(|f| (f.rule.clone(), f.severity))
            .collect();
        assert_eq!(sev.get("ai-insecure-output"), Some(&Severity::High));
        assert_eq!(sev.get("smell-rare"), Some(&Severity::Medium));
    }
}
