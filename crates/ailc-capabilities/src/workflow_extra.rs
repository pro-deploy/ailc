//! Дополнительные capability семейств generate/deliver/setup.
//!
//! ПРИНЦИП тот же, что у остальных: capability = тонкий конфиг поверх одного из
//! девяти движков. Здесь — журнал архитектурных решений (E5/E7), сборка имени
//! ветки (детерминированная, без диска), черновик сообщения коммита (E2 Runner)
//! и идемпотентное развёртывание скелета `.ailc/` (E5 Generator). Никакого
//! дублирования логики движков: только сборка входа и оформление выхода.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Finding, Location, Result,
    RunInput, Severity, Tier,
};
use ailc_core::engines::runner::Runner;
use ailc_core::engines::store::Store;
use ailc_core::registry::Registry;
use ailc_core::Capability;

/// Схема входа, где осмысленен текстовый запрос (заголовок решения, источник имени ветки).
const QUERY_SCHEMA: &str =
    r#"{"type":"object","properties":{"target":{"type":"string"},"query":{"type":"string"}}}"#;
/// Схема для операций без обязательных полей (черновик коммита, развёртывание).
const EMPTY_SCHEMA: &str = r#"{"type":"object","properties":{}}"#;

/// Пространство имён журнала решений (каталог под `.ailc/`).
const NS_DECISIONS: &str = "decisions";

// ───────────────────────── generate/adr ─────────────────────────

/// Запись архитектурного решения (ADR) отдельным файлом в журнал решений.
pub struct GenerateAdr {
    manifest: CapabilityManifest,
}

impl Default for GenerateAdr {
    fn default() -> Self {
        Self::new()
    }
}

impl GenerateAdr {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "generate/adr",
                family: Family::Generate,
                engine: EngineKind::Generator,
                when_to_use: "Зафиксировать принятое архитектурное решение отдельной записью (заголовок решения — query).",
                input_schema: QUERY_SCHEMA,
                tier: Tier::Core,
                deterministic: false, // номер записи зависит от состояния журнала
                mutates: true,        // создаёт файл решения
            },
        }
    }
}

impl Capability for GenerateAdr {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        // Без заголовка решение не оформляем — явная причина, не молчаливый пропуск.
        let title = match input
            .query
            .as_deref()
            .map(str::trim)
            .filter(|q| !q.is_empty())
        {
            Some(q) => q,
            None => {
                out.skipped = Some("нужен заголовок решения в query".into());
                out.summary = "generate/adr: пропущено (нет заголовка решения)".into();
                return Ok(out);
            }
        };

        // Атомарно выделяем номер-файл, затем наполняем его шаблоном.
        let name = Store::alloc_id(ctx, NS_DECISIONS, "md")?;
        // Номер берём из имени файла «<n>.md»: до точки — число записи.
        let number = name.split('.').next().unwrap_or(name.as_str());

        // Статус и связи — часть записи, а не приписка на полях. Без них журнал решений
        // превращается в свалку: непонятно, какое решение действует, какое отменено и чем
        // именно оно заменено. Новая запись всегда рождается предложенной: принятие есть
        // отдельное человеческое действие, и подменять его фактом создания файла нельзя.
        //
        // Замена оформляется в одном вызове: если в запросе указано «заменяет ADR-N», то
        // новая запись ссылается на прежнюю, а прежняя переводится в статус «заменено» со
        // встречной ссылкой. Двусторонняя связь важна: односторонняя оставляет читателя
        // отменённого решения в неведении.
        let superseded = superseded_ref(title);
        let title_clean = strip_supersede_clause(title);

        let body = format!(
            "# ADR-{number}: {title_clean}\n\n\
             - Статус: предложено\n\
             - Дата: {date}\n\
             - Заменяет: {replaces}\n\
             - Заменено: нет\n\n\
             ## Контекст\n\n## Решение\n\n## Последствия\n",
            date = today(),
            replaces = superseded
                .map(|n| format!("ADR-{n}"))
                .unwrap_or_else(|| "нет".to_string()),
        );
        Store::write(ctx, NS_DECISIONS, &name, &body)?;

        // Встречная ссылка в заменяемом решении.
        let mut note = String::new();
        if let Some(old_n) = superseded {
            match mark_superseded(ctx, old_n, number) {
                Ok(true) => note = format!("; ADR-{old_n} переведено в статус «заменено»"),
                Ok(false) => note = format!("; ADR-{old_n} не найдено, встречной ссылки нет"),
                Err(e) => note = format!("; не удалось обновить ADR-{old_n}: {e}"),
            }
        }

        let artifact = format!(".ailc/{NS_DECISIONS}/{name}");
        out.artifacts.push(artifact.clone());
        out.summary =
            format!("generate/adr: ADR-{number} записан (статус «предложено») → {artifact}{note}");
        Ok(out)
    }
}

/// Допустимые статусы решения. Жизненный цикл намеренно короткий: длинные схемы статусов
/// на практике не поддерживаются и вырождаются в один-единственный «принято».
pub const ADR_STATUSES: &[&str] = &["предложено", "принято", "отклонено", "заменено"];

/// Сегодняшняя дата в записи решения. Берётся из системных часов через `date`, а при их
/// недоступности опускается: неверная дата в журнале решений хуже отсутствующей.
fn today() -> String {
    std::process::Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "не указана".to_string())
}

/// Номер решения, которое заменяется этим. Распознаются обороты «заменяет ADR-7»,
/// «отменяет ADR-7», «supersedes ADR-7» в любом регистре.
fn superseded_ref(title: &str) -> Option<u32> {
    let lower = title.to_lowercase();
    for marker in [
        "заменяет adr-",
        "отменяет adr-",
        "supersedes adr-",
        "заменяет ",
    ] {
        if let Some(i) = lower.find(marker) {
            let tail = &lower[i + marker.len()..];
            let digits: String = tail
                .trim_start_matches("adr-")
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(n) = digits.parse::<u32>() {
                return Some(n);
            }
        }
    }
    None
}

/// Заголовок без служебного оборота о замене: он уже выражен полем связи.
fn strip_supersede_clause(title: &str) -> String {
    let lower = title.to_lowercase();
    for marker in ["заменяет adr-", "отменяет adr-", "supersedes adr-"] {
        if let Some(i) = lower.find(marker) {
            let head = title[..i]
                .trim()
                .trim_end_matches(&[',', ';', '(', '—'][..]);
            if !head.is_empty() {
                return head.trim().to_string();
            }
        }
    }
    title.trim().to_string()
}

/// Перевести решение в статус «заменено» и проставить встречную ссылку. Возвращает
/// признак «запись найдена»: молчаливое отсутствие связи недопустимо, вызывающий обязан
/// сообщить об этом человеку.
fn mark_superseded(ctx: &Ctx, old_number: u32, by_number: &str) -> Result<bool> {
    let path = ctx
        .root
        .join(".ailc")
        .join(NS_DECISIONS)
        .join(format!("{old_number}.md"));
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(false);
    };
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut seen_status = false;
    let mut seen_link = false;
    for l in lines.iter_mut() {
        if l.starts_with("- Статус:") {
            *l = "- Статус: заменено".to_string();
            seen_status = true;
        } else if l.starts_with("- Заменено:") {
            *l = format!("- Заменено: ADR-{by_number}");
            seen_link = true;
        }
    }
    // Запись прежнего формата (без полей): поля дописываются после заголовка, чтобы связь
    // не потерялась из-за возраста файла.
    if !seen_status || !seen_link {
        let insert_at = if lines.first().is_some_and(|l| l.starts_with('#')) {
            1
        } else {
            0
        };
        let mut add = Vec::new();
        if !seen_status {
            add.push("- Статус: заменено".to_string());
        }
        if !seen_link {
            add.push(format!("- Заменено: ADR-{by_number}"));
        }
        add.push(String::new());
        for (k, l) in add.into_iter().enumerate() {
            lines.insert(insert_at + k, l);
        }
    }
    std::fs::write(&path, lines.join("\n") + "\n")?;
    Ok(true)
}

// ───────────────────────── deliver/branch-name ─────────────────────────

/// Перевод одной буквы кириллицы в латиницу (нижний регистр на входе).
fn cyr_to_lat(c: char) -> Option<&'static str> {
    let s = match c {
        'а' => "a",
        'б' => "b",
        'в' => "v",
        'г' => "g",
        'д' => "d",
        'е' => "e",
        'ё' => "e",
        'ж' => "zh",
        'з' => "z",
        'и' => "i",
        'й' => "y",
        'к' => "k",
        'л' => "l",
        'м' => "m",
        'н' => "n",
        'о' => "o",
        'п' => "p",
        'р' => "r",
        'с' => "s",
        'т' => "t",
        'у' => "u",
        'ф' => "f",
        'х' => "h",
        'ц' => "c",
        'ч' => "ch",
        'ш' => "sh",
        'щ' => "sch",
        'ъ' => "",
        'ы' => "y",
        'ь' => "",
        'э' => "e",
        'ю' => "yu",
        'я' => "ya",
        _ => return None,
    };
    Some(s)
}

/// Собрать «слаг» имени ветки: нижний регистр, транслитерация кириллицы,
/// прочие не буквы/цифры → `-`, схлопывание повторов, обрезка по длине.
fn slugify(input: &str, max_len: usize) -> String {
    let mut buf = String::new();
    for ch in input.chars() {
        let lower = ch.to_lowercase().next().unwrap_or(ch);
        if lower.is_ascii_alphanumeric() {
            buf.push(lower);
        } else if let Some(lat) = cyr_to_lat(lower) {
            buf.push_str(lat);
        } else {
            buf.push('-');
        }
    }

    // Схлопываем повторяющиеся разделители в один.
    let mut slug = String::new();
    let mut prev_dash = false;
    for ch in buf.chars() {
        if ch == '-' {
            if !prev_dash {
                slug.push('-');
            }
            prev_dash = true;
        } else {
            slug.push(ch);
            prev_dash = false;
        }
    }

    // Обрезаем по длине, затем убираем краевые разделители.
    let trimmed: String = slug.chars().take(max_len).collect();
    trimmed.trim_matches('-').to_string()
}

pub struct BranchName {
    manifest: CapabilityManifest,
}

impl Default for BranchName {
    fn default() -> Self {
        Self::new()
    }
}

impl BranchName {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "deliver/branch-name",
                family: Family::Deliver,
                engine: EngineKind::Store, // условный движок-владелец; на диск ничего не пишет
                when_to_use:
                    "Собрать корректное имя git-ветки из описания задачи (описание — query).",
                input_schema: QUERY_SCHEMA,
                tier: Tier::Core,
                deterministic: true, // одинаковый вход → одинаковое имя
                mutates: false,
            },
        }
    }
}

impl Capability for BranchName {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, _ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        // Без описания собирать имя не из чего — явная причина.
        let source = match input
            .query
            .as_deref()
            .map(str::trim)
            .filter(|q| !q.is_empty())
        {
            Some(q) => q,
            None => {
                out.skipped =
                    Some("нужно описание задачи в query — из него собирается имя ветки".into());
                out.summary = "deliver/branch-name: пропущено (нет описания)".into();
                return Ok(out);
            }
        };

        // Префикс занимает место в общем лимите ~50 символов.
        let prefix = "feat/";
        let slug = slugify(source, 50usize.saturating_sub(prefix.len()));

        // После нормализации могло не остаться ни одного латинского символа/цифры.
        if slug.is_empty() {
            out.skipped = Some(
                "из описания не удалось собрать имя (нет латиницы или цифр после нормализации)"
                    .into(),
            );
            out.summary = "deliver/branch-name: пропущено (пустое имя после нормализации)".into();
            return Ok(out);
        }

        let branch = format!("{prefix}{slug}");
        out.records.push(branch.clone());
        out.summary = format!("deliver/branch-name: {branch}");
        Ok(out)
    }
}

// ───────────────────────── deliver/commit-draft ─────────────────────────

pub struct CommitDraft {
    manifest: CapabilityManifest,
}

impl Default for CommitDraft {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitDraft {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "deliver/commit-draft",
                family: Family::Deliver,
                engine: EngineKind::Runner,
                when_to_use: "Подготовить черновик сообщения коммита по подготовленным изменениям (git diff --cached). Сам не коммитит.",
                input_schema: EMPTY_SCHEMA,
                tier: Tier::Core,
                deterministic: false, // зависит от состояния рабочего дерева и наличия git
                mutates: false,       // только читает diff, ничего не коммитит
            },
        }
    }
}

impl Capability for CommitDraft {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        let res = Runner::run(ctx, "git", &["diff", "--cached", "--stat"]);

        // git нет — явная причина (через Runner::skipped).
        if !res.ran {
            let reason = res
                .skipped_reason
                .unwrap_or_else(|| "git недоступен".into());
            out.skipped = Some(reason.clone());
            out.summary = format!("deliver/commit-draft: пропущено — {reason}");
            return Ok(out);
        }

        // git есть, но команда не прошла — скорее всего это не репозиторий.
        if !res.exit_ok {
            let detail = res
                .tail(3)
                .into_iter()
                .next()
                .unwrap_or_else(|| "git не вернул изменений".into());
            let reason = format!("git не смог прочитать индекс (не репозиторий?): {detail}");
            out.skipped = Some(reason.clone());
            out.summary = format!("deliver/commit-draft: пропущено — {reason}");
            return Ok(out);
        }

        // Собираем список изменённых файлов из вывода `--stat`.
        // Строки вида « path/к/файлу | 12 +++--», итог « N files changed,…».
        let mut files: Vec<String> = Vec::new();
        for line in res.stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match trimmed.split_once('|') {
                Some((path, _)) => {
                    let path = path.trim();
                    if !path.is_empty() {
                        files.push(path.to_string());
                    }
                }
                None => continue, // итоговая строка-сводка — пропускаем
            }
        }

        // Пустой индекс — нечего предлагать в коммит, явная причина.
        if files.is_empty() {
            out.skipped = Some("нет подготовленных изменений (git add не выполнен)".into());
            out.summary = "deliver/commit-draft: пропущено (пустой индекс)".into();
            return Ok(out);
        }

        // Краткое резюме первой строки: один файл → его имя, несколько → счёт.
        let headline = if files.len() == 1 {
            format!("изменения в {}", files[0])
        } else {
            format!("изменения в {} файлах", files.len())
        };

        let mut body = String::new();
        for f in &files {
            body.push_str(&format!("- {f}\n"));
        }

        // Черновик в формате Conventional Commit, на русском. НЕ коммитим.
        let draft = format!("feat: {headline}\n\nЗатронутые файлы:\n{}", body.trim_end());
        out.records.push(draft);
        out.metrics.push(("files".into(), files.len() as f64));
        out.summary = format!(
            "deliver/commit-draft: черновик готов ({} файлов; коммит не выполнен)",
            files.len()
        );
        Ok(out)
    }
}

// ───────────────────────── setup/init ─────────────────────────

pub struct SetupInit {
    manifest: CapabilityManifest,
}

impl Default for SetupInit {
    fn default() -> Self {
        Self::new()
    }
}

impl SetupInit {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "setup/init",
                family: Family::Setup,
                engine: EngineKind::Generator,
                when_to_use: "Развернуть скелет среды ailc в проекте (конституция, слои, рабочая память). Идемпотентно.",
                input_schema: EMPTY_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: true, // создаёт файлы скелета
            },
        }
    }
}

/// Шаблон конституции: правила как ДАННЫЕ (FORBID/REQUIRE/REQUIRE_EACH) с атрибутами
/// и неприкосновенным разделом «Правила команды» (его пополняет governance/rule-add).
const CONSTITUTION_TEMPLATE: &str = "# Конституция проекта

Здесь живут правила-инварианты проекта в виде данных. Каждая строка — одно правило.
Авторитет задаёт их один раз; остальные наследуют, ничего не выбирая. Проверяет
инструмент quality.check/constitution при каждом прогоне и в вердикте сдачи.

Формат строки (атрибуты в скобках опциональны, порядок свободный):
- `FORBID [warn] [in: путь] <подстрока> # обоснование` — запрещено; нарушение на каждое вхождение.
- `REQUIRE [warn] [in: путь] <подстрока> # обоснование` — обязательно хотя бы раз в проекте.
- `REQUIRE_EACH [warn] [in: путь] <подстрока> # обоснование` — обязательно в каждом файле.

`[warn]` понижает правило до предупреждения (видно, но не блокирует), `[in: путь]`
ограничивает область действия префиксом пути, текст после ` #` — обоснование для людей.
Поиск идёт только по исполняемому коду: комментарии, строки и тесты не считаются.

Примеры (замените на свои):
FORBID прямой доступ к базе данных из слоя представления
FORBID секреты в исходном коде
REQUIRE [warn] тесты для каждого публичного модуля
REQUIRE запись архитектурного решения при смене границ слоёв

## Правила команды

Сюда дописывайте свои правила (рукой или одной репликой агенту: он вызовет
governance/rule-add, и новое правило сразу примерится к коду).
";

/// Шаблон карты слоёв: какому модулю на какие модули разрешено ссылаться.
const LAYERS_TEMPLATE: &str = "# Карта разрешённых зависимостей между слоями.
# Слева — модуль, справа через запятую — те, на кого ему разрешено ссылаться.
# Пример (замените на свои модули):
модуль: разрешённый1, разрешённый2
";

/// Пустой шаблон активного рабочего контекста (рабочая память).
const ACTIVE_CONTEXT_TEMPLATE: &str = "# Активный контекст

_Над чем идёт работа прямо сейчас. Заполняется по ходу дела._

## Сейчас в работе

## Следующие шаги

## Открытые вопросы
";

/// Идемпотентно развернуть скелет состояния `.ailc/`: конституция, карта слоёв, рабочая
/// память. Уже существующие файлы не трогает. Возвращает список реально СОЗДАННЫХ файлов.
/// Эту функцию использует и capability `setup/scaffold`, и MCP-сервер при инициализации,
/// чтобы среда ставилась сама при первом подключении, а не только правило в CLAUDE.md.
pub fn scaffold_state(ctx: &Ctx) -> std::io::Result<Vec<&'static str>> {
    let files: [(&str, &str); 3] = [
        (".ailc/constitution.md", CONSTITUTION_TEMPLATE),
        (".ailc/layers.txt", LAYERS_TEMPLATE),
        (
            ".ailc/memory-bank/active-context.md",
            ACTIVE_CONTEXT_TEMPLATE,
        ),
    ];
    let mut created = Vec::new();
    for (rel, template) in files {
        let path = ctx.root.join(rel);
        // Идемпотентность: существующий файл не перезатираем.
        if path.exists() {
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, template)?;
        created.push(rel);
    }
    Ok(created)
}

impl Capability for SetupInit {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        // Та же логика, что выполняется и при подключении MCP-сервера.
        let created = scaffold_state(ctx)?;
        let created_n = created.len();
        let existing = 3 - created_n;
        for rel in created {
            out.artifacts.push(rel.to_string());
        }

        out.metrics.push(("created".into(), created_n as f64));
        out.metrics.push(("existing".into(), existing as f64));
        out.summary = if created_n == 0 {
            "среда ailc развёрнута (всё уже на месте, ничего не менялось)".into()
        } else {
            format!("среда ailc развёрнута (создано файлов: {created_n}, уже было: {existing})")
        };
        Ok(out)
    }
}

// ───────────────────────── verify/adr-lifecycle ─────────────────────────

/// Проверка журнала архитектурных решений: статусы и связи.
///
/// Статусы и ссылки полезны ровно настолько, насколько им можно доверять. Запись без
/// статуса, с выдуманным статусом, со ссылкой на несуществующее решение или отменённая
/// без указания заменившего её решения делает журнал недостоверным, а недостоверный
/// журнал хуже отсутствующего: по нему принимают решения. Проверка сообщает о таких
/// местах как о находках качества, но не блокирует сдачу: журнал решений есть
/// организационная практика, а не свойство кода.
pub struct AdrLifecycle {
    manifest: CapabilityManifest,
}

impl Default for AdrLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl AdrLifecycle {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "verify/adr-lifecycle",
                family: Family::Verify,
                engine: EngineKind::Store,
                when_to_use: "Проверить журнал решений: у каждой записи есть допустимый статус, ссылки на заменяемые решения существуют, а отменённое решение называет заменившее его.",
                input_schema: EMPTY_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for AdrLifecycle {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let dir = ctx.root.join(".ailc").join(NS_DECISIONS);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            out.skipped = Some("журнал решений отсутствует (.ailc/decisions)".into());
            out.summary = "verify/adr-lifecycle: пропущено (нет журнала решений)".into();
            return Ok(out);
        };

        // Устойчивый порядок: номера решений сортируются как числа, а не как строки.
        let mut numbers: Vec<u32> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.strip_suffix(".md")?.parse::<u32>().ok()
            })
            .collect();
        numbers.sort_unstable();
        if numbers.is_empty() {
            out.skipped = Some("в журнале решений нет записей".into());
            out.summary = "verify/adr-lifecycle: пропущено (журнал пуст)".into();
            return Ok(out);
        }

        let known: std::collections::BTreeSet<u32> = numbers.iter().copied().collect();
        for n in &numbers {
            let rel = format!(".ailc/{NS_DECISIONS}/{n}.md");
            let Ok(text) = std::fs::read_to_string(dir.join(format!("{n}.md"))) else {
                continue;
            };
            let field = |name: &str| -> Option<String> {
                text.lines()
                    .find_map(|l| l.trim().strip_prefix(name).map(|v| v.trim().to_string()))
            };

            let status = field("- Статус:");
            match status.as_deref() {
                None => push_adr(
                    &mut out,
                    &rel,
                    "adr-no-status",
                    format!(
                        "ADR-{n}: нет поля «Статус». Допустимые значения: {}",
                        ADR_STATUSES.join(", ")
                    ),
                ),
                Some(v) if !ADR_STATUSES.contains(&v) => push_adr(
                    &mut out,
                    &rel,
                    "adr-unknown-status",
                    format!(
                        "ADR-{n}: неизвестный статус «{v}». Допустимые: {}",
                        ADR_STATUSES.join(", ")
                    ),
                ),
                _ => {}
            }

            if let Some(v) = field("- Заменяет:") {
                if let Some(target) = v.strip_prefix("ADR-").and_then(|d| d.parse::<u32>().ok()) {
                    if !known.contains(&target) {
                        push_adr(
                            &mut out,
                            &rel,
                            "adr-dangling-link",
                            format!("ADR-{n}: ссылается на несуществующее решение ADR-{target}"),
                        );
                    }
                }
            }

            if status.as_deref() == Some("заменено") {
                let by = field("- Заменено:").unwrap_or_default();
                if by.is_empty() || by == "нет" {
                    push_adr(
                        &mut out,
                        &rel,
                        "adr-superseded-without-successor",
                        format!("ADR-{n}: отменено, но не названо решение, которое его заменило"),
                    );
                }
            }
        }

        out.summary = format!(
            "verify/adr-lifecycle: {} записей, {} нарушений целостности журнала",
            numbers.len(),
            out.findings.len()
        );
        Ok(out)
    }
}

/// Находка по журналу решений. Уверенность низкая по существу (это организационная
/// практика, а не свойство кода), поэтому важность средняя и вердикт она не блокирует.
fn push_adr(out: &mut CapabilityOutput, rel: &str, rule: &str, message: String) {
    out.findings.push(Finding {
        rule: rule.to_string(),
        severity: Severity::Medium,
        message,
        location: Some(Location {
            file: rel.to_string(),
            line: 1,
        }),
        evidence: None,
        verified: true,
        source: "verify/adr-lifecycle".into(),
    });
}

/// Регистрирует capability семейств generate/deliver/setup из этого модуля.
pub fn register(reg: &mut Registry) {
    reg.register(Box::new(GenerateAdr::new()));
    reg.register(Box::new(AdrLifecycle::new()));
    reg.register(Box::new(BranchName::new()));
    reg.register(Box::new(CommitDraft::new()));
    reg.register(Box::new(SetupInit::new()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_core::registry::Registry;
    use ailc_testkit::TempTree;

    /// Временное дерево проекта со служебным каталогом `.ailc`, который журнал решений
    /// ожидает готовым. Помощник оставлен именно ради этого дополнительного шага: сам
    /// по себе `TempTree::new` создаёт только пустой корень. Возвращается именно дерево,
    /// а не готовый контекст, потому что уборка привязана к времени жизни объекта: тест
    /// обязан удерживать его до последнего утверждения.
    fn проект() -> TempTree {
        let t = TempTree::new("adr");
        std::fs::create_dir_all(t.path().join(".ailc")).unwrap();
        t
    }

    fn reg() -> Registry {
        let mut r = Registry::new();
        crate::register_core(&mut r);
        r
    }

    /// Жизненный цикл решения: новая запись рождается предложенной, а замена ставит
    /// ДВУСТОРОННЮЮ связь. Односторонняя оставила бы читателя отменённого решения в
    /// неведении, что и делает журнал решений бесполезным со временем.
    #[test]
    fn замена_решения_ставит_двустороннюю_связь() {
        let t = проект();
        let ctx = t.ctx();
        let reg = reg();
        let adr = reg
            .get("generate/adr")
            .expect("generate/adr зарегистрирован");

        let first = RunInput {
            query: Some("выбрать PostgreSQL как основное хранилище".into()),
            ..Default::default()
        };
        adr.run(&ctx, &first).expect("первое решение записано");

        let second = RunInput {
            query: Some("перейти на ClickHouse для аналитики, заменяет ADR-1".into()),
            ..Default::default()
        };
        let out = adr.run(&ctx, &second).expect("второе решение записано");
        assert!(
            out.summary.contains("переведено в статус «заменено»"),
            "встречная связь сообщается человеку: {}",
            out.summary
        );

        let one = std::fs::read_to_string(ctx.root.join(".ailc/decisions/1.md")).unwrap();
        let two = std::fs::read_to_string(ctx.root.join(".ailc/decisions/2.md")).unwrap();
        assert!(
            one.contains("- Статус: заменено"),
            "прежнее решение отменено: {one}"
        );
        assert!(one.contains("- Заменено: ADR-2"), "ссылка вперёд: {one}");
        assert!(
            two.contains("- Статус: предложено"),
            "новое решение предложено: {two}"
        );
        assert!(two.contains("- Заменяет: ADR-1"), "ссылка назад: {two}");
        assert!(
            !two.contains("заменяет ADR-1:") && two.contains("ClickHouse"),
            "служебный оборот убран из заголовка: {two}"
        );
    }

    /// Ссылка на несуществующее решение не молчит и не рушит запись.
    #[test]
    fn ссылка_на_отсутствующее_решение_сообщается() {
        let t = проект();
        let ctx = t.ctx();
        let reg = reg();
        let out = reg
            .get("generate/adr")
            .unwrap()
            .run(
                &ctx,
                &RunInput {
                    query: Some("новое решение, заменяет ADR-42".into()),
                    ..Default::default()
                },
            )
            .expect("запись создана");
        assert!(
            out.summary.contains("не найдено"),
            "отсутствие адресата сообщается: {}",
            out.summary
        );
    }
    /// Проверка целостности журнала: ловит запись без статуса, выдуманный статус,
    /// повисшую ссылку и отменённое решение без указания преемника.
    #[test]
    fn проверка_журнала_решений_ловит_нарушения() {
        let t = проект();
        let ctx = t.ctx();
        let dir = ctx.root.join(".ailc/decisions");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("1.md"), "# ADR-1: без статуса\n").unwrap();
        std::fs::write(
            dir.join("2.md"),
            "# ADR-2: странный статус\n- Статус: почти принято\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("3.md"),
            "# ADR-3: повисшая ссылка\n- Статус: принято\n- Заменяет: ADR-99\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("4.md"),
            "# ADR-4: отменено без преемника\n- Статус: заменено\n- Заменено: нет\n",
        )
        .unwrap();

        let out = reg()
            .get("verify/adr-lifecycle")
            .expect("проверка журнала зарегистрирована")
            .run(&ctx, &RunInput::default())
            .expect("проверка отрабатывает");
        let rules: Vec<&str> = out.findings.iter().map(|f| f.rule.as_str()).collect();
        for expect in [
            "adr-no-status",
            "adr-unknown-status",
            "adr-dangling-link",
            "adr-superseded-without-successor",
        ] {
            assert!(
                rules.contains(&expect),
                "ожидали {expect}, получили {rules:?}"
            );
        }
    }

    /// Исправный журнал нарушений не даёт: проверка не шумит на здоровом проекте.
    #[test]
    fn исправный_журнал_решений_молчит() {
        let t = проект();
        let ctx = t.ctx();
        let reg = reg();
        let adr = reg.get("generate/adr").unwrap();
        adr.run(
            &ctx,
            &RunInput {
                query: Some("первое решение".into()),
                ..Default::default()
            },
        )
        .unwrap();
        adr.run(
            &ctx,
            &RunInput {
                query: Some("второе решение, заменяет ADR-1".into()),
                ..Default::default()
            },
        )
        .unwrap();

        let out = reg
            .get("verify/adr-lifecycle")
            .unwrap()
            .run(&ctx, &RunInput::default())
            .unwrap();
        assert!(
            out.findings.is_empty(),
            "журнал, созданный самим инструментом, обязан быть целостным: {:?}",
            out.findings
        );
    }
}
