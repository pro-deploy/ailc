//! Дополнительные capability семейств generate/deliver/setup.
//!
//! ПРИНЦИП тот же, что у остальных: capability = тонкий конфиг поверх одного из
//! девяти движков. Здесь — журнал архитектурных решений (E5/E7), сборка имени
//! ветки (детерминированная, без диска), черновик сообщения коммита (E2 Runner)
//! и идемпотентное развёртывание скелета `.ailc/` (E5 Generator). Никакого
//! дублирования логики движков: только сборка входа и оформление выхода.

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Tier,
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
        let title = match input.query.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
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

        let body = format!(
            "# ADR-{number}: {title}\n\n## Контекст\n\n## Решение\n\n## Последствия\n"
        );
        Store::write(ctx, NS_DECISIONS, &name, &body)?;

        let artifact = format!(".ailc/{NS_DECISIONS}/{name}");
        out.artifacts.push(artifact.clone());
        out.summary = format!("generate/adr: ADR-{number} записан → {artifact}");
        Ok(out)
    }
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
                when_to_use: "Собрать корректное имя git-ветки из описания задачи (описание — query).",
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
        let source = match input.query.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
            Some(q) => q,
            None => {
                out.skipped = Some("нужно описание задачи в query — из него собирается имя ветки".into());
                out.summary = "deliver/branch-name: пропущено (нет описания)".into();
                return Ok(out);
            }
        };

        // Префикс занимает место в общем лимите ~50 символов.
        let prefix = "feat/";
        let slug = slugify(source, 50usize.saturating_sub(prefix.len()));

        // После нормализации могло не остаться ни одного латинского символа/цифры.
        if slug.is_empty() {
            out.skipped =
                Some("из описания не удалось собрать имя (нет латиницы или цифр после нормализации)".into());
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

/// Шаблон конституции: правила как ДАННЫЕ (FORBID/REQUIRE), с пояснением.
const CONSTITUTION_TEMPLATE: &str = "# Конституция проекта

Здесь живут правила-инварианты проекта в виде данных. Каждая строка — одно правило.
Авторитет задаёт их один раз; младшие участники наследуют, ничего не выбирая.

Формат строки:
- `FORBID <что запрещено>` — нарушение блокирует.
- `REQUIRE <что обязательно>` — отсутствие блокирует.

Примеры (замените на свои):
FORBID прямой доступ к базе данных из слоя представления
FORBID секреты в исходном коде
REQUIRE тесты для каждого публичного модуля
REQUIRE запись архитектурного решения при смене границ слоёв
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
        (".ailc/memory-bank/active-context.md", ACTIVE_CONTEXT_TEMPLATE),
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

/// Регистрирует capability семейств generate/deliver/setup из этого модуля.
pub fn register(reg: &mut Registry) {
    reg.register(Box::new(GenerateAdr::new()));
    reg.register(Box::new(BranchName::new()));
    reg.register(Box::new(CommitDraft::new()));
    reg.register(Box::new(SetupInit::new()));
}
