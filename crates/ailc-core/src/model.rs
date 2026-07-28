//! Модель проекта — единый детерминированный свод фактов о системе.
//!
//! Зачем нужен отдельный слой. До сих пор каждый генератор документа самостоятельно
//! обращался к движкам: спецификация звала извлечение поверхности и статистику модулей,
//! описание архитектуры звало их же повторно, диаграммы звали в третий раз. Одна и та же
//! работа выполнялась многократно, а расхождение результатов между документами ничем не
//! исключалось. Модель собирается один раз за прогон, и все документы строятся из неё,
//! поэтому документы комплекта заведомо согласованы между собой.
//!
//! ПРОИСХОЖДЕНИЕ ОБЯЗАТЕЛЬНО. Каждый факт несёт сведения о том, откуда он получен:
//! движок-источник, файл, строка и уверенность. Без происхождения утверждение документа
//! невозможно ни проверить, ни отличить вывод из кода от предположения, а документ по
//! стандарту без проверяемости утверждений не имеет ценности.
//!
//! ЧЕСТНЫЕ ПРОБЕЛЫ. То, что установить не удалось, не подменяется правдоподобной
//! выдумкой и не замалчивается: перечень неустановленного ведётся в `gaps` и попадает в
//! документ как запись об отсутствии сведений, чего прямо требует и сам стандарт.

use crate::engines::codeintel::CodeIntelEngine;
use crate::engines::store::Store;
use crate::engines::surface;
use crate::engines::walk::{ext_of, is_test_dir_path, is_test_path, walk};
use ailc_contracts::{Confidence, Ctx, Result, RunInput};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// Версия схемы модели. Увеличивается при изменении состава полей, чтобы потребитель мог
/// отличить формат, который он понимает, от незнакомого.
///
/// Версия 2 добавила объявления, доступные извне, с сигнатурами и описаниями, а также
/// интерфейс командной строки и конфигурационные параметры. Прежняя запись модели после
/// повышения версии не читается и пересобирается заново: пересборка дешева, а молчаливое
/// чтение неполной модели дало бы документ с недостающими разделами без всякого признака,
/// что чего-то не хватает.
pub const SCHEMA_VERSION: u32 = 2;

/// Пространство хранения модели в служебном каталоге проекта.
const NS: &str = "model";
/// Имя файла модели.
const FILE: &str = "model.json";

/// Уверенность в факте. Повторяет контрактную шкалу, но пригодна к сериализации.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Certainty {
    /// Факт прочитан из объявления, которое не допускает иного толкования
    /// (поле манифеста сборки, объявление символа в разобранном дереве).
    Precise,
    /// Факт распознан устойчивым образцом (вызов, характерный для фреймворка).
    Pattern,
    /// Факт выведен эвристикой и подлежит подтверждению человеком.
    Heuristic,
}

impl From<Confidence> for Certainty {
    fn from(c: Confidence) -> Self {
        match c {
            Confidence::High => Certainty::Precise,
            Confidence::Medium => Certainty::Pattern,
            Confidence::Low => Certainty::Heuristic,
        }
    }
}

/// Происхождение факта: чем установлен и где это видно.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    /// Движок или разборщик, установивший факт.
    pub engine: String,
    /// Файл относительно корня проекта, если факт привязан к файлу.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Строка в файле, если факт привязан к строке.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub certainty: Certainty,
}

impl Origin {
    /// Факт, прочитанный из объявления в конкретном файле.
    pub fn declared(engine: &str, file: impl Into<String>) -> Self {
        Self {
            engine: engine.to_string(),
            file: Some(file.into()),
            line: None,
            certainty: Certainty::Precise,
        }
    }

    /// Факт, распознанный образцом в конкретном месте.
    pub fn matched(engine: &str, file: impl Into<String>, line: u32) -> Self {
        Self {
            engine: engine.to_string(),
            file: Some(file.into()),
            line: Some(line),
            certainty: Certainty::Pattern,
        }
    }

    /// Факт, выведенный движком по совокупности данных, без единственного места.
    pub fn derived(engine: &str, certainty: Certainty) -> Self {
        Self {
            engine: engine.to_string(),
            file: None,
            line: None,
            certainty,
        }
    }
}

/// Значение вместе с происхождением.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact<T> {
    pub value: T,
    #[serde(flatten)]
    pub origin: Origin,
}

impl<T> Fact<T> {
    pub fn new(value: T, origin: Origin) -> Self {
        Self { value, origin }
    }
}

/// Неустановленное сведение: что именно не удалось выяснить и почему.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gap {
    /// Что не установлено, в терминах документа.
    pub what: String,
    /// Почему не установлено: чего не хватило в проекте или в возможностях извлечения.
    pub why: String,
}

/// Идентификация продукта: то, чем документ подписывается на титульном листе.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Identity {
    pub name: Option<Fact<String>>,
    pub version: Option<Fact<String>>,
    pub license: Option<Fact<String>>,
    pub description: Option<Fact<String>>,
    pub repository: Option<Fact<String>>,
    pub authors: Vec<Fact<String>>,
    /// Отпечаток текущего состояния истории изменений.
    pub commit: Option<Fact<String>>,
}

/// Технологическое окружение: чем система написана и чем собирается.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Environment {
    pub stacks: Vec<Fact<String>>,
    pub languages: Vec<Fact<String>>,
    /// Зафиксированные версии инструментария (канал Rust, версия Node и подобное).
    pub toolchains: Vec<Fact<String>>,
    pub manifests: Vec<Fact<String>>,
}

/// Модуль системы как единица состава.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub name: String,
    pub definitions: u32,
    pub exported: u32,
    pub languages: Vec<String>,
    pub top_exports: Vec<String>,
}

/// Объявление, доступное извне, вместе с его описанием.
///
/// Перечень имён отвечает на вопрос «что есть», но документ по стандарту требует
/// ответа на вопрос «что оно делает». Сигнатура и комментарий документации дают этот
/// ответ там, где автор кода его уже написал, и честно молчат там, где не написал.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEntry {
    pub name: String,
    pub kind: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extends: Vec<String>,
    #[serde(flatten)]
    pub origin: Origin,
}

/// Структура системы: состав, связи и точки входа.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Structure {
    pub modules: Vec<Module>,
    pub entry_points: Vec<Fact<String>>,
    /// Направленные связи между модулями (зависимость по импортам).
    pub dependencies: Vec<(String, String)>,
    /// Циклические связи, подлежащие распутыванию.
    pub cycles: Vec<Vec<String>>,
    pub files: u32,
    pub lines: u64,
    pub public_symbols: u32,
    /// Артефакты, производимые сборкой (исполняемые файлы, библиотеки).
    pub artifacts: Vec<Fact<String>>,
    /// Объявления, доступные извне, с сигнатурами и комментариями документации.
    #[serde(default)]
    pub api: Vec<ApiEntry>,
}

/// Поверхность системы: чем она обменивается с внешним миром.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SurfaceModel {
    pub routes: Vec<Fact<String>>,
    pub env: Vec<Fact<String>>,
    pub services: Vec<Fact<String>>,
    pub data_models: Vec<Fact<String>>,
    /// Каталоги миграций схемы базы данных.
    pub migrations: Vec<Fact<String>>,
    /// Файлы контрактных схем интерфейса (OpenAPI, gRPC, GraphQL).
    pub api_schemas: Vec<Fact<String>>,
    /// Подкоманды интерфейса командной строки. Без них раздел руководства пользователя об
    /// описании операций пришлось бы добывать опросом, хотя код о них знает.
    #[serde(default)]
    pub cli_commands: Vec<Fact<String>>,
    /// Ключи и параметры командной строки.
    #[serde(default)]
    pub cli_flags: Vec<Fact<String>>,
    /// Имена конфигурационных параметров из файлов настроек. Значения намеренно не
    /// извлекаются: значение может содержать секрет, и его попадание в документ было бы
    /// утечкой.
    #[serde(default)]
    pub config_params: Vec<Fact<String>>,
}

/// Зависимость поставки с версией.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

/// Развёртывание: где и как система исполняется.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Deployment {
    pub containers: Vec<Fact<String>>,
    pub ports: Vec<Fact<String>>,
}

/// Полная модель проекта.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectModel {
    pub schema_version: u32,
    pub identity: Identity,
    pub environment: Environment,
    pub structure: Structure,
    pub surface: SurfaceModel,
    pub dependencies: Vec<Dependency>,
    pub deployment: Deployment,
    pub gaps: Vec<Gap>,
}

// ───────────────────────────── сборка модели ─────────────────────────────

/// Собрать модель проекта из движков и манифестов сборки.
///
/// Все перечни упорядочены детерминированно: модель служит источником документов, а
/// недетерминированный порядок означал бы, что регенерация без единого изменения кода
/// каждый раз объявляет документ обновлённым.
pub fn build(ctx: &Ctx, input: &RunInput) -> Result<ProjectModel> {
    let mut m = ProjectModel {
        schema_version: SCHEMA_VERSION,
        ..Default::default()
    };

    m.identity = identity(ctx, &mut m.gaps);
    m.environment = environment(ctx);
    m.structure = structure(ctx, input)?;
    m.surface = surface_model(ctx, input)?;
    m.dependencies = dependencies(ctx);
    m.deployment = deployment(ctx, input)?;

    note_gaps(&m.clone(), &mut m.gaps);
    Ok(m)
}

/// Имя файла схемы модели.
const SCHEMA_FILE: &str = "schema.json";

/// Схема модели: машинный контракт для потребителей файла модели.
///
/// Перечень свойств верхнего уровня поддерживается в согласии со структурой
/// [`ProjectModel`] тестом `схема_описывает_все_разделы_модели`: расхождение схемы с
/// действительностью это ровно тот дрейф документации, борьбе с которым посвящён продукт,
/// и допускать его в собственном контракте нельзя.
pub const SCHEMA: &str = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Модель проекта ailc",
  "description": "Детерминированный свод фактов о системе. Каждый факт несёт происхождение: движок-источник, файл, строку и уверенность.",
  "type": "object",
  "required": ["schema_version", "identity", "environment", "structure", "surface", "dependencies", "deployment", "gaps"],
  "properties": {
    "schema_version": { "type": "integer", "description": "Версия схемы; несовпадение означает незнакомый формат" },
    "identity": { "type": "object", "description": "Идентификация продукта: наименование, версия, лицензия, правообладатели, отпечаток состояния истории" },
    "environment": { "type": "object", "description": "Технологическое окружение: стек, языки, зафиксированные версии инструментария, манифесты сборки" },
    "structure": { "type": "object", "description": "Состав системы: модули, точки входа, связи, циклы, артефакты сборки, объявления с сигнатурами и описаниями" },
    "surface": { "type": "object", "description": "Поверхность системы: маршруты, переменные окружения, внешние сервисы, модели данных, миграции, контрактные схемы, интерфейс командной строки, конфигурационные параметры" },
    "dependencies": { "type": "array", "description": "Зависимости поставки с версиями", "items": { "type": "object", "required": ["ecosystem", "name", "version"] } },
    "deployment": { "type": "object", "description": "Развёртывание: контейнеры и объявленные порты" },
    "gaps": { "type": "array", "description": "Честные пробелы: что установить не удалось и почему", "items": { "type": "object", "required": ["what", "why"] } }
  }
}
"#;

/// Записать модель и её схему в служебный каталог проекта.
/// Возвращает относительные пути обоих файлов.
pub fn write(ctx: &Ctx, m: &ProjectModel) -> Result<(String, String)> {
    let json = serde_json::to_string_pretty(m)
        .map_err(|e| ailc_contracts::CapError(format!("модель не сериализуется: {e}")))?;
    Store::write(ctx, NS, FILE, &json)?;
    Store::write(ctx, NS, SCHEMA_FILE, SCHEMA)?;
    Ok((
        format!(".ailc/{NS}/{FILE}"),
        format!(".ailc/{NS}/{SCHEMA_FILE}"),
    ))
}

/// Прочитать ранее записанную модель, если она есть и её схема понятна.
pub fn read(ctx: &Ctx) -> Option<ProjectModel> {
    let text = std::fs::read_to_string(ctx.root.join(format!(".ailc/{NS}/{FILE}"))).ok()?;
    let m: ProjectModel = serde_json::from_str(&text).ok()?;
    (m.schema_version == SCHEMA_VERSION).then_some(m)
}

// ───────────────────────────── идентификация ─────────────────────────────

/// Прочитать значение строки из таблицы TOML по пути ключей.
fn toml_str(v: &toml::Value, path: &[&str]) -> Option<String> {
    let mut cur = v;
    for k in path {
        cur = cur.get(k)?;
    }
    cur.as_str().map(str::to_string)
}

fn identity(ctx: &Ctx, gaps: &mut Vec<Gap>) -> Identity {
    let mut id = Identity::default();
    let root = &ctx.root;

    // Rust: корневой Cargo.toml. Наследование через `workspace = true` разрешается тем,
    // что сведения о выпуске рабочего пространства лежат в этом же файле.
    if let Ok(text) = std::fs::read_to_string(root.join("Cargo.toml")) {
        if let Ok(v) = text.parse::<toml::Value>() {
            let o = || Origin::declared("manifest.cargo", "Cargo.toml");
            for path in [["package", "name"], ["workspace", "package"]] {
                if path[1] == "name" {
                    if let Some(s) = toml_str(&v, &path) {
                        id.name = Some(Fact::new(s, o()));
                    }
                }
            }
            for base in [vec!["package"], vec!["workspace", "package"]] {
                let mut p = base.clone();
                p.push("version");
                if id.version.is_none() {
                    if let Some(s) = toml_str(&v, &p) {
                        id.version = Some(Fact::new(s, o()));
                    }
                }
                let mut p = base.clone();
                p.push("license");
                if id.license.is_none() {
                    if let Some(s) = toml_str(&v, &p) {
                        id.license = Some(Fact::new(s, o()));
                    }
                }
                let mut p = base.clone();
                p.push("description");
                if id.description.is_none() {
                    if let Some(s) = toml_str(&v, &p) {
                        id.description = Some(Fact::new(s, o()));
                    }
                }
                let mut p = base.clone();
                p.push("repository");
                if id.repository.is_none() {
                    if let Some(s) = toml_str(&v, &p) {
                        id.repository = Some(Fact::new(s, o()));
                    }
                }
                let mut p = base;
                p.push("authors");
                if id.authors.is_empty() {
                    let mut cur = &v;
                    let mut ok = true;
                    for k in &p {
                        match cur.get(k) {
                            Some(next) => cur = next,
                            None => {
                                ok = false;
                                break;
                            }
                        }
                    }
                    if ok {
                        if let Some(arr) = cur.as_array() {
                            for a in arr {
                                if let Some(s) = a.as_str() {
                                    id.authors.push(Fact::new(s.to_string(), o()));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Node: package.json.
    if let Ok(text) = std::fs::read_to_string(root.join("package.json")) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            let o = || Origin::declared("manifest.npm", "package.json");
            let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
            if id.name.is_none() {
                if let Some(x) = s("name") {
                    id.name = Some(Fact::new(x, o()));
                }
            }
            if id.version.is_none() {
                if let Some(x) = s("version") {
                    id.version = Some(Fact::new(x, o()));
                }
            }
            if id.license.is_none() {
                if let Some(x) = s("license") {
                    id.license = Some(Fact::new(x, o()));
                }
            }
            if id.description.is_none() {
                if let Some(x) = s("description") {
                    id.description = Some(Fact::new(x, o()));
                }
            }
            if id.authors.is_empty() {
                if let Some(x) = s("author") {
                    id.authors.push(Fact::new(x, o()));
                }
            }
        }
    }

    // Python: pyproject.toml (современный `[project]` и устаревший `[tool.poetry]`).
    if let Ok(text) = std::fs::read_to_string(root.join("pyproject.toml")) {
        if let Ok(v) = text.parse::<toml::Value>() {
            let o = || Origin::declared("manifest.python", "pyproject.toml");
            for base in [["project"], ["tool"]] {
                let p: Vec<&str> = if base[0] == "tool" {
                    vec!["tool", "poetry"]
                } else {
                    vec!["project"]
                };
                let mut key = p.clone();
                key.push("name");
                if id.name.is_none() {
                    if let Some(s) = toml_str(&v, &key) {
                        id.name = Some(Fact::new(s, o()));
                    }
                }
                let mut key = p.clone();
                key.push("version");
                if id.version.is_none() {
                    if let Some(s) = toml_str(&v, &key) {
                        id.version = Some(Fact::new(s, o()));
                    }
                }
                let mut key = p;
                key.push("description");
                if id.description.is_none() {
                    if let Some(s) = toml_str(&v, &key) {
                        id.description = Some(Fact::new(s, o()));
                    }
                }
            }
        }
    }

    // Имя как последнее средство — имя корневого каталога. Это эвристика, и она честно
    // помечена как таковая: имя каталога не является объявленным именем продукта.
    if id.name.is_none() {
        if let Some(n) = std::fs::canonicalize(root)
            .unwrap_or_else(|_| root.clone())
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
        {
            id.name = Some(Fact::new(
                n,
                Origin::derived("filesystem", Certainty::Heuristic),
            ));
        }
    }

    // Лицензия из файла LICENSE, если манифест о ней умалчивает.
    if id.license.is_none() {
        for name in ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"] {
            if let Ok(text) = std::fs::read_to_string(root.join(name)) {
                let head: String = text.chars().take(4000).collect();
                let kind = if head.contains("Apache License") {
                    Some("Apache-2.0")
                } else if head.contains("MIT License")
                    || head.contains("Permission is hereby granted, free of charge")
                {
                    Some("MIT")
                } else if head.contains("GNU GENERAL PUBLIC LICENSE") {
                    Some("GPL")
                } else if head.contains("Mozilla Public License") {
                    Some("MPL-2.0")
                } else if head.contains("BSD") {
                    Some("BSD")
                } else {
                    None
                };
                if let Some(k) = kind {
                    id.license = Some(Fact::new(
                        k.to_string(),
                        Origin {
                            engine: "license.file".into(),
                            file: Some(name.into()),
                            line: None,
                            certainty: Certainty::Pattern,
                        },
                    ));
                }
                break;
            }
        }
    }

    id.commit = git_commit(root).map(|c| Fact::new(c, Origin::derived("git", Certainty::Precise)));
    if id.commit.is_none() {
        gaps.push(Gap {
            what: "отпечаток состояния истории изменений".into(),
            why: "каталог не является репозиторием системы контроля версий".into(),
        });
    }
    id
}

/// Текущий коммит, если проект ведётся в git.
fn git_commit(root: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

// ───────────────────────────── окружение ─────────────────────────────

fn environment(ctx: &Ctx) -> Environment {
    let root = &ctx.root;
    let mut e = Environment::default();

    for s in crate::stack::detect(root) {
        e.stacks.push(Fact::new(
            s.to_string(),
            Origin::derived("stack", Certainty::Pattern),
        ));
    }

    // Манифесты сборки: их наличие само по себе является фактом для раздела о видах
    // обеспечения и для перечня источников разработки.
    for name in [
        "Cargo.toml",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "build.sbt",
        "Gemfile",
        "composer.json",
        "Package.swift",
        "Podfile",
        "pubspec.yaml",
        "CMakeLists.txt",
        "Makefile",
    ] {
        if root.join(name).exists() {
            e.manifests.push(Fact::new(
                name.to_string(),
                Origin::declared("manifest", name),
            ));
        }
    }

    // Зафиксированные версии инструментария: без них раздел о средствах разработки
    // нечем наполнить, а прогон невоспроизводим.
    if let Ok(text) = std::fs::read_to_string(root.join("rust-toolchain.toml")) {
        if let Ok(v) = text.parse::<toml::Value>() {
            if let Some(ch) = toml_str(&v, &["toolchain", "channel"]) {
                e.toolchains.push(Fact::new(
                    format!("Rust {ch}"),
                    Origin::declared("toolchain", "rust-toolchain.toml"),
                ));
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string(root.join(".nvmrc")) {
        let v = text.trim().to_string();
        if !v.is_empty() {
            e.toolchains.push(Fact::new(
                format!("Node {v}"),
                Origin::declared("toolchain", ".nvmrc"),
            ));
        }
    }
    if let Ok(text) = std::fs::read_to_string(root.join(".python-version")) {
        let v = text.trim().to_string();
        if !v.is_empty() {
            e.toolchains.push(Fact::new(
                format!("Python {v}"),
                Origin::declared("toolchain", ".python-version"),
            ));
        }
    }
    if let Ok(text) = std::fs::read_to_string(root.join("go.mod")) {
        for line in text.lines() {
            if let Some(v) = line.trim().strip_prefix("go ") {
                e.toolchains.push(Fact::new(
                    format!("Go {}", v.trim()),
                    Origin::declared("toolchain", "go.mod"),
                ));
                break;
            }
        }
    }

    e.stacks.sort_by(|a, b| a.value.cmp(&b.value));
    e.toolchains.sort_by(|a, b| a.value.cmp(&b.value));
    e
}

// ───────────────────────────── структура ─────────────────────────────

fn structure(ctx: &Ctx, input: &RunInput) -> Result<Structure> {
    let stats = CodeIntelEngine::module_stats(ctx, input)?;
    let graph = CodeIntelEngine::dependency_graph(ctx, input)?;
    let pmap = CodeIntelEngine::project_map(ctx, input)?;
    let syms = CodeIntelEngine::symbols(ctx, input)?;

    let mut s = Structure {
        files: pmap.total_files,
        lines: pmap.total_lines as u64,
        ..Default::default()
    };

    // Каталоги тестовой раскладки в состав системы не входят: документ описывает
    // продукт, а не репозиторий.
    for (name, st) in stats.iter().filter(|(n, _)| !is_test_dir_path(n)) {
        let mut top = st.top_exports.clone();
        top.sort();
        s.modules.push(Module {
            name: name.clone(),
            definitions: st.total,
            exported: st.exported,
            // Множество уже упорядочено по построению, обход даёт устойчивый порядок.
            languages: st.langs.iter().cloned().collect(),
            top_exports: top,
        });
    }
    s.modules.sort_by(|a, b| a.name.cmp(&b.name));

    for e in &pmap.entry_points {
        s.entry_points.push(Fact::new(
            e.clone(),
            Origin::derived("codeintel", Certainty::Pattern),
        ));
    }
    s.entry_points.sort_by(|a, b| a.value.cmp(&b.value));

    s.dependencies = graph
        .edges
        .iter()
        .filter(|(a, b)| !is_test_dir_path(a) && !is_test_dir_path(b))
        .cloned()
        .collect();
    s.dependencies.sort();
    s.cycles = graph.cycles();
    s.cycles.sort();

    s.public_symbols = syms
        .iter()
        .filter(|x| x.exported && !is_test_path(&x.file) && !is_test_dir_path(&x.file))
        .count() as u32;

    s.artifacts = artifacts(ctx);

    // Объявления, доступные извне, вместе с сигнатурами и описаниями. Перечень имён
    // отвечает на вопрос «что есть», а документ по стандарту требует ответа на вопрос
    // «что оно делает»; сигнатура и комментарий автора дают этот ответ там, где автор его
    // уже написал, и молчат там, где не написал.
    s.api = crate::engines::apidoc::ApiDoc::extract(ctx, input)?
        .into_iter()
        .filter(|it| it.exported)
        .map(|it| ApiEntry {
            origin: Origin {
                engine: "apidoc".into(),
                file: Some(it.file.clone()),
                line: Some(it.line),
                certainty: Certainty::Precise,
            },
            name: it.name,
            kind: it.kind,
            signature: it.signature,
            doc: it.doc,
            extends: it.extends,
        })
        .collect();
    s.api.sort_by(|a, b| {
        (a.origin.file.as_deref(), a.origin.line, a.name.as_str()).cmp(&(
            b.origin.file.as_deref(),
            b.origin.line,
            b.name.as_str(),
        ))
    });
    Ok(s)
}

/// Артефакты сборки: что именно поставляется по результатам сборки.
fn artifacts(ctx: &Ctx) -> Vec<Fact<String>> {
    let root = &ctx.root;
    let mut out: Vec<Fact<String>> = Vec::new();

    // Манифест корня и, если это рабочее пространство, манифесты его участников:
    // в рабочем пространстве артефакты объявлены именно у участников, а корневой
    // манифест перечисляет только их состав.
    let mut cargo_manifests: Vec<String> = vec!["Cargo.toml".to_string()];
    if let Ok(text) = std::fs::read_to_string(root.join("Cargo.toml")) {
        if let Ok(v) = text.parse::<toml::Value>() {
            if let Some(members) = v
                .get("workspace")
                .and_then(|w| w.get("members"))
                .and_then(|m| m.as_array())
            {
                for m in members.iter().filter_map(|x| x.as_str()) {
                    // Образец вида `crates/*` раскрывается перечнем подкаталогов.
                    if let Some(prefix) = m.strip_suffix("/*") {
                        if let Ok(rd) = std::fs::read_dir(root.join(prefix)) {
                            for e in rd.flatten() {
                                if e.path().is_dir() {
                                    cargo_manifests.push(format!(
                                        "{prefix}/{}/Cargo.toml",
                                        e.file_name().to_string_lossy()
                                    ));
                                }
                            }
                        }
                    } else {
                        cargo_manifests.push(format!("{m}/Cargo.toml"));
                    }
                }
            }
        }
    }
    cargo_manifests.sort();
    for rel in &cargo_manifests {
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
            continue;
        };
        let Ok(v) = text.parse::<toml::Value>() else {
            continue;
        };
        let dir = rel.trim_end_matches("Cargo.toml");
        let pkg = toml_str(&v, &["package", "name"]);
        if let Some(bins) = v.get("bin").and_then(|b| b.as_array()) {
            for b in bins {
                if let Some(n) = b.get("name").and_then(|x| x.as_str()) {
                    out.push(Fact::new(
                        format!("исполняемый файл {n}"),
                        Origin::declared("manifest.cargo", rel.clone()),
                    ));
                }
            }
        } else if root.join(format!("{dir}src/main.rs")).exists() {
            // Раскладка по умолчанию: наличие точки входа означает исполняемый файл,
            // названный по имени пакета.
            if let Some(n) = &pkg {
                out.push(Fact::new(
                    format!("исполняемый файл {n}"),
                    Origin::declared("manifest.cargo", rel.clone()),
                ));
            }
        }
        if v.get("lib").is_some() || root.join(format!("{dir}src/lib.rs")).exists() {
            let name = pkg.clone().unwrap_or_else(|| "без имени".to_string());
            out.push(Fact::new(
                format!("библиотека {name}"),
                Origin::declared("manifest.cargo", rel.clone()),
            ));
        }
    }
    if let Ok(text) = std::fs::read_to_string(root.join("package.json")) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            match v.get("bin") {
                Some(serde_json::Value::String(s)) => out.push(Fact::new(
                    format!("исполняемый файл {s}"),
                    Origin::declared("manifest.npm", "package.json"),
                )),
                Some(serde_json::Value::Object(map)) => {
                    for k in map.keys() {
                        out.push(Fact::new(
                            format!("исполняемый файл {k}"),
                            Origin::declared("manifest.npm", "package.json"),
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    out.sort_by(|a, b| a.value.cmp(&b.value));
    out.dedup_by(|a, b| a.value == b.value);
    out
}

// ───────────────────────────── поверхность ─────────────────────────────

fn surface_model(ctx: &Ctx, input: &RunInput) -> Result<SurfaceModel> {
    let s = surface::extract(ctx, input)?;
    let f = |items: &[surface::SurfaceItem]| -> Vec<Fact<String>> {
        items
            .iter()
            .map(|it| {
                Fact::new(
                    it.value.clone(),
                    Origin::matched("surface", it.file.clone(), it.line),
                )
            })
            .collect()
    };
    let mut m = SurfaceModel {
        routes: f(&s.routes),
        env: f(&s.env),
        services: f(&s.services),
        data_models: f(&s.models),
        ..Default::default()
    };

    // Миграции схемы базы данных и контрактные схемы интерфейса: без них разделы об
    // информационном обеспечении и о совместимости остаются пустыми.
    let root = ctx.root.clone();
    let mut migrations: BTreeSet<String> = BTreeSet::new();
    let mut schemas: BTreeSet<String> = BTreeSet::new();
    walk(&ctx.base(input)?, &mut |path| {
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        if is_test_path(&rel) {
            return;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if matches!(ext_of(path), "proto" | "graphql" | "gql")
            || name.starts_with("openapi.")
            || name.starts_with("swagger.")
        {
            schemas.insert(rel.clone());
        }
        // Каталог миграций опознаётся по сегменту пути, а не по имени файла: раскладки
        // экосистем различаются, общим остаётся именно каталог.
        for seg in rel.split(['/', '\\']) {
            if matches!(
                seg.to_ascii_lowercase().as_str(),
                "migrations" | "migrate" | "alembic" | "changelog"
            ) {
                let dir = rel
                    .split_once(seg)
                    .map(|(a, _)| format!("{a}{seg}"))
                    .unwrap_or_else(|| seg.to_string());
                migrations.insert(dir);
                break;
            }
        }
    })?;
    m.migrations = migrations
        .into_iter()
        .map(|d| {
            let o = Origin::declared("model.migrations", d.clone());
            Fact::new(d, o)
        })
        .collect();
    m.api_schemas = schemas
        .into_iter()
        .map(|d| {
            let o = Origin::declared("model.schemas", d.clone());
            Fact::new(d, o)
        })
        .collect();

    // Интерфейс командной строки и конфигурационные параметры. Без них раздел
    // руководства пользователя об описании операций и раздел об условиях эксплуатации
    // приходилось бы добывать опросом, хотя код о них знает.
    let cli = crate::engines::cli::extract(ctx, input)?;
    let в_факты = |items: Vec<crate::engines::cli::CliItem>| -> Vec<Fact<String>> {
        items
            .into_iter()
            .map(|it| {
                let o = Origin::matched("cli", it.file, it.line);
                Fact::new(it.value, o)
            })
            .collect()
    };
    m.cli_commands = в_факты(cli.commands);
    m.cli_flags = в_факты(cli.flags);
    m.config_params = в_факты(cli.config);
    Ok(m)
}

// ───────────────────────────── зависимости и развёртывание ─────────────────────────────

fn dependencies(ctx: &Ctx) -> Vec<Dependency> {
    let (pkgs, _manifests) = crate::engines::osv::packages(&ctx.root);
    let mut out: Vec<Dependency> = pkgs
        .into_iter()
        .map(|(eco, name, version)| Dependency {
            ecosystem: eco.to_string(),
            name,
            version,
        })
        .collect();
    out.sort_by(|a, b| {
        (a.ecosystem.as_str(), a.name.as_str()).cmp(&(b.ecosystem.as_str(), b.name.as_str()))
    });
    out.dedup_by(|a, b| a.ecosystem == b.ecosystem && a.name == b.name && a.version == b.version);
    out
}

fn deployment(ctx: &Ctx, input: &RunInput) -> Result<Deployment> {
    let sg = CodeIntelEngine::service_graph(ctx, input)?;
    let mut d = Deployment::default();
    for c in &sg.containers {
        d.containers.push(Fact::new(
            c.clone(),
            Origin::derived("codeintel.services", Certainty::Pattern),
        ));
    }
    d.containers.sort_by(|a, b| a.value.cmp(&b.value));

    // Порты: объявление EXPOSE в описании образа и раздел ports в описании композиции.
    let root = ctx.root.clone();
    let mut ports: BTreeSet<(String, String, u32)> = BTreeSet::new();
    walk(&ctx.base(input)?, &mut |path| {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let is_docker = name.starts_with("dockerfile");
        let is_compose =
            name.contains("compose") && (name.ends_with(".yml") || name.ends_with(".yaml"));
        if !is_docker && !is_compose {
            return;
        }
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        let Some(text) = std::fs::read_to_string(path).ok() else {
            return;
        };
        for (i, line) in text.lines().enumerate() {
            let t = line.trim();
            if is_docker {
                if let Some(rest) = t
                    .strip_prefix("EXPOSE ")
                    .or_else(|| t.strip_prefix("expose "))
                {
                    for p in rest.split_whitespace() {
                        ports.insert((p.to_string(), rel.clone(), (i as u32) + 1));
                    }
                }
            } else if let Some(rest) = t.strip_prefix("- \"").or_else(|| t.strip_prefix("- ")) {
                // Строка перечня портов композиции вида `- "8080:80"`.
                let val = rest.trim_matches('"');
                if val.contains(':')
                    && val
                        .split(':')
                        .all(|x| x.chars().all(|c| c.is_ascii_digit()))
                {
                    ports.insert((val.to_string(), rel.clone(), (i as u32) + 1));
                }
            }
        }
    })?;
    d.ports = ports
        .into_iter()
        .map(|(p, file, line)| Fact::new(p, Origin::matched("model.deployment", file, line)))
        .collect();
    Ok(d)
}

// ───────────────────────────── честные пробелы ─────────────────────────────

/// Дописать в перечень пробелов то, что документу требуется, но в проекте не найдено.
///
/// Пробел это не ошибка извлечения, а сведение об отсутствии: раздел документа
/// сохраняется, и в нём приводится запись об отсутствии, чего прямо требует стандарт.
fn note_gaps(m: &ProjectModel, gaps: &mut Vec<Gap>) {
    if m.identity.version.is_none() {
        gaps.push(Gap {
            what: "версия продукта".into(),
            why: "ни один манифест сборки не объявляет поля версии".into(),
        });
    }
    if m.identity.license.is_none() {
        gaps.push(Gap {
            what: "условия использования продукта".into(),
            why: "манифест не объявляет лицензии и файла лицензии в корне нет".into(),
        });
    }
    if m.identity.authors.is_empty() {
        gaps.push(Gap {
            what: "правообладатель и разработчик".into(),
            why: "манифест не объявляет авторов".into(),
        });
    }
    if m.environment.toolchains.is_empty() {
        gaps.push(Gap {
            what: "требования к версиям инструментария".into(),
            why: "версия инструментария в проекте не зафиксирована".into(),
        });
    }
    if m.deployment.containers.is_empty() && m.deployment.ports.is_empty() {
        gaps.push(Gap {
            what: "карта развёртывания".into(),
            why: "описаний образов и композиций в проекте не найдено".into(),
        });
    }
    if m.surface.api_schemas.is_empty()
        && m.surface.routes.is_empty()
        && m.surface.cli_commands.is_empty()
    {
        gaps.push(Gap {
            what: "интерфейс прикладного программирования".into(),
            why: "ни маршрутов, ни контрактных схем, ни команд интерфейса командной строки в коде не обнаружено".into(),
        });
    }
    if m.surface.config_params.is_empty() {
        gaps.push(Gap {
            what: "конфигурационные параметры".into(),
            why: "файлов настроек известного вида в проекте не найдено".into(),
        });
    }
    if m.structure.api.iter().all(|e| e.doc.is_none()) && !m.structure.api.is_empty() {
        gaps.push(Gap {
            what: "описания объявлений, доступных извне".into(),
            why: "ни одно объявление не снабжено комментарием документации в исходном тексте"
                .into(),
        });
    }
    gaps.sort_by(|a, b| a.what.cmp(&b.what));
    gaps.dedup_by(|a, b| a.what == b.what);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> Ctx {
        let root = std::env::temp_dir().join(format!(
            "ailc-model-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("src")).unwrap();
        Ctx::new(root.to_str().unwrap())
    }

    /// Сведения о продукте читаются из манифеста сборки, и каждое несёт происхождение:
    /// без этого утверждение документа невозможно проверить.
    #[test]
    fn идентификация_читается_из_манифеста_с_происхождением() {
        let ctx = tmp("идент");
        std::fs::write(
            ctx.root.join("Cargo.toml"),
            "[package]\nname = \"учёт\"\nversion = \"1.2.3\"\nlicense = \"Apache-2.0\"\nauthors = [\"Иванов\"]\n",
        )
        .unwrap();
        std::fs::write(ctx.root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();

        let m = build(&ctx, &RunInput::default()).unwrap();
        let v = m.identity.version.expect("версия обязана быть прочитана");
        assert_eq!(v.value, "1.2.3");
        assert_eq!(v.origin.file.as_deref(), Some("Cargo.toml"));
        assert_eq!(v.origin.certainty, Certainty::Precise);
        assert_eq!(
            m.identity.license.map(|l| l.value).as_deref(),
            Some("Apache-2.0")
        );
        assert_eq!(m.identity.name.map(|n| n.value).as_deref(), Some("учёт"));
        assert_eq!(m.identity.authors.len(), 1);
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// В рабочем пространстве артефакты объявлены у участников, а не в корне: корневой
    /// манифест перечисляет только состав, и разбор одного лишь корня оставлял бы раздел
    /// о поставляемых артефактах пустым при заведомо существующих артефактах.
    #[test]
    fn артефакты_собираются_по_участникам_рабочего_пространства() {
        let ctx = tmp("артефакты");
        std::fs::create_dir_all(ctx.root.join("crates/сервис/src")).unwrap();
        std::fs::create_dir_all(ctx.root.join("crates/ядро/src")).unwrap();
        std::fs::write(
            ctx.root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\n",
        )
        .unwrap();
        std::fs::write(
            ctx.root.join("crates/сервис/Cargo.toml"),
            "[package]\nname = \"сервис\"\n",
        )
        .unwrap();
        std::fs::write(ctx.root.join("crates/сервис/src/main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(
            ctx.root.join("crates/ядро/Cargo.toml"),
            "[package]\nname = \"ядро\"\n",
        )
        .unwrap();
        std::fs::write(ctx.root.join("crates/ядро/src/lib.rs"), "pub fn f() {}\n").unwrap();

        let m = build(&ctx, &RunInput::default()).unwrap();
        let values: Vec<&str> = m
            .structure
            .artifacts
            .iter()
            .map(|a| a.value.as_str())
            .collect();
        assert!(
            values.contains(&"исполняемый файл сервис"),
            "точка входа участника даёт исполняемый файл: {values:?}"
        );
        assert!(
            values.contains(&"библиотека ядро"),
            "участник с библиотекой даёт библиотеку: {values:?}"
        );
        assert!(
            m.structure
                .artifacts
                .iter()
                .all(|a| a.origin.file.is_some()),
            "каждый артефакт обязан указывать манифест, из которого он объявлен"
        );
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Неустановленное сведение становится честной записью об отсутствии, а не
    /// правдоподобной выдумкой и не молчанием.
    #[test]
    fn неустановленное_попадает_в_перечень_пробелов() {
        let ctx = tmp("пробелы");
        std::fs::write(ctx.root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        let m = build(&ctx, &RunInput::default()).unwrap();
        assert!(
            m.gaps.iter().any(|g| g.what.contains("версия продукта")),
            "отсутствие версии обязано быть зафиксировано: {:?}",
            m.gaps
        );
        assert!(
            m.gaps.iter().all(|g| !g.why.trim().is_empty()),
            "у каждого пробела обязана быть причина: {:?}",
            m.gaps
        );
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Модель служит источником документов, поэтому её сборка обязана быть
    /// воспроизводимой: иначе регенерация без изменений кода каждый раз объявляла бы
    /// документ обновлённым.
    #[test]
    fn сборка_модели_детерминирована() {
        let ctx = tmp("детерм");
        std::fs::write(
            ctx.root.join("Cargo.toml"),
            "[package]\nname = \"с\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            ctx.root.join("src/lib.rs"),
            "pub fn один() {}\npub fn два() {}\n",
        )
        .unwrap();
        let a = build(&ctx, &RunInput::default()).unwrap();
        let b = build(&ctx, &RunInput::default()).unwrap();
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
            "две сборки модели подряд обязаны совпадать"
        );
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Записанная модель читается обратно, а несовместимая версия схемы отвергается.
    #[test]
    fn модель_записывается_и_читается() {
        let ctx = tmp("запись");
        std::fs::write(ctx.root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        let m = build(&ctx, &RunInput::default()).unwrap();
        let (rel, schema) = write(&ctx, &m).unwrap();
        assert_eq!(rel, ".ailc/model/model.json");
        assert_eq!(schema, ".ailc/model/schema.json");
        let back = read(&ctx).expect("записанная модель обязана читаться");
        assert_eq!(back.schema_version, SCHEMA_VERSION);
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Схема обязана описывать ровно те разделы, которые модель выдаёт. Расхождение
    /// схемы с действительностью это тот самый дрейф документации, ради борьбы с которым
    /// существует продукт, и в собственном машинном контракте он недопустим.
    #[test]
    fn схема_описывает_все_разделы_модели() {
        let ctx = tmp("схема");
        std::fs::write(ctx.root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        let m = build(&ctx, &RunInput::default()).unwrap();

        let value = serde_json::to_value(&m).unwrap();
        let model_keys: BTreeSet<String> = value
            .as_object()
            .expect("модель сериализуется объектом")
            .keys()
            .cloned()
            .collect();

        let schema: serde_json::Value = serde_json::from_str(SCHEMA).expect("схема разбирается");
        let schema_keys: BTreeSet<String> = schema["properties"]
            .as_object()
            .expect("в схеме есть свойства")
            .keys()
            .cloned()
            .collect();

        assert_eq!(
            model_keys, schema_keys,
            "перечень разделов модели и перечень свойств схемы обязаны совпадать"
        );
        let _ = std::fs::remove_dir_all(&ctx.root);
    }
}
