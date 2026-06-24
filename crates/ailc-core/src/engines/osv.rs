//! Нативная проверка зависимостей по базе уязвимостей формата OSV.
//!
//! Работает ОФЛАЙН и БЕЗ внешних инструментов: разбирает lock-файлы проекта на
//! чистом Rust и сверяет версии со вшитым снимком OSV. Это закрывает «pip-audit
//! смотрит в окружение, а не в проект» и «нужен установленный аудитор + сеть».
//!
//! Снимок (`assets/osv/snapshot.json`) — стартовый набор известных уязвимостей.
//! Прод-обновление: выгрузить per-ecosystem дампы OSV.dev, затем пересобрать снимок.
//! Сравнение версий теперь корректное и зависит от экосистемы: для PyPI применяется
//! правило PEP 440 (учёт epoch перед символом '!' и понижение приоритета сегмента
//! pre-release), для npm и crates.io применяется semver с тем же понижением
//! pre-release, для Go распознаются псевдоверсии вида `0.0.0-timestamp-hash`, которые
//! помечаются непроверяемыми, а не сравниваются молча по огрублённым числам.

use ailc_contracts::{Finding, Severity};
use serde::Deserialize;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Запись об уязвимости (упрощённый OSV: один пакет/диапазон на запись).
#[derive(Deserialize)]
struct Vuln {
    id: String,
    ecosystem: String,
    package: String,
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
    severity: String,
    summary: String,
}

/// Метаданные снимка: дата сборки и заявленное число записей. Позволяют показать
/// возраст базы в сводке и обнаружить рассинхронизацию заявленного и фактического
/// числа записей.
#[derive(Deserialize)]
struct Snapshot {
    #[serde(default)]
    generated_at: Option<String>,
    #[serde(default)]
    count: Option<usize>,
    #[serde(default)]
    vulns: Vec<Vuln>,
}

/// Загруженная база уязвимостей вместе с признаком успешной загрузки. Признак
/// `loaded=false` отличает реально пустой/битый снимок от снимка без записей по
/// конкретной экосистеме: первое означает «база не работает», второе — «база чиста».
struct Database {
    loaded: bool,
    generated_at: Option<String>,
    /// Заявленное в метаданных число записей. Сверяется с фактическим числом для
    /// обнаружения повреждения или неполной ручной правки снимка.
    count_declared: Option<usize>,
    vulns: Vec<Vuln>,
}

/// Разобрать встроенный снимок. Поддерживает ОБА формата: новый объектный
/// (`{ "generated_at": .., "count": .., "vulns": [..] }`) и устаревший «голый массив»
/// записей. При неудаче разбора возвращается `loaded=false`, чтобы потребитель явно
/// сообщил «база не загружена», а не выдал тишину за «уязвимостей нет».
fn load_db(raw: &str) -> Database {
    // Новый объектный формат с метаданными.
    if let Ok(snap) = serde_json::from_str::<Snapshot>(raw) {
        if !snap.vulns.is_empty() {
            return Database {
                loaded: true,
                generated_at: snap.generated_at,
                count_declared: snap.count,
                vulns: snap.vulns,
            };
        }
    }
    // Устаревший формат: голый массив записей без метаданных.
    if let Ok(vulns) = serde_json::from_str::<Vec<Vuln>>(raw) {
        if !vulns.is_empty() {
            return Database {
                loaded: true,
                generated_at: None,
                count_declared: None,
                vulns,
            };
        }
    }
    // Снимок битый или пуст: честно признаём, что база не загружена.
    Database {
        loaded: false,
        generated_at: None,
        count_declared: None,
        vulns: Vec::new(),
    }
}

fn db() -> &'static Database {
    static DB: OnceLock<Database> = OnceLock::new();
    DB.get_or_init(|| load_db(include_str!("../../assets/osv/snapshot.json")))
}

/// Результат нативной проверки.
pub struct OsvReport {
    pub findings: Vec<Finding>,
    /// Сколько зависимостей с известной версией удалось проверить.
    pub checked: usize,
    /// Найденные lock-файлы (для честного «пропущено», если их нет).
    pub manifests: Vec<&'static str>,
    /// Экосистемы, зависимости которых разобраны, но в снимке базы нет ни одной
    /// записи по ним: «проверено» там не значит «покрыто», человек должен видеть.
    /// Поле сохранено в прежней семантике (на уровне экосистемы) ради совместимости
    /// с существующими потребителями.
    pub uncovered: Vec<&'static str>,
    /// Конкретные пакеты `(экосистема, имя)`, по которым в снимке нет ни одной записи.
    /// Покрытие считается на уровне пакета: даже в «покрытой» экосистеме отдельный
    /// пакет может отсутствовать в базе, и тогда его «0 уязвимостей» не гарантия.
    pub uncovered_packages: Vec<(&'static str, String)>,
    /// Сколько проверенных зависимостей реально присутствует в снимке базы (то есть
    /// по ним покрытие настоящее). `checked - covered` соответствует числу пакетов,
    /// чья чистота не подтверждена базой.
    pub covered: usize,
    /// Найденные, но пока не поддержанные парсером lock-файлы с указанием пути.
    /// Честно выносятся в сводку как «найдено, но не разобрано — не покрыто».
    pub unparsed_lockfiles: Vec<String>,
    /// Признак успешной загрузки снимка базы. `false` означает, что снимок битый или
    /// пуст, и любой вердикт «уязвимостей нет» недостоверен.
    pub db_loaded: bool,
    /// Дата сборки снимка базы (если присутствует в метаданных), для показа возраста.
    pub db_generated_at: Option<String>,
    /// Подозрительные записи самого снимка (например, без границ introduced и fixed):
    /// такие записи не применяются к версиям, но о них честно сообщается.
    pub suspicious_records: Vec<String>,
    /// Зависимости, замеченные без точной версии (диапазоны requirements, vcs-ссылки,
    /// нефиксированные версии Pipfile): их нельзя сверить с базой, поэтому они честно
    /// помечаются непроверяемыми, а не выдаются за «проверено и чисто».
    pub unverifiable: Vec<(&'static str, String)>,
}

/// Тип распознанного lock-файла. Используется при обходе дерева, чтобы единообразно
/// перечислять и парсить найденные файлы, в том числе в монорепозиториях.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LockKind {
    RequirementsTxt,
    CargoLock,
    PackageLockJson,
    YarnLock,
    PnpmLock,
    GoSum,
    GradleLockfile,
    PubspecLock,
    PodfileLock,
    PoetryLock,
    PipfileLock,
    ComposerLock,
    GemfileLock,
}

impl LockKind {
    /// Распознать тип lock-файла по имени. requirements*.txt распознаётся гибко, чтобы
    /// покрыть requirements-dev.txt и requirements/base.txt в монорепозиториях.
    fn detect(file_name: &str) -> Option<LockKind> {
        let lower = file_name.to_ascii_lowercase();
        Some(match lower.as_str() {
            "cargo.lock" => LockKind::CargoLock,
            "package-lock.json" => LockKind::PackageLockJson,
            "yarn.lock" => LockKind::YarnLock,
            "pnpm-lock.yaml" => LockKind::PnpmLock,
            "go.sum" => LockKind::GoSum,
            "gradle.lockfile" => LockKind::GradleLockfile,
            "pubspec.lock" => LockKind::PubspecLock,
            "podfile.lock" => LockKind::PodfileLock,
            "poetry.lock" => LockKind::PoetryLock,
            "pipfile.lock" => LockKind::PipfileLock,
            "composer.lock" => LockKind::ComposerLock,
            "gemfile.lock" => LockKind::GemfileLock,
            other => {
                if other == "requirements.txt"
                    || (other.starts_with("requirements") && other.ends_with(".txt"))
                {
                    LockKind::RequirementsTxt
                } else {
                    return None;
                }
            }
        })
    }

    /// Стабильное короткое имя для списка manifests (совместимо с прежними значениями).
    fn manifest_label(self) -> &'static str {
        match self {
            LockKind::RequirementsTxt => "requirements.txt",
            LockKind::CargoLock => "Cargo.lock",
            LockKind::PackageLockJson => "package-lock.json",
            LockKind::YarnLock => "yarn.lock",
            LockKind::PnpmLock => "pnpm-lock.yaml",
            LockKind::GoSum => "go.sum",
            LockKind::GradleLockfile => "gradle.lockfile",
            LockKind::PubspecLock => "pubspec.lock",
            LockKind::PodfileLock => "Podfile.lock",
            LockKind::PoetryLock => "poetry.lock",
            LockKind::PipfileLock => "Pipfile.lock",
            LockKind::ComposerLock => "composer.lock",
            LockKind::GemfileLock => "Gemfile.lock",
        }
    }
}

/// Зависимость, извлечённая из lock-файла, либо отметка о непроверяемой строке.
/// Непроверяемые имена (диапазоны без точного пина) сохраняются отдельно, чтобы
/// честно отражать, что зависимость замечена, но её версия неизвестна и не сверена.
struct Parsed {
    deps: Vec<(&'static str, String, String)>,
    /// Имена зависимостей, замеченных без точной версии: их нельзя сверить с базой.
    unpinned: Vec<(&'static str, String)>,
}

impl Parsed {
    fn new() -> Self {
        Parsed {
            deps: Vec::new(),
            unpinned: Vec::new(),
        }
    }
}

/// Зависимости проекта из lock-файлов: (экосистема, имя, версия) + найденные манифесты.
/// Единый разбор переиспользуют scan (OSV), generate/sbom, security.scan/licenses.
///
/// Совместимость API сохранена: возвращается прежний кортеж. Внутри теперь выполняется
/// рекурсивный обход дерева проекта ограниченной глубины с уважением .gitignore и
/// исключением node_modules/target, поэтому lock-файлы монорепозиториев тоже попадают
/// в результат. Зависимости дедуплицируются по (экосистема, имя, версия).
pub fn packages(root: &Path) -> (Vec<(&'static str, String, String)>, Vec<&'static str>) {
    let collected = collect(root);
    (collected.deps, collected.manifests)
}

/// Полный результат разбора дерева: зависимости, найденные манифесты, непроверяемые
/// строки и обнаруженные, но не поддержанные парсером lock-файлы.
struct CollectResult {
    deps: Vec<(&'static str, String, String)>,
    manifests: Vec<&'static str>,
    unpinned: Vec<(&'static str, String)>,
    unparsed_lockfiles: Vec<String>,
}

/// Обойти дерево проекта, найти все lock-файлы и разобрать их.
fn collect(root: &Path) -> CollectResult {
    let mut found: Vec<(LockKind, PathBuf)> = Vec::new();
    let gitignore = GitIgnore::load(root);
    walk(root, root, 0, &gitignore, &mut found);

    // Стабильный порядок обхода: по типу, затем по пути. Делает результат
    // детерминированным независимо от порядка файлов в файловой системе.
    found.sort_by(|a, b| (a.0 as u8).cmp(&(b.0 as u8)).then_with(|| a.1.cmp(&b.1)));

    let mut deps: Vec<(&'static str, String, String)> = Vec::new();
    let mut unpinned: Vec<(&'static str, String)> = Vec::new();
    let mut manifests: Vec<&'static str> = Vec::new();
    let mut unparsed: Vec<String> = Vec::new();

    for (kind, path) in &found {
        let label = kind.manifest_label();
        if !manifests.contains(&label) {
            manifests.push(label);
        }
        let Ok(txt) = fs::read_to_string(path) else {
            // Файл найден, но прочитать не удалось: честно считаем его неразобранным.
            unparsed.push(rel_display(root, path));
            continue;
        };
        let parsed = parse_lock(*kind, &txt);
        if parsed.deps.is_empty() && parsed.unpinned.is_empty() {
            // Парсер не извлёк ни одной зависимости: возможно, формат за пределами
            // поддержки (например berry-вариант с непривычной разметкой). Сообщаем
            // честно как о найденном, но не разобранном файле.
            unparsed.push(rel_display(root, path));
            continue;
        }
        deps.extend(parsed.deps);
        unpinned.extend(parsed.unpinned);
    }

    // Дедупликация (экосистема, имя, версия): один и тот же модуль может встречаться
    // в нескольких строках (go.sum) или в нескольких lock-файлах монорепозитория.
    dedup_deps(&mut deps);
    unpinned.sort();
    unpinned.dedup();

    CollectResult {
        deps,
        manifests,
        unpinned,
        unparsed_lockfiles: unparsed,
    }
}

/// Дедупликация списка зависимостей по полному кортежу (экосистема, имя, версия).
/// Несколько РАЗНЫХ версий одного модуля сохраняются, дублируется лишь точное совпадение.
fn dedup_deps(deps: &mut Vec<(&'static str, String, String)>) {
    let mut seen: BTreeSet<(&'static str, String, String)> = BTreeSet::new();
    deps.retain(|d| seen.insert(d.clone()));
}

/// Отобразить путь относительно корня для сводки (без утечки абсолютного пути машины).
fn rel_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// Максимальная глубина обхода дерева. Защищает от патологически глубоких структур и
/// от циклов по символическим ссылкам, оставаясь достаточной для типичных монорепо.
const MAX_DEPTH: usize = 12;

/// Каталоги, которые никогда не обходим: артефакты сборки и кэши менеджеров пакетов.
/// node_modules и target исключаются всегда, даже если в .gitignore их нет.
fn is_excluded_dir(name: &str) -> bool {
    matches!(
        name,
        "node_modules"
            | "target"
            | ".git"
            | "build"
            | "dist"
            | ".gradle"
            | ".venv"
            | "venv"
            | "vendor"
            | ".idea"
            | ".tox"
            | "__pycache__"
            | ".next"
            | ".cargo"
            | "Pods"
    )
}

/// Рекурсивный обход дерева. Уважает простые правила .gitignore (имена и каталоги),
/// пропускает исключённые каталоги и не превышает лимит глубины.
fn walk(
    root: &Path,
    dir: &Path,
    depth: usize,
    gitignore: &GitIgnore,
    out: &mut Vec<(LockKind, PathBuf)>,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        // Символические ссылки не разыменовываем: защита от циклов и выхода за корень.
        if file_type.is_symlink() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if file_type.is_dir() {
            if is_excluded_dir(&name) || gitignore.ignores_dir(root, &path, &name) {
                continue;
            }
            walk(root, &path, depth + 1, gitignore, out);
        } else if file_type.is_file() {
            if gitignore.ignores_file(root, &path, &name) {
                continue;
            }
            if let Some(kind) = LockKind::detect(&name) {
                out.push((kind, path));
            }
        }
    }
}

/// Минималистичный разбор .gitignore корня проекта. Поддерживает наиболее частые
/// формы: имя файла или каталога, шаблон с завершающим слешем (каталог), путь от
/// корня с ведущим слешем. Это сознательно консервативно: цель — не пропустить
/// игнорируемые сборочные артефакты, а не реализовать полную семантику gitignore.
struct GitIgnore {
    /// Точные имена (без слешей), игнорируемые на любом уровне.
    names: Vec<String>,
    /// Имена каталогов (запись со слешем на конце), игнорируемые на любом уровне.
    dir_names: Vec<String>,
    /// Пути, привязанные к корню (запись с ведущим слешем), без учёта завершающего слеша.
    rooted: Vec<String>,
}

impl GitIgnore {
    fn load(root: &Path) -> GitIgnore {
        let mut gi = GitIgnore {
            names: Vec::new(),
            dir_names: Vec::new(),
            rooted: Vec::new(),
        };
        let Ok(txt) = fs::read_to_string(root.join(".gitignore")) else {
            return gi;
        };
        for raw in txt.lines() {
            let line = raw.trim();
            // Пустые строки, комментарии и отрицания (!) пропускаем: отрицание означает
            // «не игнорировать», и его безопасно трактовать как отсутствие правила.
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }
            let line = line.trim_end_matches('/');
            if line.is_empty() {
                continue;
            }
            if let Some(stripped) = raw.trim().strip_prefix('/') {
                gi.rooted.push(stripped.trim_end_matches('/').to_string());
                continue;
            }
            if raw.trim().ends_with('/') {
                gi.dir_names.push(line.to_string());
            } else if line.contains('/') {
                // Путь с внутренним слешем без ведущего: трактуем как привязанный к корню.
                gi.rooted.push(line.to_string());
            } else {
                gi.names.push(line.to_string());
            }
        }
        gi
    }

    fn rel(root: &Path, path: &Path) -> String {
        path.strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    }

    fn ignores_dir(&self, root: &Path, path: &Path, name: &str) -> bool {
        if self.names.iter().any(|n| n.as_str() == name)
            || self.dir_names.iter().any(|n| n.as_str() == name)
        {
            return true;
        }
        let rel = Self::rel(root, path);
        self.rooted.iter().any(|r| r.as_str() == rel)
    }

    fn ignores_file(&self, root: &Path, path: &Path, name: &str) -> bool {
        if self.names.iter().any(|n| n.as_str() == name) {
            return true;
        }
        let rel = Self::rel(root, path);
        self.rooted.iter().any(|r| r.as_str() == rel)
    }
}

/// Разобрать содержимое lock-файла указанного типа.
fn parse_lock(kind: LockKind, txt: &str) -> Parsed {
    match kind {
        LockKind::RequirementsTxt => parse_requirements(txt),
        LockKind::CargoLock => parse_cargo_lock(txt),
        LockKind::PackageLockJson => parse_npm_lock(txt),
        LockKind::YarnLock => parse_yarn_lock(txt),
        LockKind::PnpmLock => parse_pnpm_lock(txt),
        LockKind::GoSum => parse_go_sum(txt),
        LockKind::GradleLockfile => parse_gradle_lockfile(txt),
        LockKind::PubspecLock => parse_pubspec_lock(txt),
        LockKind::PodfileLock => parse_podfile_lock(txt),
        LockKind::PoetryLock => parse_poetry_lock(txt),
        LockKind::PipfileLock => parse_pipfile_lock(txt),
        LockKind::ComposerLock => parse_composer_lock(txt),
        LockKind::GemfileLock => parse_gemfile_lock(txt),
    }
}

pub fn scan(root: &Path) -> OsvReport {
    let collected = collect(root);
    let deps = collected.deps;
    let checked = deps.len();
    let database = db();
    let mut findings = Vec::new();
    let mut suspicious_records: Vec<String> = Vec::new();
    let mut suspicious_seen: BTreeSet<String> = BTreeSet::new();

    // Целостность снимка: если заявленное в метаданных число записей расходится с
    // фактическим, снимок повреждён или правлен вручную неполно. Сообщаем честно.
    if let Some(declared) = database.count_declared {
        if declared != database.vulns.len() {
            suspicious_records.push(format!(
                "снимок базы: заявлено {declared} записей, фактически {} — снимок повреждён или неполон",
                database.vulns.len()
            ));
        }
    }

    for (eco, name, ver) in &deps {
        for v in &database.vulns {
            if !v.ecosystem.eq_ignore_ascii_case(eco) || !v.package.eq_ignore_ascii_case(name) {
                continue;
            }
            match affected(ver, v) {
                AffectMatch::Yes => {
                    findings.push(Finding {
                        rule: "vulnerable-dependency".into(),
                        severity: sev(&v.severity),
                        message: format!(
                            "{name}@{ver} уязвим ({}): {} — обнови до {}",
                            v.id,
                            v.summary,
                            v.fixed.as_deref().unwrap_or("исправленной версии")
                        ),
                        location: None,
                        evidence: Some(format!("{eco}:{name}@{ver}")),
                        verified: true,
                        source: "security.scan/deps".into(),
                    });
                }
                AffectMatch::Suspicious => {
                    // Запись снимка без обеих границ нельзя применять: иначе пакет
                    // вечно-уязвим при любой версии. Не глушим молча, а эскалируем как
                    // подозрительную запись базы и сообщаем о ней один раз.
                    if suspicious_seen.insert(v.id.clone()) {
                        suspicious_records.push(format!(
                            "{} ({}:{}) — запись снимка без introduced и fixed, пропущена",
                            v.id, v.ecosystem, v.package
                        ));
                    }
                }
                AffectMatch::Uncomparable => {
                    // Версия не сравнима по семантике (например, Go-псевдоверсия или
                    // нечисловой суффикс): не глушим находку молча, а сообщаем как
                    // недостоверную, чтобы человек проверил вручную.
                    findings.push(Finding {
                        rule: "vulnerable-dependency-uncertain".into(),
                        severity: sev(&v.severity),
                        message: format!(
                            "{name}@{ver} возможно уязвим ({}): {} — версия не сравнима с диапазоном автоматически, проверьте вручную",
                            v.id, v.summary
                        ),
                        location: None,
                        evidence: Some(format!("{eco}:{name}@{ver}")),
                        verified: false,
                        source: "security.scan/deps".into(),
                    });
                }
                AffectMatch::No => {}
            }
        }
    }

    // Честность покрытия на уровне ЭКОСИСТЕМЫ (сохранена прежняя семантика поля
    // uncovered ради совместимости): если зависимости экосистемы разобраны, а в снимке
    // базы по ней ноль записей, «0 уязвимостей» это не «чисто», а «база не покрывает».
    let mut uncovered: Vec<&'static str> = Vec::new();
    for eco in [
        "PyPI",
        "crates.io",
        "npm",
        "Go",
        "Maven",
        "Pub",
        "CocoaPods",
        "Packagist",
        "RubyGems",
    ] {
        let present = deps.iter().any(|(e, _, _)| *e == eco);
        let in_db = database
            .vulns
            .iter()
            .any(|v| v.ecosystem.eq_ignore_ascii_case(eco));
        if present && !in_db {
            uncovered.push(eco);
        }
    }

    // Честность покрытия на уровне ПАКЕТА: даже в покрытой экосистеме конкретный
    // пакет может отсутствовать в базе. Считаем его непокрытым и отражаем долю реально
    // сверённых зависимостей через covered.
    let mut uncovered_packages: Vec<(&'static str, String)> = Vec::new();
    let mut covered = 0usize;
    for (eco, name, _ver) in &deps {
        let in_db = database
            .vulns
            .iter()
            .any(|v| v.ecosystem.eq_ignore_ascii_case(eco) && v.package.eq_ignore_ascii_case(name));
        if in_db {
            covered += 1;
        } else {
            uncovered_packages.push((*eco, name.clone()));
        }
    }
    uncovered_packages.sort();
    uncovered_packages.dedup();

    OsvReport {
        findings,
        checked,
        manifests: collected.manifests,
        uncovered,
        uncovered_packages,
        covered,
        unparsed_lockfiles: collected.unparsed_lockfiles,
        db_loaded: database.loaded,
        db_generated_at: database.generated_at.clone(),
        suspicious_records,
        unverifiable: collected.unpinned,
    }
}

// ───────────────────────── Парсеры lock-файлов ─────────────────────────

/// PyPI requirements.txt. Извлекает имя для КАЖДОЙ строки; точные пины `name==version`
/// сверяются, а непиновые строки (диапазоны >=, ~=, <, маркеры окружения, vcs-ссылки)
/// помечаются непроверяемыми. Суффикс extras в квадратных скобках срезается, чтобы
/// `requests[security]==2.19.0` совпало с `requests` в снимке. Включения `-r`/`--requirement`
/// и `-c`/`--constraint` отмечаются, но сами файлы рекурсивно подбираются обходом дерева
/// по имени requirements*.txt, поэтому здесь достаточно не терять имя зависимости.
fn parse_requirements(txt: &str) -> Parsed {
    let mut p = Parsed::new();
    for raw in txt.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        // Включения других файлов: реальные файлы подберёт обход дерева, здесь пропускаем.
        if line.starts_with("-r")
            || line.starts_with("--requirement")
            || line.starts_with("-c")
            || line.starts_with("--constraint")
            || line.starts_with("-e")
            || line.starts_with("--editable")
            || line.starts_with("--")
        {
            continue;
        }
        // vcs-ссылки и прямые URL: версия не зафиксирована точно.
        if line.contains("://") {
            continue;
        }
        // Отрезаем маркеры окружения (после ';') и хеши (' --hash').
        let core = line.split(';').next().unwrap_or(line).trim();
        let core = core.split(" --hash").next().unwrap_or(core).trim();
        if let Some((name, ver)) = core.split_once("==") {
            let name = normalize_py_name(name);
            let ver = ver
                .trim()
                .trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '!' && c != '+');
            if !name.is_empty() && !ver.is_empty() {
                p.deps.push(("PyPI", name, ver.to_string()));
                continue;
            }
        }
        // Непиновая строка: вытаскиваем только имя и помечаем непроверяемым.
        let name = normalize_py_name(core);
        if !name.is_empty() && name.chars().next().is_some_and(|c| c.is_alphanumeric()) {
            p.unpinned.push(("PyPI", name));
        }
    }
    p
}

/// Нормализация имени Python-пакета: срезаем extras в квадратных скобках и любые
/// операторы версии, нижний регистр. `requests[security]>=2.0` ведёт к `requests`.
fn normalize_py_name(raw: &str) -> String {
    let s = raw.trim();
    // Имя заканчивается перед первым из: '[', оператором сравнения, пробелом.
    let end = s
        .find(|c: char| {
            c == '[' || c == '=' || c == '<' || c == '>' || c == '~' || c == '!' || c.is_whitespace()
        })
        .unwrap_or(s.len());
    s[..end].trim().to_lowercase()
}

/// crates.io Cargo.lock (TOML): массив таблиц [[package]].
fn parse_cargo_lock(txt: &str) -> Parsed {
    let mut p = Parsed::new();
    if let Ok(val) = txt.parse::<toml::Value>() {
        if let Some(pkgs) = val.get("package").and_then(toml::Value::as_array) {
            for pkg in pkgs {
                if let (Some(n), Some(v)) = (
                    pkg.get("name").and_then(toml::Value::as_str),
                    pkg.get("version").and_then(toml::Value::as_str),
                ) {
                    p.deps.push(("crates.io", n.to_string(), v.to_string()));
                }
            }
        }
    }
    p
}

/// npm package-lock.json. Версию формата определяем по наличию блока `packages`:
/// при lockfileVersion 2 и 3 присутствуют ОБА блока (packages и dependencies), и чтение
/// обоих удваивало бы зависимости. Поэтому при наличии `packages` читаем ТОЛЬКО его,
/// иначе (v1) читаем `dependencies`. Scoped-имена `@scope/pkg` сохраняются целиком.
fn parse_npm_lock(txt: &str) -> Parsed {
    let mut p = Parsed::new();
    let Ok(val): Result<serde_json::Value, _> = serde_json::from_str(txt) else {
        return p;
    };
    if let Some(pkgs) = val.get("packages").and_then(serde_json::Value::as_object) {
        // lockfile v2/v3: { "packages": { "node_modules/lodash": { "version": ".." } } }.
        for (path, meta) in pkgs {
            // Корневой пакет имеет пустой ключ "" — это сам проект, не зависимость.
            if path.is_empty() {
                continue;
            }
            let name = path.rsplit("node_modules/").next().unwrap_or("");
            if name.is_empty() {
                continue;
            }
            if let Some(v) = meta.get("version").and_then(serde_json::Value::as_str) {
                p.deps.push(("npm", name.to_lowercase(), v.to_string()));
            }
        }
        return p;
    }
    // lockfile v1: { "dependencies": { "lodash": { "version": ".." } } }.
    if let Some(d) = val.get("dependencies").and_then(serde_json::Value::as_object) {
        collect_npm_v1(d, &mut p.deps);
    }
    p
}

/// Рекурсивно собрать зависимости из дерева v1 (поле dependencies может быть вложенным).
fn collect_npm_v1(
    obj: &serde_json::Map<String, serde_json::Value>,
    deps: &mut Vec<(&'static str, String, String)>,
) {
    for (name, meta) in obj {
        if let Some(v) = meta.get("version").and_then(serde_json::Value::as_str) {
            deps.push(("npm", name.to_lowercase(), v.to_string()));
        }
        if let Some(nested) = meta.get("dependencies").and_then(serde_json::Value::as_object) {
            collect_npm_v1(nested, deps);
        }
    }
}

/// yarn.lock. Поддерживает классический формат v1 (заголовок `name@range:` затем
/// `  version "x.y.z"`) и формат berry/v2 (заголовок в кавычках, `version: x.y.z`).
/// Имя извлекается из заголовка: до последнего символа '@', при этом ведущий '@'
/// scoped-имени сохраняется (`"@babel/core@^7.0.0":` ведёт к `@babel/core`).
fn parse_yarn_lock(txt: &str) -> Parsed {
    let mut p = Parsed::new();
    let mut current: Option<String> = None;
    for raw in txt.lines() {
        if raw.trim_start().starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        let trimmed = raw.trim();
        if indent == 0 && trimmed.ends_with(':') && !trimmed.is_empty() {
            // Строка-заголовок: один или несколько спецификаторов через запятую.
            let header = trimmed.trim_end_matches(':');
            // Берём первый спецификатор до запятой.
            let first = header.split(',').next().unwrap_or(header).trim();
            let first = first.trim_matches('"');
            current = yarn_name_from_spec(first);
        } else if indent > 0 {
            let t = trimmed;
            // berry: `version: 1.2.3`; v1: `version "1.2.3"`.
            let ver = t
                .strip_prefix("version:")
                .or_else(|| t.strip_prefix("version "))
                .map(|s| s.trim().trim_matches('"').to_string());
            if let (Some(name), Some(v)) = (&current, ver) {
                if !v.is_empty() {
                    p.deps.push(("npm", name.clone(), v));
                    current = None;
                }
            }
        }
    }
    p
}

/// Извлечь имя пакета из yarn-спецификатора `name@range`. Сохраняет ведущий '@'
/// у scoped-имён: для `@babel/core@^7.0.0` имя `@babel/core`, для `lodash@^4.0.0` — `lodash`.
fn yarn_name_from_spec(spec: &str) -> Option<String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    // Для scoped-имени первый '@' это часть имени; ищем разделитель после позиции 1.
    let search_from = usize::from(spec.starts_with('@'));
    let at = spec[search_from..].find('@').map(|i| i + search_from);
    let name = match at {
        Some(pos) => &spec[..pos],
        None => spec,
    };
    let name = name.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_lowercase())
    }
}

/// pnpm-lock.yaml. Версии берём из секции `packages:`, где ключи имеют вид
/// `/name/1.2.3` (lockfile v5/v6) или `/name@1.2.3` (lockfile v9), в том числе со
/// scoped-именами `/@scope/name@1.2.3`. Разбор отступов простой и не требует YAML-движка.
fn parse_pnpm_lock(txt: &str) -> Parsed {
    let mut p = Parsed::new();
    let mut in_packages = false;
    for raw in txt.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent == 0 {
            in_packages = trimmed == "packages:";
            continue;
        }
        if !in_packages {
            continue;
        }
        // Ключи пакетов идут с отступом 2 и заканчиваются на ':'. Содержимое записи
        // (resolution, dependencies и т. п.) имеет отступ глубже и здесь не нужно.
        if indent == 2 && trimmed.ends_with(':') {
            let key = trimmed.trim_end_matches(':').trim_matches('\'').trim_matches('"');
            if let Some((name, ver)) = pnpm_split_key(key) {
                p.deps.push(("npm", name, ver));
            }
        }
    }
    p
}

/// Разобрать ключ записи pnpm в (имя, версия). Поддерживает оба разделителя версии:
/// '@' (v9: `@scope/name@1.2.3` или `name@1.2.3`) и '/' (v5/v6: `/name/1.2.3`).
fn pnpm_split_key(key: &str) -> Option<(String, String)> {
    let key = key.trim_start_matches('/');
    if key.is_empty() {
        return None;
    }
    // Отрезаем хвост вида `(peer)` после версии, если он есть.
    let key = key.split('(').next().unwrap_or(key);
    // Сначала пробуем формат v9 с разделителем '@' (но не ведущий '@' scoped-имени).
    let search_from = usize::from(key.starts_with('@'));
    if let Some(rel) = key[search_from..].find('@') {
        let at = rel + search_from;
        let name = key[..at].trim().to_lowercase();
        let ver = key[at + 1..].trim();
        if !name.is_empty() && ver.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return Some((name, ver.to_string()));
        }
    }
    // Формат v5/v6: последний сегмент после '/' это версия.
    if let Some(slash) = key.rfind('/') {
        let name = key[..slash].trim().to_lowercase();
        let ver = key[slash + 1..].trim();
        if !name.is_empty() && ver.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return Some((name, ver.to_string()));
        }
    }
    None
}

/// Go go.sum (`module v1.2.3 h1:…`). Строки `…/go.mod` это хеши манифестов, пропускаем.
/// Дедупликация выполняется централизованно в collect, здесь лишь извлекаем записи.
fn parse_go_sum(txt: &str) -> Parsed {
    let mut p = Parsed::new();
    for line in txt.lines() {
        let mut it = line.split_whitespace();
        if let (Some(name), Some(ver)) = (it.next(), it.next()) {
            if ver.ends_with("/go.mod") {
                continue;
            }
            if let Some(v) = ver.strip_prefix('v') {
                p.deps.push(("Go", name.to_string(), v.to_string()));
            }
        }
    }
    p
}

/// Maven/Gradle gradle.lockfile (`group:artifact:version=конфигурации`). Поддерживает
/// и трёхчастные координаты `group:artifact:version`, и четырёхчастные с классификатором
/// `group:artifact:classifier:version`, в которых версия это последний компонент.
fn parse_gradle_lockfile(txt: &str) -> Parsed {
    let mut p = Parsed::new();
    for line in txt.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        let coord = line.split('=').next().unwrap_or("").trim();
        if coord.is_empty() {
            continue;
        }
        let parts: Vec<&str> = coord.split(':').collect();
        match parts.as_slice() {
            [group, artifact, version] => {
                p.deps.push((
                    "Maven",
                    format!("{group}:{artifact}").to_lowercase(),
                    (*version).to_string(),
                ));
            }
            [group, artifact, _classifier, version] => {
                // Четырёхкомпонентная координата: версия это последний элемент.
                p.deps.push((
                    "Maven",
                    format!("{group}:{artifact}").to_lowercase(),
                    (*version).to_string(),
                ));
            }
            _ => {}
        }
    }
    p
}

/// Pub (Flutter/Dart) pubspec.lock (YAML): имя пакета на отступе 2, version глубже.
fn parse_pubspec_lock(txt: &str) -> Parsed {
    let mut p = Parsed::new();
    let mut current: Option<String> = None;
    for line in txt.lines() {
        let indent = line.len() - line.trim_start().len();
        let t = line.trim();
        if indent == 2 && t.ends_with(':') && !t.starts_with('#') {
            current = Some(t.trim_end_matches(':').to_lowercase());
        } else if indent >= 4 {
            if let (Some(name), Some(v)) = (&current, t.strip_prefix("version:")) {
                p.deps
                    .push(("Pub", name.clone(), v.trim().trim_matches('"').to_string()));
            }
        }
    }
    p
}

/// CocoaPods Podfile.lock (секция PODS: `  - Name (1.2.3)`).
fn parse_podfile_lock(txt: &str) -> Parsed {
    let mut p = Parsed::new();
    let mut in_pods = false;
    for line in txt.lines() {
        if line.starts_with("PODS:") {
            in_pods = true;
            continue;
        }
        if !line.starts_with(' ') && line.trim_end().ends_with(':') {
            in_pods = false;
        }
        if !in_pods {
            continue;
        }
        // Только верхний уровень `  - Name (1.2.3)`; вложенные зависимости глубже и несут
        // диапазоны (`(= 1.2.3)`), а не фактические версии.
        if let Some(rest) = line.strip_prefix("  - ") {
            if let Some((name, tail)) = rest.split_once(" (") {
                let ver = tail.trim_end().trim_end_matches(':').trim_end_matches(')');
                if ver.starts_with(|c: char| c.is_ascii_digit()) {
                    p.deps.push(("CocoaPods", name.to_lowercase(), ver.to_string()));
                }
            }
        }
    }
    p
}

/// Poetry poetry.lock (TOML): массив таблиц [[package]] с полями name и version.
fn parse_poetry_lock(txt: &str) -> Parsed {
    let mut p = Parsed::new();
    if let Ok(val) = txt.parse::<toml::Value>() {
        if let Some(pkgs) = val.get("package").and_then(toml::Value::as_array) {
            for pkg in pkgs {
                if let (Some(n), Some(v)) = (
                    pkg.get("name").and_then(toml::Value::as_str),
                    pkg.get("version").and_then(toml::Value::as_str),
                ) {
                    p.deps.push(("PyPI", n.to_lowercase(), v.to_string()));
                }
            }
        }
    }
    p
}

/// Pipenv Pipfile.lock (JSON): секции `default` и `develop`, значения с полем version
/// вида `==1.2.3`. Извлекаем имя и точную версию, отбрасывая ведущий оператор `==`.
fn parse_pipfile_lock(txt: &str) -> Parsed {
    let mut p = Parsed::new();
    let Ok(val): Result<serde_json::Value, _> = serde_json::from_str(txt) else {
        return p;
    };
    for section in ["default", "develop"] {
        if let Some(obj) = val.get(section).and_then(serde_json::Value::as_object) {
            for (name, meta) in obj {
                if let Some(ver) = meta.get("version").and_then(serde_json::Value::as_str) {
                    let ver = ver.trim_start_matches("==").trim();
                    if !ver.is_empty() && ver.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                        p.deps.push(("PyPI", name.to_lowercase(), ver.to_string()));
                    } else {
                        // Версия задана диапазоном или vcs-ссылкой: непроверяема.
                        p.unpinned.push(("PyPI", name.to_lowercase()));
                    }
                } else {
                    p.unpinned.push(("PyPI", name.to_lowercase()));
                }
            }
        }
    }
    p
}

/// Composer composer.lock (JSON): массивы `packages` и `packages-dev`, элементы с
/// полями name (`vendor/lib`) и version (часто с префиксом `v`).
fn parse_composer_lock(txt: &str) -> Parsed {
    let mut p = Parsed::new();
    let Ok(val): Result<serde_json::Value, _> = serde_json::from_str(txt) else {
        return p;
    };
    for section in ["packages", "packages-dev"] {
        if let Some(arr) = val.get(section).and_then(serde_json::Value::as_array) {
            for pkg in arr {
                if let (Some(name), Some(ver)) = (
                    pkg.get("name").and_then(serde_json::Value::as_str),
                    pkg.get("version").and_then(serde_json::Value::as_str),
                ) {
                    let ver = ver.trim_start_matches('v').trim();
                    p.deps
                        .push(("Packagist", name.to_lowercase(), ver.to_string()));
                }
            }
        }
    }
    p
}

/// Bundler Gemfile.lock. Зависимости перечислены в секции GEM под `  specs:`, каждая
/// строка вида `    name (1.2.3)`. Транзитивные зависимости идут с большим отступом и
/// без скобок с версией, поэтому версия берётся только из строк со скобкой.
fn parse_gemfile_lock(txt: &str) -> Parsed {
    let mut p = Parsed::new();
    let mut in_specs = false;
    for line in txt.lines() {
        let trimmed = line.trim_end();
        // Начало секции спецификаций.
        if trimmed.trim() == "specs:" {
            in_specs = true;
            continue;
        }
        // Новая секция верхнего уровня (например PLATFORMS, DEPENDENCIES) завершает specs.
        if !line.starts_with(' ') && !trimmed.is_empty() {
            in_specs = false;
        }
        if !in_specs {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        // Прямые гемы идут с отступом 4; их зависимости глубже (отступ 6) и без версии.
        if indent == 4 {
            let t = line.trim();
            if let Some((name, tail)) = t.split_once(" (") {
                let ver = tail.trim_end_matches(')').trim();
                if ver.starts_with(|c: char| c.is_ascii_digit()) {
                    p.deps
                        .push(("RubyGems", name.to_lowercase(), ver.to_string()));
                }
            }
        }
    }
    p
}

// ───────────────────────── Сравнение версий и попадание в диапазон ─────────────────────────

/// Результат проверки попадания версии в уязвимый диапазон.
enum AffectMatch {
    /// Версия точно в уязвимом диапазоне.
    Yes,
    /// Версия точно вне диапазона.
    No,
    /// Запись снимка некорректна (нет ни introduced, ни fixed): не применяется.
    Suspicious,
    /// Версию нельзя надёжно сравнить (Go-псевдоверсия, нечисловая схема): эскалируем.
    Uncomparable,
}

/// Версия попадает в уязвимый диапазон, если introduced <= ver < fixed. Сравнение
/// зависит от экосистемы и корректно учитывает pre-release и epoch.
fn affected(ver: &str, v: &Vuln) -> AffectMatch {
    // T56: запись без обеих границ нельзя применять, иначе пакет вечно-уязвим.
    if v.introduced.is_none() && v.fixed.is_none() {
        return AffectMatch::Suspicious;
    }
    let eco = Ecosystem::of(&v.ecosystem);
    // Go-псевдоверсии и иные несравнимые формы версии проверяемого пакета: эскалируем,
    // а не глушим молча. Границы диапазона в снимке ведём в нормальной форме, поэтому
    // несравнимость проверяем по самой версии пакета.
    if eco == Ecosystem::Go && is_go_pseudo_version(ver) {
        return AffectMatch::Uncomparable;
    }
    let intro = v.introduced.as_deref().unwrap_or("0");
    if cmp_ver(ver, intro, eco) == Ordering::Less {
        return AffectMatch::No;
    }
    match v.fixed.as_deref() {
        Some(fixed) => {
            if cmp_ver(ver, fixed, eco) == Ordering::Less {
                AffectMatch::Yes
            } else {
                AffectMatch::No
            }
        }
        // Есть introduced, но нет fixed: уязвимы все версии начиная с introduced.
        None => AffectMatch::Yes,
    }
}

/// Экосистема для выбора правил сравнения версий.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ecosystem {
    /// PEP 440: epoch перед '!', pre-release строго меньше релиза.
    PyPI,
    /// semver: pre-release строго меньше одноимённого релиза.
    Semver,
    /// Go: распознаём псевдоверсии.
    Go,
    /// Прочее: числовое сравнение с понижением pre-release.
    Other,
}

impl Ecosystem {
    fn of(name: &str) -> Ecosystem {
        if name.eq_ignore_ascii_case("PyPI") {
            Ecosystem::PyPI
        } else if name.eq_ignore_ascii_case("npm") || name.eq_ignore_ascii_case("crates.io") {
            Ecosystem::Semver
        } else if name.eq_ignore_ascii_case("Go") {
            Ecosystem::Go
        } else {
            Ecosystem::Other
        }
    }
}

/// Go-псевдоверсия: `vX.Y.Z-0.timestamp-hash` или `vX.Y.Z-pre.0.timestamp-hash`, где
/// timestamp это 14-значная отметка даты и времени, а hash это короткий идентификатор
/// коммита. Такие версии нельзя сравнивать с обычными по числам, поэтому помечаем
/// непроверяемыми. Версия передаётся уже без ведущего 'v'.
fn is_go_pseudo_version(ver: &str) -> bool {
    // Признак: наличие сегмента после дефиса, в котором есть 14-значная отметка времени
    // и последующий шестнадцатеричный хеш длиной не менее 12 символов.
    let Some((_, suffix)) = ver.split_once('-') else {
        return false;
    };
    let segments: Vec<&str> = suffix.split('-').collect();
    // Ищем 14-значную числовую отметку и хеш минимум 12 hex-символов далее.
    let has_timestamp = segments.iter().any(|s| {
        let digits: String = s.chars().filter(char::is_ascii_digit).collect();
        digits.len() >= 14
    });
    let has_hash = segments
        .iter()
        .any(|s| s.len() >= 12 && s.chars().all(|c| c.is_ascii_hexdigit()));
    has_timestamp && has_hash
}

/// Сравнение версий с учётом экосистемы. Возвращает порядок a относительно b.
fn cmp_ver(a: &str, b: &str, eco: Ecosystem) -> Ordering {
    match eco {
        Ecosystem::PyPI => cmp_pep440(a, b),
        _ => cmp_semverish(a, b),
    }
}

/// Версия, разобранная на компоненты для сравнения: epoch, числовое ядро (release) и
/// признак/маркер pre-release. Пустой `pre` означает финальный релиз.
struct ParsedVer {
    epoch: u64,
    release: Vec<u64>,
    /// Маркер pre-release для упорядочивания: пустой вектор означает финальный релиз
    /// (который СТАРШЕ любого pre-release с тем же ядром).
    pre: Vec<PreToken>,
}

/// Токен сегмента pre-release: либо число, либо строка (например `rc`, `alpha`).
/// Строки сравниваются лексикографически, число считается младше строки (как в semver,
/// где числовые идентификаторы имеют меньший приоритет, чем алфавитно-цифровые).
#[derive(PartialEq, Eq)]
enum PreToken {
    Num(u64),
    Str(String),
}

impl PartialOrd for PreToken {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PreToken {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (PreToken::Num(a), PreToken::Num(b)) => a.cmp(b),
            (PreToken::Str(a), PreToken::Str(b)) => a.cmp(b),
            // Числовой идентификатор всегда младше алфавитно-цифрового (правило semver).
            (PreToken::Num(_), PreToken::Str(_)) => Ordering::Less,
            (PreToken::Str(_), PreToken::Num(_)) => Ordering::Greater,
        }
    }
}

/// Сравнение двух разобранных версий по правилу: сначала epoch, затем числовое ядро,
/// затем pre-release (финальный релиз старше pre-release при равном ядре).
fn cmp_parsed(a: &ParsedVer, b: &ParsedVer) -> Ordering {
    match a.epoch.cmp(&b.epoch) {
        Ordering::Equal => {}
        other => return other,
    }
    // Сравнение числового ядра покомпонентно с дополнением нулями.
    for i in 0..a.release.len().max(b.release.len()) {
        let x = a.release.get(i).copied().unwrap_or(0);
        let y = b.release.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    // Ядра равны: решает pre-release. Релиз без pre-release СТАРШЕ любого pre-release.
    match (a.pre.is_empty(), b.pre.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater, // a финальный, b pre-release: a старше
        (false, true) => Ordering::Less,    // a pre-release, b финальный: a младше
        (false, false) => {
            for i in 0..a.pre.len().max(b.pre.len()) {
                match (a.pre.get(i), b.pre.get(i)) {
                    (Some(x), Some(y)) => match x.cmp(y) {
                        Ordering::Equal => continue,
                        other => return other,
                    },
                    // Более короткий набор pre-идентификаторов младше при равном префиксе.
                    (Some(_), None) => return Ordering::Greater,
                    (None, Some(_)) => return Ordering::Less,
                    (None, None) => break,
                }
            }
            Ordering::Equal
        }
    }
}

/// Разбить строку pre-release на токены по точкам, число ведёт к Num, иначе Str.
fn pre_tokens(s: &str) -> Vec<PreToken> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split('.')
        .filter(|p| !p.is_empty())
        .map(|p| match p.parse::<u64>() {
            Ok(n) => PreToken::Num(n),
            Err(_) => PreToken::Str(p.to_ascii_lowercase()),
        })
        .collect()
}

/// Разобрать числовое ядро версии: компоненты, разделённые точками, из каждого берутся
/// только ведущие цифры. Например `1.2.3` переходит в `[1, 2, 3]`, а `1.2` в `[1, 2]`.
fn parse_release_core(s: &str) -> Vec<u64> {
    s.split('.')
        .map(|p| {
            p.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse::<u64>()
                .unwrap_or(0)
        })
        .collect()
}

/// Разбор версии в стиле semver (npm, crates.io) и универсального запасного варианта.
/// Ядро до первого '-' или '+', сегмент pre-release после '-' (метаданные сборки после
/// '+' игнорируются как не влияющие на приоритет по semver).
fn parse_semverish(s: &str) -> ParsedVer {
    let s = s.trim().trim_start_matches('v');
    // Метаданные сборки после '+' не влияют на сравнение.
    let s = s.split('+').next().unwrap_or(s);
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, p),
        None => (s, ""),
    };
    ParsedVer {
        epoch: 0,
        release: parse_release_core(core),
        pre: pre_tokens(pre),
    }
}

/// Сравнение в стиле semver с понижением приоритета pre-release.
fn cmp_semverish(a: &str, b: &str) -> Ordering {
    cmp_parsed(&parse_semverish(a), &parse_semverish(b))
}

/// Разбор версии PyPI по упрощённому PEP 440: epoch перед '!', ядро релиза, затем
/// сегмент pre-release. Распознаются формы `1.2.3`, `1!2.3`, `2.15.0rc1`, `2.15.0-rc1`,
/// `1.0a2`, `1.0.dev1`. Post-release (`.postN`) трактуется как старше базового релиза.
fn parse_pep440(s: &str) -> ParsedVer {
    let s = s.trim().to_ascii_lowercase();
    // epoch: число перед '!'.
    let (epoch, rest) = match s.split_once('!') {
        Some((e, r)) => (e.trim().parse::<u64>().unwrap_or(0), r),
        None => (0, s.as_str()),
    };
    // Отделяем сегмент pre/dev/post: ищем первую букву или явный разделитель '-'/'_'.
    // PEP 440 допускает написание без разделителя (2.15.0rc1) и с ним (2.15.0-rc1).
    let split_at = rest
        .char_indices()
        .find(|(_, c)| *c == '-' || *c == '_' || c.is_ascii_alphabetic())
        .map(|(i, _)| i)
        .unwrap_or(rest.len());
    let core = &rest[..split_at];
    let suffix_raw = rest[split_at..].trim_start_matches(['-', '_']);

    // Классификация суффикса PEP 440 по приоритету относительно финального релиза.
    // Порядок возрастания приоритета: dev < a/alpha < b/beta < rc/c < (релиз) < post.
    let pre = classify_pep440_suffix(suffix_raw);

    ParsedVer {
        epoch,
        release: parse_release_core(core),
        pre,
    }
}

/// Преобразовать суффикс PEP 440 в токены pre-release. Возврат пустого вектора означает
/// финальный релиз. Post-release кодируется как «выше релиза» через специальный токен.
fn classify_pep440_suffix(suffix: &str) -> Vec<PreToken> {
    if suffix.is_empty() {
        return Vec::new();
    }
    // Числовой ранг стадии PEP 440 по возрастанию приоритета. Финальный релиз
    // кодируется пустым pre (см. cmp_parsed) и стоит между rc (ранг 3) и post (ранг 5).
    // Значение 4 зарезервировано как «нераспознанная стадия» и обрабатывается отдельно.
    let (stage_name, num_part) = split_alpha_num(suffix);
    let (rank, num): (u64, u64) = match stage_name.as_str() {
        "dev" => (0, num_part),
        "a" | "alpha" => (1, num_part),
        "b" | "beta" => (2, num_part),
        "rc" | "c" | "pre" | "preview" => (3, num_part),
        // post и rev это пост-релиз: СТАРШЕ финального релиза (обрабатывается в cmp_pep440).
        "post" | "rev" | "r" => (5, num_part),
        // Нераспознанный суффикс.
        _ => (4, num_part),
    };
    if rank == 4 {
        // Нераспознанная стадия: считаем pre-release с её именем, чтобы НЕ завысить версию
        // (неизвестный суффикс безопаснее трактовать как «младше релиза»).
        return vec![PreToken::Str(stage_name), PreToken::Num(num)];
    }
    vec![PreToken::Num(rank), PreToken::Num(num)]
}

/// Разбить суффикс на алфавитную стадию и числовую часть: `rc1` ведёт к ("rc", 1),
/// `dev` ведёт к ("dev", 0), `post2` ведёт к ("post", 2).
fn split_alpha_num(s: &str) -> (String, u64) {
    let alpha: String = s.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
    let rest: String = s.chars().skip_while(|c| c.is_ascii_alphabetic()).collect();
    let num = rest
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>()
        .parse::<u64>()
        .unwrap_or(0);
    (alpha, num)
}

/// Сравнение версий PyPI по PEP 440. Post-release обрабатывается особо: при равном ядре
/// версия с post-суффиксом старше финального релиза.
fn cmp_pep440(a: &str, b: &str) -> Ordering {
    let pa = parse_pep440(a);
    let pb = parse_pep440(b);
    // Особый случай post-release: pre кодирован как [Num(5), Num(n)]; такая версия должна
    // быть СТАРШЕ финального релиза (пустой pre) при равном ядре. cmp_parsed по умолчанию
    // считает непустой pre младше пустого, поэтому post обрабатываем явно.
    let post_rank = |pv: &ParsedVer| -> Option<u64> {
        match pv.pre.first() {
            Some(PreToken::Num(5)) => pv.pre.get(1).map(|t| match t {
                PreToken::Num(n) => *n,
                PreToken::Str(_) => 0,
            }),
            _ => None,
        }
    };
    match (post_rank(&pa), post_rank(&pb)) {
        // Оба post либо оба не-post: обычное сравнение разобранных версий.
        (Some(_), Some(_)) | (None, None) => cmp_parsed(&pa, &pb),
        // a это post, b нет: при равном ядре post старше любого не-post (релиза или pre).
        (Some(_), None) => match cmp_core_only(&pa, &pb) {
            Ordering::Equal => Ordering::Greater,
            other => other,
        },
        // b это post, a нет: симметрично.
        (None, Some(_)) => match cmp_core_only(&pa, &pb) {
            Ordering::Equal => Ordering::Less,
            other => other,
        },
    }
}

/// Сравнить только epoch и числовое ядро, без учёта pre-release.
fn cmp_core_only(a: &ParsedVer, b: &ParsedVer) -> Ordering {
    match a.epoch.cmp(&b.epoch) {
        Ordering::Equal => {}
        other => return other,
    }
    for i in 0..a.release.len().max(b.release.len()) {
        let x = a.release.get(i).copied().unwrap_or(0);
        let y = b.release.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

fn sev(s: &str) -> Severity {
    match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" | "MODERATE" => Severity::Medium,
        // LOW и любое нераспознанное значение трактуем как низкую важность.
        _ => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ───────── Снимок базы (T52, T56) ─────────

    #[test]
    fn snapshot_loads_and_is_nonempty() {
        // Встроенный снимок обязан загружаться, иначе вердикт «уязвимостей нет» ложен.
        let d = db();
        assert!(d.loaded, "снимок базы должен успешно загружаться");
        assert!(!d.vulns.is_empty(), "снимок не должен быть пуст");
        assert!(d.generated_at.is_some(), "у снимка должна быть дата сборки");
    }

    #[test]
    fn snapshot_count_matches_declared() {
        // Заявленное в метаданных число записей должно совпадать с фактическим.
        let snap: Snapshot =
            serde_json::from_str(include_str!("../../assets/osv/snapshot.json")).unwrap();
        if let Some(count) = snap.count {
            assert_eq!(count, snap.vulns.len(), "count в снимке рассинхронизирован");
        }
    }

    #[test]
    fn load_db_supports_bare_array() {
        // Устаревший формат «голый массив» обязан поддерживаться для совместимости.
        let raw = r#"[{"id":"X","ecosystem":"npm","package":"lodash","fixed":"1.0.0","severity":"HIGH","summary":"s"}]"#;
        let d = load_db(raw);
        assert!(d.loaded);
        assert_eq!(d.vulns.len(), 1);
    }

    #[test]
    fn load_db_marks_broken_as_not_loaded() {
        // Битый JSON ведёт к db_loaded=false, а не к тихому пустому вектору.
        let d = load_db("{ это не json");
        assert!(!d.loaded, "битый снимок должен помечаться как не загруженный");
        assert!(d.vulns.is_empty());
        let d2 = load_db("[]");
        assert!(!d2.loaded, "пустой массив это не рабочая база");
    }

    #[test]
    fn affected_suspicious_record_not_applied() {
        // T56: запись без introduced и без fixed это подозрительная запись, не уязвимость.
        let v = Vuln {
            id: "BAD".into(),
            ecosystem: "npm".into(),
            package: "foo".into(),
            introduced: None,
            fixed: None,
            severity: "HIGH".into(),
            summary: "опечатка снимка".into(),
        };
        assert!(matches!(affected("1.0.0", &v), AffectMatch::Suspicious));
    }

    #[test]
    fn affected_open_range_without_fixed_is_yes() {
        // Есть introduced, нет fixed: уязвимы все версии начиная с introduced.
        let v = Vuln {
            id: "OPEN".into(),
            ecosystem: "npm".into(),
            package: "foo".into(),
            introduced: Some("1.0.0".into()),
            fixed: None,
            severity: "HIGH".into(),
            summary: "без фикса".into(),
        };
        assert!(matches!(affected("1.5.0", &v), AffectMatch::Yes));
        assert!(matches!(affected("0.9.0", &v), AffectMatch::No));
    }

    // ───────── Сравнение версий (T53) ─────────

    #[test]
    fn semver_prerelease_is_lower_than_release() {
        // Эталонный Log4Shell: 2.15.0-rc1 строго МЕНЬШЕ релиза 2.15.0.
        assert_eq!(cmp_semverish("2.15.0-rc1", "2.15.0"), Ordering::Less);
        assert_eq!(cmp_semverish("2.15.0", "2.15.0-rc1"), Ordering::Greater);
        assert_eq!(cmp_semverish("1.0.0-alpha", "1.0.0-beta"), Ordering::Less);
        assert_eq!(cmp_semverish("1.0.0-alpha.1", "1.0.0-alpha.2"), Ordering::Less);
    }

    #[test]
    fn semver_numeric_ordering_holds() {
        assert_eq!(cmp_semverish("1.2.10", "1.2.9"), Ordering::Greater);
        assert_eq!(cmp_semverish("1.2.0", "1.2"), Ordering::Equal);
        assert_eq!(cmp_semverish("1.2.3", "1.2.3"), Ordering::Equal);
    }

    #[test]
    fn semver_build_metadata_ignored() {
        // Метаданные сборки после '+' не влияют на приоритет.
        assert_eq!(cmp_semverish("1.2.3+build5", "1.2.3"), Ordering::Equal);
    }

    #[test]
    fn pep440_epoch_respected() {
        // epoch старше: 1!2.0 строго больше 9.9 без epoch.
        assert_eq!(cmp_pep440("1!2.0", "9.9"), Ordering::Greater);
        assert_eq!(cmp_pep440("2.0", "1!1.0"), Ordering::Less);
    }

    #[test]
    fn pep440_prerelease_lower_than_release() {
        // rc1 без разделителя и с разделителем оба строго меньше релиза.
        assert_eq!(cmp_pep440("2.15.0rc1", "2.15.0"), Ordering::Less);
        assert_eq!(cmp_pep440("2.15.0-rc1", "2.15.0"), Ordering::Less);
        assert_eq!(cmp_pep440("1.0a2", "1.0"), Ordering::Less);
        assert_eq!(cmp_pep440("1.0.dev1", "1.0a1"), Ordering::Less);
    }

    #[test]
    fn pep440_post_release_higher_than_release() {
        // post-release старше базового релиза при равном ядре.
        assert_eq!(cmp_pep440("1.0.post1", "1.0"), Ordering::Greater);
        assert_eq!(cmp_pep440("1.0", "1.0.post1"), Ordering::Less);
    }

    #[test]
    fn go_pseudo_version_detected() {
        // Псевдоверсия Go распознаётся и помечается несравнимой.
        assert!(is_go_pseudo_version("0.0.0-20210101000000-abcdef123456"));
        assert!(is_go_pseudo_version(
            "0.4.1-0.20220101120000-0123456789abcdef"
        ));
        assert!(!is_go_pseudo_version("1.2.3"));
        assert!(!is_go_pseudo_version("1.2.3-rc1"));
    }

    #[test]
    fn go_pseudo_version_escalated_not_silently_skipped() {
        // T53: суффикс-псевдоверсия не глушится, а эскалируется как несравнимая.
        let v = Vuln {
            id: "CVE-2022-32149".into(),
            ecosystem: "Go".into(),
            package: "golang.org/x/text".into(),
            introduced: Some("0".into()),
            fixed: Some("0.3.8".into()),
            severity: "HIGH".into(),
            summary: "DoS".into(),
        };
        assert!(matches!(
            affected("0.0.0-20210101000000-abcdef123456", &v),
            AffectMatch::Uncomparable
        ));
        // Обычная версия сравнивается как и раньше.
        assert!(matches!(affected("0.3.7", &v), AffectMatch::Yes));
        assert!(matches!(affected("0.3.8", &v), AffectMatch::No));
    }

    #[test]
    fn log4shell_rc_now_caught() {
        // Регрессия T53: уязвимый release candidate Log4Shell больше не проскакивает.
        let v = Vuln {
            id: "CVE-2021-44228".into(),
            ecosystem: "Maven".into(),
            package: "org.apache.logging.log4j:log4j-core".into(),
            introduced: Some("2.0".into()),
            fixed: Some("2.15.0".into()),
            severity: "CRITICAL".into(),
            summary: "Log4Shell".into(),
        };
        // 2.15.0-rc1 < 2.15.0 (fixed) и >= 2.0 (introduced): уязвим.
        assert!(matches!(affected("2.15.0-rc1", &v), AffectMatch::Yes));
        // Финальный 2.15.0 это фикс: не уязвим.
        assert!(matches!(affected("2.15.0", &v), AffectMatch::No));
    }

    // ───────── Парсеры lock-файлов (T54, T55) ─────────

    #[test]
    fn requirements_strips_extras_and_marks_unpinned() {
        // T55: extras срезаются, точный пин сверяется, диапазон помечается непроверяемым.
        let p = parse_requirements(
            "requests[security]==2.19.0\njinja2>=2.10\nflask # комментарий\n-r base.txt\n",
        );
        assert!(p
            .deps
            .iter()
            .any(|(e, n, v)| *e == "PyPI" && n == "requests" && v == "2.19.0"));
        assert!(
            p.unpinned.iter().any(|(_, n)| n == "jinja2"),
            "диапазон помечен непроверяемым"
        );
        assert!(
            p.unpinned.iter().any(|(_, n)| n == "flask"),
            "имя без версии помечено непроверяемым"
        );
        // Включение -r не порождает ложного имени.
        assert!(!p.unpinned.iter().any(|(_, n)| n.contains("base")));
    }

    #[test]
    fn npm_v2_no_double_count() {
        // T55: при наличии блока packages блок dependencies не читается (нет дублей).
        let json = r#"{
            "lockfileVersion": 2,
            "packages": {
                "": { "name": "root" },
                "node_modules/lodash": { "version": "4.17.20" },
                "node_modules/@babel/core": { "version": "7.0.0" }
            },
            "dependencies": {
                "lodash": { "version": "4.17.20" },
                "@babel/core": { "version": "7.0.0" }
            }
        }"#;
        let p = parse_npm_lock(json);
        let lodash = p.deps.iter().filter(|(_, n, _)| n == "lodash").count();
        assert_eq!(lodash, 1, "lodash не должен дублироваться при v2");
        assert!(
            p.deps.iter().any(|(_, n, _)| n == "@babel/core"),
            "scoped-имя сохранено целиком"
        );
        // Корневой пакет "" не считается зависимостью.
        assert!(!p.deps.iter().any(|(_, n, _)| n == "root"));
    }

    #[test]
    fn npm_v1_reads_dependencies() {
        let json = r#"{
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": { "version": "4.17.20" }
            }
        }"#;
        let p = parse_npm_lock(json);
        assert!(p.deps.iter().any(|(_, n, v)| n == "lodash" && v == "4.17.20"));
    }

    #[test]
    fn gradle_four_part_coordinate_kept() {
        // T55: координата с классификатором (4 части) не теряется.
        let p = parse_gradle_lockfile(
            "# generated\norg.example:lib:linux-x86_64:1.2.3=runtimeClasspath\norg.example:simple:2.0.0=compileClasspath\n",
        );
        assert!(
            p.deps
                .iter()
                .any(|(_, n, v)| n == "org.example:lib" && v == "1.2.3"),
            "четырёхчастная координата разобрана: {:?}",
            p.deps
        );
        assert!(p
            .deps
            .iter()
            .any(|(_, n, v)| n == "org.example:simple" && v == "2.0.0"));
    }

    #[test]
    fn go_sum_dedups_repeated_module_version() {
        // T55: одна и та же (eco,name,version) не множится; go.mod-строки пропущены.
        let mut deps = parse_go_sum(
            "golang.org/x/text v0.3.7 h1:abc=\ngolang.org/x/text v0.3.7/go.mod h1:def=\ngolang.org/x/text v0.3.7 h1:abc=\n",
        )
        .deps;
        dedup_deps(&mut deps);
        let count = deps
            .iter()
            .filter(|(_, n, v)| n == "golang.org/x/text" && v == "0.3.7")
            .count();
        assert_eq!(count, 1, "повтор одной версии схлопнут");
    }

    #[test]
    fn yarn_v1_and_berry_parsed() {
        // T54: оба формата yarn.lock разбираются, scoped-имя сохранено.
        let v1 = "lodash@^4.0.0:\n  version \"4.17.20\"\n  resolved \"...\"\n\n\"@babel/core@^7.0.0\":\n  version \"7.1.0\"\n";
        let p = parse_yarn_lock(v1);
        assert!(p.deps.iter().any(|(_, n, v)| n == "lodash" && v == "4.17.20"));
        assert!(p
            .deps
            .iter()
            .any(|(_, n, v)| n == "@babel/core" && v == "7.1.0"));

        let berry = "\"lodash@npm:^4.0.0\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n";
        let pb = parse_yarn_lock(berry);
        assert!(
            pb.deps.iter().any(|(_, n, v)| n == "lodash" && v == "4.17.21"),
            "berry-формат разобран: {:?}",
            pb.deps
        );
    }

    #[test]
    fn pnpm_lock_v6_and_v9_keys() {
        // T54: ключи pnpm v5/v6 (`/name/ver`) и v9 (`name@ver`) разбираются.
        let p = parse_pnpm_lock(
            "lockfileVersion: '6.0'\npackages:\n\n  /lodash/4.17.20:\n    resolution: {integrity: sha}\n\n  /@babel/core/7.0.0:\n    resolution: {integrity: sha}\n",
        );
        assert!(
            p.deps.iter().any(|(_, n, v)| n == "lodash" && v == "4.17.20"),
            "v6-ключ разобран: {:?}",
            p.deps
        );
        assert!(p
            .deps
            .iter()
            .any(|(_, n, v)| n == "@babel/core" && v == "7.0.0"));

        let v9 = "lockfileVersion: '9.0'\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha}\n\n  '@babel/core@7.1.0':\n    resolution: {integrity: sha}\n";
        let p9 = parse_pnpm_lock(v9);
        assert!(
            p9.deps.iter().any(|(_, n, v)| n == "lodash" && v == "4.17.21"),
            "v9-ключ разобран: {:?}",
            p9.deps
        );
        assert!(p9
            .deps
            .iter()
            .any(|(_, n, v)| n == "@babel/core" && v == "7.1.0"));
    }

    #[test]
    fn poetry_pipfile_composer_gemfile_parsed() {
        // T54: TOML/JSON/текстовые парсеры новых менеджеров извлекают имя и версию.
        let poetry = "[[package]]\nname = \"requests\"\nversion = \"2.19.0\"\n\n[[package]]\nname = \"jinja2\"\nversion = \"2.11.0\"\n";
        let pp = parse_poetry_lock(poetry);
        assert!(pp.deps.iter().any(|(e, n, v)| *e == "PyPI" && n == "requests" && v == "2.19.0"));

        let pipfile = r#"{"default":{"requests":{"version":"==2.19.0"}},"develop":{"pytest":{"version":"==7.0.0"}}}"#;
        let pf = parse_pipfile_lock(pipfile);
        assert!(pf.deps.iter().any(|(e, n, v)| *e == "PyPI" && n == "requests" && v == "2.19.0"));
        assert!(pf.deps.iter().any(|(_, n, v)| n == "pytest" && v == "7.0.0"));

        let composer = r#"{"packages":[{"name":"guzzlehttp/guzzle","version":"v6.5.5"}],"packages-dev":[{"name":"phpunit/phpunit","version":"9.5.0"}]}"#;
        let pc = parse_composer_lock(composer);
        assert!(pc.deps.iter().any(|(e, n, v)| *e == "Packagist" && n == "guzzlehttp/guzzle" && v == "6.5.5"));
        assert!(pc.deps.iter().any(|(_, n, v)| n == "phpunit/phpunit" && v == "9.5.0"));

        let gemfile = "GEM\n  remote: https://rubygems.org/\n  specs:\n    omniauth (1.9.1)\n    rack (2.2.3)\n      rack-test (>= 0.5)\n\nPLATFORMS\n  ruby\n";
        let pg = parse_gemfile_lock(gemfile);
        assert!(
            pg.deps.iter().any(|(e, n, v)| *e == "RubyGems" && n == "omniauth" && v == "1.9.1"),
            "Gemfile: прямой гем разобран: {:?}",
            pg.deps
        );
        // Транзитивный rack-test (с отступом 6, без скобок версии) не должен попасть как версия.
        assert!(!pg.deps.iter().any(|(_, n, _)| n == "rack-test"));
    }

    #[test]
    fn pipfile_unpinned_marked() {
        // Версия задана не точным пином: помечается непроверяемой.
        let pipfile = r#"{"default":{"flask":{"version":">=2.0"}}}"#;
        let pf = parse_pipfile_lock(pipfile);
        assert!(pf.deps.is_empty());
        assert!(pf.unpinned.iter().any(|(_, n)| n == "flask"));
    }

    #[test]
    fn scan_surfaces_unverifiable_dependencies() {
        // T55: непиновая строка requirements попадает в отчёт как непроверяемая, а не
        // выдаётся за «проверено и чисто».
        use std::fs as f;
        let dir = std::env::temp_dir().join(format!("osv_unv_{}", std::process::id()));
        let _ = f::remove_dir_all(&dir);
        f::create_dir_all(&dir).unwrap();
        f::write(dir.join("requirements.txt"), "requests==2.18.0\njinja2>=2.10\n").unwrap();
        let rep = scan(&dir);
        assert!(
            rep.unverifiable.iter().any(|(e, n)| *e == "PyPI" && n == "jinja2"),
            "диапазон помечен непроверяемым: {:?}",
            rep.unverifiable
        );
        // Точный пин при этом проверен и попал в checked.
        assert_eq!(rep.checked, 1, "проверена только закреплённая версия");
        let _ = f::remove_dir_all(&dir);
    }

    // ───────── Обход дерева монорепозитория (T54) ─────────

    #[test]
    fn monorepo_recursive_walk_finds_nested_lockfiles() {
        use std::fs as f;
        let dir = std::env::temp_dir().join(format!("osv_walk_{}", std::process::id()));
        let _ = f::remove_dir_all(&dir);
        f::create_dir_all(dir.join("packages/api")).unwrap();
        f::create_dir_all(dir.join("services/web")).unwrap();
        f::create_dir_all(dir.join("node_modules/should-skip")).unwrap();
        // Корневой и вложенные lock-файлы.
        f::write(dir.join("requirements.txt"), "requests==2.18.0\n").unwrap();
        f::write(
            dir.join("packages/api/package-lock.json"),
            r#"{"lockfileVersion":2,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#,
        )
        .unwrap();
        f::write(
            dir.join("services/web/yarn.lock"),
            "minimist@^1.0.0:\n  version \"1.2.0\"\n",
        )
        .unwrap();
        // Внутри node_modules не должно сканироваться.
        f::write(
            dir.join("node_modules/should-skip/package-lock.json"),
            r#"{"lockfileVersion":2,"packages":{"node_modules/evil":{"version":"6.6.6"}}}"#,
        )
        .unwrap();

        let (deps, manifests) = packages(&dir);
        assert!(deps.iter().any(|(_, n, _)| n == "requests"), "корневой requirements");
        assert!(deps.iter().any(|(_, n, _)| n == "lodash"), "вложенный package-lock");
        assert!(deps.iter().any(|(_, n, _)| n == "minimist"), "вложенный yarn.lock");
        assert!(!deps.iter().any(|(_, n, _)| n == "evil"), "node_modules исключён");
        assert!(manifests.contains(&"requirements.txt"));
        assert!(manifests.contains(&"yarn.lock"));
        let _ = f::remove_dir_all(&dir);
    }

    #[test]
    fn gitignore_respected_for_directories() {
        use std::fs as f;
        let dir = std::env::temp_dir().join(format!("osv_gi_{}", std::process::id()));
        let _ = f::remove_dir_all(&dir);
        f::create_dir_all(dir.join("ignored_dir")).unwrap();
        f::write(dir.join(".gitignore"), "ignored_dir/\n").unwrap();
        f::write(
            dir.join("ignored_dir/package-lock.json"),
            r#"{"lockfileVersion":2,"packages":{"node_modules/hidden":{"version":"1.0.0"}}}"#,
        )
        .unwrap();
        f::write(dir.join("go.sum"), "example.com/m v1.0.0 h1:x=\n").unwrap();
        let (deps, _m) = packages(&dir);
        assert!(!deps.iter().any(|(_, n, _)| n == "hidden"), ".gitignore уважён");
        assert!(deps.iter().any(|(_, n, _)| n == "example.com/m"));
        let _ = f::remove_dir_all(&dir);
    }

    // ───────── Покрытие на уровне пакета (T52) ─────────

    #[test]
    fn per_package_coverage_reported() {
        use std::fs as f;
        let dir = std::env::temp_dir().join(format!("osv_cov_{}", std::process::id()));
        let _ = f::remove_dir_all(&dir);
        f::create_dir_all(&dir).unwrap();
        // lodash есть в снимке (покрыт), unknownpkg в снимке отсутствует (не покрыт).
        f::write(
            dir.join("package-lock.json"),
            r#"{"lockfileVersion":2,"packages":{"node_modules/lodash":{"version":"4.17.20"},"node_modules/unknownpkg":{"version":"1.0.0"}}}"#,
        )
        .unwrap();
        let rep = scan(&dir);
        assert!(rep.db_loaded, "снимок загружен");
        assert_eq!(rep.checked, 2);
        assert_eq!(rep.covered, 1, "покрыт только lodash");
        assert!(rep
            .uncovered_packages
            .iter()
            .any(|(e, n)| *e == "npm" && n == "unknownpkg"));
        // npm как экосистема покрыта (lodash есть), поэтому в uncovered её нет.
        assert!(!rep.uncovered.contains(&"npm"));
        let _ = f::remove_dir_all(&dir);
    }

    #[test]
    fn unparsed_lockfile_reported_honestly() {
        use std::fs as f;
        let dir = std::env::temp_dir().join(format!("osv_unp_{}", std::process::id()));
        let _ = f::remove_dir_all(&dir);
        f::create_dir_all(&dir).unwrap();
        // composer.lock без распознаваемого содержимого: найден, но не разобран.
        f::write(dir.join("composer.lock"), "{ битый json").unwrap();
        let rep = scan(&dir);
        assert!(
            rep.unparsed_lockfiles.iter().any(|p| p.contains("composer.lock")),
            "необработанный lock-файл честно отражён: {:?}",
            rep.unparsed_lockfiles
        );
        let _ = f::remove_dir_all(&dir);
    }
}
