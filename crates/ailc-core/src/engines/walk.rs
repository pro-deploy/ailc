//! Общий обход дерева исходников — переиспользуется всеми движками,
//! чтобы логика обхода/отсева существовала ровно в одном месте
//! (в ailc она была продублирована в ~35 файлах).

use ailc_contracts::Result;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Верхняя граница размера файла, который имеет смысл читать целиком в память и
/// прогонять по содержимому. Сверхкрупный файл (минифицированный бандл, дамп,
/// словарь токенайзера, медиа) не является исходником, его построчное сканирование
/// бессмысленно и опасно по памяти/процессорному времени. Файлы крупнее этой
/// границы фиксируются поимённо в [`WalkStats`], а не читаются молча.
///
/// Граница совпадает с историческим порогом отсева data-блобов: исходный код по
/// сути никогда не превышает примерно один мегабайт.
pub const MAX_SCAN_BYTES: u64 = 1_000_000;

/// Жёсткий предел глубины рекурсии обхода. Служит дополнительным барьером против
/// патологически глубоких деревьев и против остаточных симлинк-циклов на тот
/// случай, если канонизация пути по каким-либо причинам не сработала (например на
/// сетевой файловой системе). При достижении предела каталог не раскрывается, а
/// факт ограничения фиксируется в [`WalkStats::depth_capped`].
pub const MAX_WALK_DEPTH: usize = 64;

/// Что осталось ВНЕ охвата обхода — для инварианта «нет молчаливых пропусков»:
/// сканер обязан уметь сказать, сколько и почему он не смотрел.
#[derive(Default)]
pub struct WalkStats {
    /// Скрытые файлы/каталоги (имя с точки: .env, .github, …).
    pub hidden: u64,
    /// Служебные каталоги (target, node_modules, vendor, …).
    pub service_dirs: u64,
    /// Крупные data-блобы (> ~1 МБ — бандлы, дампы, словари).
    pub data_blobs: u64,
    /// Пропущенные символические ссылки (на файлы и на каталоги). За симлинки
    /// обход не следует: каталог-симлинк может вести наружу корня (утечка чужих
    /// файлов), а цикл симлинков ведёт к бесконечной рекурсии (см. T41).
    pub symlinks: u64,
    /// Каталоги, повторно встреченные через канонически тот же путь (симлинк-цикл
    /// либо жёсткая ссылка): такой каталог не раскрывается второй раз.
    pub revisited_dirs: u64,
    /// Сколько раз обход упёрся в предел глубины [`MAX_WALK_DEPTH`] и не стал
    /// раскрывать каталог глубже.
    pub depth_capped: u64,
    /// Файлы крупнее [`MAX_SCAN_BYTES`], которые не читались по содержимому.
    /// Хранятся поимённо, чтобы пропуск был не обезличенным числом, а конкретным
    /// перечнем (инвариант «нет молчаливых пропусков», см. T64). Имена берутся как
    /// предоставлены обходом (как правило это абсолютные пути элементов дерева).
    pub oversized_files: Vec<String>,
}

impl WalkStats {
    /// Сколько файлов крупнее [`MAX_SCAN_BYTES`] было пропущено. Совпадает с длиной
    /// [`WalkStats::oversized_files`]; вынесено отдельным методом для читаемости и
    /// для совместимости с историческим именованием.
    pub fn oversized(&self) -> u64 {
        self.oversized_files.len() as u64
    }

    pub fn total(&self) -> u64 {
        self.hidden
            + self.service_dirs
            + self.data_blobs
            + self.symlinks
            + self.revisited_dirs
            + self.depth_capped
            + self.oversized()
    }

    /// Короткая причина пропусков для сводки (пусто, если пропусков нет).
    pub fn note(&self) -> String {
        if self.total() == 0 {
            return String::new();
        }
        let mut parts = Vec::new();
        if self.hidden > 0 {
            parts.push(format!("{} скрытых", self.hidden));
        }
        if self.service_dirs > 0 {
            parts.push(format!("{} служебных каталогов", self.service_dirs));
        }
        if self.data_blobs > 0 {
            parts.push(format!("{} крупных файлов", self.data_blobs));
        }
        if self.oversized() > 0 {
            parts.push(format!("{} сверхкрупных файлов", self.oversized()));
        }
        if self.symlinks > 0 {
            parts.push(format!("{} симлинков", self.symlinks));
        }
        if self.revisited_dirs > 0 {
            parts.push(format!("{} повторных каталогов", self.revisited_dirs));
        }
        if self.depth_capped > 0 {
            parts.push(format!("{} по пределу глубины", self.depth_capped));
        }
        format!("; вне охвата: {}", parts.join(", "))
    }
}

/// Режим обхода. Определяет, как обращаться со скрытыми (с точки) элементами.
///
/// Большинство сканеров кода игнорируют dotfiles осознанно: там лежит служебная
/// инфраструктура (.git, .github, .vscode), а не исходный код. Но секрет-сканер
/// обязан смотреть именно туда, поскольку чаще всего секреты хранятся в скрытых
/// файлах вида `.env`, `.npmrc`, `.aws/credentials` (см. T02). Для этого вводится
/// отдельный режим [`WalkMode::Secrets`], который не отбрасывает dotfiles из
/// allow-list, а передаёт их в обработчик.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum WalkMode {
    /// Обычный обход кода: любой элемент, имя которого начинается с точки,
    /// пропускается целиком и учитывается в [`WalkStats::hidden`].
    #[default]
    Code,
    /// Обход для секрет-сканера: dotfiles и dot-каталоги из allow-list
    /// (см. [`is_secret_dotfile`] и [`is_secret_dotdir`]) не пропускаются, а
    /// читаются/раскрываются. Прочие скрытые элементы по-прежнему отбрасываются
    /// (служебный шум вроде .git/objects не нужен и опасен по объёму).
    Secrets,
}

/// Рекурсивный обход с отсевом служебных каталогов. Кросс-платформенно (std).
///
/// Симлинки не раскрываются и не передаются в обработчик (защита от утечки файлов
/// вне корня и от симлинк-циклов, см. T41). Файлы крупнее [`MAX_SCAN_BYTES`] не
/// передаются в обработчик (см. T64). Все пропуски, если нужно их видеть, доступны
/// через [`walk_stats`].
pub fn walk(dir: &Path, f: &mut dyn FnMut(&Path)) -> Result<()> {
    walk_stats(dir, f, &mut WalkStats::default())
}

/// Обход с учётом пропущенного — позволяет сканерам честно отчитаться,
/// что осталось вне охвата (скрытое, служебное, блобы, симлинки), а не молчать.
///
/// Это обход в режиме [`WalkMode::Code`]. Для секрет-сканера предназначен
/// [`walk_secrets`], который дополнительно заходит в dotfiles из allow-list.
pub fn walk_stats(dir: &Path, f: &mut dyn FnMut(&Path), stats: &mut WalkStats) -> Result<()> {
    walk_mode(dir, WalkMode::Code, f, stats)
}

/// Обход для секрет-сканера: как [`walk_stats`], но не отбрасывает dotfiles и
/// dot-каталоги из секрет-allow-list, а читает/раскрывает их (см. T02). Так
/// `.env`, `.env.production`, `.npmrc`, `.aws/credentials`, `.docker/config.json`
/// и подобные попадают в обработчик и могут быть просканированы на секреты.
pub fn walk_secrets(dir: &Path, f: &mut dyn FnMut(&Path), stats: &mut WalkStats) -> Result<()> {
    walk_mode(dir, WalkMode::Secrets, f, stats)
}

/// Общая реализация обхода с явным режимом и учётом пропущенного. Ведёт набор
/// канонических путей уже посещённых каталогов (защита от симлинк-циклов и
/// жёстких ссылок) и ограничивает глубину рекурсии [`MAX_WALK_DEPTH`].
pub fn walk_mode(
    dir: &Path,
    mode: WalkMode,
    f: &mut dyn FnMut(&Path),
    stats: &mut WalkStats,
) -> Result<()> {
    // Точка входа: одиночный файл явно указан пользователем — отдаём его без
    // отсева (исторический контракт), но симлинк-файл всё равно не следуем,
    // чтобы случайный указатель на чужой файл не привёл к чтению извне корня.
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                stats.symlinks += 1;
                return Ok(());
            }
            if ft.is_file() {
                f(dir);
                return Ok(());
            }
        }
        Err(_) => return Ok(()),
    }
    let mut visited: HashSet<PathBuf> = HashSet::new();
    // Корень тоже фиксируем как посещённый, чтобы симлинк, ведущий обратно в
    // корень, не вызвал повторный заход.
    if let Ok(real) = dir.canonicalize() {
        visited.insert(real);
    }
    walk_inner(dir, mode, f, stats, &mut visited, 0)
}

/// Внутренняя рекурсивная часть обхода. `depth` — текущая глубина (0 на корне),
/// `visited` — набор канонических путей уже раскрытых каталогов.
fn walk_inner(
    dir: &Path,
    mode: WalkMode,
    f: &mut dyn FnMut(&Path),
    stats: &mut WalkStats,
    visited: &mut HashSet<PathBuf>,
    depth: usize,
) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();

        // Тип записи берём БЕЗ следования за симлинком: entry.file_type() (а при
        // его недоступности symlink_metadata) не разыменовывает ссылку, в отличие
        // от is_dir()/is_file(). Это и есть защита от утечки наружу корня и от
        // симлинк-циклов (T41).
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => match fs::symlink_metadata(&path) {
                Ok(m) => m.file_type(),
                Err(_) => continue,
            },
        };

        if file_type.is_symlink() {
            // За симлинками не следуем ни на файлы, ни на каталоги: каталог-симлинк
            // может вести за пределы корня, а цикл симлинков — к бесконечной
            // рекурсии. Фиксируем факт пропуска поимённо в счётчике.
            stats.symlinks += 1;
            continue;
        }

        // Скрытые элементы (имя с точки). В режиме секретов не отбрасываем те, что
        // входят в allow-list секрет-сканера, а читаем/раскрываем их.
        if name.starts_with('.') {
            let is_dir = file_type.is_dir();
            // `.well-known` (RFC 8615) — стандартный ПУБЛИЧНЫЙ каталог: в нём лежат
            // assetlinks.json и apple-app-site-association, на которые есть мобильные
            // правила. Это не служебный dotfile, поэтому заходим в него во всех режимах,
            // иначе эти правила никогда не увидели бы свои целевые файлы.
            let well_known = is_dir && name.as_ref() == ".well-known";
            let allow = well_known
                || match mode {
                    WalkMode::Secrets if is_dir => is_secret_dotdir(name.as_ref()),
                    WalkMode::Secrets => is_secret_dotfile(name.as_ref()),
                    WalkMode::Code => false,
                };
            if !allow {
                stats.hidden += 1;
                continue;
            }
        }

        if matches!(
            name.as_ref(),
            "target" | "node_modules" | "vendor" | "dist" | "build" | "__pycache__"
        ) {
            stats.service_dirs += 1;
            continue;
        }

        if file_type.is_dir() {
            // Предел глубины как жёсткий барьер: даже если канонизация не отсекла
            // цикл, рекурсия не уйдёт глубже фиксированного уровня.
            if depth + 1 > MAX_WALK_DEPTH {
                stats.depth_capped += 1;
                continue;
            }
            // Канонический путь каталога: если он уже посещался, значит мы пришли
            // сюда повторно (симлинк-цикл, жёсткая ссылка, монтирование) — второй
            // раз не раскрываем.
            if let Ok(real) = path.canonicalize() {
                if !visited.insert(real) {
                    stats.revisited_dirs += 1;
                    continue;
                }
            }
            walk_inner(&path, mode, f, stats, visited, depth + 1)?;
        } else if file_type.is_file() {
            // Сверхкрупный файл не читаем по содержимому: фиксируем его поимённо,
            // чтобы пропуск был виден человеку (T64). Историческое отсечение
            // data-блобов сохраняем тем же порогом.
            match fs::metadata(&path) {
                Ok(m) if m.len() > MAX_SCAN_BYTES => {
                    stats.data_blobs += 1;
                    stats
                        .oversized_files
                        .push(path.to_string_lossy().into_owned());
                }
                Ok(_) => f(&path),
                // Размер не удалось узнать (файл исчез/нет прав): не считаем его
                // блобом, отдаём в обработчик — тот сам аккуратно обработает отказ
                // чтения. Это сохраняет прежнее поведение для нечитаемых файлов.
                Err(_) => f(&path),
            }
        }
        // Прочие типы (сокеты, FIFO, устройства) молча пропускаем: читать нечего.
    }
    Ok(())
}

/// Файл — это крупный сгенерированный data-ассет (словарь токенайзера, минифицированный
/// бандл, дамп), а не исходник. Исходный код по сути никогда не превышает ~1 МБ —
/// сканировать такие блобы по содержимому бессмысленно и даёт ложные срабатывания.
/// (Явно указанный одиночный файл не отсеивается — отсев только при обходе дерева.)
pub fn is_data_blob(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.len() > MAX_SCAN_BYTES).unwrap_or(false)
}

/// Имя скрытого ФАЙЛА входит в allow-list секрет-сканера: такие dotfiles чаще всего
/// и содержат секреты, поэтому в режиме [`WalkMode::Secrets`] они не пропускаются.
///
/// Покрываются: семейство `.env` (включая `.env.production`, `.env.local` и т. п.),
/// `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, а также имена `credentials` и
/// `config.json`/`config` (они лежат внутри dot-каталогов `.aws`/`.docker`, и сюда
/// мы попадаем уже спустившись в такой каталог).
pub fn is_secret_dotfile(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == ".env"
        || l.starts_with(".env.")
        || l == ".npmrc"
        || l == ".pypirc"
        || l == ".netrc"
        || l == ".git-credentials"
        || l == ".dockercfg"
        // Файлы внутри .aws / .docker: после спуска в dot-каталог имя уже без точки.
        || l == "credentials"
        || l == "config.json"
        || l == "config"
}

/// Имя скрытого КАТАЛОГА, в который секрет-сканеру нужно зайти: там лежат файлы с
/// учётными данными. Это `.aws` (внутри `credentials`/`config`) и `.docker`
/// (внутри `config.json`). Каталог `.git` сознательно не раскрываем по дереву:
/// его объекты бинарны и огромны, анализ истории — отдельный режим, не обход.
pub fn is_secret_dotdir(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == ".aws" || l == ".docker"
}

/// Расширение файла в нижнем регистре (без точки).
pub fn ext_of(path: &Path) -> &str {
    path.extension().and_then(|e| e.to_str()).unwrap_or("")
}

/// Имя файла (последний сегмент) пути в нижнем регистре. Кросс-платформенно по
/// обоим разделителям.
fn file_name_lower(rel: &str) -> &str {
    rel.rsplit(['/', '\\']).next().unwrap_or(rel)
}

/// Относительный путь похож на тест-файл/фикстуру. Сканеры безопасности и качества
/// их пропускают: тесты легитимно содержат фейк-секреты, фикстуры-уязвимости и
/// допустимые .unwrap()/panic — это не находки прод-кода.
///
/// Критерий СТРОГИЙ и опирается на ИМЯ файла, а не на путь (см. T43). Прежняя
/// реализация срабатывала на любой путь с подстрокой `/tests/` либо на имя,
/// начинающееся с `test_`, из-за чего прод-файл вида `src/integration/tests/handler.go`
/// или `core/test_utils_PRODUCTION.py` ложно исключался из сканеров, что давало
/// управляемый молчаливый пропуск. Теперь тест-файлом считается только файл со
/// строгим тест-суффиксом имени либо файл, лежащий непосредственно в каталоге
/// тестовой раскладки конкретных экосистем.
pub fn is_test_path(rel: &str) -> bool {
    let l = rel.to_ascii_lowercase();
    let name = file_name_lower(&l);

    // Строгие тест-суффиксы ИМЕНИ файла по экосистемам.
    if name.ends_with("_test.go")          // Go
        || name.ends_with("_test.py")      // pytest по суффиксу
        || name.ends_with(".test.ts")      // Jest/Vitest TS
        || name.ends_with(".test.tsx")
        || name.ends_with(".test.js")
        || name.ends_with(".test.jsx")
        || name.ends_with(".spec.ts")
        || name.ends_with(".spec.tsx")
        || name.ends_with(".spec.js")
        || name.ends_with(".spec.jsx")
        || name.ends_with("test.java")     // FooTest.java / FooTests.java
        || name.ends_with("tests.java")
        || name.ends_with("spec.rb")       // RSpec
        || name.ends_with("_spec.rb")
    {
        return true;
    }

    // Имя, НАЧИНАЮЩЕЕСЯ с `test_` — но только у файлов исходного кода, у которых
    // этот префикс действительно обозначает тест (pytest, gtest). Прежняя широкая
    // проверка срабатывала на любое имя с таким префиксом, из-за чего конфиг или
    // секрет вида `test_secrets.yaml`/`test_keys.txt` молча выпадал из сканера.
    // Теперь префикс `test_` остаётся легитимным маркером теста лишь для исходных
    // расширений, а не для произвольных файлов конфигурации или секретов.
    if name.starts_with("test_") {
        if let Some(ext) = name.rsplit('.').next() {
            if matches!(ext, "py" | "go" | "rs" | "cc" | "cpp" | "c") {
                return true;
            }
        }
    }

    // Rust: интеграционные тесты Cargo живут в каталоге `tests/` (любой `.rs` там —
    // тест), а юнит-модули — в подкаталоге `tests` или файле `tests.rs`/`test.rs`.
    // Ограничиваем расширением `.rs`, чтобы НЕ повторить прежнюю широкую ошибку с
    // подстрокой `/tests/` для прод-кода других экосистем. В тестах unwrap/panic и
    // проглоченные ошибки легитимны и находкой смелов быть не должны.
    if name.ends_with(".rs")
        && (l.starts_with("tests/")
            || l.contains("/tests/")
            || name == "tests.rs"
            || name == "test.rs")
    {
        return true;
    }

    false
}

/// Строже, чем [`is_test_path`], специально для секрет-правил и точных сигнатур:
/// тест-файлом считается ТОЛЬКО файл со строгим тест-суффиксом исходного кода.
/// Каталог-сегмент `tests` сам по себе НЕ исключает файл (см. T43): секрет,
/// положенный в `any/tests/.env`, прод-секрет всё равно подлежит проверке.
///
/// Эта функция предназначена для режима, где пропуск секрета по тест-пути
/// недопустим: секрет в тест-файле должен оставаться находкой (возможно с
/// пониженной достоверностью на стороне вызывающего), а не молча теряться.
pub fn is_test_path_secrets(rel: &str) -> bool {
    let l = rel.to_ascii_lowercase();
    let name = file_name_lower(&l);
    // Только строгие суффиксы тест-исходников JS/TS. Конфиги, dotfiles и секреты под
    // `tests/`, а также Go-тестфайлы (`_test.go`) и Java-тесты НЕ исключаются и
    // проверяются как прод: секрет в них является настоящей утечкой (часто токен CI),
    // поэтому для секрет-режима выбран более широкий охват сканирования.
    name.ends_with(".test.ts")
        || name.ends_with(".test.tsx")
        || name.ends_with(".test.js")
        || name.ends_with(".spec.ts")
        || name.ends_with(".spec.tsx")
        || name.ends_with(".spec.js")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Уникальная пустая временная папка для файловых фикстур обхода.
    fn tmp() -> PathBuf {
        let n = CNT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ailc-walk-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }

    /// Собрать относительные (от корня) пути всех переданных в обработчик файлов.
    fn collect(dir: &Path, mode: WalkMode) -> (Vec<String>, WalkStats) {
        let mut seen = Vec::new();
        let mut stats = WalkStats::default();
        walk_mode(
            dir,
            mode,
            &mut |p| {
                let rel = p
                    .strip_prefix(dir)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .replace('\\', "/");
                seen.push(rel);
            },
            &mut stats,
        )
        .unwrap();
        seen.sort();
        (seen, stats)
    }

    // ---- T43: строгий is_test_path ----

    #[test]
    fn is_test_path_strict_suffixes_positive() {
        assert!(is_test_path("pkg/foo_test.go"));
        assert!(is_test_path("src/comp/Button.test.tsx"));
        assert!(is_test_path("src/comp/util.spec.ts"));
        assert!(is_test_path("tests/test_login.py"));
        assert!(is_test_path("FooTest.java"));
    }

    #[test]
    fn is_test_path_rust_layout() {
        // Rust: интеграционные тесты Cargo в каталоге tests/ и юнит-модули tests.rs —
        // тестовый код, где unwrap/panic легитимны (раньше ошибочно флагались как смелы).
        assert!(is_test_path("tests/tests.rs"));
        assert!(is_test_path("tests/integration.rs"));
        assert!(is_test_path("crate/tests/walk.rs"));
        assert!(is_test_path("src/foo/tests.rs"));
        // Прод-исходники .rs вне tests/ остаются под сканером.
        assert!(!is_test_path("src/time.rs"));
        assert!(!is_test_path("src/walk.rs"));
        // Прежняя точность сохранена: под сегментом tests только .rs, не другие языки.
        assert!(!is_test_path("any/tests/handler.go"));
    }

    #[test]
    fn is_test_path_does_not_exclude_prod_under_tests_dir() {
        // Прод-файл под сегментом tests НЕ должен считаться тестом (T43): иначе
        // секрет в any/tests/handler.go выпал бы из сканера.
        assert!(!is_test_path("src/integration/tests/handler.go"));
        assert!(!is_test_path("any/tests/config.yaml"));
        assert!(!is_test_path("core/test_utils_PRODUCTION.txt"));
        assert!(!is_test_path("tests/.env"));
    }

    #[test]
    fn is_test_path_secrets_is_even_stricter() {
        // Для секретов только строгий суффикс исходника считается тестом.
        assert!(is_test_path_secrets("pkg/foo.test.ts"));
        assert!(is_test_path_secrets("pkg/bar.spec.tsx"));
        // .env и любые конфиги под tests/ остаются прод-целью.
        assert!(!is_test_path_secrets("tests/.env"));
        assert!(!is_test_path_secrets("any/tests/config.yaml"));
        assert!(!is_test_path_secrets("FooTest.java"));
        assert!(!is_test_path_secrets("pkg/foo_test.go"));
    }

    // ---- T02: секрет-режим и allow-list dotfiles ----

    #[test]
    fn is_secret_dotfile_allow_list() {
        assert!(is_secret_dotfile(".env"));
        assert!(is_secret_dotfile(".env.production"));
        assert!(is_secret_dotfile(".env.local"));
        assert!(is_secret_dotfile(".npmrc"));
        assert!(is_secret_dotfile(".pypirc"));
        assert!(is_secret_dotfile(".netrc"));
        assert!(is_secret_dotfile(".git-credentials"));
        // файлы внутри .aws/.docker (имя уже без точки)
        assert!(is_secret_dotfile("credentials"));
        assert!(is_secret_dotfile("config.json"));
        // НЕ секрет-dotfile
        assert!(!is_secret_dotfile(".gitignore"));
        assert!(!is_secret_dotfile(".eslintrc"));
    }

    #[test]
    fn code_mode_skips_dotfiles_secrets_mode_reads_them() {
        let dir = tmp();
        write(&dir, "src/main.rs", "fn main() {}");
        write(&dir, ".env", "AWS_SECRET=xxx");
        write(&dir, ".aws/credentials", "key=zzz");
        write(&dir, ".docker/config.json", "{}");
        write(&dir, ".gitignore", "target");

        // Режим кода: dotfiles целиком вне охвата.
        let (code_seen, code_stats) = collect(&dir, WalkMode::Code);
        assert!(code_seen.contains(&"src/main.rs".to_string()));
        assert!(!code_seen.iter().any(|p| p.contains(".env")));
        assert!(code_stats.hidden >= 1);

        // Режим секретов: .env, .aws/credentials, .docker/config.json попадают в обход.
        let (sec_seen, _) = collect(&dir, WalkMode::Secrets);
        assert!(sec_seen.contains(&".env".to_string()));
        assert!(sec_seen.contains(&".aws/credentials".to_string()));
        assert!(sec_seen.contains(&".docker/config.json".to_string()));
        // .gitignore не в allow-list — по-прежнему пропущен.
        assert!(!sec_seen.contains(&".gitignore".to_string()));
    }

    // ---- T64: лимит размера и поимённая фиксация пропусков ----

    #[test]
    fn oversized_file_skipped_and_recorded_by_name() {
        let dir = tmp();
        write(&dir, "small.rs", "fn a() {}");
        let big = "x".repeat((MAX_SCAN_BYTES as usize) + 10);
        write(&dir, "huge.bundle.js", &big);

        let (seen, stats) = collect(&dir, WalkMode::Code);
        assert!(seen.contains(&"small.rs".to_string()));
        assert!(!seen.iter().any(|p| p.contains("huge.bundle.js")));
        assert_eq!(stats.oversized(), 1);
        assert_eq!(stats.data_blobs, 1);
        assert!(stats
            .oversized_files
            .iter()
            .any(|p| p.contains("huge.bundle.js")));
        assert!(stats.note().contains("сверхкрупных"));
    }

    // ---- T41: симлинки и циклы ----

    #[cfg(unix)]
    #[test]
    fn directory_symlink_is_not_followed() {
        use std::os::unix::fs::symlink;
        let dir = tmp();
        write(&dir, "real/secret.rs", "fn s() {}");
        // Симлинк на каталог внутри корня: не должен раскрываться.
        symlink(dir.join("real"), dir.join("link")).unwrap();

        let (seen, stats) = collect(&dir, WalkMode::Code);
        // Файл виден один раз — через реальный путь, не через симлинк.
        assert_eq!(
            seen.iter().filter(|p| p.ends_with("secret.rs")).count(),
            1
        );
        assert!(!seen.iter().any(|p| p.starts_with("link/")));
        assert!(stats.symlinks >= 1);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_cycle_does_not_recurse_forever() {
        use std::os::unix::fs::symlink;
        let dir = tmp();
        write(&dir, "a/file.rs", "fn a() {}");
        // Цикл: a/loop ведёт обратно на каталог a.
        symlink(dir.join("a"), dir.join("a/loop")).unwrap();

        // Главное — обход завершается (нет бесконечной рекурсии). Симлинк не следуем.
        let (seen, stats) = collect(&dir, WalkMode::Code);
        assert!(seen.contains(&"a/file.rs".to_string()));
        assert!(stats.symlinks >= 1);
    }

    #[cfg(unix)]
    #[test]
    fn file_symlink_is_not_read() {
        use std::os::unix::fs::symlink;
        let dir = tmp();
        write(&dir, "real.rs", "fn r() {}");
        symlink(dir.join("real.rs"), dir.join("alias.rs")).unwrap();

        let (seen, stats) = collect(&dir, WalkMode::Code);
        assert!(seen.contains(&"real.rs".to_string()));
        assert!(!seen.contains(&"alias.rs".to_string()));
        assert!(stats.symlinks >= 1);
    }

    #[test]
    fn single_file_entry_is_emitted() {
        let dir = tmp();
        write(&dir, "one.rs", "fn one() {}");
        let mut seen = Vec::new();
        let mut stats = WalkStats::default();
        walk_stats(&dir.join("one.rs"), &mut |p| {
            seen.push(p.to_string_lossy().into_owned());
        }, &mut stats)
        .unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].ends_with("one.rs"));
    }

    #[test]
    fn service_dirs_skipped() {
        let dir = tmp();
        write(&dir, "src/lib.rs", "fn l() {}");
        write(&dir, "node_modules/pkg/index.js", "x");
        write(&dir, "target/debug/app", "bin");
        let (seen, stats) = collect(&dir, WalkMode::Code);
        assert!(seen.contains(&"src/lib.rs".to_string()));
        assert!(!seen.iter().any(|p| p.starts_with("node_modules/")));
        assert!(!seen.iter().any(|p| p.starts_with("target/")));
        assert!(stats.service_dirs >= 2);
    }
}
