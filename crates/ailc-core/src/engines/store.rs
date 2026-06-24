//! E7 Store — атомарный файловый CRUD «запись-на-файл» под каталогом `<root>/.co/`.
//!
//! Один движок на всех писателей состояния (память, журнал решений, бэклог): логика
//! путей/создания/чтения существует ровно здесь, без дублирования. Каждая логическая
//! запись — отдельный файл, поэтому правки не конфликтуют, а выдача нового id атомарна
//! за счёт `O_EXCL` (create_new): операционная система гарантирует, что create_new
//! удастся ровно одному претенденту на имя.

use ailc_contracts::{CapError, Ctx, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Монотонный счётчик для уникальных имён временных файлов в одном процессе. Вместе с
/// идентификатором процесса даёт имя tmp-файла, не сталкивающееся ни с другими потоками
/// этого процесса, ни (практически) с другими процессами на том же каталоге.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Маркер промежуточного файла атомарной записи: подстрока в имени `.<имя>.tmp.<pid>.<seq>`.
/// Единственная точка истины формата, чтобы запись (atomic_write) и фильтр чтения
/// (is_temp_artifact) не разошлись.
const TMP_MARKER: &str = ".tmp.";

/// Является ли имя файла промежуточным артефактом атомарной записи. Такие файлы существуют
/// лишь в окне между записью содержимого и переименованием и НЕ должны попадать в выдачу
/// read_all как обычные записи.
fn is_temp_artifact(name: &str) -> bool {
    name.starts_with('.') && name.contains(TMP_MARKER)
}

/// Проверка одного компонента пути: запрещаем выход из песочницы `.co/`.
/// Имя/namespace приходят из ввода (например input.target) — без этого был бы
/// path traversal (`../../etc`).
fn safe_component(s: &str) -> Result<()> {
    if s.is_empty()
        || s == "."
        || s == ".."
        || s.contains('/')
        || s.contains('\\')
        || s.contains('\0')
    {
        return Err(CapError(format!("недопустимое имя пути: {s:?}")));
    }
    Ok(())
}

pub struct Store;

impl Store {
    /// Каталог пространства имён: `<root>/.co/<namespace>/`.
    fn namespace_dir(ctx: &Ctx, namespace: &str) -> PathBuf {
        ctx.root.join(".co").join(namespace)
    }

    /// Прочитать все файлы из `.co/<namespace>/`.
    /// Возвращает пары (имя файла, содержимое). Если каталога нет или он пуст —
    /// пустой список (не ошибка): отсутствие записей — нормальное состояние.
    pub fn read_all(ctx: &Ctx, namespace: &str) -> Result<Vec<(String, String)>> {
        safe_component(namespace)?;
        let dir = Self::namespace_dir(ctx, namespace);
        let mut items: Vec<(String, String)> = Vec::new();

        // Каталога нет → записей нет. Возвращаем пусто, не ошибку.
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => return Ok(items),
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue, // имя не в UTF-8 — пропускаем конкретный файл, не весь обход
            };
            // Промежуточные файлы атомарной записи (см. atomic_write) НЕ являются
            // записями: они существуют лишь в окне между записью и rename. Их формат
            // `.<имя>.tmp.<pid>.<seq>` (ведущая точка плюс маркер `.tmp.`). Пропускаем,
            // чтобы конкурентный читатель не принял недописанный снимок за запись.
            if is_temp_artifact(&name) {
                continue;
            }
            // Нечитаемый/бинарный файл → пропуск конкретного файла, не всего движка.
            let content = match fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            items.push((name, content));
        }

        // Стабильный порядок: по имени файла (числовые id сортируются как строки —
        // достаточно для предсказуемой выдачи).
        items.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(items)
    }

    /// Атомарно записать/перезаписать файл `.co/<namespace>/<name>` (с созданием каталогов).
    ///
    /// Запись идёт в две стадии: содержимое целиком пишется во ВРЕМЕННЫЙ файл в том же
    /// каталоге, после чего файл атомарно переименовывается в целевое имя (T74). Так
    /// читатель того же файла (например verify/api-break, читающий baseline) никогда не
    /// увидит наполовину записанный или пустой файл: операционная система гарантирует, что
    /// rename в пределах одной файловой системы атомарен и заменяет цель целиком. До этой
    /// правки использовался прямой `fs::write`, который усекает файл, а затем дописывает
    /// содержимое, оставляя окно, в котором конкурентный читатель получал пустой/частичный
    /// снимок и выдавал ложный слом контракта. Временный файл лежит рядом с целью
    /// (а не в общем temp-каталоге системы), чтобы rename не пересекал границу файловой
    /// системы (где он перестал бы быть атомарным и копировал бы байты).
    pub fn write(ctx: &Ctx, namespace: &str, name: &str, content: &str) -> Result<()> {
        safe_component(namespace)?;
        safe_component(name)?;
        let dir = Self::namespace_dir(ctx, namespace);
        fs::create_dir_all(&dir)?;
        Self::atomic_write(&dir, name, content.as_bytes())
    }

    /// Записать `bytes` в `dir/name` атомарно: временный файл рядом с целью плюс rename.
    /// Имя временного файла уникально (идентификатор процесса плюс монотонный счётчик плюс
    /// целевое имя), чтобы два одновременных писателя не затёрли промежуточный файл друг
    /// друга до переименования. При любой ошибке временный файл подчищается, чтобы не
    /// копить мусор в каталоге.
    fn atomic_write(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let tmp_name = format!(".{name}{TMP_MARKER}{pid}.{seq}");
        let tmp_path = dir.join(&tmp_name);
        let final_path = dir.join(name);

        // Стадия 1: полностью записать содержимое во временный файл и сбросить на диск.
        // Любая ошибка ввода-вывода сопровождается подчисткой временного файла, чтобы не
        // копить мусор в каталоге, поэтому выделяем запись в отдельную функцию и
        // обрабатываем её результат единообразно.
        if let Err(e) = Self::write_tmp(&tmp_path, bytes) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e.into());
        }

        // Стадия 2: атомарная публикация. Если переименование не удалось, убираем tmp.
        if let Err(e) = fs::rename(&tmp_path, &final_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e.into());
        }
        Ok(())
    }

    /// Записать `bytes` во временный файл `tmp_path` и синхронизировать содержимое на
    /// носитель. Синхронизация (`sync_all`) гарантирует, что байты дошли до диска прежде,
    /// чем atomic_write опубликует файл переименованием: это страхует от рваного снимка
    /// при аварийном завершении в окне между записью и rename.
    fn write_tmp(tmp_path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let mut f = fs::File::create(tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }

    /// Дописать строку в файл `.co/<namespace>/<name>` (для журнала решений).
    /// Создаёт файл и каталоги, если их нет. Строка завершается переводом строки.
    pub fn append(ctx: &Ctx, namespace: &str, name: &str, line: &str) -> Result<()> {
        safe_component(namespace)?;
        safe_component(name)?;
        let dir = Self::namespace_dir(ctx, namespace);
        fs::create_dir_all(&dir)?;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(name))?;
        writeln!(file, "{line}")?;
        Ok(())
    }

    /// Атомарно выделить новый числовой id и создать под него файл.
    /// Перебирает 1, 2, 3… и пытается создать `<n>.<ext>` через `create_new` (O_EXCL):
    /// первый, кому это удалось, и есть владелец id. Возвращает имя файла `<n>.<ext>`.
    pub fn alloc_id(ctx: &Ctx, namespace: &str, ext: &str) -> Result<String> {
        safe_component(namespace)?;
        safe_component(ext)?;
        let dir = Self::namespace_dir(ctx, namespace);
        fs::create_dir_all(&dir)?;

        let mut n: u64 = 1;
        loop {
            let name = format!("{n}.{ext}");
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(&name))
            {
                // Имя было свободно — файл наш, id выдан.
                Ok(_) => return Ok(name),
                Err(e) => match e.kind() {
                    // Имя занято — пробуем следующее число.
                    std::io::ErrorKind::AlreadyExists => {
                        n += 1;
                        continue;
                    }
                    // Любая другая ошибка ввода-вывода — наверх через From<io::Error>.
                    _ => return Err(e.into()),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Уникальный временный корень проекта на каждый тест, чтобы прогоны не пересекались.
    fn temp_ctx() -> Ctx {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!("ailc-store-test-{pid}-{seq}-{nanos}"));
        fs::create_dir_all(&root).unwrap();
        Ctx::new(root)
    }

    #[test]
    fn write_then_read_roundtrip() {
        // T74: содержимое атомарной записи читается полностью и без искажений.
        let ctx = temp_ctx();
        Store::write(&ctx, "ns", "baseline.txt", "первая\nвторая\n").unwrap();
        let items = Store::read_all(&ctx, "ns").unwrap();
        assert_eq!(items.len(), 1, "ровно одна запись (без tmp-мусора)");
        assert_eq!(items[0].0, "baseline.txt");
        assert_eq!(items[0].1, "первая\nвторая\n");
    }

    #[test]
    fn overwrite_replaces_content_wholesale() {
        // Повторная запись заменяет содержимое целиком (rename заменяет цель), а не
        // дописывает к старому.
        let ctx = temp_ctx();
        Store::write(&ctx, "ns", "f.txt", "длинное-старое-содержимое").unwrap();
        Store::write(&ctx, "ns", "f.txt", "новое").unwrap();
        let items = Store::read_all(&ctx, "ns").unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].1, "новое", "новая запись замещает старую целиком");
    }

    #[test]
    fn no_temp_files_left_after_successful_write() {
        // После успешной записи в каталоге не остаётся промежуточных tmp-файлов.
        let ctx = temp_ctx();
        Store::write(&ctx, "ns", "f.txt", "данные").unwrap();
        let dir = Store::namespace_dir(&ctx, "ns");
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        assert_eq!(names, vec!["f.txt".to_string()], "лишних файлов быть не должно");
    }

    #[test]
    fn read_all_skips_temp_artifacts() {
        // Если в каталоге внезапно оказался tmp-артефакт (имитация окна записи), read_all
        // его не возвращает как запись.
        let ctx = temp_ctx();
        let dir = Store::namespace_dir(&ctx, "ns");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("real.txt"), "настоящая").unwrap();
        // Промежуточный файл в формате atomic_write: ведущая точка плюс маркер `.tmp.`.
        fs::write(dir.join(".real.txt.tmp.123.4"), "недописанное").unwrap();
        let items = Store::read_all(&ctx, "ns").unwrap();
        assert_eq!(items.len(), 1, "tmp-артефакт пропущен");
        assert_eq!(items[0].0, "real.txt");
    }

    #[test]
    fn is_temp_artifact_classifies_names() {
        // Позитив и негатив классификатора промежуточных файлов.
        assert!(is_temp_artifact(".baseline.txt.tmp.123.0"));
        assert!(is_temp_artifact(".f.tmp.1.2"));
        assert!(!is_temp_artifact("baseline.txt"), "обычное имя не tmp");
        assert!(!is_temp_artifact(".gitignore"), "точка-файл без маркера не tmp");
        assert!(
            !is_temp_artifact("name.tmp.1.2"),
            "без ведущей точки это не наш артефакт"
        );
    }

    #[test]
    fn write_rejects_unsafe_names() {
        // Защита от path traversal сохраняется и в атомарной записи.
        let ctx = temp_ctx();
        assert!(Store::write(&ctx, "..", "f.txt", "x").is_err());
        assert!(Store::write(&ctx, "ns", "../escape", "x").is_err());
        assert!(Store::write(&ctx, "ns", "", "x").is_err());
    }
}
