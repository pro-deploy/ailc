//! Журнал архитектурных решений (ADR): где лежат записи и как выделяется номер.
//!
//! Новые записи создаются в видимом каталоге [`DIR`] (`docs/adr/`), рядом с брифом, картой
//! ландшафта и спеками фич. Прежде они создавались в скрытом `.ailc/decisions/`, и человек,
//! которому на этапе согласования предстояло утвердить решения, не видел их ни в файловом
//! менеджере, ни в обычном просмотре проекта. Записи из прежнего каталога [`LEGACY_DIR`]
//! по-прежнему читаются и остаются на своём месте: их перенос сдвинул бы пути в снимке
//! заморозки у проектов с уже согласованными требованиями, и гейт счёл бы это изменением
//! после согласования.
//!
//! Номер у записи общий для обоих каталогов: следующий номер больше наибольшего в любом из
//! них, поэтому новая запись не может совпасть по номеру со старой. Если запись с одним
//! номером всё же есть в обоих каталогах, действует запись из [`DIR`].

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use ailc_contracts::{Ctx, Result};

/// Каталог новых записей относительно корня проекта.
pub const DIR: &str = "docs/adr";

/// Прежний каталог записей, только для чтения и правки существующих.
pub const LEGACY_DIR: &str = ".ailc/decisions";

/// Одна запись журнала решений.
#[derive(Debug, Clone)]
pub struct Record {
    pub number: u32,
    /// Путь относительно корня проекта, через прямую косую черту.
    pub rel: String,
    pub path: PathBuf,
}

/// Номер записи из имени файла: ведущие цифры перед `-` или `.md`. Понимает и новое имя
/// `0001-заголовок.md`, и прежнее `1.md`.
fn number_of(name: &str) -> Option<u32> {
    let stem = name.strip_suffix(".md")?;
    let digits: String = stem.chars().take_while(char::is_ascii_digit).collect();
    let rest = &stem[digits.len()..];
    if digits.is_empty() || !(rest.is_empty() || rest.starts_with('-')) {
        return None;
    }
    digits.parse().ok()
}

/// Часть имени файла из заголовка решения: строчные буквы и цифры через дефис, не длиннее
/// 60 символов. Кириллица сохраняется, как и в именах спек фич (`docs/фичи/`).
fn slug(title: &str) -> String {
    let mut out = String::new();
    for ch in title.chars().flat_map(char::to_lowercase) {
        if ch.is_alphanumeric() {
            out.push(ch);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
        if out.chars().count() >= 60 {
            break;
        }
    }
    out.trim_matches('-').to_string()
}

fn numbered(ctx: &Ctx, dir: &str) -> Vec<Record> {
    fs::read_dir(ctx.root.join(dir))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let number = number_of(&name)?;
            Some(Record {
                number,
                rel: format!("{dir}/{name}"),
                path: e.path(),
            })
        })
        .collect()
}

/// Все записи обоих каталогов, по возрастанию номера; при совпадении номера побеждает
/// запись из [`DIR`].
pub fn list(ctx: &Ctx) -> Vec<Record> {
    let mut by_number: BTreeMap<u32, Record> = BTreeMap::new();
    for r in numbered(ctx, LEGACY_DIR) {
        by_number.insert(r.number, r);
    }
    for r in numbered(ctx, DIR) {
        by_number.insert(r.number, r);
    }
    by_number.into_values().collect()
}

/// Запись с номером `number`, если она есть.
pub fn find(ctx: &Ctx, number: u32) -> Option<Record> {
    list(ctx).into_iter().find(|r| r.number == number)
}

/// Атомарно выделить следующий номер и записать новую запись в [`DIR`] под именем
/// `0001-заголовок.md`: по имени файла видно, о чём решение, а номер с ведущими нулями
/// сохраняет порядок при сортировке по имени. Текст строится замыканием от выделенного
/// номера, потому что номер входит в заголовок записи. Возвращает созданную запись.
pub fn create(ctx: &Ctx, title: &str, body: impl Fn(u32) -> String) -> Result<Record> {
    let dir = ctx.root.join(DIR);
    fs::create_dir_all(&dir)?;
    let mut number = list(ctx).last().map_or(1, |r| r.number + 1);
    loop {
        let s = slug(title);
        let file = if s.is_empty() {
            format!("{number:04}.md")
        } else {
            format!("{number:04}-{s}.md")
        };
        let path = dir.join(&file);
        // `create_new` исключает гонку двух одновременных вызовов: проигравший получает
        // ошибку «уже существует» и берёт следующий номер.
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                f.write_all(body(number).as_bytes())?;
                let rec = Record {
                    number,
                    rel: format!("{DIR}/{file}"),
                    path,
                };
                note_in_process_journal(ctx, &rec);
                return Ok(rec);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => number += 1,
            Err(e) => return Err(e.into()),
        }
    }
}

/// Отметить создание записи в журнале процесса поставки, если процесс в проекте начат.
/// Прежде журнал фиксировал только переходы между этапами, и по истории нельзя было
/// понять, когда появилось решение. Проект без процесса журнал не получает.
fn note_in_process_journal(ctx: &Ctx, rec: &Record) {
    if ctx.root.join(".ailc/process/state.toml").exists() {
        let title = fs::read_to_string(&rec.path)
            .ok()
            .and_then(|t| {
                t.lines()
                    .find(|l| l.starts_with("# "))
                    .map(|l| l.trim_start_matches("# ").trim().to_string())
            })
            .unwrap_or_else(|| format!("ADR-{}", rec.number));
        crate::process::plan::journal(ctx, &format!("ADR СОЗДАН: {title} ({})", rec.rel));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_testkit::TempTree;

    fn ctx(t: &TempTree) -> Ctx {
        Ctx::new(t.path())
    }

    #[test]
    fn новая_запись_создаётся_в_docs_adr_с_номером_после_старых() {
        let t = TempTree::new("adr-new");
        t.write(".ailc/decisions/1.md", "# ADR-1: старое\n");
        t.write(".ailc/decisions/2.md", "# ADR-2: старое\n");
        let c = ctx(&t);
        let rec = create(&c, "Новое решение", |n| {
            format!("# ADR-{n}: новое\n")
        })
        .unwrap();
        assert_eq!(rec.number, 3);
        assert_eq!(rec.rel, "docs/adr/0003-новое-решение.md");
        assert_eq!(fs::read_to_string(&rec.path).unwrap(), "# ADR-3: новое\n");
        let rels: Vec<String> = list(&c).into_iter().map(|r| r.rel).collect();
        assert_eq!(
            rels,
            [
                ".ailc/decisions/1.md",
                ".ailc/decisions/2.md",
                "docs/adr/0003-новое-решение.md"
            ]
        );
    }

    #[test]
    fn номер_читается_из_нового_и_прежнего_имени() {
        assert_eq!(number_of("0007-выбор-хранилища.md"), Some(7));
        assert_eq!(number_of("12.md"), Some(12));
        assert_eq!(number_of("readme.md"), None);
        assert_eq!(number_of("2fa.md"), None);
        assert_eq!(slug("Сервер комнат: WebSocket!"), "сервер-комнат-websocket");
    }

    #[test]
    fn при_совпадении_номера_действует_запись_из_docs_adr() {
        let t = TempTree::new("adr-dup");
        t.write(".ailc/decisions/1.md", "старая");
        t.write("docs/adr/1.md", "новая");
        let c = ctx(&t);
        let r = find(&c, 1).unwrap();
        assert_eq!(r.rel, "docs/adr/1.md");
        assert_eq!(list(&c).len(), 1);
    }

    #[test]
    fn создание_отмечается_в_журнале_только_при_начатом_процессе() {
        let t = TempTree::new("adr-journal");
        let c = ctx(&t);
        create(&c, "без процесса", |n| {
            format!("# ADR-{n}: без процесса\n")
        })
        .unwrap();
        assert!(!t.path().join(".ailc/process/journal.md").exists());

        t.write(".ailc/process/state.toml", "");
        create(&c, "с процессом", |n| {
            format!("# ADR-{n}: с процессом\n")
        })
        .unwrap();
        let j = fs::read_to_string(t.path().join(".ailc/process/journal.md")).unwrap();
        assert!(j.contains("ADR СОЗДАН: ADR-2: с процессом (docs/adr/0002-с-процессом.md)"));
    }
}
