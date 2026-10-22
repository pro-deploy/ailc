//! Общий кэш исходников и деревьев разбора на время ОДНОГО прогона.
//!
//! Каждая capability обходит дерево проекта сама, и прежде каждая же сама читала файл с
//! диска и сама строила дерево разбора tree-sitter. При прогоне Definition of Done один и
//! тот же файл поэтому читался столько раз, сколько проверок его касается, а структурный
//! анализ, проход по ПДн в логах и анализ заражения вместе разбирали его до пяти раз.
//! Этот модуль делает чтение и разбор однократными в пределах прогона: первая проверка,
//! запросившая файл, кладёт содержимое (и при необходимости дерево) в кэш, остальные
//! получают ту же копию через `Arc`.
//!
//! Область действия задаётся явно охранным объектом [`RunScope`]. Вне области кэш
//! отключён и функции модуля ведут себя ровно как прямое чтение с диска и прямой разбор.
//! Это существенно для сервера протокола MCP, который живёт весь сеанс среды разработки:
//! между прогонами человек правит файлы, и содержимое прошлого прогона не должно пережить
//! его конец. Области вкладываются (оркестратор открывает свою, конвейер внутри него
//! свою), кэш очищается, когда закрывается последняя из открытых.
//!
//! Устаревание внутри прогона закрыто двумя независимыми мерами. Во-первых, каждая запись
//! хранит размер и время изменения файла, снятые ДО чтения, и при каждом обращении они
//! сверяются с текущими; расхождение ведёт к повторному чтению. Отметка снимается до
//! чтения намеренно: если файл изменился между снятием и чтением, в кэш попадёт более
//! новое содержимое под более старой отметкой, и следующее обращение его перечитает, то
//! есть ошибка возможна только в сторону лишнего чтения. Во-вторых, после каждой волны с
//! мутирующей capability конвейер вызывает [`invalidate_all`], поэтому правка, не
//! сдвинувшая ни размер, ни время изменения (грубое разрешение времени у файловой
//! системы), тоже не оставит читателям прежнего содержимого.
//!
//! Дерево разбора привязано к конкретной закэшированной копии текста, а не к пути. Ключом
//! служат адрес и длина текста вместе с грамматикой. Такой ключ однозначен, потому что
//! кэш сам удерживает эту копию живой (через `Arc`), и её адрес не может быть занят
//! другим содержимым, пока запись существует. Текст, полученный в обход кэша, в индексе
//! копий отсутствует, и его дерево строится заново и не кэшируется. Привязка к адресу
//! позволяет кэшировать разбор в функциях, принимающих просто `&str`, не меняя их
//! сигнатуры, и исключает выдачу дерева строгого варианта текста для устойчивого.
//!
//! Память ограничена бюджетом [`BUDGET_BYTES`]. Запись, не уместившаяся в бюджет, не
//! кэшируется, но вызывающий всё равно получает результат: превышение бюджета замедляет
//! прогон до прежнего уровня, но не меняет его итог. Кэш отключается переменной
//! окружения `AILC_NO_SOURCE_CACHE`.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;

use tree_sitter::{Language, Parser, Tree};

/// Предельный суммарный объём кэша в байтах (тексты плюс оценка деревьев).
pub const BUDGET_BYTES: usize = 512 * 1024 * 1024;

/// Оценочный множитель памяти дерева разбора относительно длины исходника. Точный размер
/// дерева tree-sitter наружу не сообщает; множитель взят с запасом, чтобы бюджет
/// ограничивал память консервативно.
const TREE_COST_FACTOR: usize = 4;

/// Отметка состояния файла: размер и время изменения.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
}

fn stamp_of(path: &Path) -> io::Result<Stamp> {
    let meta = std::fs::metadata(path)?;
    Ok(Stamp {
        len: meta.len(),
        modified: meta.modified().ok(),
    })
}

/// Кэшированное состояние одного файла. Строгий и устойчивый варианты текста хранятся
/// раздельно, потому что их семантика различна: строгий повторяет `fs::read_to_string`
/// (ошибка на байтах вне UTF-8), устойчивый повторяет `codeintel::read_source` (срез BOM,
/// замена недопустимых байтов, нормализация переводов строк).
struct Entry {
    stamp: Stamp,
    strict: Option<Arc<str>>,
    lossy: Option<Arc<str>>,
}

/// Ключ копии текста: адрес первого байта и длина.
type TextKey = (usize, usize);

fn key_of(text: &str) -> TextKey {
    (text.as_ptr() as usize, text.len())
}

struct State {
    /// Число открытых областей [`RunScope`]; ноль означает, что кэш выключен.
    depth: usize,
    used: usize,
    files: BTreeMap<PathBuf, Entry>,
    /// Индекс закэшированных копий текста по адресу. Наличие ключа здесь и есть
    /// доказательство того, что копия удерживается кэшем.
    texts: BTreeMap<TextKey, Arc<str>>,
    /// Деревья по копии текста; грамматик у одной копии бывает больше одной лишь в
    /// вырожденных случаях, поэтому список линейный.
    trees: BTreeMap<TextKey, Vec<(Language, Arc<Tree>)>>,
}

/// Экземпляр кэша. В продукте используется единственный общий экземпляр процесса
/// ([`GLOBAL`]), за которым стоят свободные функции модуля; отдельные экземпляры нужны
/// модульным тестам, чтобы параллельно идущие тесты конвейера не влияли на их состояние.
pub struct Cache {
    state: Mutex<State>,
}

static GLOBAL: Cache = Cache::new();

impl Cache {
    const fn new() -> Self {
        Self {
            state: Mutex::new(State {
                depth: 0,
                used: 0,
                files: BTreeMap::new(),
                texts: BTreeMap::new(),
                trees: BTreeMap::new(),
            }),
        }
    }

    /// Захват состояния. Отравление мьютекса (паника в другом потоке под захватом) не
    /// должно выключать проверки: под захватом не выполняется ничего, способного
    /// паниковать посреди изменения, поэтому состояние остаётся согласованным.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl State {
    fn clear(&mut self) {
        self.files.clear();
        self.texts.clear();
        self.trees.clear();
        self.used = 0;
    }

    /// Убрать копию текста из индекса вместе с её деревьями.
    fn forget_text(&mut self, text: &Arc<str>) {
        let k = key_of(text);
        if self.texts.remove(&k).is_some() {
            self.used = self.used.saturating_sub(text.len());
        }
        if let Some(ts) = self.trees.remove(&k) {
            self.used = self
                .used
                .saturating_sub(ts.len() * text.len() * TREE_COST_FACTOR);
        }
    }
}

/// Охранный объект области прогона: пока он жив, чтение и разбор кэшируются.
pub struct RunScope {
    cache: Option<&'static Cache>,
}

impl RunScope {
    /// Открыть область общего кэша процесса. При `AILC_NO_SOURCE_CACHE` возвращает
    /// пустой объект, и кэш остаётся выключенным.
    pub fn enter() -> Self {
        if crate::env::is_set("AILC_NO_SOURCE_CACHE") {
            return Self { cache: None };
        }
        GLOBAL.enter()
    }
}

impl Drop for RunScope {
    fn drop(&mut self) {
        let Some(cache) = self.cache else {
            return;
        };
        let mut st = cache.state();
        st.depth = st.depth.saturating_sub(1);
        if st.depth == 0 {
            st.clear();
        }
    }
}

/// Сбросить всё закэшированное (после мутирующего шага). Область при этом остаётся
/// открытой, и последующие чтения снова наполняют кэш уже новым содержимым.
pub fn invalidate_all() {
    GLOBAL.invalidate_all();
}

/// Аналог `fs::read_to_string`: ошибка на содержимом вне UTF-8, текст без изменений.
pub fn read_to_string(path: &Path) -> io::Result<Arc<str>> {
    GLOBAL.read_to_string(path)
}

/// Аналог прежнего `codeintel::read_source`: устойчивое декодирование с нормализацией.
pub fn read_source(path: &Path) -> Option<Arc<str>> {
    GLOBAL.read_source(path)
}

/// Дерево разбора текста `text` грамматикой `language`.
///
/// Если `text` есть закэшированная копия (получена из [`read_to_string`] или
/// [`read_source`] в текущей области), дерево строится один раз и далее выдаётся из кэша.
/// Любой другой текст разбирается заново. `None` означает, что грамматику не удалось
/// установить или разбор не состоялся, как и при прямом вызове `Parser::parse`.
///
/// Возвращается клон дерева: в tree-sitter он разделяет узлы с оригиналом по счётчику
/// ссылок и стоит постоянное время, поэтому вызывающий владеет деревом и может держать
/// его сколь угодно долго независимо от сброса кэша.
pub fn parse(text: &str, language: &Language) -> Option<Tree> {
    GLOBAL.parse(text, language)
}

fn parse_fresh(text: &str, language: &Language) -> Option<Tree> {
    let mut parser = Parser::new();
    parser.set_language(language).ok()?;
    parser.parse(text, None)
}

impl Cache {
    fn enter(&'static self) -> RunScope {
        self.state().depth += 1;
        RunScope { cache: Some(self) }
    }

    fn invalidate_all(&self) {
        self.state().clear();
    }

    /// Общий путь чтения текста. `pick` выбирает вариант в записи, `load` читает с диска.
    fn cached_text(
        &self,
        path: &Path,
        pick: fn(&mut Entry) -> &mut Option<Arc<str>>,
        load: impl FnOnce() -> io::Result<String>,
    ) -> io::Result<Arc<str>> {
        if self.state().depth == 0 {
            return load().map(Arc::from);
        }
        let stamp = stamp_of(path)?;
        {
            let mut st = self.state();
            if let Some(e) = st.files.get_mut(path) {
                if e.stamp == stamp {
                    if let Some(t) = pick(e) {
                        return Ok(Arc::clone(t));
                    }
                }
            }
        }
        // Чтение и декодирование выполняются вне захвата: параллельные проверки не должны
        // ждать чужой ввод-вывод. Два потока могут прочитать один файл одновременно, это
        // безвредно: в кэше останется одна из двух одинаковых копий.
        let text: Arc<str> = Arc::from(load()?);
        let mut st = self.state();
        if st.depth == 0 || st.used + text.len() > BUDGET_BYTES {
            return Ok(text);
        }
        let mut stale: Vec<Arc<str>> = Vec::new();
        let e = st.files.entry(path.to_path_buf()).or_insert(Entry {
            stamp,
            strict: None,
            lossy: None,
        });
        if e.stamp != stamp {
            stale.extend(e.strict.take());
            stale.extend(e.lossy.take());
            e.stamp = stamp;
        }
        let slot = pick(e);
        if let Some(old) = slot.take() {
            stale.push(old);
        }
        *slot = Some(Arc::clone(&text));
        for old in &stale {
            st.forget_text(old);
        }
        st.texts.insert(key_of(&text), Arc::clone(&text));
        st.used += text.len();
        Ok(text)
    }

    fn read_to_string(&self, path: &Path) -> io::Result<Arc<str>> {
        self.cached_text(path, |e| &mut e.strict, || std::fs::read_to_string(path))
    }

    fn read_source(&self, path: &Path) -> Option<Arc<str>> {
        self.cached_text(
            path,
            |e| &mut e.lossy,
            || std::fs::read(path).map(|b| crate::engines::codeintel::decode_source(&b)),
        )
        .ok()
    }

    fn parse(&self, text: &str, language: &Language) -> Option<Tree> {
        let k = key_of(text);
        {
            let st = self.state();
            if st.depth == 0 || !st.texts.contains_key(&k) {
                drop(st);
                return parse_fresh(text, language);
            }
            if let Some(ts) = st.trees.get(&k) {
                if let Some((_, t)) = ts.iter().find(|(l, _)| l == language) {
                    return Some((**t).clone());
                }
            }
        }
        let tree = parse_fresh(text, language)?;
        let cost = text.len() * TREE_COST_FACTOR;
        let mut st = self.state();
        // Копия могла быть вытеснена, пока шёл разбор: тогда дерево не кэшируем, иначе ключ
        // по адресу перестал бы быть однозначным.
        if st.texts.contains_key(&k) && st.used + cost <= BUDGET_BYTES {
            let ts = st.trees.entry(k).or_default();
            if !ts.iter().any(|(l, _)| l == language) {
                ts.push((language.clone(), Arc::new(tree.clone())));
                st.used += cost;
            }
        }
        Some(tree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Каждый тест работает на СОБСТВЕННОМ экземпляре кэша: общий экземпляр процесса
    /// параллельно используют тесты конвейера и гейта, и проверки состояния на нём были бы
    /// неустойчивыми.
    fn fresh() -> &'static Cache {
        Box::leak(Box::new(Cache::new()))
    }

    fn tmp(tag: &str, body: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ailc-source-cache-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("a.rs");
        std::fs::write(&p, body).unwrap();
        p
    }

    fn rust() -> Language {
        tree_sitter_rust::LANGUAGE.into()
    }

    fn trees_cached(c: &Cache) -> usize {
        c.state().trees.values().map(Vec::len).sum()
    }

    #[test]
    fn вне_области_чтение_не_кэшируется() {
        let c = fresh();
        let p = tmp("noscope", "fn a() {}\n");
        let a = c.read_to_string(&p).unwrap();
        let b = c.read_to_string(&p).unwrap();
        assert_eq!(&*a, "fn a() {}\n");
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn в_области_повторное_чтение_и_разбор_берутся_из_кэша() {
        let c = fresh();
        let p = tmp("hit", "fn a() {}\n");
        let _scope = c.enter();
        let a = c.read_to_string(&p).unwrap();
        let b = c.read_to_string(&p).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let t1 = c.parse(&a, &rust()).unwrap();
        assert_eq!(trees_cached(c), 1);
        let t2 = c.parse(&b, &rust()).unwrap();
        assert_eq!(trees_cached(c), 1);
        assert_eq!(t1.root_node().to_sexp(), t2.root_node().to_sexp());
    }

    #[test]
    fn текст_вне_кэша_разбирается_но_не_кэшируется() {
        let c = fresh();
        let _scope = c.enter();
        let own = String::from("fn a() {}\n");
        assert!(c.parse(&own, &rust()).is_some());
        assert_eq!(trees_cached(c), 0);
    }

    #[test]
    fn строгий_и_устойчивый_варианты_не_смешиваются() {
        let c = fresh();
        let p = tmp("variants", "fn a() {}\r\n");
        let _scope = c.enter();
        let strict = c.read_to_string(&p).unwrap();
        let lossy = c.read_source(&p).unwrap();
        assert_eq!(&*strict, "fn a() {}\r\n");
        assert_eq!(&*lossy, "fn a() {}\n");
        c.parse(&strict, &rust()).unwrap();
        c.parse(&lossy, &rust()).unwrap();
        assert_eq!(trees_cached(c), 2);
    }

    #[test]
    fn изменение_файла_в_области_перечитывается() {
        let c = fresh();
        let p = tmp("stale", "fn a() {}\n");
        let _scope = c.enter();
        let old = c.read_to_string(&p).unwrap();
        c.parse(&old, &rust()).unwrap();
        std::fs::write(&p, "fn longer() {}\n").unwrap();
        assert_eq!(&*c.read_to_string(&p).unwrap(), "fn longer() {}\n");
        // Дерево прежней копии ушло вместе с ней.
        assert_eq!(trees_cached(c), 0);
    }

    #[test]
    fn сброс_после_мутатора_ловит_правку_той_же_длины() {
        let c = fresh();
        let p = tmp("same-len", "fn a() {}\n");
        let _scope = c.enter();
        let before = std::fs::metadata(&p).unwrap().modified().unwrap();
        assert_eq!(&*c.read_to_string(&p).unwrap(), "fn a() {}\n");
        std::fs::write(&p, "fn b() {}\n").unwrap();
        // Возвращаем прежнее время изменения: отметка совпадает, и без сброса кэш
        // отдал бы прежнее содержимое.
        let f = std::fs::File::options().write(true).open(&p).unwrap();
        f.set_modified(before).unwrap();
        drop(f);
        c.invalidate_all();
        assert_eq!(&*c.read_to_string(&p).unwrap(), "fn b() {}\n");
    }

    #[test]
    fn закрытие_последней_области_очищает_кэш() {
        let c = fresh();
        let p = tmp("drop", "fn a() {}\n");
        let first = {
            let _outer = c.enter();
            let a = {
                let _inner = c.enter();
                c.read_to_string(&p).unwrap()
            };
            // Внутренняя область закрыта, внешняя ещё открыта: кэш жив.
            assert!(Arc::ptr_eq(&a, &c.read_to_string(&p).unwrap()));
            a
        };
        assert!(c.state().texts.is_empty());
        let _scope = c.enter();
        assert!(!Arc::ptr_eq(&first, &c.read_to_string(&p).unwrap()));
    }
}
