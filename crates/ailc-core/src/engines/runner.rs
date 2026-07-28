//! E2 ExternalRunner — запуск внешних инструментов (тесты, линтеры, сканеры) с
//! graceful-фолбэком и ЯВНЫМ пропуском, если инструмента нет. Кросс-платформенно:
//! собственный поиск бинаря по PATH (+ PATHEXT на Windows).
//!
//! Один движок для всех «обёрток вокруг CLI» — логика запуска/захвата/пропуска не
//! дублируется по капабилити (в ailc это было размазано по test/lint/sast/…).

use ailc_contracts::Ctx;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Жёсткий лимит на внешний инструмент: зависший/интерактивный CLI не должен
/// навсегда блокировать оркестратор.
const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Лимит для инструментов, которым нужно собрать проект (см. `Runner::run_build`).
/// Пятнадцать минут заведомо перекрывают холодную сборку рабочей области среднего размера и
/// при этом остаются пределом: зависший навсегда процесс всё равно будет остановлен.
const BUILD_TIMEOUT_SECS: u64 = 900;

// Инструменту, собирающему проект, отводится заведомо больше времени, чем обычному: иначе
// hard-ось «Тесты» не закрывается на проекте среднего размера ни при каком качестве кода, а
// исход зависит от того, была ли сборка тёплой. Инвариант закреплён проверкой времени
// компиляции: она сильнее рантайм-теста, поскольку нарушение соотношения не соберётся вовсе.
const _: () = assert!(
    BUILD_TIMEOUT_SECS > DEFAULT_TIMEOUT_SECS,
    "предел сборки обязан превышать обычный предел инструмента"
);

/// Разобрать значение переменной `AILC_TOOL_TIMEOUT_SECS`, отбросив бессмысленное.
///
/// Функция выделена из `Runner::run_build` ради проверяемости: разбор переменной окружения
/// внутри запуска процесса тестом не покрывается, а именно здесь и живёт возможность
/// молчаливо получить нулевой либо мусорный предел. Ноль и нечисловое значение отвергаются в
/// пользу встроенного предела: остановка инструмента немедленно после запуска выглядела бы
/// как «инструмент отсутствует» и снимала бы ось с проверки, то есть ошибка в настройке
/// оборачивалась бы не отказом, а незаметным ослаблением вердикта.
fn build_timeout_secs(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(BUILD_TIMEOUT_SECS)
}

/// Потолок объёма вывода одного внешнего инструмента. Сверх него чтение продолжается (иначе
/// заполнится канал и процесс встанет), но данные отбрасываются, а факт усечения сообщается.
/// Без потолка болтливый инструмент (сборщик, прогон тестов с подробным выводом, покрытие)
/// целиком помещался в память.
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// Сколько ждать завершения дренажа ПОСЛЕ того, как процесс завершён либо остановлен.
///
/// Этот срок и есть исправление вечного зависания. Канал закрывается только когда его
/// закроют ВСЕ держатели, а остановка прямого потомка не останавливает его собственных
/// потомков: `npm test` порождает `node`, тот порождает наблюдатель или демон, и внук
/// продолжает держать унаследованный канал. Прежде здесь стояло безусловное присоединение к
/// потоку дренажа, поэтому чтение не возвращалось никогда. Цикл обслуживания MCP
/// последователен, значит сервер вставал целиком и навсегда.
const DRAIN_GRACE: Duration = Duration::from_secs(3);

/// Результат запуска внешнего инструмента.
pub struct ToolResult {
    /// Удалось ли вообще запустить (false = бинаря нет / ошибка запуска).
    pub ran: bool,
    pub skipped_reason: Option<String>,
    pub exit_ok: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl ToolResult {
    fn skipped(reason: String) -> Self {
        Self {
            ran: false,
            skipped_reason: Some(reason),
            exit_ok: false,
            code: None,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    /// Последние `n` непустых строк вывода (stdout + stderr).
    pub fn tail(&self, n: usize) -> Vec<String> {
        let mut lines: Vec<String> = self
            .stdout
            .lines()
            .chain(self.stderr.lines())
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .collect();
        let len = lines.len();
        if len > n {
            lines = lines.split_off(len - n);
        }
        lines
    }
}

/// Паспорт внешнего инструмента: чем именно выполнялась проверка.
///
/// Нужен по двум причинам. Первая: раздел о средствах разработки в документах по
/// стандартам требует перечня применяемых средств, и перечень без версий бесполезен.
/// Вторая: прогон, о котором неизвестно, какой версией инструмента он выполнен,
/// невоспроизводим, а невоспроизводимый прогон доказательством не является.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPassport {
    /// Имя, под которым инструмент вызывается.
    pub name: String,
    /// Полный путь найденного исполняемого файла.
    pub path: String,
    /// Версия в том виде, в каком её сообщил сам инструмент, либо None, если он о ней
    /// умолчал. Версия не выдумывается: неизвестное остаётся неизвестным.
    pub version: Option<String>,
}

pub struct Runner;

impl Runner {
    /// Есть ли исполняемый файл в PATH (кросс-платформенно).
    pub fn available(bin: &str) -> bool {
        which(bin).is_some()
    }

    /// Паспорт инструмента: путь и версия. None означает, что инструмента нет в PATH.
    ///
    /// Версия спрашивается у самого инструмента общепринятыми ключами. Первая строка
    /// вывода берётся целиком: разбор её на составляющие потребовал бы знания формата
    /// каждого инструмента, а такое знание устаревает быстрее, чем сами инструменты.
    pub fn passport(ctx: &Ctx, bin: &str) -> Option<ToolPassport> {
        let path = which(bin)?;
        let mut version = None;
        for flag in ["--version", "-version", "version", "-V"] {
            let r = Self::run_timeout(ctx, bin, &[flag], 10);
            if !r.ran {
                continue;
            }
            let line = r
                .stdout
                .lines()
                .chain(r.stderr.lines())
                .map(str::trim)
                .find(|l| !l.is_empty());
            if let Some(l) = line {
                // Инструмент, не понявший ключ, обычно печатает подсказку по
                // использованию; такой ответ версией не является.
                let low = l.to_ascii_lowercase();
                if low.starts_with("usage") || low.starts_with("использование") {
                    continue;
                }
                version = Some(l.chars().take(120).collect::<String>());
                break;
            }
        }
        Some(ToolPassport {
            name: bin.to_string(),
            path: path.to_string_lossy().to_string(),
            version,
        })
    }

    /// Запустить `bin args` в корне проекта с дефолтным тайм-аутом.
    /// Бинаря нет либо превышено время: `ToolResult::skipped` (явный пропуск с причиной).
    pub fn run(ctx: &Ctx, bin: &str, args: &[&str]) -> ToolResult {
        Self::run_timeout(ctx, bin, args, DEFAULT_TIMEOUT_SECS)
    }

    /// Запустить инструмент, которому нужно СОБРАТЬ проект: прогон тестов, линтер с
    /// проверкой типов, сборка.
    ///
    /// Обычный лимит писался против зависшего или ожидающего ввода инструмента, и две минуты
    /// для такого случая величина правильная. Компилятору она не подходит, и это установлено
    /// измерением на самом инструменте: собственный набор тестов ailc идёт около восьмидесяти
    /// секунд ЧИСТОГО исполнения при уже готовой сборке, а после любой правки к этому
    /// добавляется компиляция рабочей области. Прежде ось «Тесты» вылетала по времени и
    /// вердикт получал состояние «не подтверждено», то есть hard-ось нельзя было закрыть на
    /// проекте среднего размера ни при каком качестве кода. Хуже того, исход зависел от того,
    /// была ли сборка тёплой, поэтому один и тот же код давал то подтверждённый, то
    /// неподтверждённый результат.
    ///
    /// Значение переопределяется переменной окружения `AILC_TOOL_TIMEOUT_SECS`: в
    /// непрерывной интеграции разумно задать собственный предел, согласованный с лимитом
    /// задания, вместо того чтобы полагаться на встроенный.
    pub fn run_build(ctx: &Ctx, bin: &str, args: &[&str]) -> ToolResult {
        let raw = crate::env::var("AILC_TOOL_TIMEOUT_SECS");
        Self::run_timeout(ctx, bin, args, build_timeout_secs(raw.as_deref()))
    }

    pub fn run_timeout(ctx: &Ctx, bin: &str, args: &[&str], timeout_secs: u64) -> ToolResult {
        if !Self::available(bin) {
            return ToolResult::skipped(format!("инструмент `{bin}` не установлен"));
        }
        let mut child = match Command::new(bin)
            .args(args)
            .current_dir(&ctx.root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return ToolResult::skipped(format!("не удалось запустить `{bin}`: {e}")),
        };

        // Дренаж потоков в отдельных нитях — чтобы заполнение буфера pipe не повесило
        // дочерний процесс, пока мы ждём его завершения.
        let out_d = spawn_drain(child.stdout.take());
        let err_d = spawn_drain(child.stderr.take());

        let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break None; // тайм-аут
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break None,
            }
        };

        // Ждём дренаж ОГРАНИЧЕННОЕ время и забираем то, что успело накопиться. Присоединение
        // к потоку здесь недопустимо: канал может остаться открытым у переживших потомков
        // (см. `DRAIN_GRACE`), и тогда ожидание не закончится никогда.
        let drain_until = Instant::now() + DRAIN_GRACE;
        let stdout = out_d.take(drain_until);
        let stderr = err_d.take(drain_until);

        match status {
            Some(st) => ToolResult {
                ran: true,
                skipped_reason: None,
                exit_ok: st.success(),
                code: st.code(),
                stdout,
                stderr,
            },
            None => ToolResult::skipped(format!(
                "`{bin}` превысил лимит времени ({timeout_secs}с) и был остановлен"
            )),
        }
    }
}

/// Накопитель вывода одного канала внешнего процесса.
struct Drain {
    data: Arc<Mutex<Vec<u8>>>,
    done: Arc<AtomicBool>,
    truncated: Arc<AtomicBool>,
    /// Канал вообще не читался (процесс запущен без перехвата вывода).
    absent: bool,
}

impl Drain {
    /// Забрать накопленное, подождав завершения чтения НЕ ПОЗЖЕ момента `until`.
    ///
    /// Срок задаётся моментом, а не длительностью, потому что каналов два, и оба удерживаются
    /// одним и тем же пережившим потомком. При длительности ожидание было бы
    /// последовательным и удваивалось бы на ровном месте.
    ///
    /// Возвращает то, что успело накопиться, ДАЖЕ если чтение не завершилось: частичный вывод
    /// полезнее пустоты, а ждать дольше нельзя, потому что канал может удерживаться пережившим
    /// потомком неограниченно долго.
    fn take(self, until: Instant) -> String {
        if self.absent {
            return String::new();
        }
        while !self.done.load(Ordering::Relaxed) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        let bytes = self
            .data
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone());
        // Перевод с ЗАМЕНОЙ некорректных последовательностей. Прежде использовалось
        // `read_to_string`, которое на выводе не в UTF-8 возвращает ошибку и оставляет строку
        // ПУСТОЙ; ошибка при этом игнорировалась, и вышележащая логика (признак «тесты
        // прошли», поиск маркеров сбоя, выдержка вывода для человека) рассуждала о пустых
        // данных как о достоверных, то есть потеря вывода была невидимой.
        let mut s = String::from_utf8_lossy(&bytes).into_owned();
        if self.truncated.load(Ordering::Relaxed) {
            s.push_str(&format!(
                "\n[вывод усечён: превышен предел {MAX_OUTPUT_BYTES} байт]"
            ));
        }
        if !self.done.load(Ordering::Relaxed) {
            s.push_str(
                "\n[вывод неполон: канал остался открыт у пережившего потомка, чтение прервано \
                 по сроку ожидания]",
            );
        }
        s
    }
}

/// Запустить чтение канала в отдельном потоке с потолком объёма.
///
/// Чтение продолжается и после достижения потолка, но данные отбрасываются: прекратить читать
/// нельзя, иначе заполнится буфер канала и процесс встанет на записи.
fn spawn_drain<R: Read + Send + 'static>(pipe: Option<R>) -> Drain {
    let data = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let truncated = Arc::new(AtomicBool::new(false));
    let Some(mut p) = pipe else {
        done.store(true, Ordering::Relaxed);
        return Drain {
            data,
            done,
            truncated,
            absent: true,
        };
    };
    let (d2, done2, tr2) = (Arc::clone(&data), Arc::clone(&done), Arc::clone(&truncated));
    std::thread::spawn(move || {
        let mut buf = [0u8; 64 * 1024];
        loop {
            match p.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut g = d2.lock().unwrap_or_else(|e| e.into_inner());
                    if g.len() >= MAX_OUTPUT_BYTES {
                        tr2.store(true, Ordering::Relaxed);
                        continue; // читаем дальше, но не копим
                    }
                    let room = MAX_OUTPUT_BYTES - g.len();
                    let take = n.min(room);
                    g.extend_from_slice(&buf[..take]);
                    if take < n {
                        tr2.store(true, Ordering::Relaxed);
                    }
                }
            }
        }
        done2.store(true, Ordering::Relaxed);
    });
    Drain {
        data,
        done,
        truncated,
        absent: false,
    }
}

/// Кросс-платформенный поиск бинаря по PATH (+ PATHEXT на Windows).
fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.BAT;.CMD".into())
            .split(';')
            .map(str::to_string)
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path) {
        for ext in &exts {
            let candidate = dir.join(format!("{bin}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_testkit::TempTree;

    /// Временное дерево с готовым сценарием оболочки `p.sh`.
    ///
    /// Помощник сохранён (в отличие от простого вызова `TempTree::new`), поскольку он не
    /// только создаёт дерево, но и записывает в него сценарий, который затем запускается
    /// во всех проверках запуска. Возвращается именно дерево, а не контекст проверки:
    /// контекст получается вызовом `ctx()`, а дерево обязано жить до конца теста, иначе
    /// уборка при разрушении объекта удалила бы каталог прямо во время запуска.
    fn tmp_with(script: &str) -> TempTree {
        let t = TempTree::new("runner");
        t.write("p.sh", script);
        t
    }

    /// РЕГРЕССИЯ на вечное зависание. Прямой потомок завершается сразу, но порождённый им
    /// внук продолжает держать унаследованный канал вывода. Прежде здесь стояло безусловное
    /// присоединение к потоку дренажа, а канал закрывается только когда его закроют ВСЕ
    /// держатели, поэтому чтение не возвращалось, пока жив внук (у настоящего демона это
    /// «никогда»). Цикл обслуживания MCP последователен, значит сервер вставал целиком.
    ///
    /// Проверяется именно ВОЗВРАТ управления в разумный срок и сохранение уже полученного
    /// вывода: частичный вывод полезнее пустоты.
    #[cfg(unix)]
    #[test]
    fn переживший_потомок_не_вешает_запуск_навсегда() {
        // Внук живёт заведомо дольше срока ожидания дренажа и держит stdout открытым.
        let t = tmp_with("#!/bin/sh\n( sleep 30 ) &\necho готово\nexit 0\n");
        let ctx = t.ctx();
        let t0 = Instant::now();
        let r = Runner::run_timeout(&ctx, "sh", &["p.sh"], 5);
        let elapsed = t0.elapsed();

        assert!(r.ran, "процесс запустился и завершился штатно");
        assert!(
            r.stdout.contains("готово"),
            "уже полученный вывод сохранён: {:?}",
            r.stdout
        );
        assert!(
            r.stdout.contains("вывод неполон"),
            "неполнота вывода сообщена честно, а не скрыта: {:?}",
            r.stdout
        );
        assert!(
            elapsed < DRAIN_GRACE + Duration::from_secs(7),
            "управление вернулось по сроку ожидания, а не по времени жизни внука: {elapsed:?}"
        );
    }

    /// Вывод не в UTF-8 не имеет права молча превращаться в пустой. Прежде применялось
    /// `read_to_string`, которое на такой последовательности возвращает ошибку и оставляет
    /// строку пустой, а ошибка игнорировалась: вышележащая логика считала пустоту достоверным
    /// выводом инструмента.
    #[cfg(unix)]
    #[test]
    fn вывод_не_в_utf8_не_теряется() {
        let t = tmp_with("#!/bin/sh\nprintf 'нач\\377\\376кон'\n");
        let ctx = t.ctx();
        let r = Runner::run_timeout(&ctx, "sh", &["p.sh"], 5);
        assert!(r.ran, "процесс запустился");
        assert!(
            r.stdout.contains("нач") && r.stdout.contains("кон"),
            "корректная часть вывода сохранена, некорректные байты заменены: {:?}",
            r.stdout
        );
    }

    /// Обычный быстрый процесс не платит за срок ожидания дренажа: канал закрывается сразу,
    /// и запуск завершается почти мгновенно.
    #[cfg(unix)]
    #[test]
    fn обычный_запуск_не_ждёт_срок_дренажа() {
        let t = tmp_with("#!/bin/sh\necho быстро\n");
        let ctx = t.ctx();
        let t0 = Instant::now();
        let r = Runner::run_timeout(&ctx, "sh", &["p.sh"], 5);
        assert!(r.stdout.contains("быстро"));
        assert!(
            !r.stdout.contains("вывод неполон"),
            "полный вывод не помечается неполным: {:?}",
            r.stdout
        );
        assert!(
            t0.elapsed() < DRAIN_GRACE,
            "быстрый процесс не ждёт срока дренажа: {:?}",
            t0.elapsed()
        );
    }

    /// Настройка предела читается из окружения, но бессмысленное значение отвергается в
    /// пользу встроенного: ноль остановил бы инструмент сразу после запуска, и ось молча
    /// вышла бы из проверки вместо того, чтобы честно провалиться.
    #[test]
    fn настройка_предела_отвергает_бессмысленное_значение() {
        assert_eq!(build_timeout_secs(Some("300")), 300);
        assert_eq!(build_timeout_secs(Some("  300  ")), 300);
        assert_eq!(build_timeout_secs(Some("0")), BUILD_TIMEOUT_SECS);
        assert_eq!(build_timeout_secs(Some("много")), BUILD_TIMEOUT_SECS);
        assert_eq!(build_timeout_secs(Some("")), BUILD_TIMEOUT_SECS);
        assert_eq!(build_timeout_secs(None), BUILD_TIMEOUT_SECS);
    }
}
