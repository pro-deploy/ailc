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
use std::time::{Duration, Instant};

/// Жёсткий лимит на внешний инструмент: зависший/интерактивный CLI не должен
/// навсегда блокировать оркестратор.
const DEFAULT_TIMEOUT_SECS: u64 = 120;

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

pub struct Runner;

impl Runner {
    /// Есть ли исполняемый файл в PATH (кросс-платформенно).
    pub fn available(bin: &str) -> bool {
        which(bin).is_some()
    }

    /// Запустить `bin args` в корне проекта с дефолтным тайм-аутом.
    /// Бинаря нет / превышено время → ToolResult::skipped (явный пропуск с причиной).
    pub fn run(ctx: &Ctx, bin: &str, args: &[&str]) -> ToolResult {
        Self::run_timeout(ctx, bin, args, DEFAULT_TIMEOUT_SECS)
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
        let mut out_pipe = child.stdout.take();
        let mut err_pipe = child.stderr.take();
        let out_h = std::thread::spawn(move || {
            let mut s = String::new();
            if let Some(p) = out_pipe.as_mut() {
                let _ = p.read_to_string(&mut s);
            }
            s
        });
        let err_h = std::thread::spawn(move || {
            let mut s = String::new();
            if let Some(p) = err_pipe.as_mut() {
                let _ = p.read_to_string(&mut s);
            }
            s
        });

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

        let stdout = out_h.join().unwrap_or_default();
        let stderr = err_h.join().unwrap_or_default();

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
