//! `ailc doctor` — диагностика подключения одним вызовом.
//!
//! Превращает «танцы с бубнами» при установке в детерминированный отчёт: где бинарь,
//! виден ли npx, есть ли засада с nvm, подключён ли ailc в конфиги редакторов, и
//! ГОТОВЫЙ сниппет под каждую обнаруженную среду. Без LLM и без сети.

use std::path::{Path, PathBuf};

/// Точка входа: `ailc doctor [путь-к-проекту]`.
pub fn run(args: &[String]) {
    let root = args.get(2).cloned().unwrap_or_else(|| ".".to_string());
    let root = std::fs::canonicalize(&root).unwrap_or_else(|_| PathBuf::from(&root));

    println!("ailc doctor · диагностика подключения\n");

    // ── Бинарь ──
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok());
    let exe_str = exe
        .as_deref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "неизвестно".to_string());
    println!("Бинарь:    {exe_str}");
    println!(
        "Версия:    {} · платформа {}-{}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    // ── Node и npx (для пути через npx ailc-mcp) ──
    let npx = find_in_path("npx");
    match &npx {
        Some(p) => println!("npx:       найден · {}", p.display()),
        None => println!("npx:       не найден в PATH — путь через `npx ailc-mcp` не сработает"),
    }
    let nvm = home_dir().map(|h| h.join(".nvm").is_dir()).unwrap_or(false);
    if nvm {
        println!(
            "nvm:       обнаружен ~/.nvm — редактор, запущенный из дока или меню, может НЕ\n\
             \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}видеть npx. Надёжнее указать в конфиге абсолютный путь к бинарю ailc."
        );
    }

    // ── Проект ──
    println!("\nПроект:    {}", root.display());
    let mark = |b: bool| if b { "есть" } else { "нет" };
    println!(
        "  git-репозиторий: {} · каталог .ailc: {} · файл .mcp.json: {}",
        mark(root.join(".git").exists()),
        mark(root.join(".ailc").is_dir()),
        mark(root.join(".mcp.json").is_file())
    );

    // ── Подключение в редакторах ──
    println!("\nРедакторы:");
    let project_mcp = read(&root.join(".mcp.json"));
    editor_line(
        "Claude Code",
        project_mcp.as_deref().map(has_ailc_entry),
        ".mcp.json в корне проекта",
    );
    let cursor_cfg = home_dir().map(|h| h.join(".cursor/mcp.json"));
    editor_line(
        "Cursor",
        cursor_cfg
            .as_deref()
            .and_then(read)
            .as_deref()
            .map(has_ailc_entry),
        "~/.cursor/mcp.json",
    );
    println!(
        "  VS Code · Copilot: конфиг открывается через палитру команд, пункт\n\
         \u{20}\u{20}\u{20}\u{20}«MCP: Open User Configuration» (schema `servers`, поле `type: stdio`)."
    );

    // ── Готовые сниппеты ──
    let cmd = exe
        .as_deref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "ailc".to_string());
    println!("\nГотовый сниппет (Claude Code / Cursor, абсолютный путь — работает всегда):");
    println!(
        "  {{ \"mcpServers\": {{ \"ailc\": {{ \"command\": \"{cmd}\", \"args\": [\"serve\"] }} }} }}"
    );
    println!("\nСниппет для VS Code (GitHub Copilot, режим агента):");
    println!(
        "  {{ \"servers\": {{ \"ailc\": {{ \"type\": \"stdio\", \"command\": \"{cmd}\", \"args\": [\"serve\"] }} }} }}"
    );
    if npx.is_some() && !nvm {
        println!("\nКороткий путь через npx (Node установлен без nvm):");
        println!("  {{ \"mcpServers\": {{ \"ailc\": {{ \"command\": \"npx\", \"args\": [\"-y\", \"ailc-mcp\"] }} }} }}");
    }
    println!("\nОдна команда для Claude Code:");
    println!("  claude mcp add ailc -- {cmd} serve");
    println!("\nПосле подключения перезапустите редактор и спросите агента:");
    println!("  «проверь, всё ли ок перед сдачей» — AILC подхватит остальное сам.");
}

/// Строка отчёта по редактору: подключён / не подключён / конфиг не найден.
fn editor_line(name: &str, connected: Option<bool>, where_: &str) {
    let status = match connected {
        Some(true) => "ailc подключён ✓".to_string(),
        Some(false) => format!("конфиг есть ({where_}), ailc в нём НЕ прописан"),
        None => format!("конфиг не найден ({where_})"),
    };
    println!("  {name}: {status}");
}

/// Есть ли в JSON-конфиге запись сервера ailc. Нарочно подстрочно и без парсера:
/// конфиги пишут руками, и битый JSON не должен ронять диагностику.
pub fn has_ailc_entry(config: &str) -> bool {
    config.contains("\"ailc\"")
}

fn read(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

/// Поиск исполняемого файла в PATH текущего процесса (как его видит терминал).
fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{bin}.cmd"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    None
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ailc_entry_detected_in_config() {
        assert!(has_ailc_entry(
            r#"{ "mcpServers": { "ailc": { "command": "npx" } } }"#
        ));
        assert!(!has_ailc_entry(r#"{ "mcpServers": { "other": {} } }"#));
    }

    #[test]
    fn find_in_path_locates_shell() {
        // sh есть на любой Unix-системе; на Windows тест не о нём.
        #[cfg(unix)]
        assert!(find_in_path("sh").is_some());
        assert!(find_in_path("ailc-definitely-missing-binary").is_none());
    }
}
