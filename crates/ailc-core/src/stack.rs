//! Определение стека проекта по манифестам сборки — ЕДИНЫЙ источник истины.
//!
//! Используется и аркой (`generate/architecture`, раздел «Развёртывание»), и контекстом
//! планировщику (`orchestrator::project_context`). Покрывает все 15 языков движка;
//! манифесты с переменным именем (C#/.NET — `*.csproj`/`*.sln`, Xcode — `*.xcodeproj`)
//! распознаются по расширению в корне.

use std::path::Path;

/// Есть ли в корне файл/папка с одним из расширений (для манифестов с переменным
/// именем: `*.csproj`/`*.sln` — C#, `*.xcodeproj` — Xcode).
pub fn has_ext(root: &Path, exts: &[&str]) -> bool {
    std::fs::read_dir(root)
        .map(|rd| {
            rd.flatten().any(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                exts.iter().any(|x| n.ends_with(x))
            })
        })
        .unwrap_or(false)
}

/// Метки стека по найденным манифестам (дедуплицированы, в порядке таблицы).
/// Пустой результат = стек не распознан.
pub fn detect(root: &Path) -> Vec<&'static str> {
    const M: &[(&str, &str)] = &[
        ("Cargo.toml", "Rust"),
        ("go.mod", "Go"),
        ("package.json", "Node/JS/TS"),
        ("pyproject.toml", "Python"),
        ("requirements.txt", "Python"),
        ("setup.py", "Python"),
        ("pom.xml", "Java/Maven"),
        ("build.gradle", "JVM/Gradle"),
        ("build.gradle.kts", "Kotlin/Gradle"),
        ("build.sbt", "Scala/sbt"),
        ("Gemfile", "Ruby"),
        ("composer.json", "PHP"),
        ("Package.swift", "Swift/SwiftPM"),
        ("Podfile", "iOS/CocoaPods"),
        ("pubspec.yaml", "Flutter/Dart"),
        ("CMakeLists.txt", "C/C++ (CMake)"),
        ("Makefile", "Make"),
    ];
    let mut found: Vec<&'static str> = Vec::new();
    for (f, label) in M {
        if root.join(f).exists() && !found.contains(label) {
            found.push(label);
        }
    }
    if has_ext(root, &[".csproj", ".sln"]) && !found.contains(&"C#/.NET") {
        found.push("C#/.NET");
    }
    if has_ext(root, &[".xcodeproj"]) && !found.contains(&"Swift/Xcode") {
        found.push("Swift/Xcode");
    }
    // Запасной признак по расширениям исходных файлов. Манифест сборки есть не у всякого
    // проекта: одиночный сервис на Flask из нескольких файлов `.py`, набор сценариев или
    // учебный репозиторий манифеста не имеют, и прежде такой проект получал отметку «стек
    // не распознан», из-за чего часть осей вердикта не выполнялась вовсе. Признак по
    // расширениям заведомо слабее манифеста, поэтому применяется ТОЛЬКО когда манифестов
    // не нашлось ни одного, и берётся единственный преобладающий язык.
    if found.is_empty() {
        if let Some(label) = dominant_language(root) {
            found.push(label);
        }
    }
    found
}

/// Преобладающий язык по расширениям файлов в корне и на один уровень вглубь.
///
/// Обход намеренно неглубокий и дешёвый: паспорт обязан вычисляться на каждый прогон.
/// Возвращает метку языка, если его файлов не меньше [`MIN_SOURCE_FILES`] и он строго
/// преобладает; при неоднозначности возвращает None, чтобы не выдумывать стек.
fn dominant_language(root: &Path) -> Option<&'static str> {
    const MIN_SOURCE_FILES: usize = 2;
    const BY_EXT: &[(&str, &str)] = &[
        ("rs", "Rust"),
        ("go", "Go"),
        ("py", "Python"),
        ("ts", "Node/JS/TS"),
        ("tsx", "Node/JS/TS"),
        ("js", "Node/JS/TS"),
        ("jsx", "Node/JS/TS"),
        ("java", "Java/Maven"),
        ("kt", "Kotlin/Gradle"),
        ("scala", "Scala/sbt"),
        ("rb", "Ruby"),
        ("php", "PHP"),
        ("swift", "Swift/SwiftPM"),
        ("dart", "Flutter/Dart"),
        ("cs", "C#/.NET"),
        ("cpp", "C/C++ (CMake)"),
        ("cc", "C/C++ (CMake)"),
        ("c", "C/C++ (CMake)"),
    ];

    let mut counts: std::collections::BTreeMap<&'static str, usize> = Default::default();
    let mut count_dir = |dir: &Path| {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let path = e.path();
            if !path.is_file() {
                continue;
            }
            let ext = path
                .extension()
                .and_then(|x| x.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if let Some((_, label)) = BY_EXT.iter().find(|(x, _)| *x == ext) {
                *counts.entry(label).or_default() += 1;
            }
        }
    };
    count_dir(root);
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name();
            let name = name.to_string_lossy();
            // Служебные и зависимые каталоги в подсчёт не входят.
            if p.is_dir() && !name.starts_with('.') && name != "node_modules" && name != "target" {
                count_dir(&p);
            }
        }
    }

    let mut ranked: Vec<(&'static str, usize)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    match ranked.as_slice() {
        [(label, n), rest @ ..] if *n >= MIN_SOURCE_FILES => {
            let ambiguous = rest.first().is_some_and(|(_, m)| *m == *n);
            (!ambiguous).then_some(*label)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str, files: &[&str]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ailc-stack-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for rel in files {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "x").unwrap();
        }
        dir
    }

    /// T-11: проект без манифеста сборки опознаётся по расширениям исходников.
    #[test]
    fn стек_по_расширениям_без_манифеста() {
        let d = tmp("py", &["app.py", "views.py", "utils/helpers.py"]);
        assert_eq!(detect(&d), vec!["Python"]);
        std::fs::remove_dir_all(&d).ok();
    }

    /// Манифест всегда важнее расширений: запасной признак не применяется.
    #[test]
    fn манифест_имеет_приоритет_над_расширениями() {
        let d = tmp("mixed", &["Cargo.toml", "a.py", "b.py", "c.py"]);
        assert_eq!(detect(&d), vec!["Rust"]);
        std::fs::remove_dir_all(&d).ok();
    }

    /// При равенстве языков стек не выдумывается.
    #[test]
    fn неоднозначность_не_даёт_стек() {
        let d = tmp("amb", &["a.py", "b.py", "a.rb", "b.rb"]);
        assert!(detect(&d).is_empty());
        std::fs::remove_dir_all(&d).ok();
    }

    /// Единственный файл слишком слабый признак.
    #[test]
    fn единственный_файл_не_даёт_стек() {
        let d = tmp("one", &["script.py"]);
        assert!(detect(&d).is_empty());
        std::fs::remove_dir_all(&d).ok();
    }
}
