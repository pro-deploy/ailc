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
    found
}
