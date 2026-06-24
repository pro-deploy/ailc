//! Автофикс — БЕЗОПАСНАЯ починка: запускаем собственные авто-фиксеры проекта
//! (форматтеры + линтеры с `--fix`). Это детерминированно чинит формат/стиль/линт.
//! Семантику/безопасность (секрет, инъекция) НЕ трогаем — их решает человек.
//! Это и есть «чинит за них» в безопасном объёме + шаг fix в loop-until-dry.

use crate::engines::runner::Runner;
use ailc_contracts::Ctx;

pub struct FixStep {
    pub tool: String,
    pub ran: bool,
    pub ok: bool,
    pub note: String,
}

pub struct Fixer;

impl Fixer {
    /// Запустить применимые авто-фиксеры по типу проекта. Каждый — отдельным шагом,
    /// недоступные пропускаются явно (нет молчаливых пропусков).
    pub fn run(ctx: &Ctx) -> Vec<FixStep> {
        let has = |f: &str| ctx.root.join(f).exists();
        let mut steps = Vec::new();

        if has("Cargo.toml") {
            steps.push(step(ctx, "cargo", &["fmt"]));
            steps.push(step(
                ctx,
                "cargo",
                &["clippy", "--fix", "--allow-dirty", "--allow-no-vcs", "--workspace"],
            ));
        }
        if has("go.mod") {
            steps.push(step(ctx, "gofmt", &["-w", "."]));
        }
        if has("pyproject.toml") || has("requirements.txt") || has("setup.py") {
            steps.push(step(ctx, "ruff", &["check", "--fix", "."]));
            steps.push(step(ctx, "ruff", &["format", "."]));
        }
        if has("package.json") {
            steps.push(step(ctx, "eslint", &[".", "--fix"]));
            steps.push(step(ctx, "prettier", &["-w", "."]));
        }
        // Остальные стеки движка — формат/линт-фикс, где есть стандартный инструмент.
        if has("build.sbt") {
            steps.push(step(ctx, "scalafmt", &["."]));
        }
        if has("build.gradle.kts") || has("build.gradle") {
            steps.push(step(ctx, "ktlint", &["-F"]));
        }
        if has("Package.swift") {
            steps.push(step(ctx, "swiftformat", &["."]));
        }
        if has("pubspec.yaml") {
            steps.push(step(ctx, "dart", &["format", "."]));
        }
        if has("Gemfile") {
            steps.push(step(ctx, "rubocop", &["-A"]));
        }
        if has("composer.json") {
            steps.push(step(ctx, "php-cs-fixer", &["fix"]));
        }
        if crate::stack::has_ext(&ctx.root, &[".sln", ".csproj"]) {
            steps.push(step(ctx, "dotnet", &["format"]));
        }
        steps
    }
}

fn step(ctx: &Ctx, bin: &str, args: &[&str]) -> FixStep {
    let label = format!("{bin} {}", args.join(" "));
    let r = Runner::run(ctx, bin, args);
    if !r.ran {
        FixStep {
            tool: label,
            ran: false,
            ok: false,
            note: r.skipped_reason.unwrap_or_else(|| "недоступен".into()),
        }
    } else {
        FixStep {
            tool: label,
            ran: true,
            ok: r.exit_ok,
            note: if r.exit_ok {
                "применён".into()
            } else {
                format!("завершился с кодом {:?}", r.code)
            },
        }
    }
}
