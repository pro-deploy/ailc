//! ailc — функциональный бенчмарк качества фич.
//!
//! Гоняет КАЖДУЮ зарегистрированную capability и весь front-door агента
//! (`Orchestrator::scan_all` / `dod` / `run`) на реальных внешних репозиториях и
//! выносит честный вердикт: что РЕАЛЬНО работает (а не заявлено).
//!
//! Это не бенч скорости — это бенч ПОКРЫТИЯ и КАЧЕСТВА фич. Для каждой capability
//! по корпусу считается:
//!   • OK      — хотя бы на одной репе дала осмысленный результат (находки/записи/артефакт)
//!               или отработала «чисто» (без ошибок, нечего сообщать);
//!   • SKIP    — на всех репах честно пропущена (корпус не содержит подходящего стека) —
//!               фича есть, но корпусом не задействована;
//!   • FAIL    — где-то упала (panic) / вернула ошибку / превысила лимит времени.
//!
//! Каждый вызов capability изолирован `catch_unwind` + таймаутом: падение или зависание
//! ОДНОЙ фичи не валит весь прогон (нужна debug-сборка — там `panic = unwind`).
//!
//! Запуск:  cargo run --example bench -- <корпус-дир> [вых-дир]
//!   <корпус-дир> — каталог, чьи прямые подкаталоги суть репозитории для прогона.
//!   [вых-дир]    — куда писать REPORT.md + results.json (по умолчанию ./benchmarks).

use ailc_contracts::{Ctx, RunInput, Severity};
use ailc_core::engines::codeintel::CodeIntelEngine;
use ailc_core::orchestrator::Orchestrator;
use ailc_core::registry::Registry;
use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Бюджет времени на ОДИН вызов capability. Runner внутри сам убивает внешний
/// тулчейн по 120с; берём с запасом, после — фиксируем TIMEOUT и идём дальше.
const CAP_BUDGET: Duration = Duration::from_secs(150);
/// Бюджет на ОДИН прогон агента (dod гоняет реальные test+lint несколько стеков).
const AGENT_BUDGET: Duration = Duration::from_secs(600);

#[derive(Clone)]
#[allow(dead_code)] // часть полей — носители данных для JSON/будущих срезов, читаются не все
enum Outcome {
    /// Отработала и выдала содержимое: (findings, records, metrics, artifacts).
    Produced(usize, usize, usize, usize),
    /// Отработала чисто — нечего сообщать (валидный пустой результат сканера).
    Clean,
    /// Честный пропуск с причиной (инвариант «нет молчаливых пропусков»).
    Skip(String),
    /// `cap.run` вернул Err.
    Error(String),
    /// Поймали панику.
    Panic(String),
    /// Превысила бюджет времени.
    Timeout,
}

/// Результат одного вызова (repo × cap).
struct CapRun {
    repo: String,
    id: String,
    family: String,
    engine: String,
    mutates: bool,
    outcome: Outcome,
    sample: Option<String>,
}

/// Изолированный вызов capability с таймаутом и ловлей паники.
/// Возвращает (Outcome, severity-распределение, образец находки, миллисекунды).
fn run_cap_isolated(
    reg: &Registry,
    id: &str,
    ctx: &Ctx,
    input: &RunInput,
) -> (Outcome, [usize; 5], Option<String>, u128) {
    let cap = match reg.get_arc(id) {
        Some(c) => c,
        None => return (Outcome::Error("нет в реестре".into()), [0; 5], None, 0),
    };
    let ctx = ctx.clone();
    let input = input.clone();
    let (tx, rx) = mpsc::channel();
    let start = Instant::now();
    let handle = std::thread::spawn(move || {
        let res = std::panic::catch_unwind(AssertUnwindSafe(|| cap.run(&ctx, &input)));
        let _ = tx.send(res);
    });

    let payload = rx.recv_timeout(CAP_BUDGET);
    let ms = start.elapsed().as_millis();
    let mut sev = [0usize; 5];
    let mut sample = None;

    let outcome = match payload {
        Err(_) => Outcome::Timeout, // поток оставляем — Runner убьёт subprocess сам
        Ok(Err(panic)) => {
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "паника".into());
            Outcome::Panic(msg)
        }
        Ok(Ok(Err(e))) => Outcome::Error(format!("{e}")),
        Ok(Ok(Ok(out))) => {
            for f in &out.findings {
                sev[sev_idx(f.severity)] += 1;
            }
            if let Some(f) = out.findings.first() {
                let loc = f
                    .location
                    .as_ref()
                    .map(|l| format!(" ({}:{})", l.file, l.line))
                    .unwrap_or_default();
                sample = Some(format!("[{}] {} — {}{loc}", f.severity, f.rule, f.message));
            } else if let Some(r) = out.records.first() {
                sample = Some(r.clone());
            } else if let Some(a) = out.artifacts.first() {
                sample = Some(format!("→ {a}"));
            }
            if let Some(reason) = out.skipped {
                Outcome::Skip(reason)
            } else if !out.findings.is_empty()
                || !out.records.is_empty()
                || !out.metrics.is_empty()
                || !out.artifacts.is_empty()
            {
                Outcome::Produced(
                    out.findings.len(),
                    out.records.len(),
                    out.metrics.len(),
                    out.artifacts.len(),
                )
            } else {
                Outcome::Clean
            }
        }
    };
    // Не join'им зависший поток (Timeout) — он завершится сам после kill subprocess.
    if !matches!(outcome, Outcome::Timeout) {
        let _ = handle.join();
    }
    (outcome, sev, sample, ms)
}

fn sev_idx(s: Severity) -> usize {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Выбрать реальный символ репы для query-зависимых фич (find_usages):
/// самый часто встречающийся экспортируемый символ (≥3 симв.), иначе "main".
fn pick_query(ctx: &Ctx) -> String {
    let input = RunInput::default();
    let syms = CodeIntelEngine::symbols(ctx, &input).unwrap_or_default();
    let freq = CodeIntelEngine::identifier_freq(ctx, &input).unwrap_or_default();
    syms.iter()
        .filter(|s| s.exported && s.name.chars().count() >= 3)
        .max_by_key(|s| freq.get(&s.name).copied().unwrap_or(0))
        .map(|s| s.name.clone())
        .unwrap_or_else(|| "main".to_string())
}

/// Прогон агента с таймаутом (отдельный поток): возвращает значение замыкания или None.
fn with_budget<T: Send + 'static>(
    budget: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<(T, u128)> {
    let (tx, rx) = mpsc::channel();
    let start = Instant::now();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(budget) {
        Ok(v) => Some((v, start.elapsed().as_millis())),
        Err(_) => None,
    }
}

struct RepoMeta {
    name: String,
    lang: String,
    commit: String,
    files: usize,
    vulnerable: bool,
}

fn git_short(dir: &Path) -> String {
    std::process::Command::new("git")
        .args(["-C", &dir.display().to_string(), "rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "—".into())
}

fn count_files(dir: &Path) -> usize {
    fn walk(d: &Path, acc: &mut usize) {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                let name = e.file_name();
                if name == ".git" {
                    continue;
                }
                if p.is_dir() {
                    walk(&p, acc);
                } else {
                    *acc += 1;
                }
            }
        }
    }
    let mut n = 0;
    walk(dir, &mut n);
    n
}

/// Грубое определение основного языка по маркер-файлам.
fn detect_lang(dir: &Path) -> String {
    let has = |f: &str| dir.join(f).exists();
    if has("Cargo.toml") {
        "Rust".into()
    } else if has("go.mod") {
        "Go".into()
    } else if has("package.json") {
        "JS/TS".into()
    } else if has("composer.json") || dir.join("index.php").exists() {
        "PHP".into()
    } else if has("pyproject.toml") || has("setup.py") || has("requirements.txt") {
        "Python".into()
    } else if has("pubspec.yaml") {
        "Dart/Flutter".into()
    } else {
        "—".into()
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let corpus = match args.get(1) {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("использование: cargo run --example bench -- <корпус-дир> [вых-дир]");
            std::process::exit(2);
        }
    };
    let outdir = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("benchmarks"));

    // Известные «учебно-уязвимые» приложения — для ground-truth детекта.
    let known_vulnerable = ["nodegoat", "dvwa", "webgoat", "juice", "vulnerable"];

    // Корпус: прямые подкаталоги.
    let mut repos: Vec<RepoMeta> = Vec::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&corpus)
        .unwrap_or_else(|e| panic!("не читается корпус {}: {e}", corpus.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();
    for p in &entries {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let lname = name.to_lowercase();
        repos.push(RepoMeta {
            lang: detect_lang(p),
            commit: git_short(p),
            files: count_files(p),
            vulnerable: known_vulnerable.iter().any(|k| lname.contains(k)),
            name,
        });
    }
    if repos.is_empty() {
        eprintln!("в корпусе {} нет подкаталогов-репозиториев", corpus.display());
        std::process::exit(2);
    }

    // Реестр = источник истины обо ВСЕХ фичах.
    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);
    let cap_ids: Vec<(String, String, String, bool)> = reg
        .manifests()
        .iter()
        .map(|m| {
            (
                m.id.to_string(),
                m.family.to_string(),
                m.engine.to_string(),
                m.mutates,
            )
        })
        .collect();

    eprintln!(
        "ailc bench: {} capability × {} реп\n",
        cap_ids.len(),
        repos.len()
    );

    let mut runs: Vec<CapRun> = Vec::new();
    // Агрегаты агента: repo → (scan_all json, dod json, run json)
    let mut agent_rows: Vec<serde_json::Value> = Vec::new();
    // Детект на уязвимых: repo → BTreeMap<rule, count> по найденному security/quality
    let mut vuln_detect: Vec<serde_json::Value> = Vec::new();

    for repo in &repos {
        let root = corpus.join(&repo.name);
        let ctx = Ctx::new(&root);
        eprintln!("── repo: {} [{}] ──", repo.name, repo.lang);

        let query = pick_query(&ctx);

        // ---- 1. Покрытие: каждая capability ----
        // Немутирующие сперва, мутирующие в конце (чтобы записи генераторов не
        // загрязняли read-only фичи на этой же репе).
        let mut ordered: Vec<&(String, String, String, bool)> = cap_ids.iter().collect();
        ordered.sort_by_key(|(_, _, _, mutates)| *mutates);

        for (id, family, engine, mutates) in ordered {
            let input = RunInput {
                target: None,
                query: Some(query.clone()),
            };
            let (outcome, _sev, sample, ms) = run_cap_isolated(&reg, id, &ctx, &input);
            let mark = match &outcome {
                Outcome::Produced(f, r, _, a) => format!("✓ produced (f{f} r{r} a{a})"),
                Outcome::Clean => "· clean".into(),
                Outcome::Skip(_) => "○ skip".into(),
                Outcome::Error(e) => format!("✗ ERROR: {e}"),
                Outcome::Panic(p) => format!("✗ PANIC: {p}"),
                Outcome::Timeout => "✗ TIMEOUT".into(),
            };
            eprintln!("   {id:<34} {mark}  ({ms}ms)");
            runs.push(CapRun {
                repo: repo.name.clone(),
                id: id.clone(),
                family: family.clone(),
                engine: engine.clone(),
                mutates: *mutates,
                outcome,
                sample,
            });
        }

        // ---- 2. Агент end-to-end ----
        // scan_all (сплошной статический скан)
        eprintln!("   [агент] scan_all …");
        let scan = with_budget(AGENT_BUDGET, {
            let mut r = Registry::new();
            ailc_capabilities::register_core(&mut r);
            let ctx = ctx.clone();
            move || {
                let rep = Orchestrator::scan_all(&r, &ctx, &RunInput::default());
                let mut by_rule: BTreeMap<String, usize> = BTreeMap::new();
                let mut by_sev = [0usize; 5];
                for f in &rep.findings {
                    *by_rule.entry(f.rule.clone()).or_default() += 1;
                    by_sev[sev_idx(f.severity)] += 1;
                }
                // «Сигнал» = confidence >= Medium (дефолтный профиль, без стиле-шума);
                // security-сигнал — он же, ограниченный security-семейством.
                let signal = rep.findings.iter().filter(|f| f.is_signal()).count();
                let sec_signal = rep
                    .findings
                    .iter()
                    .filter(|f| f.is_signal() && f.source.starts_with("security"))
                    .count();
                (
                    rep.findings.len(),
                    rep.refuted,
                    rep.checks_run.len(),
                    rep.checks_skipped.len(),
                    by_rule,
                    by_sev,
                    signal,
                    sec_signal,
                )
            }
        });

        // dod (многоосевой вердикт — реально гоняет verify/test, verify/lint)
        eprintln!("   [агент] dod …");
        let dod = with_budget(AGENT_BUDGET, {
            let mut r = Registry::new();
            ailc_capabilities::register_core(&mut r);
            let ctx = ctx.clone();
            move || {
                let rep = Orchestrator::dod(&r, &ctx, &RunInput::default());
                let axes: Vec<(String, bool, bool, bool)> = rep
                    .axes
                    .iter()
                    .map(|a| (a.name.to_string(), a.hard, a.ran, a.ok))
                    .collect();
                (rep.passed, axes)
            }
        });

        // run (полный пайплайн агента под намерение «проверь безопасность перед сдачей»)
        eprintln!("   [агент] run «проверь безопасность перед сдачей» …");
        let run = with_budget(AGENT_BUDGET, {
            let mut r = Registry::new();
            ailc_capabilities::register_core(&mut r);
            let ctx = ctx.clone();
            move || {
                let l = Orchestrator::deterministic_gate(
                    &r,
                    &ctx,
                    &RunInput::default(),
                    "проверь безопасность перед сдачей",
                    &[
                        ailc_contracts::Family::Security,
                        ailc_contracts::Family::Quality,
                        ailc_contracts::Family::Spec,
                    ],
                    true,
                );
                (
                    l.checks_run,
                    l.findings_total,
                    l.blocking,
                    l.refuted,
                    l.score,
                    l.rigor,
                    l.passed,
                    l.headline,
                )
            }
        });

        // Запись агрегатов агента.
        let scan_json = match &scan {
            Some(((nf, refuted, cr, cs, by_rule, by_sev, signal, sec_signal), ms)) => serde_json::json!({
                "ran": true, "ms": ms,
                "findings": nf, "signal": signal, "sec_signal": sec_signal, "refuted": refuted,
                "checks_run": cr, "checks_skipped": cs,
                "by_severity": {"info": by_sev[0],"low": by_sev[1],"med": by_sev[2],"high": by_sev[3],"crit": by_sev[4]},
                "top_rules": top_n(by_rule.clone(), 12),
            }),
            None => serde_json::json!({"ran": false, "reason": "timeout"}),
        };
        let dod_json = match &dod {
            Some(((passed, axes), ms)) => serde_json::json!({
                "ran": true, "ms": ms, "passed": passed,
                "axes": axes.iter().map(|(n,hard,ran,ok)| serde_json::json!({
                    "name": n, "hard": hard, "ran": ran, "ok": ok
                })).collect::<Vec<_>>(),
            }),
            None => serde_json::json!({"ran": false, "reason": "timeout"}),
        };
        let run_json = match &run {
            Some(((cr, ft, bl, refuted, score, rigor, passed, headline), ms)) => serde_json::json!({
                "ran": true, "ms": ms,
                "checks_run": cr, "findings_total": ft, "blocking": bl, "refuted": refuted,
                "score": score, "rigor": rigor, "passed": passed, "headline": headline,
            }),
            None => serde_json::json!({"ran": false, "reason": "timeout"}),
        };

        agent_rows.push(serde_json::json!({
            "repo": repo.name, "lang": repo.lang, "vulnerable": repo.vulnerable,
            "scan_all": scan_json, "dod": dod_json, "run": run_json,
        }));

        // ---- 3. Ground-truth детект на уязвимых ----
        if repo.vulnerable {
            if let Some(((nf, refuted, _cr, _cs, by_rule, by_sev, signal, sec_signal), _)) = &scan {
                vuln_detect.push(serde_json::json!({
                    "repo": repo.name, "lang": repo.lang,
                    "confirmed_findings": nf, "signal": signal, "sec_signal": sec_signal,
                    "refuted_by_verifier": refuted,
                    "high_plus": by_sev[3] + by_sev[4],
                    "rule_classes_detected": by_rule.len(),
                    "rules": top_n(by_rule.clone(), 40),
                }));
            }
        }
        eprintln!();
    }

    // ───────── Агрегация покрытия по capability ─────────
    let mut per_cap: BTreeMap<String, CapAgg> = BTreeMap::new();
    for r in &runs {
        let e = per_cap.entry(r.id.clone()).or_insert_with(|| CapAgg {
            family: r.family.clone(),
            engine: r.engine.clone(),
            mutates: r.mutates,
            active_on: Vec::new(),
            clean_on: Vec::new(),
            skip_on: Vec::new(),
            fail_on: Vec::new(),
            total_findings: 0,
            sample: None,
        });
        match &r.outcome {
            Outcome::Produced(f, ..) => {
                e.active_on.push(r.repo.clone());
                e.total_findings += f;
                if e.sample.is_none() {
                    e.sample = r.sample.clone();
                }
            }
            Outcome::Clean => e.clean_on.push(r.repo.clone()),
            Outcome::Skip(_) => e.skip_on.push(r.repo.clone()),
            Outcome::Error(why) | Outcome::Panic(why) => {
                e.fail_on.push(format!("{}: {}", r.repo, why))
            }
            Outcome::Timeout => e.fail_on.push(format!("{}: timeout", r.repo)),
        }
    }

    let total_caps = per_cap.len();
    let n_active = per_cap.values().filter(|c| !c.active_on.is_empty()).count();
    let n_clean_only = per_cap
        .values()
        .filter(|c| c.active_on.is_empty() && !c.clean_on.is_empty() && c.fail_on.is_empty())
        .count();
    let n_skip_only = per_cap
        .values()
        .filter(|c| {
            c.active_on.is_empty() && c.clean_on.is_empty() && c.fail_on.is_empty()
        })
        .count();
    let n_fail = per_cap.values().filter(|c| !c.fail_on.is_empty()).count();

    // ───────── JSON ─────────
    std::fs::create_dir_all(&outdir).ok();
    let caps_json: Vec<serde_json::Value> = per_cap
        .iter()
        .map(|(id, c)| {
            serde_json::json!({
                "id": id, "family": c.family, "engine": c.engine, "mutates": c.mutates,
                "status": c.status(),
                "active_on": c.active_on, "clean_on": c.clean_on,
                "skip_on": c.skip_on, "fail_on": c.fail_on,
                "total_findings": c.total_findings, "sample": c.sample,
            })
        })
        .collect();

    let repos_json: Vec<serde_json::Value> = repos
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name, "lang": r.lang, "commit": r.commit,
                "files": r.files, "vulnerable": r.vulnerable,
            })
        })
        .collect();

    let summary = serde_json::json!({
        "caps_total": total_caps,
        "caps_active": n_active,
        "caps_clean_only": n_clean_only,
        "caps_skip_only": n_skip_only,
        "caps_fail": n_fail,
        "repos": repos.len(),
    });

    let full = serde_json::json!({
        "tool": "ailc functional benchmark",
        "version": env!("CARGO_PKG_VERSION"),
        "summary": summary,
        "repos": repos_json,
        "capabilities": caps_json,
        "agent": agent_rows,
        "vulnerable_detection": vuln_detect,
    });
    let json_path = outdir.join("results.json");
    std::fs::write(&json_path, serde_json::to_string_pretty(&full).unwrap()).ok();

    // ───────── Markdown ─────────
    let md = render_md(&repos, &per_cap, &summary, &agent_rows, &vuln_detect);
    let md_path = outdir.join("REPORT.md");
    std::fs::write(&md_path, md).ok();

    eprintln!(
        "ИТОГО: {n_active}/{total_caps} capability активны, {n_clean_only} чисто, {n_skip_only} только-skip, {n_fail} FAIL"
    );
    eprintln!("отчёт: {}\njson:  {}", md_path.display(), json_path.display());
}

struct CapAgg {
    family: String,
    engine: String,
    mutates: bool,
    active_on: Vec<String>,
    clean_on: Vec<String>,
    skip_on: Vec<String>,
    fail_on: Vec<String>,
    total_findings: usize,
    sample: Option<String>,
}

impl CapAgg {
    fn status(&self) -> &'static str {
        if !self.fail_on.is_empty() {
            "FAIL"
        } else if !self.active_on.is_empty() {
            "OK"
        } else if !self.clean_on.is_empty() {
            "OK·clean"
        } else {
            "SKIP"
        }
    }
}

fn top_n(map: BTreeMap<String, usize>, n: usize) -> Vec<(String, usize)> {
    let mut v: Vec<(String, usize)> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

fn render_md(
    repos: &[RepoMeta],
    per_cap: &BTreeMap<String, CapAgg>,
    summary: &serde_json::Value,
    agent_rows: &[serde_json::Value],
    vuln: &[serde_json::Value],
) -> String {
    let mut s = String::new();
    s.push_str("# ailc — функциональный бенчмарк (реальные репозитории)\n\n");
    s.push_str(&format!(
        "Бенч покрывает **все {} capability** + front-door агента (`scan_all` / `dod` / `run`) \
         на реальных внешних репозиториях. Это бенч **покрытия и качества фич**, не скорости. \
         Каждая фича изолирована (catch_unwind + таймаут): падение одной не валит прогон.\n\n",
        summary["caps_total"]
    ));

    // Сводка.
    s.push_str("## Сводка\n\n");
    s.push_str(&format!(
        "| Метрика | Значение |\n|---|---|\n\
         | Capability всего | {} |\n\
         | — активны (дали результат ≥1 репе) | **{}** |\n\
         | — отработали чисто (нечего сообщать) | {} |\n\
         | — только пропуск (корпус не задействовал) | {} |\n\
         | — **FAIL** (паника/ошибка/таймаут) | {} |\n\
         | Репозиториев в корпусе | {} |\n\n",
        summary["caps_total"],
        summary["caps_active"],
        summary["caps_clean_only"],
        summary["caps_skip_only"],
        summary["caps_fail"],
        summary["repos"],
    ));

    // Корпус.
    s.push_str("## Корпус\n\n| Репозиторий | Язык | Commit | Файлов | Уязвимый? |\n|---|---|---|---:|:---:|\n");
    for r in repos {
        s.push_str(&format!(
            "| {} | {} | `{}` | {} | {} |\n",
            r.name,
            r.lang,
            r.commit,
            r.files,
            if r.vulnerable { "да (ground-truth)" } else { "—" }
        ));
    }
    s.push('\n');

    // Покрытие по capability.
    s.push_str("## Покрытие фич\n\n");
    s.push_str("Статус: **OK** — дала осмысленный результат; **OK·clean** — отработала без находок; **SKIP** — везде честный пропуск (нет стека в корпусе); **FAIL** — упала/ошибка/таймаут.\n\n");
    s.push_str("| Capability | Сем. | Движок | Статус | Активна на | Σ находок | Образец |\n|---|---|---|:---:|---|---:|---|\n");
    // Сначала FAIL, потом OK, потом clean/skip — чтобы проблемы были сверху.
    let order = |st: &str| match st {
        "FAIL" => 0,
        "OK" => 1,
        "OK·clean" => 2,
        _ => 3,
    };
    let mut rows: Vec<(&String, &CapAgg)> = per_cap.iter().collect();
    rows.sort_by(|a, b| {
        order(a.1.status())
            .cmp(&order(b.1.status()))
            .then(a.0.cmp(b.0))
    });
    for (id, c) in rows {
        let active = if c.active_on.is_empty() {
            "—".to_string()
        } else {
            c.active_on.join(", ")
        };
        let sample = c
            .sample
            .as_deref()
            .map(|x| {
                let x = x.replace('|', "\\|");
                if x.chars().count() > 70 {
                    format!("{}…", x.chars().take(70).collect::<String>())
                } else {
                    x
                }
            })
            .unwrap_or_default();
        let fail = if c.fail_on.is_empty() {
            String::new()
        } else {
            format!(" ⚠ {}", c.fail_on.join("; "))
        };
        s.push_str(&format!(
            "| `{}` | {} | {} | {} | {}{} | {} | {} |\n",
            id,
            c.family,
            c.engine,
            c.status(),
            active,
            fail,
            c.total_findings,
            sample
        ));
    }
    s.push('\n');

    // Агент.
    s.push_str("## Агент end-to-end\n\n");
    s.push_str("`scan_all` — сплошной статический скан (Security/Quality/Compliance/Spec, с verify-проходом). `dod` — Definition of Done (реально гоняет тесты+линт стека). `run` — полный пайплайн под намерением «проверь безопасность перед сдачей».\n\n");
    s.push_str("| Репо | scan_all: всего→**сигнал** (security) / проверок | DoD: вердикт (оси ✓/всего) | run: score/rigor, блокеров, вердикт |\n|---|---|---|---|\n");
    for a in agent_rows {
        let repo = a["repo"].as_str().unwrap_or("?");
        let scan = &a["scan_all"];
        let dod = &a["dod"];
        let run = &a["run"];
        let scan_cell = if scan["ran"].as_bool().unwrap_or(false) {
            format!(
                "{}→**{}** (sec {}) / {} run",
                scan["findings"], scan["signal"], scan["sec_signal"], scan["checks_run"]
            )
        } else {
            "⏱ timeout".into()
        };
        let dod_cell = if dod["ran"].as_bool().unwrap_or(false) {
            let axes = dod["axes"].as_array().cloned().unwrap_or_default();
            let ok = axes.iter().filter(|x| x["ok"].as_bool().unwrap_or(false)).count();
            let verdict = if dod["passed"].as_bool().unwrap_or(false) {
                "✓ DoD"
            } else {
                "✗ DoD"
            };
            format!("{verdict} ({ok}/{})", axes.len())
        } else {
            "⏱ timeout".into()
        };
        let run_cell = if run["ran"].as_bool().unwrap_or(false) {
            format!(
                "{:.0}/{:.0}, {} блок, {}",
                run["score"].as_f64().unwrap_or(0.0),
                run["rigor"].as_f64().unwrap_or(0.0),
                run["blocking"],
                if run["passed"].as_bool().unwrap_or(false) { "✓" } else { "✗" }
            )
        } else {
            "⏱ timeout".into()
        };
        s.push_str(&format!("| {repo} | {scan_cell} | {dod_cell} | {run_cell} |\n"));
    }
    s.push('\n');

    // Детект на уязвимых.
    if !vuln.is_empty() {
        s.push_str("## Детект на заведомо уязвимых приложениях (ground-truth)\n\n");
        s.push_str("Учебно-уязвимые приложения OWASP — здесь находки ОЖИДАЕМЫ. Показано, сколько подтверждённых находок прошло verify-проход, сколько опровергнуто, и какие классы правил сработали.\n\n");
        for v in vuln {
            s.push_str(&format!(
                "### {} ({})\n\n- Подтверждённых: **{}** → сигнал **{}** (security **{}**) · опроверг. Verifier'ом: {} · HIGH+: {} · классов правил: {}\n\n",
                v["repo"].as_str().unwrap_or("?"),
                v["lang"].as_str().unwrap_or("?"),
                v["confirmed_findings"].as_u64().unwrap_or(0),
                v["signal"].as_u64().unwrap_or(0),
                v["sec_signal"].as_u64().unwrap_or(0),
                v["refuted_by_verifier"].as_u64().unwrap_or(0),
                v["high_plus"].as_u64().unwrap_or(0),
                v["rule_classes_detected"].as_u64().unwrap_or(0),
            ));
            if let Some(rules) = v["rules"].as_array() {
                s.push_str("| Правило | Срабатываний |\n|---|---:|\n");
                for r in rules {
                    if let Some(pair) = r.as_array() {
                        s.push_str(&format!("| `{}` | {} |\n", pair[0], pair[1]));
                    }
                }
                s.push('\n');
            }
        }
    }

    s.push_str("## Как воспроизвести\n\n```sh\n# корпус: реальные внешние репы (depth-1)\nmkdir -p ../bench-corpus && cd ../bench-corpus\ngit clone --depth 1 https://github.com/OWASP/NodeGoat.git nodegoat\ngit clone --depth 1 https://github.com/digininja/DVWA.git dvwa\ngit clone --depth 1 https://github.com/pallets/flask.git flask\ngit clone --depth 1 https://github.com/spf13/cobra.git cobra\ngit clone --depth 1 https://github.com/sharkdp/fd.git fd\ncd -\n\n# debug-сборка обязательна: catch_unwind ловит панику одной фичи (release = panic-abort)\ncargo run --example bench -- ../bench-corpus benchmarks\n```\n\n_Замечание: SKIP ≠ дефект. Это значит, что в корпусе нет соответствующего стека (например, mobile/desktop/compliance-РФ). Чтобы задействовать такие фичи — добавьте в корпус Flutter/.NET/российский проект; harness берёт любой каталог реп._\n");

    s
}
