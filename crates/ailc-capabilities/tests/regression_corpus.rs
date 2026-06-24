//! Регрессионный корпус обнаружения. Закрывает блокер «корпус не подключён к авто-тестам»
//! (B4): даёт ВОСПРОИЗВОДИМОЕ, измеримое доказательство, что детекторы реально находят
//! известные уязвимости и не шумят на чистом коде.
//!
//! Две части. Самодостаточная часть всегда выполняется в непрерывной интеграции: на
//! заведомо уязвимом коде требует находок (true positive по taint, паттернам и секрету),
//! на заведомо чистом коде требует отсутствия опасных находок (контроль ложных
//! срабатываний). Опциональная часть прогоняет внешний корпус (dvwa/nodegoat/flask и т.п.),
//! если путь задан переменной окружения `CO_MCP_BENCH_CORPUS` или лежит рядом с проектом;
//! при отсутствии корпуса осознанно пропускается с явным сообщением, без молчаливого
//! пропуска (инвариант проекта «нет молчаливых пропусков»).

use ailc_contracts::{Ctx, RunInput};
use ailc_core::registry::Registry;
use std::sync::atomic::{AtomicU32, Ordering};

static CNT: AtomicU32 = AtomicU32::new(0);

fn tmp(files: &[(&str, &str)]) -> Ctx {
    let n = CNT.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("ailc-corpus-{}-{}", std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (rel, content) in files {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }
    Ctx::new(dir)
}

fn reg() -> Registry {
    let mut r = Registry::new();
    ailc_capabilities::register_core(&mut r);
    r
}

/// Идентификаторы сработавших правил по конкретной capability на данном проекте.
fn rules(ctx: &Ctx, cap_id: &str) -> Vec<String> {
    reg()
        .get(cap_id)
        .unwrap_or_else(|| panic!("capability `{cap_id}` должна быть зарегистрирована"))
        .run(ctx, &RunInput::default())
        .unwrap()
        .findings
        .iter()
        .map(|f| f.rule.clone())
        .collect()
}

// ───────────────────────── True positive: поток данных (taint) ─────────────────────────

#[test]
fn corpus_tp_taint_command_injection() {
    // Канонический поток: недоверенный ввод request.args.get(...) через присваивание
    // доходит до стока os.system. Это то, что одно-операторный анализ и regex пропускают,
    // а межпроцедурный taint обязан ловить (правило sast/taint-command-exec).
    let ctx = tmp(&[(
        "app.py",
        "def handler(request):\n    cmd = request.args.get('c')\n    os.system(cmd)\n",
    )]);
    let found = rules(&ctx, "security.scan/taint");
    assert!(
        found.iter().any(|r| r.contains("taint")),
        "taint от request.args.get к os.system должен находиться, найдено: {found:?}"
    );
}

// ───────────────────────── True positive: паттерны OWASP ─────────────────────────

#[test]
fn corpus_tp_owasp_exec_and_weak_hash() {
    // A03 опасное исполнение команды ОС (os.system) и A02 слабый хеш (md5): оба обязаны
    // находиться. Голый eval/exec выведен из паттерна в потоковый сток
    // sast/taint-dynamic-exec, поэтому A03 проверяем на os.system.
    let ctx = tmp(&[("v.py", "x = md5(data)\ny = os.system(code)\n")]);
    let found = rules(&ctx, "security.scan/owasp");
    assert!(found.contains(&"dangerous-exec".to_string()), "A03 os.system: {found:?}");
    assert!(found.contains(&"weak-hash".to_string()), "A02 md5: {found:?}");
}

// ───────────────────────── True positive: секрет известной формы ─────────────────────────

#[test]
fn corpus_tp_secret_token() {
    // Токен GitLab известной формы glpat-...: строгий токен, опровергаться не должен.
    let ctx = tmp(&[("config.py", "gl = \"glpat-aBcDeFgHiJkLmNoPqRsT\"\n")]);
    let found = rules(&ctx, "security.scan/secret");
    assert!(!found.is_empty(), "секрет glpat должен находиться, найдено: {found:?}");
}

// ───────────────────────── Контроль ложных срабатываний на чистом коде ─────────────────────────

#[test]
fn corpus_fp_control_clean_code_quiet() {
    // Заведомо безопасный код: чистая арифметика без ввода, исполнения и крипты. Опасные
    // правила инъекций/крипты НЕ должны срабатывать (контроль ложных срабатываний).
    let ctx = tmp(&[
        ("math.go", "func add(a int, b int) int { return a + b }\n"),
        ("util.py", "def square(n):\n    return n * n\n"),
    ]);
    const DANGEROUS: &[&str] = &[
        "dangerous-exec",
        "sql-injection",
        "shell-injection",
        "weak-hash",
        "weak-crypto",
        "xss-sink",
        "ssrf",
    ];
    let owasp = rules(&ctx, "security.scan/owasp");
    assert!(
        !owasp.iter().any(|r| DANGEROUS.contains(&r.as_str())),
        "чистый код не должен давать опасных OWASP-находок: {owasp:?}"
    );
    let taint = rules(&ctx, "security.scan/taint");
    assert!(
        taint.is_empty(),
        "чистый код не должен давать taint-потоков: {taint:?}"
    );
}

// ───────────────────────── Опциональный прогон внешнего корпуса ─────────────────────────

/// Найти каталог внешнего корпуса: сначала переменная окружения, затем стандартное
/// расположение рядом с репозиторием. None, если корпус недоступен.
fn locate_corpus() -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os("CO_MCP_BENCH_CORPUS") {
        let path = std::path::PathBuf::from(p);
        if path.is_dir() {
            return Some(path);
        }
    }
    // adsl/ailc/crates/ailc-capabilities -> adsl/bench-corpus
    let fallback = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../bench-corpus");
    fallback.is_dir().then(|| fallback)
}

#[test]
fn corpus_external_vulnerable_apps_have_findings() {
    let Some(root) = locate_corpus() else {
        eprintln!(
            "ПРОПУЩЕНО: внешний корпус не найден. Задайте CO_MCP_BENCH_CORPUS=/путь к каталогу \
             с dvwa/nodegoat/flask, чтобы прогнать регрессию по реальным уязвимым приложениям."
        );
        return;
    };
    // Известно уязвимые приложения корпуса должны давать заметное число OWASP-находок.
    // Порог намеренно мягкий: цель доказать, что детекторы реально срабатывают на реальном
    // коде, а не зафиксировать точное число (оно зависит от состава корпуса).
    let found = rules(&Ctx::new(root.clone()), "security.scan/owasp");
    assert!(
        found.len() >= 3,
        "внешний корпус {root:?} должен давать находки OWASP, найдено {}: {found:?}",
        found.len()
    );
}
