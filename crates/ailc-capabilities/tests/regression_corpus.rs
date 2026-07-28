//! Регрессионный корпус обнаружения. Закрывает блокер «корпус не подключён к авто-тестам»
//! (B4): даёт ВОСПРОИЗВОДИМОЕ, измеримое доказательство, что детекторы реально находят
//! известные уязвимости и не шумят на чистом коде.
//!
//! Две части. Самодостаточная часть всегда выполняется в непрерывной интеграции: на
//! заведомо уязвимом коде требует находок (true positive по taint, паттернам и секрету),
//! на заведомо чистом коде требует отсутствия опасных находок (контроль ложных
//! срабатываний). Опциональная часть прогоняет внешний корпус (dvwa/nodegoat/flask и т.п.),
//! если путь задан переменной окружения `AILC_BENCH_CORPUS` или лежит рядом с проектом;
//! при отсутствии корпуса осознанно пропускается с явным сообщением, без молчаливого
//! пропуска (инвариант проекта «нет молчаливых пропусков»).

use ailc_contracts::{Ctx, RunInput};
use ailc_core::registry::Registry;
use ailc_testkit::TempTree;

/// Временное дерево-проект с заданными файлами. Возвращает пару из самого дерева и контекста
/// проверки с корнем в этом дереве. Дерево возвращается наружу намеренно: оно убирает свой
/// каталог при разрушении, поэтому обязано быть связано переменной и дожить до конца теста;
/// если его не связать, каталог исчезнет ещё до запуска детекторов.
fn tree(files: &[(&str, &str)]) -> (TempTree, Ctx) {
    let t = TempTree::new("corpus");
    for (rel, content) in files {
        t.write(rel, content);
    }
    let ctx = t.ctx();
    (t, ctx)
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
    let (_t, ctx) = tree(&[(
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
    let (_t, ctx) = tree(&[("v.py", "x = md5(data)\ny = os.system(code)\n")]);
    let found = rules(&ctx, "security.scan/owasp");
    assert!(
        found.contains(&"dangerous-exec".to_string()),
        "A03 os.system: {found:?}"
    );
    assert!(
        found.contains(&"weak-hash".to_string()),
        "A02 md5: {found:?}"
    );
}

// ───────────────────────── True positive: секрет известной формы ─────────────────────────

#[test]
fn corpus_tp_secret_token() {
    // Токен GitLab известной формы glpat-...: строгий токен, опровергаться не должен.
    let (_t, ctx) = tree(&[("config.py", "gl = \"glpat-aBcDeFgHiJkLmNoPqRsT\"\n")]);
    let found = rules(&ctx, "security.scan/secret");
    assert!(
        !found.is_empty(),
        "секрет glpat должен находиться, найдено: {found:?}"
    );
}

// ───────────────────────── Контроль ложных срабатываний на чистом коде ─────────────────────────

#[test]
fn corpus_fp_control_clean_code_quiet() {
    // Заведомо безопасный код: чистая арифметика без ввода, исполнения и крипты. Опасные
    // правила инъекций/крипты НЕ должны срабатывать (контроль ложных срабатываний).
    let (_t, ctx) = tree(&[
        ("math.go", "func add(a int, b int) int { return a + b }\n"),
        ("util.py", "def square(n):\n    return n * n\n"),
    ]);
    const DANGEROUS: &[&str] = &[
        "dangerous-exec",
        "sql-injection",
        "shell-injection",
        "weak-hash",
        "weak-cipher",
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

/// Очередь четвёртая: новые экосистемы. Командный сценарий, рабочий процесс непрерывной
/// интеграции и описание инфраструктуры на языке HCL до этой очереди не покрывались ни
/// одним правилом, поэтому корпус закрепляет сам факт покрытия: регрессия здесь означала
/// бы возврат к молчаливому нулю находок на заведомо уязвимых образцах.
#[test]
fn corpus_tp_новые_экосистемы_находятся() {
    let (_t, ctx) = tree(&[
        (
            "deploy.sh",
            "#!/bin/sh\ncurl -k https://example.test/install.sh | sh\nrm -rf $TARGET\n",
        ),
        (
            ".github/workflows/ci.yml",
            "on: issues\npermissions: write-all\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n",
        ),
        (
            "main.tf",
            "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\n\nprovider \"aws\" {\n  secret_key = \"AKIAIOSFODNN7EXAMPLE0000\"\n}\n",
        ),
    ]);

    let shell = rules(&ctx, "security.scan/shell");
    assert!(
        shell.iter().any(|r| r == "shell-curl-pipe-shell"),
        "загрузка с немедленным исполнением обязана находиться: {shell:?}"
    );
    let ci = rules(&ctx, "security.scan/ci");
    assert!(
        ci.iter().any(|r| r == "ci-untrusted-input-in-run"),
        "подстановка недоверенного поля события в команду обязана находиться: {ci:?}"
    );
    let tf = rules(&ctx, "security.scan/terraform");
    assert!(
        tf.iter().any(|r| r == "tf-public-bucket"),
        "публичное объектное хранилище обязано находиться: {tf:?}"
    );
}

/// Та же очередь на заведомо ЧИСТЫХ образцах: правила новых экосистем не должны шуметь на
/// общепринятых безопасных записях. Контроль ложных срабатываний здесь важнее контроля
/// находок, поскольку блокирующий вердикт на исправном коде обесценивает все остальные
/// правила разом.
#[test]
fn corpus_fp_новые_экосистемы_молчат_на_чистом() {
    let (_t, ctx) = tree(&[
        (
            "deploy.sh",
            "#!/bin/sh\nset -e\ntmp=$(mktemp)\ncurl -fsSL https://example.test/f -o \"$tmp\"\ncp \"$tmp\" \"$HOME/bin/f\"\n",
        ),
        (
            ".github/workflows/ci.yml",
            "on: pull_request\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3\n      - run: cargo test\n",
        ),
        (
            "main.tf",
            "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"private\"\n}\n\nprovider \"aws\" {\n  secret_key = var.aws_secret\n}\n",
        ),
    ]);

    for cap in [
        "security.scan/shell",
        "security.scan/ci",
        "security.scan/terraform",
    ] {
        let found = rules(&ctx, cap);
        assert!(
            found.is_empty(),
            "{cap} обязан молчать на безопасных образцах, но нашёл {found:?}"
        );
    }
}

/// Найти каталог внешнего корпуса: сначала переменная окружения, затем стандартное
/// расположение рядом с репозиторием. None, если корпус недоступен.
fn locate_corpus() -> Option<std::path::PathBuf> {
    if let Some(p) = ailc_core::env::var_os("AILC_BENCH_CORPUS") {
        let path = std::path::PathBuf::from(p);
        if path.is_dir() {
            return Some(path);
        }
    }
    // adsl/ailc/crates/ailc-capabilities -> adsl/bench-corpus
    let fallback = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../bench-corpus");
    fallback.is_dir().then_some(fallback)
}

#[test]
fn corpus_external_vulnerable_apps_have_findings() {
    let Some(root) = locate_corpus() else {
        eprintln!(
            "ПРОПУЩЕНО: внешний корпус не найден. Задайте AILC_BENCH_CORPUS=/путь к каталогу \
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
