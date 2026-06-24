//! Матрица покрытия taint по ВСЕМ заявленным языкам и основным классам стоков. Один и тот
//! же класс уязвимости (недоверенный ввод доходит до опасного стока) выражен идиоматично на
//! каждом из пятнадцати языков движка, для трёх классов: исполнение команды, SQL-инъекция,
//! обход пути. Цель: доказать, что глубокий потоковый анализ срабатывает одинаково на всех
//! заявленных языках. Язык, который здесь падает, это реальный пробел покрытия.

use ailc_contracts::{Ctx, RunInput};
use ailc_core::engines::sast::scan_taint;
use std::sync::atomic::{AtomicU32, Ordering};

static CNT: AtomicU32 = AtomicU32::new(0);

fn tmp(files: &[(&str, &str)]) -> Ctx {
    let n = CNT.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("ailc-taint-langs-{}-{}", std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (rel, content) in files {
        std::fs::write(dir.join(rel), content).unwrap();
    }
    Ctx::new(dir)
}

/// Прогнать матрицу: каждый кейс (язык, файл, код) обязан дать taint-находку с правилом,
/// содержащим `want`. Возвращает список языков-пропусков и печатает матрицу.
fn run_matrix(klass: &str, want: &str, cases: &[(&str, &str, &str)]) {
    let files: Vec<(&str, &str)> = cases.iter().map(|(_, f, code)| (*f, *code)).collect();
    let ctx = tmp(&files);
    let rep = scan_taint(&ctx, &RunInput::default()).unwrap();

    eprintln!("\n=== {klass} ===");
    let mut missing = Vec::new();
    for (lang, file, _) in cases {
        let hit = rep.findings.iter().any(|f| {
            f.location.as_ref().is_some_and(|l| l.file.ends_with(file)) && f.rule.contains(want)
        });
        eprintln!("  {:<11} {}", lang, if hit { "OK" } else { "ПРОПУСК" });
        if !hit {
            missing.push(*lang);
        }
    }
    eprintln!("Покрытие {}: {}/{} языков", klass, cases.len() - missing.len(), cases.len());
    assert!(
        missing.is_empty(),
        "{klass}: taint не сработал для языков {missing:?} (пробел покрытия, требует доработки движка)"
    );
}

#[test]
fn taint_command_injection_all_languages() {
    run_matrix("Исполнение команды", "taint-command-exec", &[
        ("python", "c.py", "import os\ndef v(request):\n    c = request.args.get('c')\n    os.system(c)\n"),
        ("javascript", "c.js", "function v(req){\n  const c = req.query.c;\n  eval(c);\n}\n"),
        ("typescript", "c.ts", "function v(req: any){\n  const c = req.query.c;\n  eval(c);\n}\n"),
        ("go", "c.go", "package main\nfunc v(r *Request){\n    name := r.FormValue(\"n\")\n    exec.Command(\"sh\", \"-c\", name)\n}\n"),
        ("java", "C.java", "class C {\n  void v(HttpServletRequest req) throws Exception {\n    String p = req.getParameter(\"p\");\n    Runtime.getRuntime().exec(p);\n  }\n}\n"),
        ("ruby", "c.rb", "def v(params)\n  c = params[:c]\n  system(c)\nend\n"),
        ("php", "c.php", "<?php\nfunction v(){\n  $c = $_GET['c'];\n  system($c);\n}\n"),
        ("csharp", "C.cs", "class C {\n  void V(){\n    var c = Request.QueryString[\"c\"];\n    System.Diagnostics.Process.Start(c);\n  }\n}\n"),
        ("rust", "c.rs", "fn v(){\n    let c = std::env::var(\"C\").unwrap();\n    std::process::Command::new(\"sh\").arg(\"-c\").arg(c);\n}\n"),
        ("kotlin", "c.kt", "fun v(call: ApplicationCall){\n    val c = call.parameters[\"c\"]\n    Runtime.getRuntime().exec(c)\n}\n"),
        ("scala", "c.scala", "def v(request: Request){\n    val c = request.getQueryString(\"c\")\n    Runtime.getRuntime().exec(c)\n}\n"),
        ("c", "c.c", "#include <stdlib.h>\nvoid v(){\n    char* c = getenv(\"C\");\n    system(c);\n}\n"),
        ("cpp", "c.cpp", "#include <cstdlib>\nvoid v(){\n    const char* c = std::getenv(\"C\");\n    system(c);\n}\n"),
        ("swift", "c.swift", "func v(req: Request) throws {\n    let c = req.query[\"c\"]!\n    system(c)\n}\n"),
        ("dart", "c.dart", "void v(request){\n  var c = request.url.queryParameters['c'];\n  Process.run(c, []);\n}\n"),
    ]);
}

#[test]
fn taint_sql_injection_all_languages() {
    run_matrix("SQL-инъекция", "taint-sql", &[
        ("python", "s.py", "def v(request):\n    q = request.args.get('q')\n    cur.execute(q)\n"),
        ("javascript", "s.js", "function v(req, db){\n  const q = req.query.q;\n  db.query(q);\n}\n"),
        ("typescript", "s.ts", "function v(req: any, db: any){\n  const q = req.query.q;\n  db.query(q);\n}\n"),
        ("go", "s.go", "package main\nfunc v(r *Request, db *DB){\n    q := r.FormValue(\"q\")\n    db.Query(q)\n}\n"),
        ("java", "S.java", "class S {\n  void v(HttpServletRequest req, Statement st) throws Exception {\n    String q = req.getParameter(\"q\");\n    st.executeQuery(q);\n  }\n}\n"),
        ("ruby", "s.rb", "def v(params, conn)\n  q = params[:q]\n  conn.execute(q)\nend\n"),
        ("php", "s.php", "<?php\nfunction v($db){\n  $q = $_GET['q'];\n  $db->query($q);\n}\n"),
        ("csharp", "S.cs", "class S {\n  void V(){\n    var q = Request.QueryString[\"q\"];\n    var cmd = new SqlCommand(q);\n  }\n}\n"),
        ("rust", "s.rs", "fn v(){\n    let q = std::env::var(\"Q\").unwrap();\n    sqlx::query(&q);\n}\n"),
        ("kotlin", "s.kt", "fun v(call: ApplicationCall, st: Statement){\n    val q = call.parameters[\"q\"]\n    st.executeQuery(q)\n}\n"),
        ("scala", "s.scala", "def v(request: Request, st: Statement){\n    val q = request.getQueryString(\"q\")\n    st.executeQuery(q)\n}\n"),
        ("c", "s.c", "#include <mysql.h>\nvoid v(MYSQL* conn){\n    char* q = getenv(\"Q\");\n    mysql_query(conn, q);\n}\n"),
        ("cpp", "s.cpp", "#include <mysql.h>\nvoid v(MYSQL* conn){\n    const char* q = std::getenv(\"Q\");\n    mysql_query(conn, q);\n}\n"),
        ("swift", "s.swift", "func v(req: Request, db: Connection) throws {\n    let q = req.query[\"q\"]!\n    try db.run(q)\n}\n"),
        ("dart", "s.dart", "void v(request, db){\n  var q = request.url.queryParameters['q'];\n  db.rawQuery(q);\n}\n"),
    ]);
}

#[test]
fn taint_path_traversal_all_languages() {
    run_matrix("Обход пути", "taint-path", &[
        ("python", "p.py", "def v(request):\n    p = request.args.get('p')\n    open(p)\n"),
        ("javascript", "p.js", "function v(req){\n  const p = req.query.p;\n  fs.readFileSync(p);\n}\n"),
        ("typescript", "p.ts", "function v(req: any){\n  const p = req.query.p;\n  fs.readFileSync(p);\n}\n"),
        ("go", "p.go", "package main\nfunc v(r *Request){\n    p := r.FormValue(\"p\")\n    os.Open(p)\n}\n"),
        ("java", "P.java", "class P {\n  void v(HttpServletRequest req) throws Exception {\n    String p = req.getParameter(\"p\");\n    new FileInputStream(p);\n  }\n}\n"),
        ("ruby", "p.rb", "def v(params)\n  p = params[:p]\n  File.open(p)\nend\n"),
        ("php", "p.php", "<?php\nfunction v(){\n  $p = $_GET['p'];\n  file_get_contents($p);\n}\n"),
        ("csharp", "P.cs", "class P {\n  void V(){\n    var p = Request.QueryString[\"p\"];\n    File.ReadAllText(p);\n  }\n}\n"),
        ("rust", "p.rs", "fn v(){\n    let p = std::env::var(\"P\").unwrap();\n    std::fs::read(p).unwrap();\n}\n"),
        ("kotlin", "p.kt", "fun v(call: ApplicationCall){\n    val p = call.parameters[\"p\"]\n    File(p).readText()\n}\n"),
        ("scala", "p.scala", "def v(request: Request){\n    val p = request.getQueryString(\"p\")\n    scala.io.Source.fromFile(p)\n}\n"),
        ("c", "p.c", "#include <stdio.h>\nvoid v(){\n    char* p = getenv(\"P\");\n    fopen(p, \"r\");\n}\n"),
        ("cpp", "p.cpp", "#include <cstdio>\nvoid v(){\n    const char* p = std::getenv(\"P\");\n    fopen(p, \"r\");\n}\n"),
        ("swift", "p.swift", "func v(req: Request) throws {\n    let p = req.query[\"p\"]!\n    let h = FileHandle(forReadingAtPath: p)\n}\n"),
        ("dart", "p.dart", "void v(request){\n  var p = request.url.queryParameters['p'];\n  File(p).readAsString();\n}\n"),
    ]);
}
