//! Минимальный MCP-сервер поверх stdio (newline-delimited JSON-RPC 2.0).
//!
//! Двунаправленный: помимо ответов клиенту умеет САМ запросить у клиента LLM через
//! `sampling/createMessage` (для E4 LlmPlanner). `Session` реализует трейт ядра
//! `Sampler`, поэтому ядро ничего не знает о транспорте. Наружу — один front-door
//! инструмент `plan`.

use ailc_contracts::{Ctx, QualityLedger, RunInput};
use ailc_core::agent::AgentOrchestrator;
use ailc_core::engines::generator::Generator;
use ailc_core::engines::index::Index;
use ailc_core::orchestrator::{Orchestrator, Sampler};
use ailc_core::registry::Registry;
use serde_json::{json, Value};
use std::io::{self, BufRead, StdinLock, StdoutLock, Write};

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Сессия: владеет потоками ввода/вывода и состоянием (поддержка sampling).
struct Session<'a> {
    reader: StdinLock<'a>,
    out: StdoutLock<'a>,
    sampling: bool,
    next_id: i64,
}

impl Session<'_> {
    fn read_line(&mut self) -> Option<String> {
        let mut buf = String::new();
        match self.reader.read_line(&mut buf) {
            Ok(0) => None,
            Ok(_) => Some(buf),
            Err(_) => None,
        }
    }

    fn send(&mut self, v: &Value) {
        let _ = writeln!(self.out, "{v}");
        let _ = self.out.flush();
    }
}

/// Запрос LLM у клиента через MCP sampling. Шлёт запрос и ждёт ответ с тем же id.
impl Sampler for Session<'_> {
    fn sample(&mut self, system: &str, user: &str) -> Option<String> {
        if !self.sampling {
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "sampling/createMessage",
            "params": {
                "messages": [{ "role": "user", "content": { "type": "text", "text": user } }],
                "systemPrompt": system,
                "maxTokens": 1024
            }
        }));
        // Читаем кадры, пока не придёт ответ с нашим id.
        loop {
            let line = self.read_line()?;
            if line.trim().is_empty() {
                continue;
            }
            let msg: Value = serde_json::from_str(&line).ok()?;
            if msg.get("id") == Some(&json!(id)) {
                return msg
                    .pointer("/result/content/text")
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
            // Прочие кадры во время sampling игнорируем (упрощение v1).
        }
    }
}

pub fn serve() {
    let mut reg = Registry::new();
    ailc_capabilities::register_core(&mut reg);

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut sess = Session {
        reader: stdin.lock(),
        out: stdout.lock(),
        sampling: false,
        next_id: 10_000,
    };

    while let Some(line) = sess.read_line() {
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let id = req.get("id").cloned();
        let method = req
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        // Запоминаем, поддерживает ли клиент sampling (объявляется в initialize).
        if method == "initialize" {
            sess.sampling = req.pointer("/params/capabilities/sampling").is_some();
            // При инициализации MCP сам готовит проект: вписывает правило для агента IDE
            // («зови ailc перед кодом») и разворачивает скелет состояния .ailc/ (конституция
            // и заготовки). Всё идемпотентно, чтобы не настраивать вручную.
            install_agent_rule(&req);
        }

        let params = req.get("params").cloned();
        let result = handle(&reg, &mut sess, &method, params.as_ref());

        if let Some(id) = id {
            let msg = match result {
                Ok(value) => json!({"jsonrpc": "2.0", "id": id, "result": value}),
                Err((code, message)) => {
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
                }
            };
            sess.send(&msg);
        }
    }
}

/// Идемпотентно вписать правило для агента IDE в управляемый блок (через E5 Generator).
/// Пишется при инициализации MCP в корне рабочей папки (её ставит IDE при запуске
/// `ailc serve`; либо `rootUri` из initialize). CLAUDE.md — всегда; .cursorrules / AGENTS.md
/// — только если уже существуют (не сорим чужими файлами). Опт-аут: env `CO_MCP_NO_RULES`.
/// Безопасно определить корень рабочей папки из запроса инициализации.
/// `rootUri` приходит ОТ КЛИЕНТА и недоверен, поэтому путь канонизируется (убираются
/// переходы вверх и симлинки) и ОБЯЗАН существовать и быть каталогом. Иначе возвращаем
/// None и не пишем ничего: создавать служебный файл по произвольному или несуществующему
/// пути недопустимо (см. T39 — обход каталога через rootUri).
fn safe_workspace_root(req: &Value) -> Option<std::path::PathBuf> {
    let raw = req
        .pointer("/params/rootUri")
        .and_then(Value::as_str)
        .map(|u| u.strip_prefix("file://").unwrap_or(u).to_string())
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_dir().ok())?;
    let root = std::fs::canonicalize(&raw).ok()?;
    root.is_dir().then_some(root)
}

fn install_agent_rule(req: &Value) {
    if std::env::var_os("CO_MCP_NO_RULES").is_some() {
        return;
    }
    let Some(root) = safe_workspace_root(req) else {
        return;
    };
    let ctx = Ctx::new(&root);

    const KEY: &str = "agent-rule";
    let content = "## ailc — автономная проверка качества\n\n\
        Перед тем как писать или менять код И перед ответом «готово / можно сдавать» — вызови\n\
        MCP-инструмент ailc `plan` с намерением простым языком (например «проверь, всё ок\n\
        перед сдачей?»). ailc адаптивно построит план, прогонит проверки, при нехватке\n\
        довызовет ещё инструменты, безопасно починит формат/линт и вынесет ДЕТЕРМИНИРОВАННЫЙ\n\
        вердикт (гарантию даёт гейт, не нейросеть). Быстрый детерминированный статус без LLM —\n\
        инструменты `dod` (готово?) и `sarif` (полный скан для CI).";

    // Пишем строго фиксированные имена напрямую под каноническим корнем. Контейнмент:
    // итоговый путь обязан лежать ВНУТРИ корня, иначе пропускаем (защита от подмены через
    // симлинк или переход вверх в имени). CLAUDE.md создаём всегда; чужие .cursorrules и
    // AGENTS.md трогаем, только если они уже существуют.
    for (always, name) in [(true, "CLAUDE.md"), (false, ".cursorrules"), (false, "AGENTS.md")] {
        let target = root.join(name);
        if target.parent() != Some(root.as_path()) {
            continue;
        }
        if always || target.exists() {
            let _ = Generator::write_block(&ctx, name, KEY, content);
        }
    }

    // Разворачиваем скелет состояния .ailc/ (конституция, карта слоёв, рабочая память).
    // Идемпотентно: существующие файлы не трогаются. Так среда ставится сама при первом
    // подключении, и проекту не нужен отдельный вызов setup/scaffold.
    let _ = ailc_capabilities::scaffold_state(&ctx);
}

fn handle(
    reg: &Registry,
    sess: &mut Session,
    method: &str,
    params: Option<&Value>,
) -> Result<Value, (i64, String)> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "ailc", "version": env!("CARGO_PKG_VERSION") }
        })),
        "tools/list" => Ok(json!({ "tools": [
            plan_tool_schema(),
            find_capability_schema(),
            run_schema(),
            autofix_schema(),
            dod_schema(),
            sarif_schema(),
            design_schema(),
        ] })),
        "tools/call" => {
            let p = params.ok_or((-32602, "missing params".to_string()))?;
            let name = p.get("name").and_then(Value::as_str).unwrap_or("");
            let args = p.get("arguments").cloned().unwrap_or_else(|| json!({}));
            match name {
                "plan" => Ok(run_plan(reg, sess, &args)),
                "find_capability" => Ok(find_capability(reg, &args)),
                "run" => Ok(run_capability(reg, &args)),
                "autofix" => Ok(run_autofix(reg, sess, &args)),
                "dod" => Ok(run_dod_tool(reg, &args)),
                "sarif" => Ok(run_sarif_tool(reg, &args)),
                "design" => Ok(run_design_tool(reg, &args)),
                other => Err((-32602, format!("неизвестный инструмент: {other}"))),
            }
        }
        "ping" => Ok(json!({})),
        _ => Err((-32601, format!("метод не найден: {method}"))),
    }
}

fn plan_tool_schema() -> Value {
    json!({
        "name": "plan",
        "description": "АДАПТИВНО прогнать проект под намерение: ИИ строит план, выполняет проверки, при нехватке ДОВЫЗЫВАЕТ ещё инструменты, безопасно ЧИНИТ и перепроверяет, затем выносит ДЕТЕРМИНИРОВАННЫЙ вердикт (QualityLedger) и решения для человека. Зови на ЛЮБОЙ запрос вида «проверь / посмотри / всё ок? / готово ли / ревью / можно сдавать». Намерение — простым языком. Требует клиента с поддержкой sampling (LLM).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "intent": { "type": "string", "description": "Что хочешь сделать, простыми словами" },
                "path": { "type": "string", "description": "Путь к проекту (по умолчанию текущая папка)" }
            },
            "required": ["intent"]
        },
        "outputSchema": {
            "type": "object",
            "description": "QualityLedger",
            "properties": {
                "passed": { "type": "boolean" },
                "score": { "type": "number" },
                "rigor": { "type": "number" },
                "blocking": { "type": "integer" },
                "warning": { "type": "integer" },
                "refuted": { "type": "integer" },
                "checks": { "type": "array", "items": { "type": "string" } },
                "open_decisions": { "type": "array", "items": { "type": "string" } },
                "tests": { "type": ["string", "null"] },
                "rounds": { "type": "array", "items": { "type": "string" }, "description": "Журнал раундов агента: что спланировал/выполнил/довызвал/починил" },
                "headline": { "type": "string" }
            }
        }
    })
}

fn run_plan(reg: &Registry, sess: &mut Session, args: &Value) -> Value {
    let intent = args
        .get("intent")
        .and_then(Value::as_str)
        .unwrap_or("проверь качество проекта")
        .to_string();
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or(".")
        .to_string();

    // Адаптивная петля требует нейросеть IDE (sampling). Без неё — НЕ keyword-фолбэк, а
    // честное направление на детерминированные команды (инвариант «без молчаливых пропусков»).
    if !sess.sampling {
        return json!({
            "content": [{ "type": "text", "text":
                "Адаптивный режим `plan` требует клиента с поддержкой sampling (LLM): план, довызов \
                 инструментов и починку ведёт модель IDE. Детерминированно, без LLM — используй \
                 инструменты `dod` (вердикт «готово?») или `sarif` (полный скан), либо CLI `ailc custodian`." }],
            "isError": true
        });
    }

    let ctx = Ctx::new(&path);
    let input = RunInput::default();

    // Гибрид: ailc САМ крутит петлю PLAN→EXECUTE→REFLECT→FIX через sampling клиента.
    // Бюджет раундов = 0 → дефолт ядра. Вердикт PASS/FAIL — детерминированный гейт.
    let ledger = AgentOrchestrator::run(reg, &ctx, &input, &intent, sess, 0);

    let structured = serde_json::to_value(&ledger).unwrap_or(Value::Null);
    let mut text = format_ledger(&ledger);
    // Канал «в чат»: если фоновый custodian оставил ALERT.md — поднимаем его ИИ.
    if let Some(alert) = custodian_alert(&path) {
        text = format!("{alert}\n\n{text}");
    }
    json!({
        "content": [ { "type": "text", "text": text } ],
        "structuredContent": structured
    })
}

/// Алерт фонового custodian (ALERT.md) одной строкой — чтобы ИИ увидел его «в чате».
fn custodian_alert(path: &str) -> Option<String> {
    let p = std::path::Path::new(path).join(".ailc/custodian/ALERT.md");
    let body = std::fs::read_to_string(&p).ok()?;
    let head: String = body
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .take(2)
        .collect::<Vec<_>>()
        .join(" · ");
    Some(format!("🔔 Custodian: {} (детали: .ailc/custodian/ALERT.md)", head.trim()))
}

fn find_capability_schema() -> Value {
    json!({
        "name": "find_capability",
        "description": "Семантически подобрать инструменты ailc под задачу (по эмбеддингам описаний, офлайн). Возвращает ранжированный список: id, семейство, близость, когда применять, схему входа. Не нужно знать все инструменты — опиши задачу словами.",
        "inputSchema": {
            "type": "object",
            "properties": { "query": { "type": "string", "description": "Что нужно сделать, словами" } },
            "required": ["query"]
        }
    })
}

fn run_schema() -> Value {
    json!({
        "name": "run",
        "description": "Выполнить конкретный инструмент ailc по id (id возьми из find_capability).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": { "type": "string", "description": "id инструмента (напр. security.scan/owasp)" },
                "path": { "type": "string", "description": "Путь к проекту (по умолчанию текущая папка)" },
                "target": { "type": "string", "description": "Подпуть внутри проекта (опц.)" },
                "query": { "type": "string", "description": "Параметр-запрос (напр. имя символа для find_usages)" }
            },
            "required": ["id"]
        },
        "outputSchema": {
            "type": "object",
            "description": "CapabilityOutput",
            "properties": {
                "summary": { "type": "string" },
                "skipped": { "type": ["string", "null"] },
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "rule": { "type": "string" },
                            "severity": { "type": "string" },
                            "message": { "type": "string" },
                            "location": { "type": ["object", "null"] },
                            "verified": { "type": "boolean" },
                            "source": { "type": "string" }
                        }
                    }
                },
                "metrics": { "type": "array" },
                "records": { "type": "array", "items": { "type": "string" } }
            }
        }
    })
}

/// E0/router наружу: семантический подбор инструментов под запрос.
fn find_capability(reg: &Registry, args: &Value) -> Value {
    let query = args.get("query").and_then(Value::as_str).unwrap_or("");
    let manifests = reg.manifests();
    let items: Vec<(String, String)> = manifests
        .iter()
        .map(|m| (m.id.to_string(), m.when_to_use.to_string()))
        .collect();

    // ГИБРИД: семантика (эмбеддинги) + keyword-бонус по совпадению слов запроса с
    // id/описанием. Так точные термины («уязвимости», «секреты») поднимают релевантные
    // инструменты, а синонимы добирает семантика. Без модели работает только keyword.
    let semantic: std::collections::HashMap<String, f32> = Index::rank(query, &items)
        .map(|v| v.into_iter().collect())
        .unwrap_or_default();
    let qwords: Vec<String> = query
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.chars().count() >= 3)
        .map(str::to_string)
        .collect();
    let mut ranked: Vec<(String, f32)> = items
        .iter()
        .map(|(id, w)| {
            let sem = semantic.get(id).copied().unwrap_or(0.0);
            let hay = format!("{id} {w}").to_lowercase();
            let kw = qwords.iter().filter(|t| hay.contains(t.as_str())).count() as f32;
            (id.clone(), sem + 0.15 * kw)
        })
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut text = format!("Инструменты под «{query}»:\n");
    let mut matches = Vec::new();
    for (id, score) in ranked.iter().take(6) {
        if let Some(m) = manifests.iter().find(|m| m.id == id) {
            let schema: Value =
                serde_json::from_str(m.input_schema).unwrap_or_else(|_| json!(m.input_schema));
            text.push_str(&format!(
                "- {} [{}] (близость {:.2}) — {}\n",
                m.id, m.family, score, m.when_to_use
            ));
            matches.push(json!({
                "id": m.id, "family": m.family.to_string(), "score": score,
                "when_to_use": m.when_to_use, "input_schema": schema
            }));
        }
    }
    if matches.is_empty() {
        text.push_str("(совпадений не найдено)\n");
    }
    json!({ "content": [{ "type": "text", "text": text }], "matches": matches })
}

fn autofix_schema() -> Value {
    json!({
        "name": "autofix",
        "description": "Семантический автофикс через LLM: гейт → для каждой находки LLM правит строку → адверсариальная перепроверка (целевая ушла И новых нет) → оставляем или откатываем. МУТИРУЕТ файлы. Нужен клиент с поддержкой sampling.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Путь к проекту (по умолчанию текущая папка)" },
                "max": { "type": "integer", "description": "Максимум правок за прогон (по умолчанию 8)" }
            }
        }
    })
}

fn run_autofix(reg: &Registry, sess: &mut Session, args: &Value) -> Value {
    if !sess.sampling {
        return json!({
            "content": [{ "type": "text", "text": "autofix требует клиента с поддержкой sampling (LLM). Для безопасной починки формата/линта без LLM используй `ailc fix`." }],
            "isError": true
        });
    }
    let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
    let max = args
        .get("max")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .unwrap_or(8);
    let ctx = Ctx::new(path);
    let rep = ailc_core::autofix::run(reg, &ctx, sess, max);

    let mut text = format!(
        "Автофикс LLM: исправлено {}, откатов {}.\n",
        rep.applied, rep.reverted
    );
    for o in &rep.outcomes {
        text.push_str(&format!("  {} [{}] {}:{}\n", o.status, o.rule, o.file, o.line));
    }
    json!({ "content": [{ "type": "text", "text": text }] })
}

/// Выполнить конкретный инструмент по id.
fn run_capability(reg: &Registry, args: &Value) -> Value {
    let id = args.get("id").and_then(Value::as_str).unwrap_or("");
    let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
    let input = RunInput {
        target: args.get("target").and_then(Value::as_str).map(str::to_string),
        query: args.get("query").and_then(Value::as_str).map(str::to_string),
    };
    let ctx = Ctx::new(path);
    match reg.get(id) {
        Some(cap) => match cap.run(&ctx, &input) {
            Ok(out) => {
                let mut text = format!("{}\n", out.summary);
                if let Some(s) = &out.skipped {
                    text.push_str(&format!("ПРОПУЩЕНО: {s}\n"));
                }
                for f in out.findings.iter().take(30) {
                    let loc = f
                        .location
                        .as_ref()
                        .map(|l| format!(" ({}:{})", l.file, l.line))
                        .unwrap_or_default();
                    text.push_str(&format!("[{}] {} — {}{loc}\n", f.severity, f.rule, f.message));
                }
                for r in out.records.iter().take(30) {
                    text.push_str(&format!("{r}\n"));
                }
                let structured = serde_json::to_value(&out).unwrap_or(Value::Null);
                json!({
                    "content": [{ "type": "text", "text": text }],
                    "structuredContent": structured
                })
            }
            Err(e) => json!({ "content": [{ "type": "text", "text": format!("ОШИБКА: {e}") }], "isError": true }),
        },
        None => {
            json!({ "content": [{ "type": "text", "text": format!("нет инструмента: {id}") }], "isError": true })
        }
    }
}

// ───────────────────── Гибрид-инструменты (агент IDE зовёт как шаги) ─────────────────────
// Унификация «за рамками оркестратора»: dod/sarif/design — детерминированные действия,
// которые модель IDE может ставить шагом своего пайплайна, а не только ailc внутри plan.

fn dod_schema() -> Value {
    json!({
        "name": "dod",
        "description": "Definition of Done — ДЕТЕРМИНИРОВАННЫЙ многоосевой вердикт «готово ли к сдаче?» (конституция · тесты · секреты · OWASP HIGH · недоделанное · дрейф доков · контракт API …). Без LLM. Hard-оси блокируют.",
        "inputSchema": {
            "type": "object",
            "properties": { "path": { "type": "string", "description": "Путь к проекту (по умолчанию текущая папка)" } }
        }
    })
}

fn run_dod_tool(reg: &Registry, args: &Value) -> Value {
    let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
    let ctx = Ctx::new(path);
    let report = Orchestrator::dod(reg, &ctx, &RunInput::default());
    let mut text = String::from("DoD — Definition of Done:\n");
    let mut axes = Vec::new();
    for a in &report.axes {
        let mark = if !a.ran {
            "⊘"
        } else if a.ok {
            "✓"
        } else {
            "✗"
        };
        let kind = if a.hard { "hard" } else { "soft" };
        let detail = if !a.ran {
            "не выполнялась".to_string()
        } else if a.name == "OWASP HIGH" {
            format!("HIGH: {}", a.high)
        } else {
            format!("находок: {}", a.findings)
        };
        text.push_str(&format!("  {mark} {} [{kind}] — {detail}\n", a.name));
        axes.push(json!({
            "name": a.name, "hard": a.hard, "ran": a.ran,
            "findings": a.findings, "high": a.high, "ok": a.ok
        }));
    }
    text.push_str(&format!(
        "\nВЕРДИКТ: {}",
        if report.passed {
            "✓ можно сдавать"
        } else {
            "✗ почини hard-оси (✗)"
        }
    ));
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": { "passed": report.passed, "axes": axes }
    })
}

fn sarif_schema() -> Value {
    json!({
        "name": "sarif",
        "description": "Полный ДЕТЕРМИНИРОВАННЫЙ скан (security · quality · compliance · доки) → отчёт SARIF 2.1.0 для CI / security-tab. В отчёт идут только ПОДТВЕРЖДЁННЫЕ находки (ложные опровергнуты Verifier'ом).",
        "inputSchema": {
            "type": "object",
            "properties": { "path": { "type": "string", "description": "Путь к проекту (по умолчанию текущая папка)" } }
        }
    })
}

fn run_sarif_tool(reg: &Registry, args: &Value) -> Value {
    let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
    let ctx = Ctx::new(path);
    let report = Orchestrator::scan_all(reg, &ctx, &RunInput::default());
    let sarif = ailc_core::sarif::to_sarif(
        &report.findings,
        env!("CARGO_PKG_VERSION"),
        report.refuted,
        &report.checks_run,
        &report.checks_skipped,
    );
    json!({ "content": [{ "type": "text", "text": sarif }] })
}

fn design_schema() -> Value {
    json!({
        "name": "design",
        "description": "Спроектировать новую фичу «как в ИТ принято»: заготовка спеки (зачем · что · критерии приёмки · затрагиваемые части из карты кода · риски) + ADR (Nygard). МУТИРУЕТ файлы (docs/.co), идемпотентно.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "feature": { "type": "string", "description": "Что хочешь сделать, простыми словами" },
                "path": { "type": "string", "description": "Путь к проекту (по умолчанию текущая папка)" }
            },
            "required": ["feature"]
        }
    })
}

fn run_design_tool(reg: &Registry, args: &Value) -> Value {
    let feature = args.get("feature").and_then(Value::as_str).unwrap_or("");
    if feature.trim().is_empty() {
        return json!({
            "content": [{ "type": "text", "text": "design требует параметр feature (что спроектировать)" }],
            "isError": true
        });
    }
    let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
    let ctx = Ctx::new(path);
    let input = RunInput {
        target: None,
        query: Some(feature.to_string()),
    };
    match reg.get("spec/feature").map(|c| c.run(&ctx, &input)) {
        Some(Ok(out)) => {
            let mut text = format!("{}\n", out.summary);
            if let Some(s) = &out.skipped {
                text.push_str(&format!("⚠ {s}\n"));
            }
            for a in &out.artifacts {
                text.push_str(&format!("📄 {a}\n"));
            }
            let structured = serde_json::to_value(&out).unwrap_or(Value::Null);
            json!({ "content": [{ "type": "text", "text": text }], "structuredContent": structured })
        }
        Some(Err(e)) => {
            json!({ "content": [{ "type": "text", "text": format!("ОШИБКА: {e}") }], "isError": true })
        }
        None => json!({ "content": [{ "type": "text", "text": "инструмент проектирования недоступен" }], "isError": true }),
    }
}

/// Человекочитаемый вердикт — то, что увидит не-эксперт в IDE.
pub fn format_ledger(l: &QualityLedger) -> String {
    let mut s = String::new();
    s.push_str(&l.headline);
    s.push('\n');
    let t = ailc_core::i18n::t;
    s.push_str(&format!("{}: {}\n", t("Проект", "Project"), l.project));
    s.push_str(&format!("{}: {}\n", t("Карта кода", "Code map"), l.map_summary));
    s.push_str(&format!("{} «{}»\n", t("Governance: политика", "Governance: policy"), l.policy_name));
    s.push_str(&format!(
        "{}: {} · {}: {} ({} {} / {} {}) · {} {:.1}/100\n",
        t("Проверок", "Checks"), l.checks_run,
        t("находок", "findings"), l.findings_total,
        t("блокеров", "blocking"), l.blocking,
        t("предупреждений", "warnings"), l.warning,
        t("качество", "quality"), l.score
    ));
    s.push_str(&format!("{}: {:.0}/100", t("Тщательность (Rigor)", "Rigor"), l.rigor));
    if l.refuted > 0 {
        s.push_str(&format!(" · {}: {}", t("verify отсеял ложных", "verify refuted false"), l.refuted));
    }
    s.push('\n');
    if !l.checks.is_empty() {
        s.push_str(&format!("{}: {}\n", t("Выполнено", "Ran"), l.checks.join(", ")));
    }
    for (id, reason) in &l.checks_skipped {
        s.push_str(&format!("⚠ {} {id}: {reason}\n", t("пропущено", "skipped")));
    }
    for a in &l.artifacts {
        s.push_str(&format!("📄 {}: {a}\n", t("создано/обновлено", "created/updated")));
    }
    if !l.open_decisions.is_empty() {
        s.push_str(&format!("\n{}:\n", t("Нужно твоё решение", "Your decision needed")));
        for d in &l.open_decisions {
            s.push_str(&format!(" • {d}\n"));
        }
    }
    if !l.advisories.is_empty() {
        s.push_str(&format!("\n📋 {}:\n", t("Советы (не блокируют сдачу)", "Advisories (non-blocking)")));
        for a in &l.advisories {
            s.push_str(&format!(" • {a}\n"));
        }
    }
    // Журнал адаптивной петли агента — чтобы человек ВИДЕЛ, что план был построен,
    // что выполнено/довызвано/починено (а не «нейросеть один раз что-то дёрнула»).
    if !l.rounds.is_empty() {
        s.push_str(&format!("\n🔁 {}:\n", t("Раунды агента", "Agent rounds")));
        for r in &l.rounds {
            s.push_str(&format!(" • {r}\n"));
        }
    }
    s
}
