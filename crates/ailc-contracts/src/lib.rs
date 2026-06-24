//! Типизированные контракты ailc.
//!
//! Это «общий язык» между шагами оркестратора. Принципиально: всё, что течёт
//! между шагами, — строго типизировано (никакого парсинга прозы, как было в ailc).
//! Пока без serde — добавим при подключении MCP-транспорта.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Результат любого capability/движка.
pub type Result<T> = std::result::Result<T, CapError>;

#[derive(Debug, Clone)]
pub struct CapError(pub String);

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CapError {}
impl From<std::io::Error> for CapError {
    fn from(e: std::io::Error) -> Self {
        CapError(e.to_string())
    }
}

/// Семейство capability (см. карту консолидации 01-CONSOLIDATION.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    CodeIntel,
    Security,
    Quality,
    Verify,
    Spec,
    Generate,
    Backlog,
    Memory,
    Deliver,
    Setup,
    Governance,
    Compliance,
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Family::CodeIntel => "code.intel",
            Family::Security => "security",
            Family::Quality => "quality",
            Family::Verify => "verify",
            Family::Spec => "spec",
            Family::Generate => "generate",
            Family::Backlog => "backlog",
            Family::Memory => "memory",
            Family::Deliver => "deliver",
            Family::Setup => "setup",
            Family::Governance => "governance",
            Family::Compliance => "compliance",
        };
        f.write_str(s)
    }
}

/// Девять переиспользуемых движков. Capability = тонкий конфиг поверх одного из них.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    Scan,      // E1: обойти файлы → правила → findings
    Runner,    // E2: внешний бинарь + детерм. фолбэк
    CodeIntel, // E3: AST→TreeSitter→regex
    Generator, // E5: шаблон → идемпотентная запись (LLM-путь — в LlmPlanner/autofix, не движок)
    Gate,      // E6: kill-switch → проверки → contract
    Store,     // E7: атомарный file-per-record CRUD
    Metric,    // E8: числовая метрика/тренд
    Diagram,   // E9: модель → mermaid/plantuml
    Index,     // E0: эмбеддинги/поиск (RAG + роутер)
}

impl fmt::Display for EngineKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EngineKind::Scan => "scan",
            EngineKind::Runner => "runner",
            EngineKind::CodeIntel => "codeintel",
            EngineKind::Generator => "generator",
            EngineKind::Gate => "gate",
            EngineKind::Store => "store",
            EngineKind::Metric => "metric",
            EngineKind::Diagram => "diagram",
            EngineKind::Index => "index",
        };
        f.write_str(s)
    }
}

/// Тир видимости: ядро day-1 или enterprise/prod-харднинг.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Core,
    Enterprise,
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Tier::Core => "core",
            Tier::Enterprise => "enterprise",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MED",
            Severity::High => "HIGH",
            Severity::Critical => "CRIT",
        })
    }
}

/// Уверенность детектора — ОТДЕЛЬНО от severity. severity = «насколько плохо, если
/// правда»; confidence = «насколько уверены, что это правда». Как у Semgrep
/// (`metadata.confidence`): точные токены / структурный AST / taint-путь → High;
/// строковые/стилевые/метрические эвристики → Low. Дефолтный «сигнальный» профиль
/// показывает в вердикте только `>= Medium`; низкоуверенный шум уходит в советы.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Location {
    pub file: String,
    pub line: u32,
}

/// Находка. `verified` и `evidence` — несущая стена анти-гейминга:
/// очки начисляются только за находку, пережившую verify и заземлённую на file:line.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    pub message: String,
    pub location: Option<Location>,
    pub evidence: Option<String>,
    pub verified: bool,
    pub source: String, // id capability-источника
}

impl Finding {
    /// Аддитивный конструктор находки. Предоставлен как единая точка создания для
    /// нового кода вместо позиционного литерала `Finding { .. }`. Уверенность здесь не
    /// задаётся напрямую: достоверность является атрибутом самого правила (см.
    /// `rule_confidence`/`confidence_for`) и вычисляется централизованно из `rule`, что
    /// и делает её настоящим атрибутом, а не захардкоженным внешним списком в гейте.
    /// Существующие места построения `Finding { .. }` остаются рабочими без изменений.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
        location: Option<Location>,
        evidence: Option<String>,
        verified: bool,
        source: impl Into<String>,
    ) -> Self {
        Self {
            rule: rule.into(),
            severity,
            message: message.into(),
            location,
            evidence,
            verified,
            source: source.into(),
        }
    }

    /// Уверенность детектора, выведенная централизованно из карты правил (ключ `rule`,
    /// НЕ язык, поэтому единая карта работает для всех языков движка). Так достоверность
    /// становится атрибутом находки/правила через явную классификацию `rule_confidence`,
    /// а не внешним захардкоженным списком в гейте.
    pub fn confidence(&self) -> Confidence {
        confidence_for(&self.rule, &self.source, self.severity)
    }

    /// «Сигнал», а не шум: по умолчанию в вердикт идёт только `confidence >= Medium`.
    /// Низкоуверенные стиль/метрики/эвристики (long-file, deep-nesting, email-literal,
    /// дрейф доков, эвристики комплаенса) переходят в советы, а не в блокеры.
    pub fn is_signal(&self) -> bool {
        self.confidence() >= Confidence::Medium
    }
}

/// Класс достоверности правила: атрибут самого детектора, а не внешний список.
/// `Heuristic` (строка/стиль/метрика/совет) переходит в Low; `Pattern` (надёжное
/// структурное/паттерн-совпадение, но не уникальный токен) переходит в Medium-сигнал;
/// `Precise` (точная сигнатура/AST/taint/заземлённый прогон) переходит в High.
/// Каждое зарегистрированное правило обязано иметь явный класс (см. тест полноты
/// `every_registered_rule_has_explicit_confidence`); отсутствие класса является дефектом
/// классификации, а не молчаливым Medium.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleConfidence {
    /// Эвристика: строковые/стилевые/метрические признаки, совещательные находки.
    Heuristic,
    /// Надёжный паттерн/структура, но не уникальный токен: сигнал средней уверенности.
    Pattern,
    /// Точная сигнатура/AST/taint/заземлённый прогон: высокая уверенность.
    Precise,
}

impl RuleConfidence {
    /// Преобразование класса правила в шкалу `Confidence`.
    pub fn level(self) -> Confidence {
        match self {
            RuleConfidence::Heuristic => Confidence::Low,
            RuleConfidence::Pattern => Confidence::Medium,
            RuleConfidence::Precise => Confidence::High,
        }
    }
}

/// Единая ЯВНАЯ карта достоверности по правилам, ЕДИНСТВЕННОЕ место правки на все
/// языки (ключ языко-независим). Возвращает класс правила, если оно зарегистрировано
/// явно, иначе `None`. `None` означает «правило не классифицировано»: вызывающий код
/// (`confidence_for`) применяет к нему дефолт Medium ради совместимости (fail-loud, без
/// молчаливого сброса), а тест полноты не даёт такому правилу остаться незамеченным.
///
/// HEURISTIC (переходит в Low): стиль, метрики, инфо-PII, дрейф/отсутствие доков,
/// эвристики РФ-комплаенса, docker-теги latest. PRECISE (переходит в High): точные
/// токены секретов, taint-пути, AST-SAST, заземлённые прогоны (упавшие тесты, уязвимые
/// зависимости). PATTERN (переходит в Medium-сигнал, осознанно): паттерн-совпадения
/// OWASP/web/AI-безопасности и структурные проверки governance, которые являются
/// настоящим сигналом, но не уникальным токеном.
pub fn rule_confidence(rule: &str) -> Option<RuleConfidence> {
    use RuleConfidence::{Heuristic, Pattern, Precise};

    // Точные сигнатуры/заземлённые проверки, минимум ложного: высокая уверенность.
    const PRECISE: &[&str] = &[
        // Секреты с надёжной формой токена.
        "aws-access-key",
        "aws-secret-key",
        "private-key",
        "github-token",
        "stripe-key",
        "gitlab-token",
        "slack-token",
        "sendgrid-key",
        "npm-token",
        "azure-account-key",
        "google-api-key",
        "llm-api-key",
        "generic-secret",
        "twilio-sid",
        "jwt",
        // Заземлённые прогоны инструментов.
        "tests-failing",
        "vulnerable-dependency",
        "vulnerable-deps",
        "coverage-failed",
        "desktop-build-fail",
        "mobile-build-fail",
        "symbol-not-found",
        "api-break",
        // SAST по AST / taint-анализу.
        "sast/dynamic-exec",
        "sast/sql-injection",
        "sast/unsafe-deserialize",
        "sast/taint-command-exec",
        "sast/taint-sql",
        "sast/taint-path",
        "sast/taint-buffer",
        // taint LLM: источник недоверенного ввода связан со стоком конкретной переменной.
        "taint-llm-output-exec",
        "taint-llm-output-raw-html",
        "pdn-log-dynamic",
    ];

    // Надёжный паттерн/структура, но не уникальный токен: осознанный Medium-сигнал.
    // Раньше эти правила тихо проваливались в дефолт Medium; теперь это ЯВНО.
    const PATTERN: &[&str] = &[
        // OWASP Top 10 (security.scan/owasp): паттерн-совпадения.
        "sql-injection",
        "dangerous-exec",
        "shell-injection",
        "weak-crypto",
        "weak-hash",
        "weak-pw-hash",
        "debug-enabled",
        "insecure-random",
        "tls-verify-off",
        "jwt-none",
        "insecure-deser",
        "xss-sink",
        "ssrf",
        "permissive-authz",
        "cors-wildcard",
        "pii-in-log",
        // web_security.rs.
        "ssrf-sink",
        "open-redirect",
        "path-traversal",
        "ssti",
        "xxe",
        "insecure-deserialize",
        "unsafe-yaml-load",
        "tls-verify-disabled",
        "insecure-cookie",
        "csrf-disabled",
        "jwt-none-alg",
        "graphql-introspection",
        "mass-assignment",
        // security_extra.rs (XSS-стоки, контейнеры).
        "raw-innerhtml",
        "react-raw-html",
        "vue-raw-html",
        "document-write",
        "html-string-concat",
        "privileged-container",
        "run-as-root",
        "add-remote-url",
        "from-latest-tag",
        // ai_security.rs (LLM-цепочки).
        "llm-prompt-untrusted-concat",
        "llm-prompt-build-untrusted",
        "llm-output-exec",
        "llm-output-raw-html",
        // verify/lint: линтер отработал и сообщил о замечаниях (заземлённый сигнал, но
        // зависит от набора правил линтера, поэтому осознанный Medium, не Precise).
        "lint",
        // smell / корректность.
        "swallowed-error",
        "swallowed-rescue",
        "empty-catch",
        "empty-except",
        "empty-function",
        "unimplemented-stub",
        // governance / архитектура / лицензии.
        "constitution-forbid",
        "constitution-require",
        "layer-violation",
        "import-cycle",
        "copyleft-license",
        // комплаенс: явное логирование персональных данных (точный признак поля).
        "pdn-in-logs",
        "pre-checked-consent",
    ];

    // Эвристики (строка/стиль/метрика/совет): низкая уверенность, шум, не блокер.
    const HEURISTIC: &[&str] = &[
        // метрики/анти-паттерны.
        "long-file",
        "deep-nesting",
        "god-file",
        "high-complexity",
        "many-params",
        "many-returns",
        "panic-path",
        // техдолг / инфо-PII / email.
        "debt-marker",
        "email-literal",
        "ssn-us",
        "credit-card",
        // документация (совещательные).
        "undocumented-api",
        "doc-missing",
        "doc-drift",
        "dead-export",
        // OSV: версия не сравнима автоматически, «проверьте вручную» (verified=false),
        // поэтому совещательная находка низкой уверенности, не блокер.
        "vulnerable-dependency-uncertain",
        // РФ-комплаенс эвристики (география/трекеры/крипто-примитивы).
        "foreign-tracker",
        "foreign-crypto-primitive",
        "foreign-db-host",
        "foreign-region",
        // docker: тег latest (стилевой признак, не уязвимость).
        "image-latest-tag",
    ];

    if PRECISE.contains(&rule) {
        Some(Precise)
    } else if PATTERN.contains(&rule) {
        Some(Pattern)
    } else if HEURISTIC.contains(&rule) {
        Some(Heuristic)
    } else if rule.starts_with("sast/") || rule.starts_with("taint") {
        // Семейство taint/AST-SAST целиком точное: будущие правила этого префикса
        // наследуют высокую уверенность по структуре анализа, а не по списку.
        Some(Precise)
    } else {
        None
    }
}

/// Достоверность по имени правила со «совместимым» дефолтом. Если правило
/// классифицировано явно (`rule_confidence`), берём его класс; иначе возвращаем
/// Medium (fail-loud, без молчаливого сброса в Low). Незаявленное правило при этом
/// остаётся сигналом, а тест полноты не позволяет ему появиться незамеченным.
fn confidence_for(rule: &str, _source: &str, _severity: Severity) -> Confidence {
    rule_confidence(rule)
        .map(RuleConfidence::level)
        .unwrap_or(Confidence::Medium)
}

/// Вид символа (для CodeIntel).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Method,
    Type,
    Interface,
    Enum,
    Trait,
    Class,
    Const,
    Variable,
}

impl fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SymbolKind::Function => "fn",
            SymbolKind::Method => "method",
            SymbolKind::Type => "type",
            SymbolKind::Interface => "interface",
            SymbolKind::Enum => "enum",
            SymbolKind::Trait => "trait",
            SymbolKind::Class => "class",
            SymbolKind::Const => "const",
            SymbolKind::Variable => "var",
        })
    }
}

/// Символ кода, извлечённый CodeIntel-движком.
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub file: String,
    pub line: u32,
    pub lang: String,
    pub exported: bool,
}

/// Единый выход capability.
/// `skipped` — инвариант «нет молчаливых пропусков»: если шаг не выполнен, тут причина.
/// `records` — обобщённые текстовые записи (символы, узлы графа и т.п.) до подключения
/// типизированного payload через serde.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CapabilityOutput {
    pub findings: Vec<Finding>,
    pub records: Vec<String>,
    pub metrics: Vec<(String, f64)>,
    pub artifacts: Vec<String>,
    pub summary: String,
    pub skipped: Option<String>,
}

impl CapabilityOutput {
    /// Классифицировать исход проверки для агрегатора Волны 2 (gate/orchestrator).
    /// Разделяет три принципиально разных состояния, которые раньше сливались:
    /// инструмент УПАЛ (сборка/конфиг/импорт), проверка ОСОЗНАННО ПРОПУЩЕНА (нет
    /// тулчейна, нет входных данных) и проверка РЕАЛЬНО ВЫПОЛНЕНА (с находками или без).
    ///
    /// Сбой инструмента распознаётся по маркерам в `summary`/`findings` (см. T87): по
    /// инварианту README «сбой инструмента не равен находке», поэтому в `Failed` он не
    /// превращается в дефект кода. Если capability уже выставил `skipped`, мы доверяем
    /// этой явной причине; но если причина похожа на поломку инструмента, мы относим её
    /// к `Failed`, а не к обычному `Skipped`, чтобы вердикт не путал «не запускалось
    /// из-за поломки» с «нечего проверять».
    pub fn outcome(&self) -> CheckOutcome {
        if let Some(reason) = &self.skipped {
            return if looks_like_tool_failure(reason) {
                CheckOutcome::Failed(reason.clone())
            } else {
                CheckOutcome::Skipped(reason.clone())
            };
        }
        // Поломка инструмента могла «просочиться» в summary даже без skipped: тогда это
        // не успешный прогон, а сбой, поэтому классифицируем явно (страховка для T87,
        // если capability не выставил skipped).
        if looks_like_tool_failure(&self.summary) {
            return CheckOutcome::Failed(self.summary.clone());
        }
        CheckOutcome::Ran
    }
}

/// Маркеры «инструмент не отработал» (сборка/конфиг/импорт/паника). Отделяют «инструмент
/// упал» от «инструмент отработал и нашёл/не нашёл замечаний» (см. T87). Регистр
/// игнорируется. Первые маркеры это сырой вывод внешних раннеров (язык-независим,
/// английский), последний это явная русскоязычная формулировка, которой сами capability
/// помечают сбой инструмента в причине/сводке («не отработал ...»), чтобы outcome()
/// классифицировал такой исход как Failed, а не как обычный Skipped.
pub fn looks_like_tool_failure(text: &str) -> bool {
    let t = text.to_lowercase();
    const MARKERS: &[&str] = &[
        "could not compile",
        "compilation failed",
        "modulenotfounderror",
        "importerror",
        "error: configuration",
        "configuration error",
        "panicked",
        "no such file or directory",
        "command not found",
        "error[e", // диагностика rustc вида error[E0277]
        "не отработал", // явная пометка сбоя инструмента из самих capability
    ];
    MARKERS.iter().any(|m| t.contains(m))
}

/// Исход одной проверки (оси) для агрегатора Волны 2. Различает «не выполнялось» от
/// «выполнено, находок нет»: раньше эти случаи неразличимо сливались, из-за чего сбой
/// инструмента превращался в находку, а недоказанный прогон выглядел как пройденный
/// (см. T87). `Skipped` несёт осознанную причину пропуска, `Failed` несёт причину сбоя
/// инструмента; `Ran` означает доказанное исполнение проверки.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "reason", rename_all = "lowercase")]
pub enum CheckOutcome {
    /// Проверка реально выполнена (находки в `CapabilityOutput.findings`, могут быть пусты).
    Ran,
    /// Проверка осознанно пропущена с причиной (нет тулчейна/входных данных и т.п.).
    Skipped(String),
    /// Инструмент проверки не отработал (сборка/конфиг/импорт/паника) с причиной.
    /// По инварианту «сбой инструмента не равен находке» это НЕ дефект кода.
    Failed(String),
}

impl CheckOutcome {
    /// Проверка реально дала результат (выполнена), а не пропущена и не сломалась.
    pub fn did_run(&self) -> bool {
        matches!(self, CheckOutcome::Ran)
    }

    /// Причина пропуска или сбоя (для журнала «нет молчаливых пропусков»); `None`, если
    /// проверка выполнена.
    pub fn reason(&self) -> Option<&str> {
        match self {
            CheckOutcome::Ran => None,
            CheckOutcome::Skipped(r) | CheckOutcome::Failed(r) => Some(r),
        }
    }
}

/// Состояние одной оси проверки (например, оси дрейфа документации `spec.check/drift`)
/// в агрегированном вердикте Волны 2: идентификатор оси, её исход и число прошедших
/// верификацию находок по ней. Позволяет gate/orchestrator явно учитывать ось, которая
/// «не выполнялась», отдельно от оси, которая «выполнена и не дала находок» (см. T87).
#[derive(Debug, Clone, Serialize)]
pub struct AxisState {
    /// Идентификатор оси/capability (например, `spec.check/drift`).
    pub axis: String,
    /// Исход выполнения оси.
    pub outcome: CheckOutcome,
    /// Сколько верифицированных находок дала ось (значимо только при `outcome == Ran`).
    pub findings: usize,
}

impl AxisState {
    /// Собрать состояние оси из её идентификатора и выхода capability.
    pub fn from_output(axis: impl Into<String>, out: &CapabilityOutput) -> Self {
        let outcome = out.outcome();
        Self {
            axis: axis.into(),
            findings: if outcome.did_run() {
                out.findings.iter().filter(|f| f.verified).count()
            } else {
                0
            },
            outcome,
        }
    }

    /// Ось выполнена и не дала верифицированных находок: «чисто», в отличие от оси,
    /// которая не выполнялась (пропуск/сбой). Это и есть различие, которого не хватало
    /// Волне 2 (см. T87).
    pub fn ran_clean(&self) -> bool {
        self.outcome.did_run() && self.findings == 0
    }
}

/// Декларативное описание инструмента для реестра и Capability Router.
#[derive(Debug, Clone)]
pub struct CapabilityManifest {
    pub id: &'static str,
    pub family: Family,
    pub engine: EngineKind,
    /// Текст для эмбеддинга/роутинга — «когда это применять».
    pub when_to_use: &'static str,
    /// JSON-схема входа (пока текстом; станет валидируемой при MCP).
    pub input_schema: &'static str,
    pub tier: Tier,
    pub deterministic: bool,
    /// Мутирующее действие → проходит через gate + confirm.
    pub mutates: bool,
}

/// Один шаг плана агента: какой инструмент запустить и зачем (человеческим языком).
#[derive(Debug, Clone, Deserialize)]
pub struct PlanStep {
    pub id: String,
    #[serde(default)]
    pub why: String,
}

/// План агента — то, что нейросеть IDE возвращает на фазе PLAN. Заменяет keyword-роутер:
/// ИИ сам решает, ЧТО запустить, строгая ли это «сдача» (`strict`), и можно ли чинить
/// (`fix`). `stop_when` — критерий достаточности для фазы рефлексии (когда прекращать
/// довызывать). Вердикт PASS/FAIL по этим находкам всё равно выносит детерминированный гейт.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AgentPlan {
    pub steps: Vec<PlanStep>,
    pub strict: bool,
    pub fix: bool,
    pub stop_when: Option<String>,
}

/// QualityLedger — ЛИЦО продукта для не-эксперта. Итог прогона пайплайна на
/// человеческом языке: что проверили, что нашли, балл качества, и какие РЕШЕНИЯ
/// нужны от человека (эскалация простыми словами, без жаргона инструментов).
#[derive(Debug, Clone, Default, Serialize)]
pub struct QualityLedger {
    pub project: String,
    pub intent: String,
    pub policy_name: String,
    pub map_summary: String,
    pub checks_run: usize,
    /// Имена выполненных проверок (что выбрал планировщик).
    pub checks: Vec<String>,
    pub checks_skipped: Vec<(String, String)>,
    pub findings_total: usize,
    pub blocking: usize,
    pub warning: usize,
    pub score: f64,
    /// Rigor Score 0..100 — ТЩАТЕЛЬНОСТЬ анализа (доля выполненных проверок),
    /// отдельно от score (чистота кода). Пропуски (нет тулчейна) снижают rigor.
    pub rigor: f64,
    /// Сколько находок опроверг состязательный verify-проход (ложные отсеяны).
    pub refuted: usize,
    pub passed: bool,
    /// Статус прогона тестов для человека (None = не запускались в этом намерении).
    pub tests: Option<String>,
    /// Созданные/изменённые файлы (генераторы).
    pub artifacts: Vec<String>,
    pub open_decisions: Vec<String>,
    /// Не блокирующие советы человеку (дрейф документации, недокументированное API) —
    /// видны в вердикте, но сдать не мешают.
    pub advisories: Vec<String>,
    /// Журнал раундов адаптивной петли агента: что спланировал, что выполнил, что
    /// довызвал, что починил. Пусто для детерминированных (не-агентных) прогонов.
    pub rounds: Vec<String>,
    pub headline: String,
}

/// Контекст исполнения.
#[derive(Debug, Clone)]
pub struct Ctx {
    pub root: PathBuf,
}

impl Ctx {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Базовый путь прогона: корень проекта или подпуть `input.target`.
    /// `target` приходит от MCP-клиента, поэтому валидируется: абсолютный путь и
    /// компоненты `..` не должны выводить сканирование за корень проекта.
    pub fn base(&self, input: &RunInput) -> Result<PathBuf> {
        match input.target.as_deref().filter(|t| !t.is_empty()) {
            None => Ok(self.root.clone()),
            Some(t) => {
                let p = std::path::Path::new(t);
                let escapes = p.is_absolute()
                    || p.components()
                        .any(|c| matches!(c, std::path::Component::ParentDir));
                if escapes {
                    return Err(CapError(format!(
                        "target «{t}» выходит за корень проекта — отказано"
                    )));
                }
                Ok(self.root.join(p))
            }
        }
    }
}

/// Вход capability (минимальный; расширяется по семействам).
#[derive(Debug, Clone, Default)]
pub struct RunInput {
    /// Подпуть внутри проекта (None = весь проект).
    pub target: Option<String>,
    /// Имя символа/строка запроса (для find_usages и подобных).
    pub query: Option<String>,
}

/// Политика гейта — часть PolicyPack (governance как ДАННЫЕ, авторит старший).
/// `block_at` — severity, начиная с которой находка блокирует.
/// `families` — какие семейства проверок гонять (пусто = все check-семейства).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GatePolicy {
    pub block_at: Severity,
    pub families: Vec<Family>,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self {
            block_at: Severity::High,
            // Spec → «актуальность документации» проверяется в гейте рядом с безопасностью.
            families: vec![Family::Security, Family::Quality, Family::Spec],
        }
    }
}

/// Пороги качества — governance как ДАННЫЕ, а не магические числа в коде. Старший
/// настраивает в `[thresholds]` секции `ailc.policy.toml`; джун наследует дефолты.
/// Веса баллов (штраф за находку severity), пороги анти-паттернов/метрик/доков.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    pub score_critical: f64,
    pub score_high: f64,
    pub score_medium: f64,
    pub score_low: f64,
    pub score_info: f64,
    /// God-файл: больше этого числа определений в одном файле.
    pub max_defs_per_file: usize,
    /// Глубина вложенности выше этого — анти-паттерн.
    pub max_nesting: usize,
    /// Ниже этого покрытия документацией публичное API помечается (%).
    pub doc_coverage_floor: f64,
    /// Метрика: «слишком длинный файл» (строк) и «слишком сложная функция».
    pub max_lines: u32,
    pub max_complexity: u32,
    /// Порог близости эмбеддингов для семантического расширения пайплайна.
    pub semantic_threshold: f32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            score_critical: 25.0,
            score_high: 10.0,
            score_medium: 3.0,
            score_low: 1.0,
            score_info: 0.2,
            max_defs_per_file: 30,
            max_nesting: 6,
            doc_coverage_floor: 50.0,
            max_lines: 400,
            max_complexity: 50,
            semantic_threshold: 0.62,
        }
    }
}

/// PolicyPack — governance как ДАННЫЕ. Авторит старший один раз; джун наследует,
/// ничего не выбирая. Загружается из `ailc.policy.toml` в корне проекта.
/// Несёт политику гейта и пороги качества; дальше — constitution, house-style, write-zones.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PolicyPack {
    pub name: String,
    pub gate: GatePolicy,
    pub thresholds: Thresholds,
}

impl Default for PolicyPack {
    fn default() -> Self {
        Self {
            name: "default".into(),
            gate: GatePolicy::default(),
            thresholds: Thresholds::default(),
        }
    }
}

/// Вердикт гейта — граница ответственности. Структурный контракт (не проза):
/// blocking vs warning, балл качества, и ЯВНЫЙ список пропущенных проверок
/// (инвариант «нет молчаливых пропусков»).
#[derive(Debug, Clone, Default)]
pub struct GateReport {
    pub passed: bool,
    pub blocking: Vec<Finding>,
    pub warning: Vec<Finding>,
    /// Низкоуверенный шум (стиль/метрики/дрейф доков, `confidence < Medium`): виден
    /// человеку как «совет», но НЕ блокирует и НЕ снижает балл. Так дефолтный вердикт
    /// ведёт сигналом, а не тонет в стилевых находках на зрелом коде.
    pub advisories: Vec<Finding>,
    pub checks_run: Vec<String>,
    pub checks_skipped: Vec<(String, String)>, // (id, причина)
    pub score: f64,                            // балл качества 0..100
    pub metrics: Vec<(String, f64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Полный список зарегистрированных правил всех движков/capability проекта.
    /// Источник истины для теста полноты классификации достоверности (T88): любое
    /// правило, эмитируемое детектором, обязано здесь присутствовать И иметь явный класс
    /// в `rule_confidence`, иначе оно молча станет Medium-сигналом. При добавлении нового
    /// правила в любой движок его нужно внести и сюда, и в `rule_confidence`.
    const KNOWN_RULES: &[&str] = &[
        // security.scan/secret.
        "aws-access-key",
        "aws-secret-key",
        "private-key",
        "generic-secret",
        "github-token",
        "stripe-key",
        "google-api-key",
        "jwt",
        "gitlab-token",
        "slack-token",
        "sendgrid-key",
        "npm-token",
        "twilio-sid",
        "azure-account-key",
        "llm-api-key",
        // security.scan/owasp.
        "sql-injection",
        "dangerous-exec",
        "shell-injection",
        "weak-crypto",
        "debug-enabled",
        "weak-hash",
        "weak-pw-hash",
        "insecure-random",
        "tls-verify-off",
        "jwt-none",
        "insecure-deser",
        "xss-sink",
        "ssrf",
        "permissive-authz",
        "cors-wildcard",
        "pii-in-log",
        // security.scan/pii.
        "ssn-us",
        "credit-card",
        "email-literal",
        // web_security.
        "ssrf-sink",
        "open-redirect",
        "path-traversal",
        "ssti",
        "xxe",
        "insecure-deserialize",
        "unsafe-yaml-load",
        "tls-verify-disabled",
        "insecure-cookie",
        "csrf-disabled",
        "jwt-none-alg",
        "graphql-introspection",
        "mass-assignment",
        // security_extra.
        "raw-innerhtml",
        "react-raw-html",
        "vue-raw-html",
        "document-write",
        "html-string-concat",
        "privileged-container",
        "run-as-root",
        "image-latest-tag",
        "from-latest-tag",
        "add-remote-url",
        // ai_security.
        "llm-prompt-untrusted-concat",
        "llm-output-exec",
        "llm-output-raw-html",
        // quality.check/smell + completeness.
        "swallowed-error",
        "panic-path",
        "debt-marker",
        "swallowed-rescue",
        "empty-catch",
        "empty-except",
        "empty-function",
        "unimplemented-stub",
        // quality метрики/анти-паттерны.
        "long-file",
        "high-complexity",
        "deep-nesting",
        "god-file",
        "many-params",
        "many-returns",
        "dead-export",
        "import-cycle",
        // spec/документация.
        "doc-drift",
        "doc-missing",
        "undocumented-api",
        // verify (заземлённые прогоны).
        "tests-failing",
        "lint",
        "coverage-failed",
        "symbol-not-found",
        "api-break",
        "desktop-build-fail",
        "mobile-build-fail",
        // supply / governance.
        "vulnerable-dependency",
        "vulnerable-dependency-uncertain",
        "vulnerable-deps",
        "copyleft-license",
        "constitution-forbid",
        "constitution-require",
        "layer-violation",
        // compliance (РФ).
        "pdn-in-logs",
        "pdn-log-dynamic",
        "foreign-db-host",
        "foreign-region",
        "foreign-tracker",
        "pre-checked-consent",
        "foreign-crypto-primitive",
        // SAST (AST/taint).
        "sast/dynamic-exec",
        "sast/sql-injection",
        "sast/unsafe-deserialize",
        "sast/taint-command-exec",
        "sast/taint-sql",
        "sast/taint-path",
        "sast/taint-buffer",
    ];

    /// T88, тест полноты: КАЖДОЕ зарегистрированное правило обязано иметь ЯВНУЮ
    /// классификацию достоверности. Новое эвристическое правило, забытое в карте, не
    /// должно молча получить Medium-сигнал; этот тест падает раньше, чем шум попадёт в
    /// вердикт.
    #[test]
    fn every_registered_rule_has_explicit_confidence() {
        for &rule in KNOWN_RULES {
            assert!(
                rule_confidence(rule).is_some(),
                "правило «{rule}» не классифицировано явно: оно по умолчанию станет \
                 Medium-сигналом и даст ложные срабатывания в вердикте; добавь его в \
                 rule_confidence (Heuristic/Pattern/Precise)"
            );
        }
    }

    /// Класс правила и итоговая достоверность согласованы между собой и с `is_signal`.
    #[test]
    fn confidence_levels_are_consistent() {
        // Heuristic переходит в Low и НЕ является сигналом (уходит в советы).
        assert_eq!(RuleConfidence::Heuristic.level(), Confidence::Low);
        let noise = Finding::new(
            "long-file",
            Severity::Low,
            "m",
            None,
            None,
            true,
            "quality.check/x",
        );
        assert_eq!(noise.confidence(), Confidence::Low);
        assert!(!noise.is_signal(), "эвристика не должна быть сигналом");

        // Pattern переходит в Medium и ЯВЛЯЕТСЯ сигналом.
        assert_eq!(RuleConfidence::Pattern.level(), Confidence::Medium);
        let owasp = Finding::new(
            "sql-injection",
            Severity::High,
            "m",
            None,
            None,
            true,
            "security.scan/owasp",
        );
        assert_eq!(owasp.confidence(), Confidence::Medium);
        assert!(owasp.is_signal(), "паттерн-правило OWASP должно быть сигналом");

        // Precise переходит в High и является сигналом.
        assert_eq!(RuleConfidence::Precise.level(), Confidence::High);
        let secret = Finding::new(
            "aws-access-key",
            Severity::Critical,
            "m",
            None,
            None,
            true,
            "security.scan/secret",
        );
        assert_eq!(secret.confidence(), Confidence::High);
        assert!(secret.is_signal());
        // Семейство taint наследует High по префиксу, без перечисления.
        assert_eq!(
            confidence_for("sast/taint-command-exec", "", Severity::High),
            Confidence::High
        );
    }

    /// Совместимость (T88): неизвестное правило не падает в Low молча, а получает Medium
    /// (fail-loud) и остаётся сигналом. Так старое поведение сохранено, но тест полноты
    /// не даёт намеренно оставить правило неклассифицированным.
    #[test]
    fn unknown_rule_defaults_to_medium_signal() {
        assert!(
            rule_confidence("totally-new-rule").is_none(),
            "неизвестное правило не классифицировано"
        );
        let f = Finding::new(
            "totally-new-rule",
            Severity::High,
            "m",
            None,
            None,
            true,
            "security.scan/owasp",
        );
        assert_eq!(f.confidence(), Confidence::Medium);
        assert!(f.is_signal(), "по умолчанию остаётся сигналом, ничего не теряем молча");
    }

    /// `Finding::new` (аддитивный конструктор) и позиционный литерал дают одно и то же.
    #[test]
    fn finding_new_matches_literal() {
        let by_new = Finding::new(
            "lint",
            Severity::Medium,
            "msg",
            None,
            None,
            true,
            "verify/lint",
        );
        let by_literal = Finding {
            rule: "lint".into(),
            severity: Severity::Medium,
            message: "msg".into(),
            location: None,
            evidence: None,
            verified: true,
            source: "verify/lint".into(),
        };
        assert_eq!(by_new.rule, by_literal.rule);
        assert_eq!(by_new.severity, by_literal.severity);
        assert_eq!(by_new.confidence(), by_literal.confidence());
    }

    /// T87, распознавание сбоя инструмента по маркерам stdout/stderr.
    #[test]
    fn tool_failure_markers_are_detected() {
        for broken in [
            "error: could not compile `foo`",
            "ModuleNotFoundError: No module named pytest",
            "thread 'main' panicked at ...",
            "error[E0277]: the trait bound is not satisfied",
            "Configuration error: invalid clippy.toml",
            "cargo: command not found",
        ] {
            assert!(looks_like_tool_failure(broken), "должно считаться сбоем: {broken}");
        }
        for ok in [
            "test result: ok. 12 passed; 0 failed",
            "warning: unused variable",
            "linter reported 3 issues",
        ] {
            assert!(
                !looks_like_tool_failure(ok),
                "не должно считаться сбоем инструмента: {ok}"
            );
        }
    }

    /// T87, `CheckOutcome` различает три состояния оси, а `AxisState` отделяет
    /// «выполнено и чисто» от «не выполнялось».
    #[test]
    fn check_outcome_distinguishes_run_skip_fail() {
        // Реальный прогон без находок: Ran, ran_clean == true.
        let ran = CapabilityOutput {
            summary: "verify/test: ✅ 5 passed".into(),
            ..Default::default()
        };
        assert_eq!(ran.outcome(), CheckOutcome::Ran);
        let axis = AxisState::from_output("verify/test", &ran);
        assert!(axis.ran_clean(), "выполнено и без находок = чисто");
        assert!(axis.outcome.did_run());
        assert_eq!(axis.outcome.reason(), None);

        // Осознанный пропуск: Skipped с причиной, did_run == false.
        let skipped = CapabilityOutput {
            skipped: Some("линтер недоступен".into()),
            ..Default::default()
        };
        assert!(matches!(skipped.outcome(), CheckOutcome::Skipped(_)));
        let axis = AxisState::from_output("verify/lint", &skipped);
        assert!(!axis.ran_clean(), "пропуск не равен чистому прогону");
        assert!(!axis.outcome.did_run());
        assert_eq!(axis.outcome.reason(), Some("линтер недоступен"));

        // Сбой инструмента: Failed, даже если причина пришла через skipped.
        let failed = CapabilityOutput {
            skipped: Some("verify/test: could not compile".into()),
            ..Default::default()
        };
        assert!(matches!(failed.outcome(), CheckOutcome::Failed(_)));
        assert!(!AxisState::from_output("verify/test", &failed).ran_clean());

        // Сбой, просочившийся в summary без skipped, тоже распознаётся как Failed.
        let leaked = CapabilityOutput {
            summary: "pytest: ModuleNotFoundError: No module named app".into(),
            ..Default::default()
        };
        assert!(matches!(leaked.outcome(), CheckOutcome::Failed(_)));
    }

    /// T87, ось дрейфа доков `spec.check/drift`: «нет находок» не путается с «не
    /// выполнялось». Это и есть то, что Волна 2 теперь различает явно.
    #[test]
    fn doc_drift_axis_run_clean_vs_not_run() {
        let clean = CapabilityOutput {
            summary: "spec.check/drift: документация актуальна".into(),
            ..Default::default()
        };
        assert!(AxisState::from_output("spec.check/drift", &clean).ran_clean());

        let not_run = CapabilityOutput {
            skipped: Some("нет спецификаций для сверки".into()),
            ..Default::default()
        };
        let axis = AxisState::from_output("spec.check/drift", &not_run);
        assert!(!axis.ran_clean());
        assert!(matches!(axis.outcome, CheckOutcome::Skipped(_)));

        // Ось с верифицированной находкой: Ran, findings посчитаны, не «чисто».
        let with_finding = CapabilityOutput {
            findings: vec![Finding::new(
                "doc-drift",
                Severity::Low,
                "док устарел",
                None,
                None,
                true,
                "spec.check/drift",
            )],
            ..Default::default()
        };
        let axis = AxisState::from_output("spec.check/drift", &with_finding);
        assert!(axis.outcome.did_run());
        assert_eq!(axis.findings, 1);
        assert!(!axis.ran_clean());
    }
}
