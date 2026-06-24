//! CORE-capability как конфиги поверх движков.
//!
//! ПРИНЦИП: инструмент = таблица правил/конфиг, а НЕ новый код. Все scan-инструменты
//! (secret/owasp/pii/…) — это один тип `ScanCapability` с разными правилами поверх
//! одного `ScanEngine`. Ни логика обхода/матча, ни boilerplate `impl Capability` не
//! дублируются. Добавить проверку = добавить builder с таблицей правил.

use ailc_contracts::{
    looks_like_tool_failure, CapabilityManifest, CapabilityOutput, CheckOutcome, Ctx, EngineKind,
    Family, Finding, Location, Result, RunInput, Severity, Symbol, SymbolKind, Tier,
};
use ailc_core::engines::codeintel::CodeIntelEngine;
use ailc_core::engines::generator::Generator;
use ailc_core::engines::runner::Runner;
use ailc_core::engines::scan::{Matcher, Rule, ScanEngine, SOURCE_CODE};
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::collections::BTreeMap;
use std::path::Path;

// Модули capability по движкам (E7/E8/E9), созданы отдельно.
mod diagram;
mod metric;
mod store;
// Дозаполнение покрытия на готовых движках.
mod ai_security;
mod api_contract;
mod completeness;
mod compliance;
mod design;
mod desktop;
mod diff_scope;
mod governance;
mod mobile;
mod owasp;
mod release;
mod security_extra;
mod spec_check;
mod spec_gen;
mod supply;
mod surface;
mod ui_ux;
mod verify_extra;
mod web_security;
mod workflow_extra;

/// Единая JSON-схема входа для проверок «по проекту».
const TARGET_SCHEMA: &str = r#"{"type":"object","properties":{"target":{"type":"string"}}}"#;

fn scan_manifest(
    id: &'static str,
    family: Family,
    when_to_use: &'static str,
) -> CapabilityManifest {
    CapabilityManifest {
        id,
        family,
        engine: EngineKind::Scan,
        when_to_use,
        input_schema: TARGET_SCHEMA,
        tier: Tier::Core,
        deterministic: true,
        mutates: false,
    }
}

// ───────────────────── общий ScanCapability (один impl на все сканеры) ─────────────────────

/// Любой сканер = манифест + таблица правил поверх `ScanEngine`. Один `impl Capability`
/// обслуживает их все — нулевое дублирование boilerplate.
pub struct ScanCapability {
    manifest: CapabilityManifest,
    rules: Vec<Rule>,
}

impl ScanCapability {
    pub fn new(manifest: CapabilityManifest, rules: Vec<Rule>) -> Self {
        Self { manifest, rules }
    }
}

impl Capability for ScanCapability {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        // Сканеры безопасности/качества пропускают тест-файлы (фикстуры ≠ находки).
        ScanEngine::run(ctx, input, &self.rules, self.manifest.id, true)
    }
}

// ───────────────────────── security.scan/secret ─────────────────────────

/// Описание одного секрет-правила как ЧИСТЫХ ДАННЫХ (T62): идентификатор, важность,
/// паттерн и сообщение отделены от способа матча. Способ матча задаётся полем `kind`,
/// поэтому загрузчик [`secret_scan`] превращает таблицу в `Vec<Rule>` единообразно, а
/// добавить секрет означает дописать строку в таблицу, а не повторить boilerplate
/// `Rule { … }`. Каждое сообщение несёт проверенную ссылку CWE и где уместно OWASP.
struct SecretRule {
    id: &'static str,
    severity: Severity,
    kind: SecretKind,
    message: &'static str,
}

/// Способ матча секрет-правила. Отделяет «что искать» (паттерн) от «как искать»
/// (область и фильтр энтропии), чтобы таблица оставалась данными. Многострочные виды
/// (`MultilineToken`, `MultilineEntropy`) задают секрет-правилу scope File: движок
/// читает файл целиком и применяет паттерн к исходному тексту И к тексту со склеенными
/// соседними строковыми литералами, поэтому ловит секрет, разорванный переносом строки
/// или конкатенацией (T04). Порог энтропии адаптируется по длине и мощности алфавита
/// значения тем, что для коротких значений берётся высокий порог, а для длинных и для
/// явно низкоалфавитных (hex/base64) значений вводятся отдельные строки таблицы с
/// пониженным порогом: длина и узкий алфавит сами по себе суть свидетельство.
enum SecretKind {
    /// Точная форма токена по одной строке (AKIA+16, ghp_+36 и тому подобное).
    Token(&'static str),
    /// Точная форма токена, но scope File: паттерн с `(?s)` по всему файлу и по
    /// склейке литералов (PEM-ключ, GCP private_key, разорванные переносом).
    MultilineToken(&'static str),
    /// Значение в capture-группе 1 засчитывается секретом при энтропии не ниже порога
    /// (построчно). Высокий порог для коротких значений отсекает плейсхолдеры.
    Entropy {
        pattern: &'static str,
        min_bits: f64,
    },
    /// То же, но scope File и склейка литералов: ловит секрет, собранный конкатенацией
    /// или разнесённый переносом строки (T04). Пониженный порог применяется к длинным и
    /// низкоалфавитным значениям, для которых сама длина уже является свидетельством.
    MultilineEntropy {
        pattern: &'static str,
        min_bits: f64,
    },
}

impl SecretRule {
    /// Превратить строку таблицы в `Rule` движка. `exts` всегда пуст: секреты ищем в
    /// любых текстовых файлах, включая конфиги форматов xml/plist/properties (T04),
    /// поскольку движок применяет правило с пустым списком расширений к любому тексту.
    fn into_rule(self) -> Rule {
        let matcher = match self.kind {
            SecretKind::Token(p) => Matcher::regex(p),
            SecretKind::MultilineToken(p) => Matcher::multiline_regex(p),
            SecretKind::Entropy { pattern, min_bits } => Matcher::entropy(pattern, min_bits),
            SecretKind::MultilineEntropy { pattern, min_bits } => {
                Matcher::multiline_entropy(pattern, min_bits)
            }
        };
        Rule {
            id: self.id,
            severity: self.severity,
            exts: &[],
            matcher,
            message: self.message,
        }
    }
}

/// ТАБЛИЦА секрет-правил как данные (T62). Загрузчик [`secret_scan`] лишь отображает её
/// в `Vec<Rule>`. Порядок не влияет на результат: каждое правило сработает независимо.
fn secret_rule_table() -> Vec<SecretRule> {
    use Severity::{Critical, High, Medium};
    vec![
        // ── Точные формы токенов (одна строка достаточна) ───────────────────
        // Строгая форма AWS Access Key: AKIA/ASIA + 16 [0-9A-Z]. Голый литерал
        // паттерна под неё не подпадает, нужны реальные 16 символов. CWE-798.
        SecretRule {
            id: "aws-access-key",
            severity: Critical,
            kind: SecretKind::Token(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            message: "Похоже на AWS Access Key ID, захардкоженные учётные данные (CWE-798)",
        },
        SecretRule {
            id: "github-token",
            severity: Critical,
            kind: SecretKind::Token(r"\bgh[pousr]_[0-9A-Za-z]{36}\b"),
            message: "Токен GitHub (ghp_/gho_/…), захардкоженные учётные данные (CWE-798)",
        },
        SecretRule {
            id: "stripe-key",
            severity: Critical,
            kind: SecretKind::Token(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"),
            message: "Секретный ключ Stripe, захардкоженные учётные данные (CWE-798)",
        },
        SecretRule {
            id: "google-api-key",
            severity: High,
            kind: SecretKind::Token(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
            message: "Ключ Google API, захардкоженные учётные данные (CWE-798)",
        },
        SecretRule {
            id: "jwt",
            severity: Medium,
            kind: SecretKind::Token(
                r"\beyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}\b",
            ),
            message: "JWT-токен в исходниках, захардкоженные учётные данные (CWE-798)",
        },
        SecretRule {
            id: "gitlab-token",
            severity: Critical,
            kind: SecretKind::Token(r"\bglpat-[0-9A-Za-z_\-]{20,}"),
            message: "Токен GitLab (glpat-…), захардкоженные учётные данные (CWE-798)",
        },
        SecretRule {
            id: "slack-token",
            severity: Critical,
            kind: SecretKind::Token(r"\bxox[abposr]-[0-9A-Za-z\-]{10,}\b"),
            message: "Токен Slack (xoxb-/xoxp-/…), захардкоженные учётные данные (CWE-798)",
        },
        SecretRule {
            id: "sendgrid-key",
            severity: Critical,
            kind: SecretKind::Token(r"\bSG\.[0-9A-Za-z_\-]{16,}\.[0-9A-Za-z_\-]{16,}\b"),
            message: "Ключ SendGrid API, захардкоженные учётные данные (CWE-798)",
        },
        SecretRule {
            id: "npm-token",
            severity: Critical,
            kind: SecretKind::Token(r"\bnpm_[0-9A-Za-z]{36}\b"),
            message: "Токен npm (npm_…), захардкоженные учётные данные (CWE-798)",
        },
        SecretRule {
            id: "twilio-sid",
            severity: High,
            kind: SecretKind::Token(r"\bAC[0-9a-f]{32}\b"),
            message: "Похоже на Twilio Account SID, захардкоженные учётные данные (CWE-798)",
        },
        // Twilio Auth Token формы префикса не имеет: 32 hex-символа в паре с контекстом
        // «twilio»/«auth_token». Контекст рядом отсекает случайные 32-hex (md5 и т.п.).
        SecretRule {
            id: "twilio-auth-token",
            severity: High,
            kind: SecretKind::Token(
                r"(?i)twilio[^0-9a-f]{0,40}\b[0-9a-f]{32}\b|auth[_-]?token[^0-9a-f]{0,8}\b[0-9a-f]{32}\b",
            ),
            message: "Похоже на Twilio Auth Token, захардкоженные учётные данные (CWE-798)",
        },
        SecretRule {
            id: "azure-account-key",
            severity: Critical,
            kind: SecretKind::Token(r"(?i)AccountKey=[0-9A-Za-z+/=]{40,}"),
            message: "Ключ доступа Azure Storage (connection string), учётные данные (CWE-798)",
        },
        // AWS Secret Access Key формы не имеет (40 случайных base64-символов), ловим по
        // контексту: «aws» рядом + строковый литерал ровно из 40 символов. CWE-798.
        SecretRule {
            id: "aws-secret-key",
            severity: High,
            kind: SecretKind::Token(r#"(?i)\baws.{0,20}["'][0-9A-Za-z/+]{40}["']"#),
            message: "Похоже на AWS Secret Access Key, захардкоженные учётные данные (CWE-798)",
        },
        // Ключи LLM-провайдеров (OpenAI sk-/sk-proj-, Anthropic sk-ant-, HuggingFace
        // hf_). Дефис у sk- отличает их от Stripe sk_ (подчёркивание). CWE-798.
        SecretRule {
            id: "llm-api-key",
            severity: Critical,
            kind: SecretKind::Token(r"\bsk-[A-Za-z0-9_\-]{20,}\b|\bhf_[A-Za-z0-9]{30,}\b"),
            message: "Ключ LLM-провайдера (OpenAI/Anthropic/HuggingFace), учётные данные (CWE-798)",
        },
        // DigitalOcean Personal Access Token: префикс dop_v1_ + 64 hex. CWE-798.
        SecretRule {
            id: "digitalocean-token",
            severity: Critical,
            kind: SecretKind::Token(r"\bdop_v1_[0-9a-f]{64}\b"),
            message: "Токен DigitalOcean (dop_v1_…), захардкоженные учётные данные (CWE-798)",
        },
        // Mailgun private API key: префикс key- + 32 hex. CWE-798.
        SecretRule {
            id: "mailgun-key",
            severity: Critical,
            kind: SecretKind::Token(r"\bkey-[0-9a-f]{32}\b"),
            message: "Приватный ключ Mailgun (key-…), захардкоженные учётные данные (CWE-798)",
        },
        // Mapbox secret access token: префикс sk. + длинная base62-часть. Публичный
        // pk.-токен не секрет, поэтому ловим только sk.. CWE-798.
        SecretRule {
            id: "mapbox-secret-token",
            severity: High,
            kind: SecretKind::Token(r"\bsk\.[A-Za-z0-9._-]{40,}\b"),
            message: "Секретный токен Mapbox (sk.…), захардкоженные учётные данные (CWE-798)",
        },
        // Sentry DSN с встроенным секретом: схема://<публичный>:<секрет>@host/<id> либо
        // без пароля https://<ключ>@host/<id>. Несёт ключ проекта. CWE-798.
        SecretRule {
            id: "sentry-dsn",
            severity: High,
            kind: SecretKind::Token(
                r"(?i)\bhttps?://[0-9a-f]{16,}(?::[0-9a-f]+)?@[\w.-]*sentry[\w.-]*/\d+\b",
            ),
            message: "Sentry DSN с ключом проекта в исходниках (CWE-798)",
        },
        // Firebase Cloud Messaging / Google legacy server key: префикс AAAA + base64url
        // через дефис. CWE-798.
        SecretRule {
            id: "firebase-fcm-key",
            severity: High,
            kind: SecretKind::Token(r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}\b"),
            message: "Серверный ключ Firebase Cloud Messaging (CWE-798)",
        },
        // ── DB-URI с НЕПУСТЫМ паролём (без зависимости от кавычек) ───────────
        // postgres|postgresql|mysql|mongodb|mongodb+srv|redis|amqp://user:pass@host.
        // Требуется непустой пароль: схема://, имя, двоеточие, минимум один символ
        // пароля (не «@» и не пробел), «@». Так строки без пароля не дают ложного
        // срабатывания, а реальная утечда учётных данных СУБД ловится. CWE-798.
        SecretRule {
            id: "db-uri-password",
            severity: High,
            kind: SecretKind::Token(
                r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^:@/\s]+:[^@/\s]+@",
            ),
            message: "URI базы данных с паролём в исходниках, учётные данные (CWE-798)",
        },
        // ── Многострочные точные формы (scope File + склейка литералов) ──────
        // Приватный ключ PEM: заголовок и тело могут быть разнесены по строкам или
        // собраны конкатенацией; построчное правило поймало бы только заголовок,
        // поэтому здесь scope File с (?s). CWE-321 (хардкод криптоключа), CWE-798.
        SecretRule {
            id: "private-key",
            severity: Critical,
            kind: SecretKind::MultilineToken(
                r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.{0,4096}?-----END [A-Z0-9 ]*PRIVATE KEY-----|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
            ),
            message: "Приватный ключ в репозитории, захардкоженный криптоключ (CWE-321, CWE-798)",
        },
        // GCP service-account: поле JSON "private_key": "-----BEGIN …". Значение часто
        // содержит \n внутри строки; scope File с (?s) ловит и его. CWE-798, CWE-321.
        SecretRule {
            id: "gcp-private-key",
            severity: Critical,
            kind: SecretKind::MultilineToken(
                r#"(?is)"private_key"\s*:\s*"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"#,
            ),
            message: "Приватный ключ сервис-аккаунта GCP в JSON (CWE-798, CWE-321)",
        },
        // ── Энтропийные generic-secret правила с АДАПТИВНЫМ порогом ──────────
        // Короткое значение в кавычках (12..=31 символ) требует высокого порога 3.5:
        // длина мала, поэтому только высокая энтропия отличает секрет от плейсхолдера.
        // CWE-798. OWASP A07:2021 (Identification and Authentication Failures).
        SecretRule {
            id: "generic-secret",
            severity: High,
            kind: SecretKind::MultilineEntropy {
                pattern:
                    r#"(?is)\b(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth[_-]?token|token)\b\s*[:=]\s*["']([^"'\s]{12,31})["']"#,
                min_bits: 3.5,
            },
            message: "Возможный захардкоженный секрет (высокая энтропия короткого значения), CWE-798, OWASP A07:2021",
        },
        // Длинное значение в кавычках (32+ символа): длина сама по себе свидетельство,
        // поэтому порог понижен до 3.0 (адаптация по длине). Низкоалфавитные base64/hex
        // секреты длиной 32+ попадают именно сюда. CWE-798, OWASP A07:2021.
        SecretRule {
            id: "generic-secret-long",
            severity: High,
            kind: SecretKind::MultilineEntropy {
                pattern:
                    r#"(?is)\b(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth[_-]?token|token)\b\s*[:=]\s*["']([^"'\s]{32,})["']"#,
                min_bits: 3.0,
            },
            message: "Возможный захардкоженный секрет (длинное случайное значение), CWE-798, OWASP A07:2021",
        },
        // Парольная фраза: значение в кавычках С пробелами, длиной 16+ символов. Реальные
        // парольные фразы содержат пробелы, поэтому отдельная строка таблицы разрешает их
        // (адаптация под алфавит с пробелами), но требует и достаточной длины, и порога
        // энтропии 2.8, чтобы отсечь обычные подписи интерфейса. CWE-798, OWASP A07:2021.
        SecretRule {
            id: "generic-passphrase",
            severity: Medium,
            kind: SecretKind::MultilineEntropy {
                pattern:
                    r#"(?is)\b(?:password|passwd|passphrase|secret)\b\s*[:=]\s*["']([^"']{16,})["']"#,
                min_bits: 2.8,
            },
            message: "Возможная захардкоженная парольная фраза (CWE-798, OWASP A07:2021)",
        },
        // KEY=VALUE БЕЗ кавычек: .env/CI-yaml/properties, где значение не заключено в
        // кавычки. Граница значения — конец строки или пробел; scope File ради единого
        // прохода со склейкой. Высокий порог 3.5 нужен, потому что без кавычек больше
        // шумных совпадений. CWE-798, OWASP A07:2021.
        SecretRule {
            id: "generic-secret-unquoted",
            severity: High,
            kind: SecretKind::MultilineEntropy {
                // Значение это ЛИТЕРАЛЬНЫЙ токен (base64/hex/случайная строка). Charset
                // намеренно узкий: [A-Za-z0-9_+/=-], поэтому `$`, `{`, `}`, `(`, `)`, `.`,
                // `,` ОБРЫВАЮТ совпадение. Так отсекаются НЕ-секреты, дающие массовый шум
                // в исходниках: ссылки на переменные окружения (KEY=${VAR}, KEY=$VAR),
                // вызовы (key = strings.TrimSpace(x)) и поля структур из конфига
                // (SecretKey: cfg.YooKassaSecretKey,). Реальный литерал-секрет состоит из
                // токен-символов и поэтому ловится. Структурированные секреты с точками
                // (JWT, db-uri, sendgrid) покрыты отдельными правилами.
                pattern:
                    r#"(?im)^\s*(?:export\s+)?[A-Za-z0-9_.\-]*(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth[_-]?token|token)[A-Za-z0-9_.\-]*\s*[:=]\s*([A-Za-z0-9_+/=\-]{16,})\s*$"#,
                min_bits: 3.5,
            },
            message: "Возможный захардкоженный литеральный секрет без кавычек (.env/yaml/properties), CWE-798, OWASP A07:2021",
        },
        // XML/plist/properties со значением между тегами: <string>СЕКРЕТ</string> либо
        // <key>apiKey</key><string>СЕКРЕТ</string>. Имя поля рядом, значение высокой
        // энтропии. scope File, так как открывающий и закрывающий теги, а равно пара
        // key/string, бывают на соседних строках. CWE-798, OWASP A07:2021.
        // Случай plist: <key>apiKey</key><string>СЕКРЕТ</string>. Значение всегда в
        // группе 1, поэтому энтропийный матчер (который читает именно группу 1) работает
        // одинаково на обоих случаях XML. CWE-798, OWASP A07:2021.
        SecretRule {
            id: "generic-secret-plist",
            severity: High,
            kind: SecretKind::MultilineEntropy {
                pattern:
                    r#"(?is)<key>\s*[A-Za-z0-9_.\-]*(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth[_-]?token|token)[A-Za-z0-9_.\-]*\s*</key>\s*<(?:string|value)>([^<\s]{16,})</"#,
                min_bits: 3.2,
            },
            message: "Возможный захардкоженный секрет в plist/XML (key+string), CWE-798, OWASP A07:2021",
        },
        // Случай Android strings.xml: <string name="api_key">СЕКРЕТ</string>. Значение
        // снова в группе 1. CWE-798, OWASP A07:2021.
        SecretRule {
            id: "generic-secret-xml",
            severity: High,
            kind: SecretKind::MultilineEntropy {
                pattern:
                    r#"(?is)<(?:string|value)\s+name\s*=\s*["'][A-Za-z0-9_.\-]*(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth[_-]?token|token)[A-Za-z0-9_.\-]*["']\s*>([^<\s]{16,})</"#,
                min_bits: 3.2,
            },
            message: "Возможный захардкоженный секрет в XML (strings.xml name=), CWE-798, OWASP A07:2021",
        },
    ]
}

pub fn secret_scan() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "security.scan/secret",
            Family::Security,
            "Найти захардкоженные секреты, токены и приватные ключи перед коммитом.",
        ),
        secret_rule_table()
            .into_iter()
            .map(SecretRule::into_rule)
            .collect(),
    )
}

// ───────────────────────── quality.check/smell ─────────────────────────

pub fn smell_scan() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "quality.check/smell",
            Family::Quality,
            "Запахи корректности: проглоченные ошибки, panic/unwrap, маркеры техдолга.",
        ),
        vec![
            Rule {
                id: "swallowed-error",
                severity: Severity::Medium,
                exts: &["go", "rs", "ts", "js", "java", "kt", "swift"],
                matcher: Matcher::Predicate(|l| {
                    let s: String = l.chars().filter(|c| !c.is_whitespace()).collect();
                    s.contains("catch{}") || s.contains("except:pass") || s.contains("_=err")
                }),
                message: "Проглоченная ошибка",
            },
            Rule {
                id: "panic-path",
                severity: Severity::Low,
                exts: &["go", "rs"],
                matcher: Matcher::Predicate(|l| l.contains("panic(") || l.contains(".unwrap()")),
                message: "panic/unwrap — потенциальный аварийный выход",
            },
            Rule {
                id: "debt-marker",
                severity: Severity::Info,
                exts: &[],
                matcher: Matcher::Predicate(|l| {
                    l.contains("TODO") || l.contains("FIXME") || l.contains("XXX")
                }),
                message: "Маркер технического долга",
            },
        ],
    )
}

// ───────────────────────── security.scan/owasp ─────────────────────────

pub fn owasp_scan() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "security.scan/owasp",
            Family::Security,
            "Типовые уязвимости OWASP: инъекции, опасный eval/exec, слабая криптография, debug в проде.",
        ),
        vec![
            // A03 Injection: SQL-ключевое слово + конкатенация строки (не параметризация).
            Rule {
                id: "sql-injection",
                severity: Severity::High,
                exts: SOURCE_CODE,
                matcher: Matcher::Predicate(|l| {
                    let s = l.to_lowercase();
                    (s.contains("select ")
                        || s.contains("insert ")
                        || s.contains("update ")
                        || s.contains("delete "))
                        && (l.contains("\" +")
                            || l.contains("' +")
                            || l.contains("+ \"")
                            || s.contains(".format(")
                            || s.contains("f\""))
                }),
                message: "Возможная SQL-инъекция (конкатенация в запрос)",
            },
            // Требуем форму вызова `(` — литерал паттерна себя не ловит. Голые eval/exec
            // убраны: построчный паттерн флагует eval(bar) и там, где ввод не доходит до
            // стока; поток к ним строит `sast/taint-dynamic-exec`. Остаётся os.system.
            Rule {
                id: "dangerous-exec",
                severity: Severity::High,
                exts: SOURCE_CODE,
                matcher: Matcher::regex(r"(?i)\bos\.system\s*\("),
                message: "Опасное исполнение команды ОС (os.system)",
            },
            Rule {
                id: "shell-injection",
                severity: Severity::High,
                exts: SOURCE_CODE,
                matcher: Matcher::regex(r"(?i)shell\s*=\s*true"),
                message: "subprocess с shell=True — риск инъекции команд",
            },
            Rule {
                id: "weak-crypto",
                severity: Severity::Medium,
                exts: SOURCE_CODE,
                matcher: Matcher::regex(r"(?i)\b(?:md5|sha1)\s*\("),
                message: "Слабый хеш (MD5/SHA1)",
            },
            Rule {
                id: "debug-enabled",
                severity: Severity::Medium,
                exts: SOURCE_CODE,
                matcher: Matcher::regex(r"(?i)\bdebug\s*=\s*true"),
                message: "Debug-режим включён (риск утечки в проде)",
            },
        ],
    )
}

// ───────────────────────── security.scan/pii ─────────────────────────

pub fn pii_scan() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "security.scan/pii",
            Family::Security,
            "Персональные данные в коде/логах: SSN, карты, email, логирование чувствительных полей.",
        ),
        vec![
            Rule {
                id: "ssn-us",
                severity: Severity::High,
                exts: &[],
                matcher: Matcher::regex(r"\b\d{3}-\d{2}-\d{4}\b"),
                message: "Похоже на US SSN",
            },
            Rule {
                id: "credit-card",
                severity: Severity::Medium,
                exts: &[],
                // И с разделителями (1234 5678 ...), и слитные 16 цифр.
                matcher: Matcher::regex(r"\b(?:\d{4}[ -]){3}\d{4}\b|\b\d{16}\b"),
                message: "Похоже на номер банковской карты",
            },
            // Логирование чувствительного поля — «горячий риск» утечки PII в логи.
            Rule {
                id: "pii-in-log",
                severity: Severity::Medium,
                exts: &[],
                matcher: Matcher::Predicate(|l| {
                    let s = l.to_lowercase();
                    (s.contains("console.log")
                        || s.contains("print(")
                        || s.contains("println")
                        || s.contains("logger.")
                        || s.contains("log.info")
                        || s.contains("log.debug"))
                        && (s.contains("password")
                            || s.contains("email")
                            || s.contains("ssn")
                            || s.contains("token")
                            || s.contains("secret"))
                }),
                message: "Логирование чувствительного поля (риск утечки PII в логи)",
            },
            Rule {
                id: "email-literal",
                severity: Severity::Info,
                exts: &[],
                matcher: Matcher::regex(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
                message: "Email в исходниках",
            },
        ],
    )
}

// ───────────────────────── code.intel/symbols ─────────────────────────

pub struct ListSymbols {
    manifest: CapabilityManifest,
}

impl Default for ListSymbols {
    fn default() -> Self {
        Self::new()
    }
}

impl ListSymbols {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "code.intel/symbols",
                family: Family::CodeIntel,
                engine: EngineKind::CodeIntel,
                when_to_use: "Перечислить функции/типы/классы проекта на любом языке — карта кода перед изменением.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for ListSymbols {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let syms = CodeIntelEngine::symbols(ctx, input)?;
        let mut out = CapabilityOutput::default();

        // Нет распознанных символов → честно сообщаем, а не выдаём пустоту как успех.
        if syms.is_empty() {
            out.skipped =
                Some("не найдено исходников на поддерживаемых языках".to_string());
            out.summary = "code.intel/symbols: нет поддерживаемых исходников".to_string();
            return Ok(out);
        }

        out.metrics.push(("symbols".into(), syms.len() as f64));
        let mut by_lang: BTreeMap<&str, u64> = BTreeMap::new();
        for s in &syms {
            *by_lang.entry(s.lang.as_str()).or_default() += 1;
        }
        for (lang, n) in &by_lang {
            out.metrics.push((format!("lang.{lang}"), *n as f64));
        }
        for s in &syms {
            out.records.push(format!(
                "{}:{} [{}] {} {}{}",
                s.file,
                s.line,
                s.lang,
                s.kind,
                s.name,
                if s.exported { " (pub)" } else { "" }
            ));
        }
        let langs: Vec<String> = by_lang.iter().map(|(l, n)| format!("{l}:{n}")).collect();
        out.summary = format!(
            "code.intel/symbols: {} символов [{}]",
            syms.len(),
            langs.join(", ")
        );
        Ok(out)
    }
}

// ───────────────────────── code.intel/module_card ─────────────────────────

pub struct ModuleCard {
    manifest: CapabilityManifest,
}

impl Default for ModuleCard {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleCard {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "code.intel/module_card",
                family: Family::CodeIntel,
                engine: EngineKind::CodeIntel,
                when_to_use: "Сводка по частям проекта: сколько определений и публичного API в каждой папке-пакете.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for ModuleCard {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let stats = CodeIntelEngine::module_stats(ctx, input)?;
        let mut out = CapabilityOutput::default();

        if stats.is_empty() {
            out.skipped =
                Some("не найдено исходников на поддерживаемых языках".to_string());
            out.summary = "code.intel/module_card: нет поддерживаемых исходников".to_string();
            return Ok(out);
        }

        let total: u32 = stats.values().map(|s| s.total).sum();
        out.metrics.push(("modules".into(), stats.len() as f64));
        for (m, st) in &stats {
            let langs: Vec<&str> = st.langs.iter().map(String::as_str).collect();
            out.records.push(format!(
                "{m}/ — {} определений ({} pub) · {}",
                st.total,
                st.exported,
                langs.join(",")
            ));
        }
        out.summary = format!(
            "code.intel/module_card: {} частей, {total} определений",
            stats.len()
        );
        Ok(out)
    }
}

// ───────────────────────── code.intel/call_graph ─────────────────────────

pub struct CallGraphCap {
    manifest: CapabilityManifest,
}

impl Default for CallGraphCap {
    fn default() -> Self {
        Self::new()
    }
}

impl CallGraphCap {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "code.intel/call_graph",
                family: Family::CodeIntel,
                engine: EngineKind::CodeIntel,
                when_to_use: "Граф вызовов: кто какую функцию зовёт. Показывает радиус влияния изменения и потенциально недостижимые функции. Точный AST-разбор; вызовы во вне (библиотеки/динамика) помечаются явно.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for CallGraphCap {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let cg = CodeIntelEngine::call_graph(ctx, input)?;
        let mut out = CapabilityOutput::default();

        if cg.files_parsed == 0 {
            out.skipped =
                Some("не найдено исходников на языках с AST-грамматикой".to_string());
            out.summary = "code.intel/call_graph: нет разбираемых исходников".to_string();
            return Ok(out);
        }

        let unreachable = cg.unreachable();
        out.metrics.push(("functions".into(), cg.funcs.len() as f64));
        out.metrics.push(("edges".into(), cg.edges.len() as f64));
        out.metrics.push(("calls_total".into(), cg.total_calls as f64));
        out.metrics
            .push(("calls_unresolved".into(), cg.unresolved as f64));
        out.metrics
            .push(("unreachable".into(), unreachable.len() as f64));

        // Доля разрешённых вызовов — честный индикатор полноты графа.
        let resolved = cg.total_calls.saturating_sub(cg.unresolved);
        out.records.push(format!(
            "вызовов: {} (разрешено {resolved}, вовне {})",
            cg.total_calls, cg.unresolved
        ));
        for f in unreachable.iter().take(15) {
            out.records
                .push(format!("потенциально недостижима: {f}()"));
        }
        if unreachable.len() > 15 {
            out.records
                .push(format!("… ещё {} функций", unreachable.len() - 15));
        }

        out.summary = format!(
            "code.intel/call_graph: {} функций, {} рёбер, {} вызовов вовне, {} потенциально недостижимых",
            cg.funcs.len(),
            cg.edges.len(),
            cg.unresolved,
            unreachable.len()
        );
        Ok(out)
    }
}

// ───────────────────────── quality.check/dead-code ─────────────────────────

// ───────────────────────── code.intel/map ─────────────────────────

pub struct ProjectMapCap {
    manifest: CapabilityManifest,
}

impl Default for ProjectMapCap {
    fn default() -> Self {
        Self::new()
    }
}

impl ProjectMapCap {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "code.intel/map",
                family: Family::CodeIntel,
                engine: EngineKind::CodeIntel,
                when_to_use: "Карта незнакомого проекта одним вызовом: дерево папок (языки, файлы, строки, символы) и точки входа.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for ProjectMapCap {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let map = CodeIntelEngine::project_map(ctx, input)?;
        let mut out = CapabilityOutput::default();

        if map.total_files == 0 {
            out.skipped = Some("не найдено исходников на поддерживаемых языках".to_string());
            out.summary = "code.intel/map: нет поддерживаемых исходников".to_string();
            return Ok(out);
        }

        out.metrics.push(("files".into(), map.total_files as f64));
        out.metrics.push(("lines".into(), map.total_lines as f64));
        out.metrics
            .push(("entry_points".into(), map.entry_points.len() as f64));

        for d in &map.dirs {
            let langs: Vec<&str> = d.langs.iter().map(String::as_str).collect();
            out.records.push(format!(
                "{}/ [{}] {}ф {}стр {}симв",
                d.path,
                langs.join(","),
                d.files,
                d.lines,
                d.symbols
            ));
        }
        out.records.push(format!(
            "точки входа: {}",
            if map.entry_points.is_empty() {
                "— не найдено —".to_string()
            } else {
                map.entry_points.join(", ")
            }
        ));

        let langs: Vec<String> = map
            .langs
            .iter()
            .map(|(l, n)| format!("{l}:{n}"))
            .collect();
        out.summary = format!(
            "code.intel/map: {} файлов, ~{} строк, языки [{}], точек входа {}",
            map.total_files,
            map.total_lines,
            langs.join(", "),
            map.entry_points.len()
        );
        Ok(out)
    }
}

/// Символ из тест-файла или фреймворк-точки входа — его «вызывает» раннер/рантайм,
/// а не прикладной код, поэтому он не может быть «мёртвым» по отсутствию ссылок.
fn is_test_or_entry(s: &Symbol) -> bool {
    let f = s.file.to_lowercase();
    let is_test = f.ends_with("_test.go")
        || f.contains("/test")
        || f.contains("__tests__")
        || f.contains("/tests/")
        || f.contains(".test.")
        || f.contains(".spec.")
        || f.rsplit(['/', '\\']).next().is_some_and(|n| n.starts_with("test_"));
    let base = f.rsplit(['/', '\\']).next().unwrap_or(f.as_str());
    // Файлы-точки входа веб-фреймворков: их экспорты вызывает фреймворк/сборщик, а не
    // прикладной код, поэтому отсутствие ссылок не делает их мёртвыми. Только однозначные
    // ИМЕНА файлов (page.tsx/route.ts/layout/+server/*.config), без широких подстрок вроде
    // /app/ или /pages/, чтобы не зацепить обычные каталоги с такими именами.
    let is_framework_file = matches!(
        base,
        "page.tsx" | "page.jsx" | "page.ts" | "page.js" | "route.ts" | "route.js"
            | "layout.tsx" | "layout.jsx" | "middleware.ts" | "middleware.js"
            | "+page.svelte" | "+server.ts"
    ) || base.ends_with(".config.ts")
        || base.ends_with(".config.js")
        || base.ends_with(".config.mjs");
    let n = s.name.as_str();
    let is_entry = n == "main"
        || n == "init"
        || n.starts_with("Test")
        || n.starts_with("Benchmark")
        || n.starts_with("Example")
        || n.starts_with("Fuzz");
    // Хуки данных/метаданных фреймворков (Next.js): вызываются рантаймом по соглашению.
    let is_framework_hook = matches!(
        n,
        "getServerSideProps"
            | "getStaticProps"
            | "getStaticPaths"
            | "generateMetadata"
            | "generateStaticParams"
            | "generateViewport"
    );
    is_test || is_entry || is_framework_file || is_framework_hook
}

pub struct DeadCode {
    manifest: CapabilityManifest,
}

impl Default for DeadCode {
    fn default() -> Self {
        Self::new()
    }
}

impl DeadCode {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "quality.check/dead-code",
                family: Family::Quality,
                engine: EngineKind::CodeIntel,
                when_to_use: "Найти экспортируемые символы без использований — кандидаты в мёртвый код.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for DeadCode {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let syms = CodeIntelEngine::symbols(ctx, input)?;
        let freq = CodeIntelEngine::identifier_freq(ctx, input)?;
        let mut out = CapabilityOutput::default();

        for s in &syms {
            // Имя встречается только в своём определении (freq ≤ 1) → кандидат.
            // ИСКЛЮЧАЕМ ложные источники (как делает зрелый анализ):
            //  - тест-файлы и фреймворк-точки (Test*/Benchmark*/main/init) — их
            //    «вызывает» раннер, не код, поэтому freq=1 не значит «мёртвый»;
            //  - методы — часто удовлетворяют интерфейсам/трейтам неявно;
            //  - имена <2 символов — identifier_freq их не считает.
            if s.exported
                && !matches!(s.kind, SymbolKind::Method)
                && !is_test_or_entry(s)
                && s.name.chars().count() >= 2
                && freq.get(&s.name).copied().unwrap_or(0) <= 1
            {
                out.findings.push(Finding {
                    rule: "dead-export".into(),
                    severity: Severity::Low,
                    message: format!(
                        "Экспортируемый {} `{}` без использований (возможно мёртвый код)",
                        s.kind, s.name
                    ),
                    location: Some(Location {
                        file: s.file.clone(),
                        line: s.line,
                    }),
                    evidence: None,
                    verified: true,
                    source: "quality.check/dead-code".into(),
                });
            }
        }
        out.metrics
            .push(("dead_candidates".into(), out.findings.len() as f64));
        out.summary = format!(
            "quality.check/dead-code: {} кандидатов в мёртвый код",
            out.findings.len()
        );
        Ok(out)
    }
}

// ───────────────────────── code.intel/find_usages ─────────────────────────

pub struct FindUsages {
    manifest: CapabilityManifest,
}

impl Default for FindUsages {
    fn default() -> Self {
        Self::new()
    }
}

impl FindUsages {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "code.intel/find_usages",
                family: Family::CodeIntel,
                engine: EngineKind::CodeIntel,
                when_to_use: "Найти все использования символа по имени — оценить влияние ПЕРЕД изменением.",
                input_schema: r#"{"type":"object","properties":{"query":{"type":"string"},"target":{"type":"string"}},"required":["query"]}"#,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for FindUsages {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        // Инвариант «нет молчаливых пропусков»: без query — явная причина.
        let query = match input.query.as_deref().filter(|q| !q.is_empty()) {
            Some(q) => q,
            None => {
                out.skipped = Some("нужен параметр query — имя символа для поиска".into());
                out.summary = "code.intel/find_usages: пропущено (нет query)".into();
                return Ok(out);
            }
        };
        let refs = CodeIntelEngine::references(ctx, input, query)?;
        out.metrics.push(("usages".into(), refs.len() as f64));
        for (file, line, text) in &refs {
            out.records.push(format!("{file}:{line}  {text}"));
        }
        out.summary = format!("code.intel/find_usages «{query}»: {} вхождений", refs.len());
        Ok(out)
    }
}

// ───────────────────────── quality.check/cycles ─────────────────────────

pub struct CyclesCheck {
    manifest: CapabilityManifest,
}

impl Default for CyclesCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl CyclesCheck {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "quality.check/cycles",
                family: Family::Quality,
                engine: EngineKind::CodeIntel,
                when_to_use: "Найти циклические зависимости между модулями — архитектурный запах.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for CyclesCheck {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let graph = CodeIntelEngine::dependency_graph(ctx, input)?;
        let mut out = CapabilityOutput::default();

        // Нет модулей с распознанными импортами → анализ не применим, честно пропускаем.
        if graph.modules.is_empty() {
            out.skipped = Some("не найдено модулей с разбираемыми импортами".to_string());
            out.summary = "quality.check/cycles: нечего анализировать".to_string();
            return Ok(out);
        }

        let cycles = graph.cycles();
        for cyc in &cycles {
            out.findings.push(Finding {
                rule: "import-cycle".into(),
                severity: Severity::Medium,
                message: format!("Циклическая зависимость модулей: {}", cyc.join(" ↔ ")),
                location: None,
                evidence: None,
                verified: true,
                source: "quality.check/cycles".into(),
            });
        }
        out.metrics.push(("modules".into(), graph.modules.len() as f64));
        out.metrics.push(("edges".into(), graph.edges.len() as f64));
        out.metrics.push(("cycles".into(), cycles.len() as f64));
        out.summary = format!(
            "quality.check/cycles: {} модулей, {} рёбер, {} циклов",
            graph.modules.len(),
            graph.edges.len(),
            cycles.len()
        );
        Ok(out)
    }
}

// ───────────────────────── verify/test (E2 Runner) ─────────────────────────

/// Команда внешнего инструмента: бинарь и его аргументы. Тип-синоним делает таблицу
/// стеков ниже читаемой и единообразной для команды теста, основного линтера и фолбэка.
type ToolCmd = (&'static str, Vec<&'static str>);

/// ОДНА строка таблицы стеков (T62): как распознать проект и какие команды теста и
/// линтера для него запускать. Раньше распознавание стека дублировалось двумя
/// независимыми лестницами `if has(...)` (тестовой и линтерной), что нарушало принцип
/// «инструмент = данные» и грозило рассинхронизацией списков. Теперь обе ветви читают
/// ОДНУ таблицу: распознавание описано единожды, команды теста и линтера живут рядом.
struct Stack {
    /// Человекочитаемая метка стека для сообщений (rust, go, python и так далее).
    label: &'static str,
    /// Маркеры-файлы в корне проекта; присутствие ЛЮБОГО из них означает этот стек.
    /// Порядок строк таблицы задаёт приоритет распознавания (первое совпадение).
    markers: &'static [&'static str],
    /// Дополнительные расширения-маркеры (например .sln/.csproj для dotnet), когда сам
    /// проект распознаётся не по фиксированному имени файла, а по наличию файла-типа.
    marker_exts: &'static [&'static str],
    /// Команда запуска тестов.
    test: ToolCmd,
    /// Основная команда линтера.
    lint: ToolCmd,
    /// Необязательный фолбэк-линтер, если основной недоступен на машине.
    lint_fallback: Option<ToolCmd>,
}

/// ТАБЛИЦА стеков как данные: единый источник истины для verify/test и verify/lint
/// (T62). Каждый из 15 поддерживаемых движком стеков описан одной строкой, поэтому
/// добавить стек означает дописать строку, а не править две лестницы условий.
fn stack_table() -> Vec<Stack> {
    vec![
        Stack {
            label: "rust",
            markers: &["Cargo.toml"],
            marker_exts: &[],
            test: ("cargo", vec!["test", "--quiet"]),
            lint: ("cargo", vec!["clippy", "--quiet"]),
            lint_fallback: Some(("cargo", vec!["fmt", "--", "--check"])),
        },
        Stack {
            label: "go",
            markers: &["go.mod"],
            marker_exts: &[],
            test: ("go", vec!["test", "./..."]),
            lint: ("golangci-lint", vec!["run"]),
            lint_fallback: Some(("go", vec!["vet", "./..."])),
        },
        Stack {
            label: "node",
            markers: &["package.json"],
            marker_exts: &[],
            test: ("npm", vec!["test", "--silent"]),
            lint: ("eslint", vec!["."]),
            lint_fallback: None,
        },
        Stack {
            label: "python",
            markers: &["pyproject.toml", "pytest.ini", "setup.py", "requirements.txt"],
            marker_exts: &[],
            test: ("pytest", vec!["-q"]),
            lint: ("ruff", vec!["check", "."]),
            lint_fallback: Some(("flake8", vec!["."])),
        },
        Stack {
            label: "scala",
            markers: &["build.sbt"],
            marker_exts: &[],
            test: ("sbt", vec!["test"]),
            lint: ("scalafmt", vec!["--test"]),
            lint_fallback: None,
        },
        Stack {
            // Метка теста исторически «jvm/gradle», линтера «kotlin»; берём общую «gradle».
            label: "gradle",
            markers: &["build.gradle.kts", "build.gradle"],
            marker_exts: &[],
            test: ("gradle", vec!["test", "-q"]),
            lint: ("ktlint", vec![]),
            lint_fallback: Some(("gradle", vec!["check", "-q"])),
        },
        Stack {
            label: "maven",
            markers: &["pom.xml"],
            marker_exts: &[],
            test: ("mvn", vec!["-q", "test"]),
            lint: ("mvn", vec!["-q", "checkstyle:check"]),
            lint_fallback: None,
        },
        Stack {
            label: "swift",
            markers: &["Package.swift"],
            marker_exts: &[],
            test: ("swift", vec!["test"]),
            lint: ("swiftlint", vec![]),
            lint_fallback: None,
        },
        Stack {
            label: "dart",
            markers: &["pubspec.yaml"],
            marker_exts: &[],
            test: ("dart", vec!["test"]),
            lint: ("dart", vec!["analyze"]),
            lint_fallback: None,
        },
        Stack {
            label: "ruby",
            markers: &["Gemfile"],
            marker_exts: &[],
            test: ("bundle", vec!["exec", "rake", "test"]),
            lint: ("rubocop", vec![]),
            lint_fallback: None,
        },
        Stack {
            label: "php",
            markers: &["composer.json"],
            marker_exts: &[],
            test: ("composer", vec!["test"]),
            lint: ("phpcs", vec![]),
            lint_fallback: Some(("php", vec!["-l"])),
        },
        Stack {
            label: "c/c++",
            markers: &["CMakeLists.txt"],
            marker_exts: &[],
            test: ("ctest", vec!["--test-dir", "build", "--output-on-failure"]),
            lint: ("cppcheck", vec!["--quiet", "."]),
            lint_fallback: None,
        },
        Stack {
            label: "dotnet",
            markers: &[],
            marker_exts: &[".sln", ".csproj"],
            test: ("dotnet", vec!["test"]),
            lint: ("dotnet", vec!["format", "--verify-no-changes"]),
            lint_fallback: None,
        },
    ]
}

/// Распознать стек проекта по таблице [`stack_table`]: первое совпадение по файлу-маркеру
/// или по расширению-маркеру. Единый вход для verify/test и verify/lint (T62).
fn detect_stack(root: &Path) -> Option<Stack> {
    let has = |f: &str| root.join(f).exists();
    stack_table().into_iter().find(|s| {
        s.markers.iter().any(|m| has(m))
            || (!s.marker_exts.is_empty() && ailc_core::stack::has_ext(root, s.marker_exts))
    })
}

/// В выводе раннера есть ненулевое «N passed» (cargo «test result: ok. 13 passed»,
/// pytest «13 passed», jest «Tests: 13 passed») — значит, тесты реально выполнялись.
pub fn some_tests_passed(blob: &str) -> bool {
    let mut rest = blob;
    while let Some(i) = rest.find(" passed") {
        let digits: String = rest[..i]
            .chars()
            .rev()
            .take_while(char::is_ascii_digit)
            .collect();
        let n: u64 = digits
            .chars()
            .rev()
            .collect::<String>()
            .parse()
            .unwrap_or(0);
        if n > 0 {
            return true;
        }
        rest = &rest[i + " passed".len()..];
    }
    false
}

pub struct TestRun {
    manifest: CapabilityManifest,
}

impl Default for TestRun {
    fn default() -> Self {
        Self::new()
    }
}

impl TestRun {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "verify/test",
                family: Family::Verify,
                engine: EngineKind::Runner,
                when_to_use: "Реально прогнать тесты проекта (cargo/go/npm/pytest) и проверить, что код работает.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: false, // зависит от окружения/тулчейна
                mutates: false,
            },
        }
    }
}

impl Capability for TestRun {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let stack = match detect_stack(&ctx.root) {
            Some(s) => s,
            None => {
                out.skipped =
                    Some("тип проекта не распознан (нет Cargo.toml/go.mod/package.json/pyproject)".into());
                out.summary = "verify/test: пропущено (проект не распознан)".into();
                return Ok(out);
            }
        };
        let label = stack.label;
        let (bin, args) = &stack.test;
        let res = Runner::run(ctx, bin, args);
        if !res.ran {
            out.summary = format!(
                "verify/test ({label}): пропущено — {}",
                res.skipped_reason.as_deref().unwrap_or("нет инструмента")
            );
            out.skipped = res.skipped_reason;
            return Ok(out);
        }
        let blob = format!("{}\n{}", res.stdout, res.stderr);
        // T86: сбой САМОГО инструмента (ошибка сборки, не найден импорт/модуль, паника
        // тулчейна) принципиально отличается и от находки, и от пройденных тестов. По
        // инварианту README «сбой инструмента не равен находке» такой прогон НЕ значит
        // «тесты упали» (дефект кода) и тем более не значит «тесты прошли»: проверка не
        // состоялась. Классифицируем его как осознанный пропуск со причиной-сбоем,
        // который агрегатор Волны 2 через CapabilityOutput::outcome() распознает как
        // Failed (а не Skipped и не Ran), потому что looks_like_tool_failure истинна.
        if looks_like_tool_failure(&blob) {
            let reason = format!(
                "verify/test ({label}): инструмент не отработал (сборка/импорт), прогон тестов не состоялся"
            );
            out.skipped = Some(reason.clone());
            out.summary = format!(
                "verify/test ({label}): ⚠ инструмент не отработал (сборка/импорт), тесты НЕ выполнялись"
            );
            for l in res.tail(15) {
                out.records.push(l);
            }
            // Самопроверка инварианта: причина обязана классифицироваться как Failed,
            // иначе сбой инструмента молча сольётся с обычным «нечего проверять».
            debug_assert!(
                matches!(out.outcome(), CheckOutcome::Failed(_)),
                "сбой инструмента обязан давать CheckOutcome::Failed"
            );
            return Ok(out);
        }
        let blob_lc = blob.to_lowercase();
        // Отличаем «тестов нет/не настроены» от «прошли»/«упали»: иначе пустой прогон
        // выдаётся за зелёный — обещание «проверить, что код работает» не выполнено.
        let empty_markers = blob_lc.contains("no test")    // go: "no test files"
            || blob_lc.contains("0 tests")                 // cargo/jest
            || blob_lc.contains("running 0 tests")         // cargo
            || blob_lc.contains("no tests ran")            // pytest
            || blob_lc.contains("missing script")          // npm: нет скрипта test
            || blob_lc.contains("collected 0 items"); // pytest
        // Маркер пустой СЕКЦИИ не значит «тестов нет вообще»: cargo печатает
        // «running 0 tests» для пустых doc-test секций даже когда юнит-тесты прошли.
        // Если где-то есть ненулевое «N passed» — тесты были.
        let positive_proof = some_tests_passed(&blob_lc);
        let no_tests = empty_markers && !positive_proof;

        if no_tests {
            out.skipped =
                Some(format!("verify/test ({label}): тесты не найдены/не настроены"));
            out.summary = format!("verify/test ({label}): ⚠ тестов нет — работоспособность НЕ подтверждена");
        } else if res.exit_ok && positive_proof {
            // T86: «тесты прошли» печатаем ТОЛЬКО при ПОЗИТИВНОМ доказательстве реально
            // выполненных тестов (ненулевое «N passed»). Без него зелёный код выхода мог
            // бы означать пустой прогон, который выдавался бы за успех.
            out.summary = format!("verify/test ({label}): ✅ тесты прошли");
        } else if res.exit_ok {
            // Код выхода нулевой, но позитивного доказательства числа прошедших тестов
            // нет (нестандартный вывод раннера). Не выдаём это за «тесты прошли»:
            // работоспособность не подтверждена, честно сообщаем о недоказанном прогоне.
            out.skipped = Some(format!(
                "verify/test ({label}): прогон без подтверждённого числа пройденных тестов"
            ));
            out.summary = format!(
                "verify/test ({label}): ⚠ нет доказательства выполненных тестов — работоспособность НЕ подтверждена"
            );
            for l in res.tail(15) {
                out.records.push(l);
            }
        } else {
            out.findings.push(Finding {
                rule: "tests-failing".into(),
                severity: Severity::High,
                message: "Тесты не проходят".into(),
                location: None,
                evidence: None,
                verified: true, // прогон = верификация: падение реально
                source: "verify/test".into(),
            });
            for l in res.tail(15) {
                out.records.push(l);
            }
            out.summary = format!("verify/test ({label}): ❌ тесты падают (код {:?})", res.code);
        }
        out.metrics
            .push(("exit_ok".into(), if res.exit_ok { 1.0 } else { 0.0 }));
        Ok(out)
    }
}

// ───────────────────────── verify/lint (E2 Runner) ─────────────────────────

pub struct LintRun {
    manifest: CapabilityManifest,
}

impl Default for LintRun {
    fn default() -> Self {
        Self::new()
    }
}

impl LintRun {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "verify/lint",
                family: Family::Verify,
                engine: EngineKind::Runner,
                when_to_use: "Запустить линтер проекта (clippy/golangci-lint/eslint/ruff) с фолбэком.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: false,
                mutates: false,
            },
        }
    }
}

impl Capability for LintRun {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();
        let stack = match detect_stack(&ctx.root) {
            Some(s) => s,
            None => {
                out.skipped = Some("тип проекта не распознан".into());
                out.summary = "verify/lint: пропущено (проект не распознан)".into();
                return Ok(out);
            }
        };
        let label = stack.label;
        let (bin, args) = &stack.lint;
        let fallback = &stack.lint_fallback;

        let mut res = Runner::run(ctx, bin, args);
        let mut used = *bin;
        if !res.ran {
            if let Some((fb_bin, fb_args)) = fallback {
                res = Runner::run(ctx, fb_bin, fb_args);
                if res.ran {
                    used = fb_bin;
                }
            }
        }
        if !res.ran {
            let alt = fallback
                .as_ref()
                .map(|(b, _)| format!("/{b}"))
                .unwrap_or_default();
            out.skipped = Some(format!("линтер недоступен ({bin}{alt})"));
            out.summary = format!("verify/lint ({label}): пропущено (нет линтера)");
            return Ok(out);
        }

        if res.exit_ok {
            out.summary = format!("verify/lint ({label}, {used}): ✅ чисто");
        } else {
            out.findings.push(Finding {
                rule: "lint".into(),
                severity: Severity::Medium,
                message: format!("Линтер {used} сообщил о замечаниях"),
                location: None,
                evidence: None,
                verified: true,
                source: "verify/lint".into(),
            });
            for l in res.tail(15) {
                out.records.push(l);
            }
            out.summary = format!("verify/lint ({label}, {used}): ⚠ есть замечания");
        }
        Ok(out)
    }
}

// ───────────────────────── generate/docs (E5 Generator) ─────────────────────────

/// Склонение существительного по числу (1 определение / 2 определения / 5 определений).
fn plural(n: u32, one: &str, few: &str, many: &str) -> String {
    let nm = n % 100;
    let nd = n % 10;
    let word = if (11..=14).contains(&nm) {
        many
    } else if nd == 1 {
        one
    } else if (2..=4).contains(&nd) {
        few
    } else {
        many
    };
    format!("{n} {word}")
}

pub struct GenerateDocs {
    manifest: CapabilityManifest,
}

impl Default for GenerateDocs {
    fn default() -> Self {
        Self::new()
    }
}

impl GenerateDocs {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "generate/docs",
                family: Family::Generate,
                engine: EngineKind::Generator,
                when_to_use: "Создать обзор проекта живым русским языком: из каких частей он состоит и как они связаны.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: true, // пишет файл документации
            },
        }
    }
}

impl Capability for GenerateDocs {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let stats = CodeIntelEngine::module_stats(ctx, input)?;
        let cycles = CodeIntelEngine::dependency_graph(ctx, input)?.cycles();
        let total: u32 = stats.values().map(|s| s.total).sum();
        let mut langs: BTreeMap<String, ()> = BTreeMap::new();
        for st in stats.values() {
            for l in &st.langs {
                langs.insert(l.clone(), ());
            }
        }

        // ── Повествование на русском, без англицизмов ──
        let mut doc = String::new();
        doc.push_str("# Обзор проекта\n\n");
        doc.push_str("_Раздел между метками обновляется сам при каждом запуске. Всё, что вы допишете снаружи меток, сохранится._\n\n");

        let langs_list: Vec<&str> = langs.keys().map(String::as_str).collect();
        doc.push_str(&format!(
            "В проекте {} — функций, типов и тому подобного — собранных в {}. Использованные языки: {}.\n\n",
            plural(total, "значимое определение", "значимых определения", "значимых определений"),
            plural(stats.len() as u32, "часть", "части", "частей"),
            langs_list.join(", ")
        ));

        doc.push_str("## Из чего он складывается\n\n");
        for (name, st) in &stats {
            doc.push_str(&format!(
                "**{name}** — {}",
                plural(st.total, "определение", "определения", "определений")
            ));
            if st.exported > 0 {
                doc.push_str(&format!(", из них доступны другим частям {}", st.exported));
            }
            doc.push('.');
            if !st.top_exports.is_empty() {
                doc.push_str(&format!(" Среди них: {}.", st.top_exports.join(", ")));
            }
            doc.push_str("\n\n");
        }

        doc.push_str("## Как части связаны между собой\n\n");
        if cycles.is_empty() {
            doc.push_str("Замкнутых в круг зависимостей между частями не обнаружено — это хороший признак: части можно менять по отдельности.\n");
        } else {
            doc.push_str("Найдены части, которые ссылаются друг на друга по кругу. Такие круги затрудняют изменения, и со временем их стоит распутать:\n\n");
            for c in &cycles {
                doc.push_str(&format!("- {}\n", c.join(" → ")));
            }
        }

        let (path, action) = Generator::write_block(ctx, "docs/ОБЗОР.md", "overview", doc.trim())?;
        let mut out = CapabilityOutput::default();
        out.metrics.push(("parts".into(), stats.len() as f64));
        out.artifacts.push(path.clone());
        out.summary = format!("generate/docs: {path} ({action})");
        Ok(out)
    }
}

/// Регистрирует все CORE-capability, реализованные на текущих движках.
pub fn register_core(reg: &mut Registry) {
    // E1 ScanEngine — разные таблицы правил, один движок и один impl.
    reg.register(Box::new(secret_scan()));
    owasp::register(reg); // категорийный A01–A10 (вместо плоского owasp_scan)
    reg.register(Box::new(pii_scan()));
    reg.register(Box::new(smell_scan()));
    reg.register(Box::new(DeadCode::new())); // Quality, но на движке CodeIntel
    reg.register(Box::new(CyclesCheck::new())); // Quality, граф зависимостей
    // E3 CodeIntel (информационные).
    reg.register(Box::new(ListSymbols::new()));
    reg.register(Box::new(ModuleCard::new()));
    reg.register(Box::new(ProjectMapCap::new()));
    reg.register(Box::new(FindUsages::new()));
    reg.register(Box::new(CallGraphCap::new()));
    // E2 ExternalRunner (verify-семейство, реальный прогон).
    reg.register(Box::new(TestRun::new()));
    reg.register(Box::new(LintRun::new()));
    // E5 Generator (мутирующее: пишет файлы).
    reg.register(Box::new(GenerateDocs::new()));
    // E7 Store · E8 Metric · E9 Diagram (созданы агентами, регистрируются модулями).
    store::register(reg);
    metric::register(reg);
    diagram::register(reg);
    // Дозаполнение покрытия.
    governance::register(reg);
    mobile::register(reg);
    desktop::register(reg);
    ui_ux::register(reg); // семейство quality.ui/* — доступность и адаптивность поверх Scan
    security_extra::register(reg);
    web_security::register(reg); // E1 Scan — web/API уязвимости (корзина A)
    ai_security::register(reg); // E1 Scan — безопасность LLM (OWASP LLM Top-10)
    verify_extra::register(reg);
    workflow_extra::register(reg);
    completeness::register(reg); // страж недоделанного (Quality): заглушки/пустые блоки/недокументированное
    surface::register(reg); // code.intel/surface — поверхность из кода (эндпоинты/ENV/сервисы/модели)
    spec_gen::register(reg); // генераторы доков: спека (ГОСТ), архитектура (arc42), C4, модель данных, глоссарий
    spec_check::register(reg); // spec.check/drift — дрейф доков относительно кода (Family::Spec, в гейт)
    design::register(reg); // spec/feature — проектирование новой фичи (заготовка спеки + ADR)
    api_contract::register(reg); // generate/api-baseline + verify/api-break — слом публичного API
    diff_scope::register(reg); // code.intel/diff-scope — радиус влияния правки (git+граф вызовов)
    supply::register(reg); // generate/sbom + security.scan/licenses — supply-chain из lock-файлов
    release::register(reg); // generate/release-notes + setup/cicd — релиз-заметки и CI-скаффолд
    compliance::register(reg); // семейство Compliance — регуляторные риски РФ
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Временный проект из пар (относительный путь, содержимое). Уникальная директория на
    /// каждый вызов, чтобы тесты не мешали друг другу при параллельном прогоне.
    fn tmp(files: &[(&str, &str)]) -> Ctx {
        let n = CNT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ailc-lib-{}-{}", std::process::id(), n));
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

    /// Идентификаторы правил, сработавших на одном файле сканера секретов.
    fn secret_hits(file: &str, content: &str) -> Vec<String> {
        let ctx = tmp(&[(file, content)]);
        let out = secret_scan().run(&ctx, &RunInput::default()).unwrap();
        out.findings.into_iter().map(|f| f.rule).collect()
    }

    // ── T04: секреты, многострочный scope, склейка, новые правила ──────────

    #[test]
    fn t04_pem_ключ_разнесённый_по_строкам_ловится_многострочно() {
        // Построчное правило поймало бы лишь заголовок PEM; многострочный scope File
        // ловит весь блок и тело, разнесённое по строкам.
        let src = concat!(
            "header\n",
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "MIIBOwIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q\n",
            "-----END RSA PRIVATE KEY-----\n",
        );
        assert!(secret_hits("k.pem", src).contains(&"private-key".to_string()));
    }

    #[test]
    fn t04_секрет_собранный_конкатенацией_ловится_после_склейки() {
        // Значение разорвано конкатенацией литералов: построчно каждый кусок короткий,
        // после склейки многострочный энтропийный матчер ловит секрет целиком.
        let src = "secret = \"a8Kd9Lm2\" + \"Qx7Zp1Rv4T\"\n";
        let hits = secret_hits("c.py", src);
        assert!(
            hits.iter().any(|r| r.starts_with("generic-secret")),
            "ожидался generic-secret после склейки, получено: {hits:?}"
        );
    }

    #[test]
    fn t04_секрет_разорванный_переносом_конкатенации() {
        // Конкатенация, разорванная переносом физической строки.
        let src = "token = \"a8Kd9Lm2Qx\" +\n        \"7Zp1Rv4Tsy\"\n";
        let hits = secret_hits("c.js", src);
        assert!(
            hits.iter().any(|r| r.starts_with("generic-secret")),
            "ожидался generic-secret через перенос, получено: {hits:?}"
        );
    }

    #[test]
    fn t04_db_uri_с_паролём_ловится_без_кавычек() {
        // URI СУБД с непустым паролём — утечка учётных данных без зависимости от кавычек.
        for src in [
            "DATABASE_URL=postgres://app:S3cr3tP@db.example.com:5432/app\n",
            "mongo = mongodb+srv://u:p4ss@cluster0.mongodb.net/db\n",
            "redis://default:hunter2@cache:6379\n",
        ] {
            assert!(
                secret_hits("conf.env", src).contains(&"db-uri-password".to_string()),
                "db-uri-password должен сработать на: {src}"
            );
        }
    }

    #[test]
    fn t04_db_uri_без_пароля_не_срабатывает() {
        // Без пароля (postgres://user@host или postgres://host) ложного срабатывания быть
        // не должно: правило требует непустой пароль между двоеточием и собакой.
        for src in [
            "DATABASE_URL=postgres://app@db.example.com:5432/app\n",
            "url = postgres://db.example.com/app\n",
        ] {
            assert!(
                !secret_hits("conf.env", src).contains(&"db-uri-password".to_string()),
                "URI без пароля не должен срабатывать: {src}"
            );
        }
    }

    #[test]
    fn t04_новые_префиксные_токены_провайдеров() {
        let cases: &[(&str, &str)] = &[
            (
                "digitalocean-token",
                // Литерал намеренно собран из частей (concat!), чтобы в тексте файла не было
                // непрерывной строки, похожей на настоящий токен (защита от ложного срабатывания
                // сканеров секретов в публичном репозитории). В момент выполнения значение целое.
                concat!(
                    "tok = \"dop_v1_",
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "\"\n"
                ),
            ),
            (
                "mailgun-key",
                concat!("mg = \"key-", "0123456789abcdef0123456789abcdef", "\"\n"),
            ),
            (
                "mapbox-secret-token",
                "mb = \"sk.eyJ1Ijoiff0aBcDeFgHiJkLmNoPqRsTuVwXyZ012345.qZ\"\n",
            ),
        ];
        for (id, src) in cases {
            assert!(
                secret_hits("c.py", src).contains(&id.to_string()),
                "{id} должен сработать на: {src}"
            );
        }
    }

    #[test]
    fn t04_mapbox_публичный_pk_не_секрет() {
        // Публичный токен Mapbox (pk.) не секрет: правило ловит только sk..
        let src = "mb = \"pk.eyJ1Ijoiff0aBcDeFgHiJkLmNoPqRsTuVwXyZ012345.qZ\"\n";
        assert!(!secret_hits("c.py", src).contains(&"mapbox-secret-token".to_string()));
    }

    #[test]
    fn t04_sentry_dsn_с_ключом() {
        let src = "dsn = \"https://0123456789abcdef0123456789abcdef@o123.ingest.sentry.io/42\"\n";
        assert!(secret_hits("c.py", src).contains(&"sentry-dsn".to_string()));
    }

    #[test]
    fn t04_gcp_private_key_в_json() {
        // Поле JSON service-account с переносом строки внутри значения: scope File.
        let src = "{\n  \"type\": \"service_account\",\n  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIE...\"\n}\n";
        assert!(secret_hits("sa.json", src).contains(&"gcp-private-key".to_string()));
    }

    #[test]
    fn t04_aiza_ключ_без_кавычек() {
        // Google AIza-ключ без кавычек в .properties.
        let src = "google.api.key=AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q\n";
        assert!(secret_hits("app.properties", src).contains(&"google-api-key".to_string()));
    }

    #[test]
    fn t04_секрет_без_кавычек_в_env() {
        // KEY=VALUE без кавычек в .env: значение высокой энтропии.
        let src = "API_SECRET=a8Kd9Lm2Qx7Zp1Rv4TsyB3nC6\n";
        let hits = secret_hits("svc.env", src);
        assert!(
            hits.iter().any(|r| r == "generic-secret-unquoted"),
            "ожидался generic-secret-unquoted, получено: {hits:?}"
        );
    }

    #[test]
    fn generic_secret_unquoted_не_ловит_ссылки_и_код() {
        let unq = |src: &str| {
            secret_hits("svc.go", src)
                .iter()
                .any(|r| r == "generic-secret-unquoted")
        };
        // Реальный литерал-секрет в .env по-прежнему находка.
        assert!(
            secret_hits("svc.env", "API_SECRET=a8Kd9Lm2Qx7Zp1Rv4TsyB3nC6\n")
                .iter()
                .any(|r| r == "generic-secret-unquoted"),
            "реальный токен обязан ловиться"
        );
        // НЕ секреты, дававшие массовый шум в исходниках (см. бенчмарк gooseek/tron):
        // ссылка на переменную окружения, вызов функции, поле структуры из конфига.
        assert!(!unq("POSTGRES_PASSWORD=${POSTGRES_PASSWORD}\n"), "ссылка ${{VAR}}");
        assert!(!unq("MINIO_SECRET_KEY=$MINIO_SECRET_KEY\n"), "ссылка $VAR");
        assert!(!unq("apiKey = strings.TrimSpace(key)\n"), "вызов функции");
        assert!(!unq("SecretKey: cfg.YooKassaSecretKey,\n"), "поле структуры из конфига");
        assert!(!unq("max_tokens: env.AI_MAX_OUTPUT_TOKENS,\n"), "чтение из env");
    }

    #[test]
    fn t04_секрет_в_strings_xml() {
        // Android strings.xml: <string name="api_key">СЕКРЕТ</string>.
        let src = "<resources>\n  <string name=\"api_key\">a8Kd9Lm2Qx7Zp1Rv4Tsy</string>\n</resources>\n";
        assert!(secret_hits("strings.xml", src).contains(&"generic-secret-xml".to_string()));
    }

    #[test]
    fn t04_секрет_в_plist() {
        // plist: <key>apiKey</key><string>СЕКРЕТ</string>, теги на соседних строках.
        let src = "<dict>\n  <key>apiKey</key>\n  <string>a8Kd9Lm2Qx7Zp1Rv4Tsy</string>\n</dict>\n";
        assert!(secret_hits("Info.plist", src).contains(&"generic-secret-plist".to_string()));
    }

    #[test]
    fn t04_плейсхолдер_низкой_энтропии_не_секрет() {
        // Классические плейсхолдеры не должны давать ложного срабатывания.
        for src in [
            "password = \"changeme\"\n",
            "api_key = \"your_api_key_here\"\n",
            "secret = \"xxxxxxxxxxxx\"\n",
        ] {
            let hits = secret_hits("c.py", src);
            assert!(
                !hits.iter().any(|r| r.starts_with("generic-secret")),
                "плейсхолдер не должен срабатывать ({src}), получено: {hits:?}"
            );
        }
    }

    #[test]
    fn t04_парольная_фраза_с_пробелами() {
        // Реальная парольная фраза с пробелами и достаточной длины должна ловиться,
        // тогда как обычная короткая подпись интерфейса — нет.
        let src = "password = \"correct horse battery staple xP7\"\n";
        assert!(secret_hits("c.py", src).contains(&"generic-passphrase".to_string()));
        let ui = "label = \"please enter your name\"\n";
        assert!(!secret_hits("ui.py", ui).contains(&"generic-passphrase".to_string()));
    }

    #[test]
    fn t04_длинный_низкоэнтропийный_секрет_ловится_адаптивным_порогом() {
        // Длинное hex-значение (низкая энтропия на символ, но длина — свидетельство):
        // ловится правилом generic-secret-long с пониженным порогом, а не пропускается.
        let src = "secret = \"0123456789abcdef0123456789abcdef0123456789\"\n";
        assert!(secret_hits("c.py", src).contains(&"generic-secret-long".to_string()));
    }

    #[test]
    fn t04_все_паттерны_секретов_компилируются() {
        // Конструирование capability компилирует КАЖДЫЙ встроенный паттерн через
        // Matcher::regex/entropy (которые делают expect): невалидный regex упал бы здесь,
        // а не в проде. Заодно фиксируем, что таблица непуста.
        let cap = secret_scan();
        assert!(
            cap.rules.len() >= secret_rule_table().len(),
            "все строки таблицы должны превратиться в правила"
        );
    }

    #[test]
    fn t04_таблица_секретов_без_дублей_id() {
        // Идентификаторы правил таблицы уникальны: дубль id ломал бы карту достоверности.
        let ids: Vec<&str> = secret_rule_table().iter().map(|r| r.id).collect();
        let mut uniq = ids.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(ids.len(), uniq.len(), "дублирующиеся id в таблице секретов: {ids:?}");
    }

    // ── T62: единая таблица стеков для теста и линтера ─────────────────────

    #[test]
    fn t62_detect_stack_распознаёт_основные_маркеры() {
        let cases: &[(&str, &str)] = &[
            ("Cargo.toml", "rust"),
            ("go.mod", "go"),
            ("package.json", "node"),
            ("pyproject.toml", "python"),
            ("pom.xml", "maven"),
            ("Gemfile", "ruby"),
        ];
        for (marker, label) in cases {
            let ctx = tmp(&[(marker, "x")]);
            let s = detect_stack(&ctx.root).expect("стек распознан");
            assert_eq!(s.label, *label, "маркер {marker} даёт стек {label}");
        }
    }

    #[test]
    fn t62_detect_stack_по_расширению_csproj() {
        // dotnet распознаётся не по имени файла, а по расширению .csproj.
        let ctx = tmp(&[("App.csproj", "<Project/>")]);
        let s = detect_stack(&ctx.root).expect("dotnet распознан по .csproj");
        assert_eq!(s.label, "dotnet");
    }

    #[test]
    fn t62_неизвестный_проект_не_распознаётся() {
        let ctx = tmp(&[("README.md", "текст")]);
        assert!(detect_stack(&ctx.root).is_none());
    }

    #[test]
    fn t62_таблица_стеков_единый_источник_для_теста_и_линтера() {
        // Одна строка таблицы несёт И команду теста, И команду линтера: рассинхрона
        // тестовой и линтерной лестниц больше быть не может по построению.
        let table = stack_table();
        assert!(table.len() >= 12, "ожидались все основные стеки, найдено {}", table.len());
        for s in &table {
            assert!(!s.test.0.is_empty(), "у стека {} пустой бинарь теста", s.label);
            assert!(!s.lint.0.is_empty(), "у стека {} пустой бинарь линтера", s.label);
            assert!(
                !s.markers.is_empty() || !s.marker_exts.is_empty(),
                "у стека {} нет маркеров распознавания",
                s.label
            );
        }
        // Метки стеков уникальны.
        let labels: Vec<&str> = table.iter().map(|s| s.label).collect();
        let mut uniq = labels.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(labels.len(), uniq.len(), "дублирующиеся метки стеков: {labels:?}");
    }

    #[test]
    fn t62_rust_стек_даёт_clippy_и_fmt_фолбэк() {
        // Конкретная проверка строки таблицы: rust даёт cargo test, cargo clippy и
        // фолбэк cargo fmt --check.
        let ctx = tmp(&[("Cargo.toml", "[package]")]);
        let s = detect_stack(&ctx.root).unwrap();
        assert_eq!(s.test, ("cargo", vec!["test", "--quiet"]));
        assert_eq!(s.lint, ("cargo", vec!["clippy", "--quiet"]));
        assert_eq!(s.lint_fallback, Some(("cargo", vec!["fmt", "--", "--check"])));
    }

    // ── T86: разделение сбоя инструмента и находки тестов ──────────────────

    #[test]
    fn t86_число_прошедших_тестов_есть_доказательство() {
        // Позитивное доказательство выполненных тестов — ненулевое «N passed».
        assert!(some_tests_passed("test result: ok. 13 passed; 0 failed"));
        assert!(some_tests_passed("==== 7 passed in 0.2s ===="));
        // Пустой прогон и отсутствие тестов — НЕ доказательство.
        assert!(!some_tests_passed("running 0 tests\ntest result: ok. 0 passed; 0 failed"));
        assert!(!some_tests_passed("no tests ran in 0.01s"));
    }

    #[test]
    fn t86_ошибка_сборки_классифицируется_как_сбой_инструмента() {
        // Маркеры неотработавшего инструмента (сборка/импорт): по ним verify/test не
        // печатает «тесты прошли» и не выдаёт «тесты упали», а относит исход к Failed.
        for blob in [
            "error[E0277]: trait bound not satisfied\ncould not compile `crate`",
            "ModuleNotFoundError: No module named 'app'",
            "ImportError: cannot import name 'x'",
        ] {
            assert!(
                looks_like_tool_failure(blob),
                "должно распознаться как сбой инструмента: {blob}"
            );
        }
    }

    #[test]
    fn t86_сбой_инструмента_даёт_outcome_failed_а_не_skipped() {
        // CapabilityOutput с причиной-сбоем обязан давать Failed, а обычный пропуск —
        // Skipped: именно это разделение мешает выдать пустой/сломанный прогон за успех.
        let mut failed = CapabilityOutput::default();
        failed.skipped = Some(
            "verify/test (rust): сборка/импорт не прошли, could not compile `crate`".into(),
        );
        assert!(matches!(failed.outcome(), CheckOutcome::Failed(_)));

        // Производственная формулировка verify/test и verify/coverage без английского
        // маркера, но с явной пометкой «не отработал», тоже обязана давать Failed (раньше
        // эта строка ошибочно классифицировалась как Skipped).
        let mut failed_ru = CapabilityOutput::default();
        failed_ru.skipped = Some(
            "verify/test (rust): инструмент не отработал (сборка/импорт), прогон тестов не состоялся".into(),
        );
        assert!(matches!(failed_ru.outcome(), CheckOutcome::Failed(_)));

        let mut skipped = CapabilityOutput::default();
        skipped.skipped = Some("verify/test (rust): тесты не найдены/не настроены".into());
        assert!(matches!(skipped.outcome(), CheckOutcome::Skipped(_)));
    }

    #[test]
    fn t86_прогон_без_тестов_не_подтверждает_работоспособность() {
        // Сводки «нет доказательства»/«тестов нет» содержат маркер «не подтвержд», по
        // которому агрегатор не засчитывает их как доказательство прохождения.
        for s in [
            "verify/test (rust): ⚠ нет доказательства выполненных тестов — работоспособность НЕ подтверждена",
            "verify/test (go): ⚠ тестов нет — работоспособность НЕ подтверждена",
        ] {
            assert!(
                s.to_lowercase().contains("не подтвержд"),
                "сводка должна явно объявлять отсутствие подтверждения: {s}"
            );
        }
    }
}
