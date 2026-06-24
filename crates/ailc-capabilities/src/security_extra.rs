//! Дополнительные security-capability поверх существующих движков — тонкие конфиги,
//! без новой логики обхода/матча/запуска.
//!
//! ПРИНЦИП тот же, что и в корне крейта: инструмент = таблица правил или короткая
//! обёртка над `Runner`, а не новый движок. `injection` и `iac` переиспользуют
//! общий `ScanCapability` поверх `ScanEngine`; `deps` — собственная обёртка над
//! `Runner` (E2), потому что определяет инструмент аудита по типу проекта.
//!
//! Анти-дублирование: eval/exec уже покрыт правилом `dangerous-exec` в `owasp_scan`,
//! поэтому здесь он сознательно НЕ повторяется. Паттерны строгие — требуют реальной
//! формы артефакта (вызов с `(`, конкретный тег/флаг), чтобы не ловить ни сами строки
//! определений правил, ни случайные вхождения слов.
//!
//! Прослеживаемость по классификаторам уязвимостей: КАЖДОЕ сообщение правила
//! безопасности обязано нести проверенную ссылку на запись каталога CWE (Common
//! Weakness Enumeration) и, где это применимо, на категорию OWASP (Open Worldwide
//! Application Security Project) Top 10 в редакции 2021 года. Это требование действует
//! и для существующих правил, и для всех вновь добавляемых. Ссылка нужна не для
//! косметики: она привязывает находку к признанной таксономии слабостей и даёт
//! человеку и системе единый идентификатор для дедупликации, приоритизации и отчётности
//! в формате SARIF.
//!
//! Многострочный охват. Часть стоков инъекций (сборка HTML или SQL через шаблонный
//! литерал либо конкатенацию) разрывается переносом строки форматтером кода, поэтому
//! для таких правил применяется матчер по всему файлу `Matcher::multiline_regex` с
//! флагом `(?s)`, при котором точка покрывает перенос строки. Построчные правила
//! продолжают использовать `Matcher::regex`. Достоверность каждого нового
//! идентификатора правила классифицируется в карте `ailc_contracts::rule_confidence`
//! отдельной дорожкой (новые идентификаторы перечислены в сводке изменений API).

use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Finding, Result, RunInput,
    Severity, Tier,
};
use ailc_core::engines::runner::Runner;
use ailc_core::engines::scan::{Matcher, Rule};
use ailc_core::registry::Registry;
use ailc_core::Capability;
use std::path::Path;

// Дочерний модуль видит приватные элементы корня крейта — переиспользуем общий
// builder сканера, фабрику манифестов и единую схему входа без копирования.
use crate::{scan_manifest, ScanCapability, TARGET_SCHEMA};

// ───────────────────────── security.scan/injection ─────────────────────────

/// Инъекции в разметку/шаблоны на стороне клиента: запись «сырого» HTML из данных.
/// Фокус — формы, не покрытые `owasp_scan` (eval/exec уже там). Паттерны требуют
/// присваивания/вызова, чтобы не срабатывать на упоминание слова в комментарии. Каждая
/// строка-сообщение несёт проверенную ссылку CWE и категорию OWASP Top 10 (2021).
pub fn injection_scan() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "security.scan/injection",
            Family::Security,
            "Инъекции в HTML/шаблоны на клиенте (межсайтовый скриптинг, XSS): запись сырого HTML из данных — innerHTML, outerHTML, insertAdjacentHTML, dangerouslySetInnerHTML, v-html, обход санитайзера Angular, document.write, сборка HTML и SQL конкатенацией или шаблонным литералом.",
        ),
        vec![
            // Присваивание в innerHTML — типовой путь отражённого/хранимого XSS.
            Rule {
                id: "raw-innerhtml",
                severity: Severity::High,
                exts: &["js", "ts", "jsx", "tsx", "vue", "svelte", "html"],
                matcher: Matcher::regex(r"\.innerHTML\s*="),
                message: "Запись в innerHTML — межсайтовый скриптинг (XSS), используйте textContent или санитизацию (CWE-79; OWASP A03:2021 Injection)",
            },
            // Присваивание в outerHTML — тот же сток сырого HTML, что и innerHTML, но
            // заменяет узел целиком; легко упустить при ревью, поэтому правило отдельное.
            Rule {
                id: "raw-outerhtml",
                severity: Severity::High,
                exts: &["js", "ts", "jsx", "tsx", "vue", "svelte", "html"],
                matcher: Matcher::regex(r"\.outerHTML\s*="),
                message: "Запись в outerHTML — межсайтовый скриптинг (XSS), узел заменяется сырым HTML, используйте безопасное построение DOM (CWE-79; OWASP A03:2021 Injection)",
            },
            // insertAdjacentHTML вставляет сырой HTML рядом с узлом; вызов с `(` —
            // строгий признак реального стока, а не упоминания имени метода.
            Rule {
                id: "insert-adjacent-html",
                severity: Severity::High,
                exts: &["js", "ts", "jsx", "tsx", "vue", "svelte", "html"],
                matcher: Matcher::regex(r"\.insertAdjacentHTML\s*\("),
                message: "insertAdjacentHTML — вставка сырого HTML, межсайтовый скриптинг (XSS), санитизируйте данные или используйте insertAdjacentText (CWE-79; OWASP A03:2021 Injection)",
            },
            // React: проп с сырым HTML. Само наличие пропа — уже сигнал на ревью.
            Rule {
                id: "react-raw-html",
                severity: Severity::High,
                exts: &["js", "ts", "jsx", "tsx"],
                matcher: Matcher::regex(r"dangerouslySetInnerHTML"),
                message: "dangerouslySetInnerHTML — сырой HTML в React, межсайтовый скриптинг (XSS), требуется санитизация (CWE-79; OWASP A03:2021 Injection)",
            },
            // Angular: явный обход штатного санитайзера разметки. bypassSecurityTrustHtml
            // и родственные методы отключают защиту фреймворка от XSS.
            Rule {
                id: "angular-bypass-sanitizer",
                severity: Severity::High,
                exts: &["ts", "js"],
                matcher: Matcher::regex(r"bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\("),
                message: "Обход санитайзера Angular (bypassSecurityTrust...) — отключает защиту от межсайтового скриптинга (XSS), санитизируйте источник вместо обхода (CWE-79; OWASP A03:2021 Injection)",
            },
            // Vue-директива сырого HTML.
            Rule {
                id: "vue-raw-html",
                severity: Severity::High,
                exts: &["vue", "html", "js", "ts"],
                matcher: Matcher::regex(r"v-html\s*="),
                message: "Директива v-html — сырой HTML во Vue, межсайтовый скриптинг (XSS), требуется санитизация (CWE-79; OWASP A03:2021 Injection)",
            },
            // document.write — устаревший и опасный путь вставки разметки.
            Rule {
                id: "document-write",
                severity: Severity::Medium,
                exts: &["js", "ts", "jsx", "tsx", "html"],
                matcher: Matcher::regex(r"\bdocument\.write(?:ln)?\s*\("),
                message: "document.write — устаревшая и небезопасная вставка разметки, межсайтовый скриптинг (XSS) (CWE-79; OWASP A03:2021 Injection)",
            },
            // Конкатенация переменной внутрь строкового HTML-тега: `"<div>" + user`
            // или `user + "</div>"`. Требуем символ `<` рядом с кавычкой и `+`, чтобы
            // отсечь обычную склейку строк.
            Rule {
                id: "html-string-concat",
                severity: Severity::Medium,
                exts: &["js", "ts", "jsx", "tsx", "java", "py", "php"],
                matcher: Matcher::regex(r#"["']\s*<[a-zA-Z/][^"']*["']\s*\+|\+\s*["']\s*</?[a-zA-Z]"#),
                message: "Сборка HTML конкатенацией строк — межсайтовый скриптинг (XSS), используйте шаблонизатор с экранированием (CWE-79; OWASP A03:2021 Injection)",
            },
            // Шаблонный литерал, собирающий HTML-тег с интерполяцией значения:
            // `` `<div>${user}</div>` ``. Многострочный матчер по всему файлу с флагом
            // `(?s)`, потому что форматтер часто разносит длинный шаблон на несколько
            // строк, и построчное правило такой сток пропустит. Требуем открывающий
            // угловой скобкой тег внутри обратных кавычек и хотя бы одну интерполяцию
            // `${...}` после него, чтобы не ловить обычные текстовые шаблоны без разметки.
            Rule {
                id: "template-literal-html",
                severity: Severity::Medium,
                exts: &["js", "ts", "jsx", "tsx", "vue", "svelte"],
                matcher: Matcher::multiline_regex(r"(?s)`[^`]*<[a-zA-Z/][^`]*\$\{[^`]*`"),
                message: "HTML собран шаблонным литералом с интерполяцией данных — межсайтовый скриптинг (XSS), экранируйте интерполируемые значения (CWE-79; OWASP A03:2021 Injection)",
            },
            // SQL-запрос, собранный конкатенацией строки запроса с переменной:
            // `"SELECT ... " + name` или `"... WHERE id=" + id`. Многострочный матчер,
            // потому что длинный запрос почти всегда разнесён по строкам. Требуем
            // ключевое слово SQL внутри кавычек и знак конкатенации `+` сразу за
            // закрывающей кавычкой, что отделяет реальный сток от обычной строки.
            Rule {
                id: "sql-string-concat",
                severity: Severity::High,
                exts: &["js", "ts", "jsx", "tsx", "java", "py", "php", "cs", "go", "rb"],
                matcher: Matcher::multiline_regex(
                    r#"(?si)["'`]\s*(?:select|insert|update|delete)\b[^"'`]*["'`]\s*\+\s*\w"#,
                ),
                message: "SQL собран конкатенацией строки запроса с переменной — внедрение SQL-кода (SQL injection), используйте параметризованный запрос (CWE-89; OWASP A03:2021 Injection)",
            },
        ],
    )
}

// ───────────────────────── security.scan/iac ─────────────────────────

/// Небезопасные настройки инфраструктуры как кода: Docker / Kubernetes / манифесты.
/// `exts` пуст — у `Dockerfile` нет расширения, а опасные настройки одинаково важны
/// в `.yaml`, `.yml` и Dockerfile; матчим по содержимому строки строгими паттернами.
/// Каждое сообщение несёт проверенную ссылку CWE и категорию OWASP Top 10 (2021).
pub fn iac_scan() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "security.scan/iac",
            Family::Security,
            "Небезопасные настройки инфраструктуры как кода (Docker и Kubernetes): привилегированный контейнер, общий с хостом сетевой стек и пространство идентификаторов процессов, разрешённое повышение привилегий, добавление всех Linux-capability, запуск от root, плавающий тег latest, загрузка по сети в образ, исполнение скрипта из сети конвейером в оболочку.",
        ),
        vec![
            // Привилегированный контейнер — полный доступ к хосту.
            Rule {
                id: "privileged-container",
                severity: Severity::High,
                exts: &["yaml", "yml"],
                matcher: Matcher::regex(r"privileged:\s*true"),
                message: "Привилегированный контейнер (privileged: true) — полный доступ к ядру и устройствам хоста (CWE-250 исполнение с лишними привилегиями; OWASP A05:2021 Security Misconfiguration)",
            },
            // Общий с хостом сетевой стек — контейнер видит весь трафик и порты хоста.
            Rule {
                id: "host-network",
                severity: Severity::High,
                exts: &["yaml", "yml"],
                matcher: Matcher::regex(r"hostNetwork:\s*true"),
                message: "hostNetwork: true — контейнер делит сетевой стек с хостом, нарушение изоляции (CWE-668 раскрытие ресурса в неположенную сферу; OWASP A05:2021 Security Misconfiguration)",
            },
            // Общее с хостом пространство идентификаторов процессов — видимость и
            // воздействие на процессы хоста из контейнера.
            Rule {
                id: "host-pid",
                severity: Severity::High,
                exts: &["yaml", "yml"],
                matcher: Matcher::regex(r"hostPID:\s*true"),
                message: "hostPID: true — контейнер делит пространство процессов с хостом, нарушение изоляции (CWE-668 раскрытие ресурса в неположенную сферу; OWASP A05:2021 Security Misconfiguration)",
            },
            // Разрешено повышение привилегий внутри процесса контейнера (setuid и т.п.).
            Rule {
                id: "allow-priv-escalation",
                severity: Severity::High,
                exts: &["yaml", "yml"],
                matcher: Matcher::regex(r"allowPrivilegeEscalation:\s*true"),
                message: "allowPrivilegeEscalation: true — процесс может повысить привилегии внутри контейнера (CWE-250 исполнение с лишними привилегиями; OWASP A05:2021 Security Misconfiguration)",
            },
            // Контейнеру выданы ВСЕ Linux-capability — эквивалент привилегированного
            // режима. КЛЮЧЕВОЕ различие: `add: ALL` опасно, а `drop: ALL` — наоборот,
            // безопасная практика сброса всех привилегий. Поэтому правило обязано
            // привязываться именно к ключу `add`, а не к голому `ALL`. Многострочный
            // матчер по всему файлу с флагом `(?s)`: требуем ключ `add:` и затем `ALL`
            // в пределах того же отображения. Допускаем две формы YAML — встроенный
            // список `add: [ALL]`/`add: ["ALL"]` на одной строке и блочную форму, где
            // `add:` стоит на отдельной строке, а `- ALL` следует одним из ближайших
            // элементов. Крейт `regex` не поддерживает опережающую проверку, поэтому
            // отсечение соседнего ключа `drop:` сделано без неё: между `add:` и `- ALL`
            // запрещён символ двоеточия (`[^:]`), а двоеточие неизбежно присутствует в
            // любом другом ключе отображения (в том числе в `drop:`), поэтому совпадение
            // не может пересечь границу ключа и дотянуться до `drop: - ALL`.
            Rule {
                id: "cap-add-all",
                severity: Severity::High,
                exts: &["yaml", "yml"],
                matcher: Matcher::multiline_regex(
                    r#"(?si)\badd\s*:\s*(?:\[[^\]]*\bALL\b[^\]]*\]|[^:]*?-\s*["']?ALL\b)"#,
                ),
                message: "Контейнеру добавлены все Linux-capability (add: ALL) — эквивалент привилегированного режима, оставьте только необходимые (CWE-250 исполнение с лишними привилегиями; OWASP A05:2021 Security Misconfiguration)",
            },
            // Явно разрешён запуск от root в Kubernetes.
            Rule {
                id: "run-as-root",
                severity: Severity::High,
                exts: &["yaml", "yml"],
                matcher: Matcher::regex(r"runAsNonRoot:\s*false"),
                message: "runAsNonRoot: false — контейнеру разрешён запуск от суперпользователя root (CWE-250 исполнение с лишними привилегиями; OWASP A05:2021 Security Misconfiguration)",
            },
            // Образ с плавающим тегом latest в манифесте k8s/compose: `image: nginx:latest`.
            Rule {
                id: "image-latest-tag",
                severity: Severity::Medium,
                exts: &["yaml", "yml"],
                matcher: Matcher::regex(r"image:\s*\S+:latest\b"),
                message: "Образ с тегом :latest — невоспроизводимая сборка, закрепите версию (CWE-1104 использование неподдерживаемого/неконтролируемого компонента; OWASP A06:2021 Vulnerable and Outdated Components)",
            },
            // Dockerfile FROM с плавающим тегом latest: `FROM node:latest`.
            Rule {
                id: "from-latest-tag",
                severity: Severity::Medium,
                exts: &["dockerfile"],
                matcher: Matcher::regex(r"(?i)^\s*FROM\s+\S+:latest\b"),
                message: "FROM ...:latest — невоспроизводимая базовая сборка, закрепите версию (CWE-1104 использование неподдерживаемого/неконтролируемого компонента; OWASP A06:2021 Vulnerable and Outdated Components)",
            },
            // Загрузка по сети прямо в образ — неаудируемый и небезопасный артефакт.
            Rule {
                id: "add-remote-url",
                severity: Severity::Medium,
                exts: &["dockerfile"],
                matcher: Matcher::regex(r"(?i)^\s*ADD\s+https?://"),
                message: "ADD по URL — загрузка по сети в образ без проверки целостности (CWE-494 загрузка кода без проверки целостности; OWASP A08:2021 Software and Data Integrity Failures)",
            },
            // Исполнение скрипта прямо из сети конвейером в оболочку: классический
            // `RUN curl ... | sh`. Источник недоверенный, целостность не проверяется.
            // Матчим инструкцию RUN с curl или wget, после которой идёт конвейер в
            // sh или bash. Логическая команда может продолжаться на следующей строке
            // через обратную косую черту, поэтому промежутки заданы как «любой символ,
            // кроме переноса строки, ЛИБО продолжение строки `\` плюс перенос»
            // (`(?:[^\n]|\\\n)`). Это удерживает совпадение в пределах одной логической
            // инструкции RUN и не даёт ему перескочить на соседнюю команду. Флаг `(?m)`
            // делает `^` началом каждой строки, потому что инструкция RUN почти никогда
            // не стоит в самом начале файла. Многострочный матчер используется именно
            // ради продолжения строки.
            Rule {
                id: "dockerfile-curl-bash",
                severity: Severity::High,
                exts: &["dockerfile"],
                matcher: Matcher::multiline_regex(
                    r"(?im)^[ \t]*RUN\b(?:[^\n]|\\\n)*?\b(?:curl|wget)\b(?:[^\n]|\\\n)*?\|[ \t]*(?:sudo[ \t]+)?(?:ba)?sh\b",
                ),
                message: "Исполнение скрипта из сети конвейером в оболочку (curl|sh) — код загружается и запускается без проверки целостности (CWE-494 загрузка кода без проверки целостности; OWASP A08:2021 Software and Data Integrity Failures)",
            },
        ],
    )
}

// ───────────────────────── security.scan/deps (E2 Runner) ─────────────────────────

/// Аудитор уязвимых зависимостей по типу проекта: маркер в корне → (бинарь, аргументы).
/// Порядок проверки фиксирован и детерминирован; первый совпавший маркер выигрывает.
fn detect_audit(root: &Path) -> Option<(&'static str, Vec<&'static str>, &'static str)> {
    let has = |f: &str| root.join(f).exists();
    if has("Cargo.toml") {
        Some(("cargo", vec!["audit"], "rust"))
    } else if has("package.json") {
        Some(("npm", vec!["audit", "--audit-level=high"], "node"))
    } else if has("requirements.txt") || has("pyproject.toml") {
        Some(("pip-audit", vec![], "python"))
    } else if has("go.mod") {
        Some(("govulncheck", vec!["./..."], "go"))
    } else {
        None
    }
}

/// security.scan/deps — реальный аудит зависимостей внешним инструментом.
/// Недетерминированно: зависит от установленного тулчейна и базы уязвимостей.
/// Кормит гейт: при найденных уязвимостях эмитит Finding severity High.
pub struct DepsAudit {
    manifest: CapabilityManifest,
}

impl Default for DepsAudit {
    fn default() -> Self {
        Self::new()
    }
}

impl DepsAudit {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "security.scan/deps",
                family: Family::Security,
                engine: EngineKind::Runner,
                when_to_use: "Проверить зависимости проекта на известные уязвимости (cargo audit / npm audit / pip-audit / govulncheck).",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: false, // зависит от тулчейна и базы уязвимостей
                mutates: false,
            },
        }
    }
}

impl Capability for DepsAudit {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn run(&self, ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
        let mut out = CapabilityOutput::default();

        // (1) Нативный OSV — офлайн, детерминированно, без внешних тулов и сети.
        // Разбирает lock-файлы проекта и сверяет со вшитым снимком базы уязвимостей.
        let native = ailc_core::engines::osv::scan(&ctx.root);
        let osv_hits = native.findings.len();
        out.findings.extend(native.findings);

        // (2) Внешний аудитор — дополняет нативный, когда установлен.
        let external = detect_audit(&ctx.root);

        // Честный пропуск: ни OSV-манифестов, ни внешнего аудитора.
        if native.manifests.is_empty() && external.is_none() {
            out.skipped = Some(
                "тип проекта не распознан (нет requirements.txt/Cargo.lock/package-lock.json/go.sum/gradle.lockfile/pubspec.lock/Podfile.lock/package.json/go.mod)"
                    .into(),
            );
            out.summary = "security.scan/deps: пропущено (проект не распознан)".into();
            return Ok(out);
        }

        let mut ext_note = String::from("внешний аудитор не запускался");
        if let Some((bin, args, label)) = external {
            // pip-audit без -r аудитит ОКРУЖЕНИЕ, а не проект → не зовём, Python уже
            // покрыт нативным OSV по requirements.txt.
            if bin == "pip-audit" {
                ext_note = "Python проверен нативно (OSV)".into();
            } else {
                let res = Runner::run(ctx, bin, &args);
                if !res.ran {
                    let reason = res
                        .skipped_reason
                        .unwrap_or_else(|| format!("инструмент `{bin}` недоступен"));
                    ext_note = format!("внешний {bin}: пропущен ({reason})");
                } else {
                    // Ненулевой код = И «есть уязвимости», И «сбой» — различаем по выводу.
                    let blob = format!("{}\n{}", res.stdout, res.stderr).to_lowercase();
                    let vulns = blob.contains("vulnerab")
                        || blob.contains("advisor")
                        || blob.contains("cve-")
                        || blob.contains("ghsa-")
                        || blob.contains("rustsec");
                    let errored = blob.contains("error:")
                        || blob.contains("failed to")
                        || blob.contains("could not")
                        || blob.contains("not found")
                        || blob.contains("no such");
                    if res.exit_ok {
                        ext_note = format!("внешний {bin} ({label}): чисто");
                    } else if vulns && !errored {
                        out.findings.push(Finding {
                            rule: "vulnerable-deps".into(),
                            severity: Severity::High,
                            message: format!(
                                "Уязвимые зависимости по данным {bin} (см. вывод) — обновите или замените затронутые пакеты (CWE-1395 зависимость от уязвимого стороннего компонента; OWASP A06:2021 Vulnerable and Outdated Components)"
                            ),
                            location: None,
                            evidence: None,
                            verified: true,
                            source: "security.scan/deps".into(),
                        });
                        for l in res.tail(15) {
                            out.records.push(l);
                        }
                        ext_note = format!("внешний {bin} ({label}): найдены уязвимости");
                    } else {
                        for l in res.tail(10) {
                            out.records.push(l);
                        }
                        ext_note =
                            format!("внешний {bin} ({label}): сбой аудитора, результат недостоверен");
                    }
                }
            }
        }

        out.metrics.push(("osv_checked".into(), native.checked as f64));
        out.metrics.push(("osv_matches".into(), osv_hits as f64));
        // Честность покрытия: «0 уязвимостей» в экосистеме, по которой база пуста, —
        // не «чисто», а «не покрыто»; человек должен это видеть в сводке.
        let uncovered_note = if native.uncovered.is_empty() {
            String::new()
        } else {
            format!(
                "; ⚠ в базе OSV нет записей для {} — покрытие ограничено",
                native.uncovered.join(", ")
            )
        };
        out.summary = format!(
            "security.scan/deps: OSV — {osv_hits} уязвимых из {} зависимостей; {ext_note}{uncovered_note}",
            native.checked
        );
        Ok(out)
    }
}

// ───────────────────────── security.scan/sast (глубокий, Enterprise) ─────────────────────────

/// security.scan/sast — структурный анализ безопасности по абстрактному синтаксическому
/// дереву (AST). Помечен `Tier::Enterprise`, и это сознательное решение, согласованное со
/// слоем детерминированных входов (см. задачу T36): в обычный авто-гейт по тиру тяжёлый
/// разбор не попадает, чтобы не запускаться в каждом цикле, однако детерминированные
/// пути обязаны включать его в пол безопасности ПО ИДЕНТИФИКАТОРУ, а не по тиру.
///
/// Включение по идентификатору уже реализовано в гейте: список
/// `ailc_core::engines::gate::SECURITY_FLOOR_IDS` содержит `security.scan/sast` и
/// `security.scan/taint`, и `GateRunner` исполняет их под таймаутом шага независимо от
/// тира. То же должно действовать в `Orchestrator::scan_all` (путь отчёта SARIF) и в
/// `Orchestrator::deterministic_gate`, иначе путь SARIF молча не запускал бы глубокий
/// анализатор. Соответствующее включение по идентификатору в этих двух функциях
/// оркестратора перечислено в сводке изменений API как обязательная встречная правка
/// смежной дорожки. Понижать тир до `Tier::Core` здесь НЕЛЬЗЯ: это сломало бы инвариант
/// гейта (тяжёлый разбор не должен запускаться в каждом обычном цикле) и заставило бы
/// SARIF исполнять анализатор без защиты по таймауту.
pub struct SastScan {
    manifest: CapabilityManifest,
}

impl Default for SastScan {
    fn default() -> Self {
        Self::new()
    }
}

impl SastScan {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "security.scan/sast",
                family: Family::Security,
                engine: EngineKind::CodeIntel,
                when_to_use: "Глубокий структурный анализ безопасности (AST): инъекции кода/команд, SQL через конкатенацию, небезопасная десериализация. Точнее regex (смотрит структуру вызова, не текст). Тяжёлый — для полного пентеста, не для обычной проверки.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Enterprise,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for SastScan {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let rep = ailc_core::engines::sast::scan(ctx, input)?;
        let mut out = CapabilityOutput::default();
        if rep.files == 0 {
            out.skipped = Some("не найдено исходников на языках с AST-грамматикой".into());
            out.summary = "security.scan/sast: нет разбираемых исходников".into();
            return Ok(out);
        }
        let n = rep.findings.len();
        out.findings = rep.findings;
        out.metrics.push(("files".into(), rep.files as f64));
        out.metrics.push(("sast_findings".into(), n as f64));
        out.summary = format!(
            "security.scan/sast: {n} структурных находок ({} файлов AST)",
            rep.files
        );
        Ok(out)
    }
}

// ───────────────────────── security.scan/taint (межоператорный поток, Enterprise) ─────────────────────────

/// security.scan/taint — анализ заражённости потока данных (taint-анализ): недоверенный
/// ввод (источник), проходящий через присваивания и достигающий опасного стока
/// исполнения, запроса SQL или открытия файла в пределах функции. Ловит то, что не видят
/// ни одно-операторный анализатор по AST, ни регулярное выражение, ни markdown-скиллы:
/// `x = request.args.get('q'); ...; os.system(x)`. Помечен `Tier::Enterprise` по той же
/// причине и с тем же договором, что и `SastScan`: в обычный авто-гейт по тиру не
/// попадает, но детерминированные пути обязаны включать его в пол безопасности по
/// идентификатору через `ailc_core::engines::gate::SECURITY_FLOOR_IDS` (гейт это уже
/// делает под таймаутом), а смежная дорожка оркестратора обязана зеркально включить его
/// по идентификатору в `scan_all` (SARIF) и `deterministic_gate`. Карта достоверности
/// относит находки taint к классу `Precise` (высокая уверенность), поэтому молчаливый
/// пропуск именно этого анализатора в отчёте недопустим (см. задачу T36).
pub struct TaintScan {
    manifest: CapabilityManifest,
}

impl Default for TaintScan {
    fn default() -> Self {
        Self::new()
    }
}

impl TaintScan {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "security.scan/taint",
                family: Family::Security,
                engine: EngineKind::CodeIntel,
                when_to_use: "Taint-анализ потока данных на всех 15 языках движка (Python/JS/TS/Go/Java/Ruby/PHP/C#/Rust/Kotlin/Scala/C/C++/Swift/Dart): недоверенный ввод (request/getParameter/$_GET/env::var/getenv/argv/fgets/req.query), достигающий стока исполнения/SQL/файла/копирования через цепочку присваиваний и границы функций — межпроцедурное внедрение команд/SQL/обход пути/переполнение буфера, с учётом санитайзеров. Видит то, что одно-операторный анализ и regex пропускают. Тяжёлый — для полного пентеста.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Enterprise,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for TaintScan {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let rep = ailc_core::engines::sast::scan_taint(ctx, input)?;
        let mut out = CapabilityOutput::default();
        if rep.files == 0 {
            out.skipped =
                Some("не найдено исходников на 15 поддерживаемых языках для taint-анализа".into());
            out.summary =
                "security.scan/taint: нет разбираемых исходников (все 15 языков движка)".into();
            return Ok(out);
        }
        let n = rep.findings.len();
        out.findings = rep.findings;
        out.metrics.push(("files".into(), rep.files as f64));
        out.metrics.push(("taint_findings".into(), n as f64));
        out.summary = format!(
            "security.scan/taint: {n} потоков источник→сток ({} файлов; 15 языков)",
            rep.files
        );
        Ok(out)
    }
}

// ───────────────────────── регистрация ─────────────────────────

/// Регистрирует дополнительные security-capability в реестре.
pub fn register(reg: &mut Registry) {
    reg.register(Box::new(injection_scan())); // E1 Scan — XSS/инъекции в разметку
    reg.register(Box::new(iac_scan())); // E1 Scan — небезопасный IaC
    reg.register(Box::new(DepsAudit::new())); // E2 Runner — аудит зависимостей
    reg.register(Box::new(SastScan::new())); // E3 AST — глубокий SAST (Enterprise)
    reg.register(Box::new(TaintScan::new())); // E3 AST — taint-поток (Enterprise)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    static CNT: AtomicU32 = AtomicU32::new(0);

    /// Уникальная пустая временная папка для файловых фикстур, без внешних зависимостей.
    fn tmp() -> PathBuf {
        let n = CNT.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("ailc-security-extra-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Записать файл по относительному пути внутри корня, создав родительские каталоги.
    fn write(dir: &Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }

    /// Прогнать произвольный сканер по корню без подпути.
    fn run_scan(cap: &ScanCapability, root: &Path) -> CapabilityOutput {
        cap.run(&Ctx::new(root), &RunInput::default()).unwrap()
    }

    /// Сколько находок данного правила в выводе.
    fn count_rule(out: &CapabilityOutput, rule: &str) -> usize {
        out.findings.iter().filter(|f| f.rule == rule).count()
    }

    /// Истина, если хотя бы одна находка данного правила присутствует.
    fn has_rule(out: &CapabilityOutput, rule: &str) -> bool {
        count_rule(out, rule) > 0
    }

    // ───────────────────────── injection: позитив ─────────────────────────

    #[test]
    fn injection_catches_classic_dom_sinks() {
        let dir = tmp();
        write(
            &dir,
            "app.js",
            "el.innerHTML = data;\nnode.outerHTML = userHtml;\ncontainer.insertAdjacentHTML('beforeend', payload);\ndocument.write(unsafe);\n",
        );
        let out = run_scan(&injection_scan(), &dir);
        assert!(has_rule(&out, "raw-innerhtml"), "innerHTML должен ловиться");
        assert!(has_rule(&out, "raw-outerhtml"), "outerHTML должен ловиться");
        assert!(
            has_rule(&out, "insert-adjacent-html"),
            "insertAdjacentHTML должен ловиться"
        );
        assert!(has_rule(&out, "document-write"), "document.write должен ловиться");
    }

    #[test]
    fn injection_catches_framework_sinks() {
        let dir = tmp();
        write(
            &dir,
            "view.tsx",
            "return <div dangerouslySetInnerHTML={{ __html: raw }} />;\n",
        );
        write(&dir, "page.vue", "<div v-html=\"raw\"></div>\n");
        write(
            &dir,
            "trust.ts",
            "const safe = this.sanitizer.bypassSecurityTrustHtml(raw);\n",
        );
        let out = run_scan(&injection_scan(), &dir);
        assert!(has_rule(&out, "react-raw-html"), "dangerouslySetInnerHTML");
        assert!(has_rule(&out, "vue-raw-html"), "v-html");
        assert!(
            has_rule(&out, "angular-bypass-sanitizer"),
            "bypassSecurityTrustHtml должен ловиться"
        );
    }

    #[test]
    fn injection_catches_template_literal_html_across_lines() {
        // Шаблонный литерал разнесён на несколько строк форматтером: построчное правило
        // его упустит, многострочное обязано поймать.
        let dir = tmp();
        write(
            &dir,
            "render.js",
            "const html = `\n  <div class=\"card\">\n    ${userName}\n  </div>\n`;\n",
        );
        let out = run_scan(&injection_scan(), &dir);
        assert!(
            has_rule(&out, "template-literal-html"),
            "HTML в шаблонном литерале с интерполяцией, разорванный переносом, должен ловиться"
        );
    }

    #[test]
    fn injection_catches_sql_concat_across_lines() {
        // Запрос SQL собран конкатенацией и разнесён по строкам.
        let dir = tmp();
        write(
            &dir,
            "dao.java",
            "String q = \"SELECT * FROM users WHERE name = \" +\n    name;\n",
        );
        let out = run_scan(&injection_scan(), &dir);
        assert!(
            has_rule(&out, "sql-string-concat"),
            "SQL, собранный конкатенацией с переменной, должен ловиться"
        );
    }

    #[test]
    fn injection_messages_carry_cwe_reference() {
        // Требование задачи: каждое сообщение правила безопасности несёт ссылку CWE.
        let dir = tmp();
        write(
            &dir,
            "app.js",
            "el.innerHTML = data;\nnode.outerHTML = x;\nc.insertAdjacentHTML('x', y);\ndocument.write(z);\n",
        );
        let out = run_scan(&injection_scan(), &dir);
        assert!(!out.findings.is_empty(), "ожидались находки");
        for f in &out.findings {
            assert!(
                f.message.contains("CWE-"),
                "сообщение правила {} обязано нести ссылку CWE: {}",
                f.rule,
                f.message
            );
        }
    }

    // ───────────────────────── injection: негатив (анти-ложные) ─────────────────────────

    #[test]
    fn injection_ignores_safe_dom_api() {
        // textContent/createTextNode и обычная склейка строк без HTML-тега не должны
        // порождать находки.
        let dir = tmp();
        write(
            &dir,
            "safe.js",
            "el.textContent = data;\nconst full = first + last;\nconst path = base + '/' + name;\n",
        );
        let out = run_scan(&injection_scan(), &dir);
        assert_eq!(out.findings.len(), 0, "безопасный код не должен давать находок: {:?}", out.findings);
    }

    #[test]
    fn injection_ignores_plain_template_literal_without_tag() {
        // Шаблонный литерал без HTML-тега (обычная подстановка в текст) не сток XSS.
        let dir = tmp();
        write(&dir, "log.js", "const msg = `привет, ${userName}, добро пожаловать`;\n");
        let out = run_scan(&injection_scan(), &dir);
        assert!(
            !has_rule(&out, "template-literal-html"),
            "текстовый шаблон без HTML-тега не должен ловиться как XSS"
        );
    }

    #[test]
    fn injection_ignores_select_word_without_concat() {
        // Слово SELECT в параметризованном запросе без конкатенации с переменной не сток.
        let dir = tmp();
        write(
            &dir,
            "dao.py",
            "cursor.execute(\"SELECT * FROM users WHERE name = ?\", (name,))\n",
        );
        let out = run_scan(&injection_scan(), &dir);
        assert!(
            !has_rule(&out, "sql-string-concat"),
            "параметризованный запрос не должен ловиться как конкатенация SQL"
        );
    }

    // ───────────────────────── iac: позитив ─────────────────────────

    #[test]
    fn iac_catches_kubernetes_misconfig() {
        let dir = tmp();
        write(
            &dir,
            "pod.yaml",
            "spec:\n  hostNetwork: true\n  hostPID: true\n  securityContext:\n    privileged: true\n    runAsNonRoot: false\n    allowPrivilegeEscalation: true\n",
        );
        let out = run_scan(&iac_scan(), &dir);
        assert!(has_rule(&out, "privileged-container"));
        assert!(has_rule(&out, "host-network"));
        assert!(has_rule(&out, "host-pid"));
        assert!(has_rule(&out, "run-as-root"));
        assert!(has_rule(&out, "allow-priv-escalation"));
    }

    #[test]
    fn iac_catches_add_all_capabilities_block_form() {
        // Блочная форма списка YAML: `add:` на отдельной строке, `- ALL` следующей.
        let dir = tmp();
        write(
            &dir,
            "caps-list.yaml",
            "securityContext:\n  capabilities:\n    add:\n      - ALL\n",
        );
        let out = run_scan(&iac_scan(), &dir);
        assert!(
            has_rule(&out, "cap-add-all"),
            "блочная форма add: - ALL должна ловиться"
        );
    }

    #[test]
    fn iac_catches_add_all_capabilities_inline_form() {
        // Встроенный список YAML: `add: ["ALL"]` на одной строке.
        let dir = tmp();
        write(
            &dir,
            "caps-inline.yaml",
            "securityContext:\n  capabilities:\n    add: [\"ALL\"]\n",
        );
        let out = run_scan(&iac_scan(), &dir);
        assert!(
            has_rule(&out, "cap-add-all"),
            "встроенная форма add: [\"ALL\"] должна ловиться"
        );
    }

    #[test]
    fn iac_catches_dockerfile_issues() {
        let dir = tmp();
        write(
            &dir,
            "Dockerfile",
            "FROM node:latest\nADD https://example.com/app.tar.gz /app\nRUN curl -fsSL https://get.example.sh | sh\n",
        );
        let out = run_scan(&iac_scan(), &dir);
        assert!(has_rule(&out, "from-latest-tag"), "FROM ...:latest");
        assert!(has_rule(&out, "add-remote-url"), "ADD по URL");
        assert!(
            has_rule(&out, "dockerfile-curl-bash"),
            "RUN curl | sh должен ловиться"
        );
    }

    #[test]
    fn iac_catches_image_latest_in_compose() {
        let dir = tmp();
        write(&dir, "compose.yml", "services:\n  web:\n    image: nginx:latest\n");
        let out = run_scan(&iac_scan(), &dir);
        assert!(has_rule(&out, "image-latest-tag"), "image: ...:latest");
    }

    #[test]
    fn iac_messages_carry_cwe_reference() {
        let dir = tmp();
        write(
            &dir,
            "pod.yaml",
            "hostNetwork: true\nhostPID: true\nprivileged: true\nrunAsNonRoot: false\nallowPrivilegeEscalation: true\nimage: nginx:latest\n",
        );
        let out = run_scan(&iac_scan(), &dir);
        assert!(!out.findings.is_empty(), "ожидались находки IaC");
        for f in &out.findings {
            assert!(
                f.message.contains("CWE-"),
                "сообщение правила {} обязано нести ссылку CWE: {}",
                f.rule,
                f.message
            );
        }
    }

    // ───────────────────────── iac: негатив (анти-ложные) ─────────────────────────

    #[test]
    fn iac_ignores_hardened_config() {
        let dir = tmp();
        write(
            &dir,
            "pod.yaml",
            "spec:\n  hostNetwork: false\n  hostPID: false\n  securityContext:\n    privileged: false\n    runAsNonRoot: true\n    allowPrivilegeEscalation: false\n    capabilities:\n      drop:\n        - ALL\n        - NET_RAW\n",
        );
        // Закреплённая версия образа, проверяемый ADD-локальный путь.
        write(&dir, "Dockerfile", "FROM node:20.11.1-alpine\nADD ./dist /app\nRUN npm ci\n");
        let out = run_scan(&iac_scan(), &dir);
        // `drop: - ALL` — это сброс всех capability, безопасная практика. Правило
        // cap-add-all привязано к ключу `add`, поэтому НЕ должно срабатывать на `drop`.
        assert!(!has_rule(&out, "cap-add-all"), "drop: ALL — безопасный сброс, не находка");
        assert!(!has_rule(&out, "privileged-container"));
        assert!(!has_rule(&out, "host-network"));
        assert!(!has_rule(&out, "host-pid"));
        assert!(!has_rule(&out, "run-as-root"));
        assert!(!has_rule(&out, "allow-priv-escalation"));
        assert!(!has_rule(&out, "from-latest-tag"), "закреплённый тег не должен ловиться");
        assert!(!has_rule(&out, "add-remote-url"), "локальный ADD не URL");
        assert!(!has_rule(&out, "dockerfile-curl-bash"), "npm ci не конвейер в оболочку");
    }

    // ───────────────────────── target traversal: отказ во всех capability ─────────────────────────

    #[test]
    fn scan_capabilities_reject_absolute_target() {
        // ScanCapability валидирует target через ctx.base: абсолютный путь уводит за
        // корень и обязан давать Err во всех сканерах семейства (security_extra).
        let dir = tmp();
        write(&dir, "app.js", "el.innerHTML = x;\n");
        let input = RunInput {
            target: Some("/etc".into()),
            query: None,
        };
        assert!(
            injection_scan().run(&Ctx::new(&dir), &input).is_err(),
            "absolute target должен быть отвергнут injection-сканером"
        );
        assert!(
            iac_scan().run(&Ctx::new(&dir), &input).is_err(),
            "absolute target должен быть отвергнут iac-сканером"
        );
    }

    #[test]
    fn scan_capabilities_reject_parent_dir_target() {
        let dir = tmp();
        write(&dir, "app.js", "el.innerHTML = x;\n");
        let input = RunInput {
            target: Some("../../secret".into()),
            query: None,
        };
        assert!(
            injection_scan().run(&Ctx::new(&dir), &input).is_err(),
            "target с .. должен быть отвергнут injection-сканером"
        );
        assert!(
            iac_scan().run(&Ctx::new(&dir), &input).is_err(),
            "target с .. должен быть отвергнут iac-сканером"
        );
    }

    #[test]
    fn deep_analyzers_reject_traversal_target() {
        // Глубокие sast/taint валидируют target через engine ctx.base(input)?: тот же
        // отказ на абсолютный путь и компоненты с двумя точками (согласовано с T42).
        let dir = tmp();
        write(&dir, "app.py", "import os\nx = input()\nos.system(x)\n");
        let abs = RunInput {
            target: Some("/etc".into()),
            query: None,
        };
        let parent = RunInput {
            target: Some("../..".into()),
            query: None,
        };
        assert!(SastScan::new().run(&Ctx::new(&dir), &abs).is_err());
        assert!(SastScan::new().run(&Ctx::new(&dir), &parent).is_err());
        assert!(TaintScan::new().run(&Ctx::new(&dir), &abs).is_err());
        assert!(TaintScan::new().run(&Ctx::new(&dir), &parent).is_err());
    }

    // ───────────────────────── T36: тир пола безопасности ─────────────────────────

    #[test]
    fn deep_analyzers_stay_enterprise_for_floor_inclusion() {
        // T36: sast/taint сознательно остаются Tier::Enterprise; детерминированные пути
        // включают их ПО ИДЕНТИФИКАТОРУ (SECURITY_FLOOR_IDS), а не по тиру. Если кто-то
        // понизит тир до Core, сломается инвариант гейта «тяжёлый разбор не в каждом
        // цикле» и SARIF будет исполнять анализатор без таймаута. Тест фиксирует контракт.
        assert_eq!(SastScan::new().manifest().tier, Tier::Enterprise);
        assert_eq!(TaintScan::new().manifest().tier, Tier::Enterprise);
        // Идентификаторы должны совпадать с полом безопасности гейта.
        assert_eq!(SastScan::new().manifest().id, "security.scan/sast");
        assert_eq!(TaintScan::new().manifest().id, "security.scan/taint");
    }

    // ───────────────────────── deps: скип честен ─────────────────────────

    #[test]
    fn deps_audit_skips_unrecognized_project() {
        let dir = tmp();
        write(&dir, "readme.txt", "просто текст\n");
        let out = DepsAudit::new()
            .run(&Ctx::new(&dir), &RunInput::default())
            .unwrap();
        assert!(out.skipped.is_some(), "нераспознанный проект — честный пропуск");
    }
}
