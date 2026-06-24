//! Семейство Compliance — детекторы регуляторных рисков РФ на уровне КОДА.
//!
//! Переиспользуют общий `ScanEngine` (правила-данные, без новой логики). Покрывают
//! то, что выражается в коде: ПДн в логах, зарубежное хранилище (локализация),
//! иностранные трекеры (трансгранична), предзаполненное согласие. Стек-специфика
//! вшита в regex (Python/Go/JS/Java/PHP) — отдельных файлов под стек не нужно.
//!
//! ВАЖНО: это ОРИЕНТИР, не юр-гарантия. Большинство требований РФ — дизайн/процессы
//! (размещение ЦОД, уведомления РКН, категорирование КИИ) — они в ЧЕК-ЛИСТ-ДЖУНА.md,
//! не в коде. Срабатывания — повод для ревью; ailc отсеивает тесты/комментарии.

use ailc_core::engines::scan::{Matcher, Rule, DEFAULT_WINDOW};
use ailc_core::registry::Registry;
use ailc_core::Capability;
use ailc_contracts::{
    CapabilityManifest, CapabilityOutput, Ctx, EngineKind, Family, Result, RunInput, Severity,
    Tier,
};

use crate::{scan_manifest, ScanCapability, TARGET_SCHEMA};

// Все 15 языков движка (+ frontend vue/svelte). Раньше список молча терял
// swift/dart/scala/c/c++ — комплаенс на них не запускался, хотя заявлен «на всех стеках».
const SRC: &[&str] = &[
    "py", "go", "js", "ts", "jsx", "tsx", "java", "php", "rb", "cs", "kt", "kts", "rs", "scala",
    "swift", "dart", "c", "cc", "cpp", "h", "hpp", "vue", "svelte",
];
const SRC_CFG: &[&str] = &[
    "py", "go", "js", "ts", "jsx", "tsx", "java", "php", "rb", "cs", "kt", "kts", "rs", "scala",
    "swift", "dart", "c", "cc", "cpp", "h", "hpp", "vue", "svelte", "yaml", "yml", "json", "toml",
    "env", "ini", "conf", "properties",
];
const SRC_HTML: &[&str] = &[
    "py", "go", "js", "ts", "jsx", "tsx", "java", "php", "rb", "cs", "kt", "kts", "rs", "scala",
    "swift", "dart", "c", "cc", "cpp", "h", "hpp", "vue", "svelte", "html",
];

/// compliance.ru/pdn-logs — российские ПДн в вызовах логирования.
///
/// Содержит два дополняющих друг друга правила. Построчное `pdn-in-logs` ловит вызов
/// логгера и поле ПДн на одной физической строке. Многострочное `pdn-in-logs-multiline`
/// со скользящим окном ловит вызов, у которого аргумент-поле перенесён форматтером на
/// следующую строку: окно объединяет соседние строки через перевод строки, поэтому
/// связывание вызова и поля переживает перенос. Чтобы окно не дублировало находку
/// построчного правила, шаблон требует хотя бы один перевод строки между токеном
/// логгера и полем ПДн (часть `[^\n]*\n`), значит срабатывает только на действительно
/// многострочных вызовах. Для исчерпывающего покрытия многострочных утечек, которые
/// regex принципиально не разбирает (учёт маскирования, глубоко разнесённые аргументы),
/// семейство дополнительно предоставляет структурную AST-компенсацию `pdn-logs-ast`,
/// включённую в дефолтный детерминированный прогон комплаенса (Tier::Core).
fn pdn_logs() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "compliance.ru/pdn-logs",
            Family::Compliance,
            "Логирование персональных данных граждан РФ (паспорт/СНИЛС/ИНН и т.п.) — нарушение 152-ФЗ. Покрывает logger/console/print/log/zap/slog на всех стеках; построчно и многострочно (аргумент перенесён на следующую строку).",
        ),
        vec![
            Rule {
                id: "pdn-in-logs",
                severity: Severity::High,
                exts: SRC,
                // Вызов логгера (любой стек) + поле ПДн на той же строке.
                matcher: Matcher::regex(
                    r"(?i)(?:console\.(?:log|info|warn|error|debug)|logger?\s*\.|logging\.|log\.(?:Print|Info|Debug|Warn|Error)|fmt\.(?:Print|Sprint)|println!|\bprint\()[^\n]{0,90}(?:passport|паспорт|снилс|\bинн\b|passport_number|passportseries|passport_series|birth_certificate|снилс|\bsnils\b)",
                ),
                message: "ПДн в логах (CWE-532 запись чувствительных данных в журнал; OWASP A09:2021 Security Logging and Monitoring Failures) — 152-ФЗ, ст.13.11 КоАП; утечка от 3 до 15 млн руб. (при повторе оборотный штраф). Маскируйте поле перед логированием.",
            },
            Rule {
                // Многострочная компенсация: вызов логгера, затем перенос строки, затем
                // поле ПДн в пределах окна. Часть `[^\n]*\n` гарантирует, что поле лежит
                // НА ДРУГОЙ строке, поэтому правило не дублирует построчное `pdn-in-logs`,
                // а покрывает именно перенос аргумента форматтером. Окно ограничивает зону
                // связывания, чтобы не порождать ложную связь между далёкими строками.
                id: "pdn-in-logs-multiline",
                severity: Severity::High,
                exts: SRC,
                matcher: Matcher::window_regex(
                    r"(?is)(?:console\.(?:log|info|warn|error|debug)|logger?\s*\.|logging\.|log\.(?:Print|Info|Debug|Warn|Error)|fmt\.(?:Print|Sprint)|println!|\bprint\()[^\n]*\n[^;{}]{0,160}?(?:passport|паспорт|снилс|\bинн\b|passport_number|passportseries|passport_series|birth_certificate|\bsnils\b)",
                    DEFAULT_WINDOW,
                ),
                message: "ПДн в многострочном вызове логирования (поле перенесено на отдельную строку) (CWE-532 запись чувствительных данных в журнал; OWASP A09:2021 Security Logging and Monitoring Failures) — 152-ФЗ, ст.13.11 КоАП. Маскируйте поле перед логированием.",
            },
        ],
    )
}

/// compliance.ru/localization — зарубежное хранилище данных (риск 242-ФЗ).
///
/// Оба правила суть СИГНАЛ УПОМИНАНИЯ зарубежной инфраструктуры в коде или конфигурации,
/// а не доказанная трансграничная передача или нарушение локализации. Хост зарубежного
/// поставщика или иностранный регион облака в репозитории требует проверки человеком:
/// какие именно данные там размещаются и относятся ли они к персональным данным граждан
/// Российской Федерации. Поэтому формулировки сообщений не утверждают факт нарушения, а
/// предлагают убедиться в соблюдении локализации (242-ФЗ).
fn localization() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "compliance.ru/localization",
            Family::Compliance,
            "Зарубежная инфраструктура хранения данных (AWS RDS/Mongo Atlas/Firebase/Supabase/иностранные регионы) — СИГНАЛ для проверки локализации ПДн граждан РФ (242-ФЗ), а не доказанное нарушение: что именно там хранится, решает ревью.",
        ),
        vec![
            Rule {
                id: "foreign-db-host",
                severity: Severity::Medium,
                exts: SRC, // хосты в коде
                matcher: Matcher::regex(
                    r"(?i)rds\.amazonaws\.com|[a-z0-9-]+\.mongodb\.net|\.firebaseio\.com|\.supabase\.co|[a-z0-9-]+\.documents\.azure\.com|\.rds\.amazonaws|\.auth0\.com",
                ),
                message: "Упоминание зарубежного хранилища данных (CWE-1327 размещение в нерегламентированной юрисдикции) — сигнал проверить локализацию ПДн граждан РФ (242-ФЗ; ст.13.11 ч.8/9: от 1 до 6 / от 6 до 18 млн руб.). Это не доказательство передачи: убедитесь, относятся ли данные к ПДн и где их первичное хранение.",
            },
            Rule {
                // Иностранный регион сам по себе шумит в lock-файлах, локалях и примерах,
                // поэтому правило требует РЯДОМ ключ региона или эндпойнта (region,
                // aws_region, endpoint, location, zone, availability_zone) либо имя
                // облачного клиента (aws, amazonaws, s3, bucket). Без такого ключа версия
                // или случайная подстрока вида us-east-1 в зависимости/локали не матчится.
                // Важность Info: это слабый географический сигнал для ревью, не блокер.
                id: "foreign-region",
                severity: Severity::Info,
                exts: SRC_CFG, // регион может быть в конфиге
                matcher: Matcher::regex(
                    r"(?i)(?:region|aws_region|endpoint|location|zone|availability_zone|aws|amazonaws|\bs3\b|bucket)[^\n]{0,40}\b(?:us-east-[12]|us-west-[12]|eu-west-[123]|eu-central-[12]|ap-southeast-[123]|ap-northeast-[123])\b|\b(?:us-east-[12]|us-west-[12]|eu-west-[123]|eu-central-[12]|ap-southeast-[123]|ap-northeast-[123])\b[^\n]{0,40}(?:region|aws_region|endpoint|location|zone|availability_zone|amazonaws|bucket)",
                ),
                message: "Иностранный регион облака рядом с ключом региона или эндпойнта (CWE-1327 размещение в нерегламентированной юрисдикции) — сигнал проверить локализацию ПДн (242-ФЗ): первичное хранение данных граждан РФ должно быть в Российской Федерации. Это не доказательство нарушения.",
            },
        ],
    )
}

/// compliance.ru/cross-border — иностранные трекеры/аналитика (трансгранична ПДн).
///
/// Правило фиксирует УПОМИНАНИЕ домена иностранной аналитики или рассылки в коде или
/// разметке, что является сигналом возможной трансграничной передачи персональных данных,
/// а не её доказательством: какие данные фактически уходят на этот домен и являются ли они
/// персональными, устанавливает ревью. Поэтому сообщение формулирует риск как повод для
/// проверки уведомления Роскомнадзора (РКН), а не как установленный факт правонарушения.
fn cross_border() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "compliance.ru/cross-border",
            Family::Compliance,
            "Иностранная аналитика/трекинг/рассылки (Google Analytics, Meta Pixel, Amplitude, Sentry, SendGrid и др.) — СИГНАЛ возможной трансграничной передачи ПДн (152-ФЗ ст.12), а не доказанная передача: какие данные уходят, решает ревью.",
        ),
        vec![Rule {
            id: "foreign-tracker",
            severity: Severity::Medium,
            exts: SRC_HTML,
            matcher: Matcher::regex(
                r"(?i)google-analytics\.com|googletagmanager\.com|connect\.facebook\.net|\.amplitude\.com|api\.mixpanel\.com|\.sentry\.io|api\.sendgrid\.com|\.segment\.(?:com|io)|static\.hotjar\.com|cdn\.segment",
            ),
            message: "Упоминание иностранного трекера или аналитики (CWE-359 раскрытие персональной информации) — сигнал возможной трансграничной передачи ПДн: 152-ФЗ ст.12 требует уведомить РКН до передачи. Если передаются ПДн граждан РФ, оцените риск (вплоть до ст.272.1 ч.4 УК РФ). Это не доказательство передачи: проверьте, какие данные уходят на домен.",
        }],
    )
}

/// compliance.ru/consent — предзаполненное согласие (152-ФЗ ст.9).
fn consent() -> ScanCapability {
    ScanCapability::new(
        scan_manifest(
            "compliance.ru/consent",
            Family::Compliance,
            "Согласие на обработку ПДн, отмеченное по умолчанию (предзаполненная галочка) — запрещено 152-ФЗ ст.9: согласие должно быть активным действием пользователя.",
        ),
        vec![Rule {
            id: "pre-checked-consent",
            severity: Severity::High,
            exts: &["jsx", "tsx", "vue", "svelte", "html", "js", "ts"],
            // Слово согласия + предзаполненное состояние на одной строке (в любом порядке).
            matcher: Matcher::regex(
                r"(?i)(?:agree|consent|согла|оферт|политик|terms|gdpr|пдн)[^\n]{0,70}(?:defaultchecked|checked\s*=\s*\{?\s*true|checked:\s*true)|(?:defaultchecked|checked\s*=\s*\{?\s*true|checked:\s*true)[^\n]{0,70}(?:agree|consent|согла|оферт|политик)",
            ),
            message: "Предзаполненное согласие — 152-ФЗ ст.9 (ред. 01.09.2025): согласие должно быть активным opt-in; нарушение — ЮЛ 300–700 тыс ₽.",
        }],
    )
}

/// compliance.ru/gost-crypto — иностранная криптография на объектах КИИ (187-ФЗ).
///
/// Импортозамещение и 187-ФЗ требуют для значимых объектов КИИ отечественной
/// криптографии (ГОСТ Р 34.10/34.11/34.12/34.13 — Магма/Кузнечик/Стрибог). Детектор
/// флагует использование иностранных крипто-примитивов (AES/RSA/ECDSA/SHA/bcrypt).
/// Низкая важность и Tier::Enterprise: для обычного сервиса это не нарушение, поэтому
/// в дефолтный прогон не входит — включается явным намерением «комплаенс КИИ».
fn gost_crypto() -> ScanCapability {
    ScanCapability::new(
        CapabilityManifest {
            id: "compliance.ru/gost-crypto",
            family: Family::Compliance,
            engine: EngineKind::Scan,
            when_to_use: "Иностранная криптография (AES/RSA/ECDSA/SHA/bcrypt) на объекте КИИ — 187-ФЗ и импортозамещение требуют ГОСТ-криптографии (Магма/Кузнечик/Стрибог). Проверка применима, только если система — значимый объект КИИ.",
            input_schema: TARGET_SCHEMA,
            tier: Tier::Enterprise,
            deterministic: true,
            mutates: false,
        },
        vec![Rule {
            id: "foreign-crypto-primitive",
            severity: Severity::Low,
            exts: &[
                "py", "go", "js", "ts", "java", "cs", "kt", "rs", "php", "rb", "swift", "c", "cpp",
            ],
            matcher: Matcher::regex(
                r#"(?i)Crypto\.Cipher\.AES|crypto/aes|crypto/rsa|crypto/ecdsa|Cipher\.getInstance\s*\(\s*["'](?:AES|DES|RSA)|RSACryptoServiceProvider|rsa\.GenerateKey|ecdsa\.GenerateKey|ed25519\.GenerateKey|hashlib\.(?:sha256|sha512|sha1|md5)|crypto\.createHash\s*\(\s*["'](?:sha256|sha1|md5)|\bFernet\s*\("#,
            ),
            message: "Иностранная криптография — на значимом объекте КИИ требуется ГОСТ (187-ФЗ, импортозамещение): ГОСТ Р 34.12 Магма/Кузнечик, 34.10 подпись, 34.11 Стрибог. Если система не КИИ — игнорируйте.",
        }],
    )
}

/// compliance.ru/pdn-logs-ast — ПДн в логах СТРУКТУРНО (AST).
///
/// Дополняет line-regex `pdn-logs` тем, что regex принципиально не умеет: многострочные
/// вызовы (аргумент на другой строке, глубоко разнесённый по нескольким строкам) и учёт
/// маскирования (поля, обёрнутые в mask/redact/anonymize, не флагуются как ложные). Без
/// этой структурной компенсации многострочные утечки персональных данных в журналы
/// систематически пропускались бы, поэтому проверка отнесена к Tier::Core и входит в
/// дефолтный детерминированный прогон комплаенса. Разбор грамматикой запускается лишь по
/// исходникам поддерживаемых языков; при их отсутствии проверка честно помечается как
/// пропущенная (skipped) и не нагружает прогон.
pub struct PdnLogsAst {
    manifest: CapabilityManifest,
}

impl Default for PdnLogsAst {
    fn default() -> Self {
        Self::new()
    }
}

impl PdnLogsAst {
    pub fn new() -> Self {
        Self {
            manifest: CapabilityManifest {
                id: "compliance.ru/pdn-logs-ast",
                family: Family::Compliance,
                engine: EngineKind::CodeIntel,
                when_to_use: "Структурная AST-проверка ПДн в логах: многострочные вызовы логирования с полями паспорт/СНИЛС/ИНН, с учётом маскирования (152-ФЗ). Компенсирует пропуск многострочных утечек построчным regex; входит в дефолтный прогон комплаенса.",
                input_schema: TARGET_SCHEMA,
                tier: Tier::Core,
                deterministic: true,
                mutates: false,
            },
        }
    }
}

impl Capability for PdnLogsAst {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    fn run(&self, ctx: &Ctx, input: &RunInput) -> Result<CapabilityOutput> {
        let rep = ailc_core::engines::sast::scan_pii_logs(ctx, input)?;
        let mut out = CapabilityOutput::default();
        if rep.files == 0 {
            out.skipped = Some("не найдено исходников на языках с AST-грамматикой".into());
            out.summary = "compliance.ru/pdn-logs-ast: нет разбираемых исходников".into();
            return Ok(out);
        }
        out.metrics.push(("files_parsed".into(), rep.files as f64));
        out.metrics
            .push(("pdn_log_calls".into(), rep.findings.len() as f64));
        out.summary = format!(
            "compliance.ru/pdn-logs-ast: {} файлов разобрано, {} вызовов логируют ПДн",
            rep.files,
            rep.findings.len()
        );
        out.findings = rep.findings;
        Ok(out)
    }
}

/// Регистрирует семейство Compliance (РФ).
pub fn register(reg: &mut Registry) {
    reg.register(Box::new(pdn_logs()));
    reg.register(Box::new(localization()));
    reg.register(Box::new(cross_border()));
    reg.register(Box::new(consent()));
    reg.register(Box::new(gost_crypto())); // КИИ: иностранная криптография (Enterprise)
    reg.register(Box::new(PdnLogsAst::new()));
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
        let dir = std::env::temp_dir().join(format!("ailc-compliance-{}-{}", std::process::id(), n));
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

    /// Идентификаторы правил, сработавших на одном файле указанного сканера.
    fn hits(cap: ScanCapability, file: &str, content: &str) -> Vec<String> {
        let ctx = tmp(&[(file, content)]);
        let out = cap.run(&ctx, &RunInput::default()).unwrap();
        out.findings.into_iter().map(|f| f.rule).collect()
    }

    // ───────────────── pdn-logs: построчно и многострочно (T81) ─────────────────

    #[test]
    fn pdn_logs_построчно_ловит_паспорт_в_логгере() {
        // Поле ПДн на той же строке, что и вызов логгера: срабатывает построчное правило.
        let h = hits(
            pdn_logs(),
            "app/handler.py",
            "logger.info(\"user passport_number=%s\", u.passport_number)\n",
        );
        assert!(h.iter().any(|r| r == "pdn-in-logs"), "ожидали pdn-in-logs, получили {h:?}");
    }

    #[test]
    fn pdn_logs_многострочно_ловит_перенесённое_поле_снилс() {
        // Аргумент-поле перенесён форматтером на следующую строку: построчное правило с
        // окном 90 символов одной строки это пропускает, ловит многострочное правило.
        let h = hits(
            pdn_logs(),
            "app/svc.py",
            "logger.info(\n    \"user snils: %s\",\n    user.snils,\n)\n",
        );
        assert!(
            h.iter().any(|r| r == "pdn-in-logs-multiline"),
            "ожидали pdn-in-logs-multiline на перенесённом поле, получили {h:?}"
        );
    }

    #[test]
    fn pdn_logs_многострочно_русское_поле_паспорт() {
        // Кириллическое поле «паспорт», перенесённое на отдельную строку.
        let h = hits(
            pdn_logs(),
            "app/log.go",
            "log.Print(\n  \"данные: паспорт\",\n)\n",
        );
        assert!(
            h.iter().any(|r| r == "pdn-in-logs-multiline"),
            "ожидали pdn-in-logs-multiline на кириллице, получили {h:?}"
        );
    }

    #[test]
    fn pdn_logs_многострочно_не_дублирует_однострочное() {
        // Когда вызов и поле на ОДНОЙ строке, многострочное правило (требующее перенос
        // между токеном логгера и полем) НЕ должно срабатывать, иначе одна утечка дала бы
        // две находки. Срабатывает только построчное.
        let h = hits(
            pdn_logs(),
            "app/one.py",
            "logger.info(\"passport_number=%s\", u.passport_number)\n",
        );
        assert!(h.iter().any(|r| r == "pdn-in-logs"), "ожидали pdn-in-logs, получили {h:?}");
        assert!(
            !h.iter().any(|r| r == "pdn-in-logs-multiline"),
            "многострочное правило не должно дублировать однострочное, получили {h:?}"
        );
    }

    #[test]
    fn pdn_logs_многострочно_не_ловит_безобидный_лог() {
        // Многострочный вызов логирования без полей ПДн не должен порождать находку.
        let h = hits(
            pdn_logs(),
            "app/ok.py",
            "logger.info(\n    \"order created: %s\",\n    order.id,\n)\n",
        );
        assert!(h.is_empty(), "не ждали находок на безобидном логе, получили {h:?}");
    }

    #[test]
    fn pdn_logs_многострочно_не_связывает_далёкие_строки() {
        // Поле ПДн дальше окна (DEFAULT_WINDOW=3 строки) от вызова логгера не должно
        // связываться: иначе порождались бы ложные связи между несвязанными местами.
        let h = hits(
            pdn_logs(),
            "app/far.py",
            "logger.info(\"start\")\nx = 1\ny = 2\nz = 3\npassport_number = u.passport_number\n",
        );
        assert!(
            !h.iter().any(|r| r == "pdn-in-logs-multiline"),
            "далёкое поле не должно связываться окном, получили {h:?}"
        );
    }

    // ───────────────── foreign-region: контекст ключа, Info (T81) ─────────────────

    #[test]
    fn foreign_region_срабатывает_рядом_с_ключом_региона() {
        // Регион рядом с ключом region: это осмысленный сигнал, срабатываем (Info).
        let ctx = tmp(&[("config/app.yaml", "aws_region: us-east-1\n")]);
        let out = localization().run(&ctx, &RunInput::default()).unwrap();
        let region: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.rule == "foreign-region")
            .collect();
        assert!(!region.is_empty(), "ожидали foreign-region рядом с ключом региона");
        assert_eq!(
            region[0].severity,
            Severity::Info,
            "foreign-region понижен до Info"
        );
    }

    #[test]
    fn foreign_region_срабатывает_рядом_с_эндпойнтом() {
        let h = hits(
            localization(),
            "config/s3.toml",
            "endpoint = \"s3.us-west-2.example.com\"\n",
        );
        assert!(
            h.iter().any(|r| r == "foreign-region"),
            "ожидали foreign-region рядом с endpoint, получили {h:?}"
        );
    }

    #[test]
    fn foreign_region_не_шумит_на_версии_в_lock() {
        // Подстрока вида us-east-1 в lock-файле без ключа региона (например в строке
        // версии) НЕ должна давать находку: это и был источник шума до сужения.
        let h = hits(
            localization(),
            "package-lock.json",
            "    \"resolved\": \"https://r.npm/us-east-1/pkg/-/pkg-1.2.3.tgz\"\n",
        );
        assert!(
            !h.iter().any(|r| r == "foreign-region"),
            "регион без ключа в lock не должен матчиться, получили {h:?}"
        );
    }

    #[test]
    fn foreign_region_не_шумит_в_локали_примера() {
        // Голое имя региона в массиве примеров/локалей без ключа региона не матчится.
        let h = hits(
            localization(),
            "data/regions.json",
            "[\"us-east-1\", \"eu-west-2\", \"ap-southeast-1\"]\n",
        );
        assert!(
            !h.iter().any(|r| r == "foreign-region"),
            "перечень регионов без ключа не должен матчиться, получили {h:?}"
        );
    }

    // ───────────────── foreign-db-host / foreign-tracker (T81) ─────────────────

    #[test]
    fn foreign_db_host_ловит_хост_rds() {
        let h = hits(
            localization(),
            "app/db.go",
            "dsn := \"db.cluster.rds.amazonaws.com:5432\"\n",
        );
        assert!(
            h.iter().any(|r| r == "foreign-db-host"),
            "ожидали foreign-db-host, получили {h:?}"
        );
    }

    #[test]
    fn foreign_db_host_сообщение_формулирует_сигнал_а_не_факт() {
        // Сообщение не должно утверждать факт нарушения: формулировка «сигнал/проверьте».
        let ctx = tmp(&[("app/db.go", "url = \"x.supabase.co\"\n")]);
        let out = localization().run(&ctx, &RunInput::default()).unwrap();
        let msg = &out
            .findings
            .iter()
            .find(|f| f.rule == "foreign-db-host")
            .expect("находка foreign-db-host")
            .message;
        assert!(
            msg.contains("сигнал") && msg.contains("CWE-1327"),
            "сообщение должно нести сигнальную формулировку и ссылку CWE, получили: {msg}"
        );
    }

    #[test]
    fn foreign_tracker_ловит_google_analytics() {
        let h = hits(
            cross_border(),
            "web/index.html",
            "<script src=\"https://www.google-analytics.com/analytics.js\"></script>\n",
        );
        assert!(
            h.iter().any(|r| r == "foreign-tracker"),
            "ожидали foreign-tracker, получили {h:?}"
        );
    }

    #[test]
    fn foreign_tracker_сообщение_не_преувеличивает() {
        // Сообщение трекера должно говорить о возможной передаче (сигнал), а не о
        // доказанной, и нести проверенную ссылку CWE.
        let ctx = tmp(&[("web/app.js", "fetch(\"https://api.mixpanel.com/track\")\n")]);
        let out = cross_border().run(&ctx, &RunInput::default()).unwrap();
        let msg = &out
            .findings
            .iter()
            .find(|f| f.rule == "foreign-tracker")
            .expect("находка foreign-tracker")
            .message;
        assert!(
            msg.contains("сигнал") && msg.contains("CWE-359"),
            "сообщение трекера должно быть сигнальным и со ссылкой CWE, получили: {msg}"
        );
    }

    // ───────────────── pdn-logs-ast в дефолтном прогоне (Tier::Core) ─────────────

    #[test]
    fn pdn_logs_ast_теперь_core_и_входит_в_дефолтный_прогон() {
        // Структурная компенсация многострочных утечек должна быть Core, чтобы попадать в
        // детерминированный прогон комплаенса (orchestrator фильтрует по Tier::Core).
        let ast = PdnLogsAst::new();
        assert_eq!(
            ast.manifest().tier,
            Tier::Core,
            "pdn-logs-ast обязан быть Core для дефолтного прогона комплаенса"
        );
        assert_eq!(ast.manifest().family, Family::Compliance);
    }
}
