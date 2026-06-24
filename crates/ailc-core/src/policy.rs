//! Загрузка PolicyPack: governance как данные.
//!
//! Старший кладёт `ailc.policy.toml` в корень проекта (или организация наследует
//! его в CI). Джун ничего не настраивает: правила применяются автоматически.
//! Нет файла, берётся безопасный дефолт. Битый файл, берётся дефолт плюс ЯВНОЕ
//! предупреждение (инвариант «нет молчаливых пропусков»).
//!
//! Доверие к политике (T33). Файл в рабочем дереве пишет тот же, чей код проверяется,
//! поэтому слепое доверие позволяет подделать вердикт ослабленной политикой (поднять
//! `block_at`, обрезать `families`, занизить веса). Защита трёхслойная:
//!   во-первых, после загрузки политика сверяется с организационным дефолтом, и при
//!   любом ослаблении в заметку выносится ЯВНОЕ предупреждение, видимое человеку;
//!   во-вторых, поддержан доверенный источник вне рабочего дерева через переменную
//!   окружения `CO_MCP_POLICY` с путём к эталонному файлу, который имеет приоритет над
//!   файлом проекта;
//!   в-третьих, поддержана сверка контрольной суммы файла проекта с эталоном через
//!   переменную окружения `CO_MCP_POLICY_SHA256`: при несовпадении применяется дефолт
//!   с предупреждением о подмене.
//!
//! Валидация значений (T34). После десериализации диапазоны проверяются явно: веса
//! `score_*` должны быть неотрицательны, пороги положительны. При нарушении берётся
//! дефолт с предупреждением, чтобы отрицательный вес не поднял балл выше ста, а нулевой
//! порог не отключил метрику молча. Итоговый балл клампится сверху уже в гейте.

use ailc_contracts::{GatePolicy, PolicyPack, Severity};
use std::path::{Path, PathBuf};

pub const POLICY_FILE: &str = "ailc.policy.toml";

/// Имя переменной окружения с путём к доверенному файлу политики вне рабочего дерева.
/// Если переменная задана и файл читается и валиден, он имеет приоритет над файлом
/// проекта: командный или CI-режим получает политику из источника, который проверяемый
/// код изменить не может.
pub const TRUSTED_POLICY_ENV: &str = "CO_MCP_POLICY";

/// Имя переменной окружения с эталонной контрольной суммой (SHA-256, шестнадцатеричная
/// строка в нижнем регистре) файла политики проекта. Если задана, фактическая сумма
/// файла сверяется с эталоном; при несовпадении файл считается подменённым и берётся
/// дефолт с предупреждением.
pub const POLICY_SHA256_ENV: &str = "CO_MCP_POLICY_SHA256";

/// Возвращает (политика, заметка-для-человека о её источнике).
///
/// Порядок разрешения источника: сначала доверенный файл из `CO_MCP_POLICY` (если задан
/// и валиден), затем файл проекта `ailc.policy.toml`. Любой выбор сопровождается
/// заметкой, а ослабление относительно организационного дефолта, поломка разбора или
/// нарушение диапазонов значений добавляют в заметку явное предупреждение.
pub fn load(root: &Path) -> (PolicyPack, Option<String>) {
    // Чтение окружения вынесено сюда (T33), а вся логика разрешения источника в чистую
    // `load_with`, чтобы тесты проверяли её детерминированно, не мутируя процессное
    // окружение (иначе параллельные тесты, читающие те же переменные, гонялись бы).
    let trusted = std::env::var_os(TRUSTED_POLICY_ENV)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty());
    load_with(root, trusted.as_deref(), trusted_checksum())
}

/// Чистое ядро разрешения источника политики (T33/T34): получает уже извлечённые из
/// окружения доверенный путь и эталонную контрольную сумму явными аргументами, поэтому
/// тестируется без мутации процессного окружения. Порядок: доверенный файл вне дерева,
/// затем файл проекта (со сверкой контрольной суммы, если эталон задан).
fn load_with(
    root: &Path,
    trusted_path: Option<&Path>,
    checksum: Option<String>,
) -> (PolicyPack, Option<String>) {
    // 1. Доверенный источник вне рабочего дерева имеет приоритет.
    if let Some(trusted) = trusted_path {
        return load_trusted(trusted);
    }
    // 2. Файл проекта в рабочем дереве: читается, но не доверяется слепо.
    let path = root.join(POLICY_FILE);
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        // Нет файла, безопасный дефолт без шумного предупреждения (штатная ситуация).
        Err(_) => return (PolicyPack::default(), None),
    };
    // Сверка контрольной суммы файла проекта с эталоном, если он задан (T33).
    if let Some(expected) = checksum {
        let actual = sha256_hex(raw.as_bytes());
        if !actual.eq_ignore_ascii_case(&expected) {
            return (
                PolicyPack::default(),
                Some(format!(
                    "⚠ контрольная сумма {POLICY_FILE} не совпала с эталоном \
                     ({POLICY_SHA256_ENV}): возможна подмена политики, применён дефолт"
                )),
            );
        }
    }
    parse_and_validate(&raw, &path.display().to_string(), false)
}

/// Загрузка из доверенного источника вне рабочего дерева. Поскольку источник доверенный,
/// его ослабление относительно дефолта предупреждением НЕ помечается (его авторит
/// старший осознанно). Однако валидация диапазонов значений применяется и здесь:
/// доверенный не значит синтаксически безупречный.
fn load_trusted(trusted: &Path) -> (PolicyPack, Option<String>) {
    match std::fs::read_to_string(trusted) {
        Ok(s) => parse_and_validate(&s, &trusted.display().to_string(), true),
        Err(e) => (
            PolicyPack::default(),
            Some(format!(
                "⚠ доверенный файл политики {} из {TRUSTED_POLICY_ENV} не читается: {e}; \
                 применён дефолт",
                trusted.display()
            )),
        ),
    }
}

/// Разобрать TOML, проверить диапазоны значений и (для недоверенного источника) сверить
/// с организационным дефолтом. Возвращает политику и заметку с предупреждениями.
fn parse_and_validate(raw: &str, origin: &str, trusted: bool) -> (PolicyPack, Option<String>) {
    let pp = match toml::from_str::<PolicyPack>(raw) {
        Ok(pp) => pp,
        // Битый TOML, дефолт плюс ЯВНОЕ предупреждение (инвариант «нет молчаливых
        // пропусков»). Заметку вызывающий обязан донести до человека.
        Err(e) => {
            return (
                PolicyPack::default(),
                Some(format!("⚠ битый {POLICY_FILE} ({origin}): {e}; применён дефолт")),
            );
        }
    };

    // T34: валидация диапазонов значений после десериализации. Нарушение диапазона
    // (отрицательный вес, нулевой или отрицательный порог) делает политику опасной:
    // отрицательный вес поднял бы балл выше ста, нулевой порог отключил бы метрику молча.
    // Поэтому при любом нарушении применяется дефолт с явным перечислением проблем.
    if let Err(problems) = validate_pack(&pp) {
        return (
            PolicyPack::default(),
            Some(format!(
                "⚠ значения политики «{}» ({origin}) вне допустимых диапазонов: {}; \
                 применён дефолт",
                pp.name,
                problems.join("; ")
            )),
        );
    }

    let base = format!("политика «{}» из {origin}", pp.name);
    // T33: ослабление относительно организационного дефолта проверяется только для
    // недоверенного источника (файл в рабочем дереве). Доверенный источник авторитетен.
    // Сверяются все три признака ослабления: порог блокировки, обрезанные семейства и
    // заниженные веса штрафов.
    let note = if trusted {
        Some(base)
    } else {
        let mut reasons = Vec::new();
        if let Some(mut r) = weaker_than_default(&pp.gate, &PolicyPack::default()) {
            reasons.append(&mut r);
        }
        if let Some(mut r) = weights_weaker_than_default(&pp) {
            reasons.append(&mut r);
        }
        if reasons.is_empty() {
            Some(base)
        } else {
            Some(format!(
                "{base}; ⚠ политика проекта СЛАБЕЕ организационного дефолта ({}): \
                 вердикт может быть мягче эталона",
                reasons.join(", ")
            ))
        }
    };
    (pp, note)
}

/// Проверка диапазонов значений политики (T34). Возвращает список нарушений человеческим
/// языком или `Ok(())`, если все значения допустимы. Веса штрафов должны быть
/// неотрицательны (отрицательный поднимал бы балл), а пороги строго положительны
/// (нулевой порог отключил бы соответствующую метрику без следа).
fn validate_pack(pp: &PolicyPack) -> std::result::Result<(), Vec<String>> {
    let t = &pp.thresholds;
    let mut problems = Vec::new();
    let weights: &[(&str, f64)] = &[
        ("score_critical", t.score_critical),
        ("score_high", t.score_high),
        ("score_medium", t.score_medium),
        ("score_low", t.score_low),
        ("score_info", t.score_info),
    ];
    for (name, v) in weights {
        if !v.is_finite() || *v < 0.0 {
            problems.push(format!("вес {name}={v} должен быть неотрицательным числом"));
        }
    }
    if t.max_defs_per_file == 0 {
        problems.push("порог max_defs_per_file должен быть больше нуля".into());
    }
    if t.max_nesting == 0 {
        problems.push("порог max_nesting должен быть больше нуля".into());
    }
    if t.max_lines == 0 {
        problems.push("порог max_lines должен быть больше нуля".into());
    }
    if t.max_complexity == 0 {
        problems.push("порог max_complexity должен быть больше нуля".into());
    }
    if !t.doc_coverage_floor.is_finite() || t.doc_coverage_floor <= 0.0 {
        problems.push("порог doc_coverage_floor должен быть больше нуля".into());
    }
    if !t.semantic_threshold.is_finite() || t.semantic_threshold <= 0.0 {
        problems.push("порог semantic_threshold должен быть больше нуля".into());
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// Сравнение политики гейта проекта с организационным дефолтом (T33). Возвращает список
/// причин ослабления человеческим языком или `None`, если политика не слабее дефолта.
/// Ослаблением считается: порог блокировки выше дефолтного (находки прежней тяжести
/// перестают блокировать), обрезанный список семейств (исключены семейства, которые
/// дефолт гонит) и занижение весов штрафов (находки меньше снижают балл).
fn weaker_than_default(p: &GatePolicy, def: &PolicyPack) -> Option<Vec<String>> {
    let mut reasons = Vec::new();

    // 1. Порог блокировки. Severity упорядочена (Info < Low < Medium < High < Critical):
    // более высокий block_at означает, что меньше находок блокирует.
    if p.block_at > def.gate.block_at {
        reasons.push(format!(
            "block_at={} строже-блокирующего дефолта {}",
            sev_name(p.block_at),
            sev_name(def.gate.block_at)
        ));
    }

    // 2. Семейства проверок. Пустой список у проекта означает «все семейства», то есть НЕ
    // ослабление по охвату. Непустой список ослабляет, если исключает семейство, которое
    // дефолт явно гонит.
    if !p.families.is_empty() {
        let cut: Vec<String> = def
            .gate
            .families
            .iter()
            .filter(|&f| !p.families.contains(f))
            .map(|f| f.to_string())
            .collect();
        if !cut.is_empty() {
            reasons.push(format!("обрезаны семейства: {}", cut.join(", ")));
        }
    }

    if reasons.is_empty() {
        None
    } else {
        Some(reasons)
    }
}

/// Сравнение весов штрафов политики с организационным дефолтом (T33). Возвращает список
/// заниженных весов или `None`. Вынесено отдельно от `weaker_than_default`, потому что
/// веса живут в `Thresholds`, а не в `GatePolicy`, и сверка нужна на уровне всего пакета.
fn weights_weaker_than_default(pp: &PolicyPack) -> Option<Vec<String>> {
    let def = PolicyPack::default();
    let t = &pp.thresholds;
    let d = &def.thresholds;
    let pairs: &[(&str, f64, f64)] = &[
        ("score_critical", t.score_critical, d.score_critical),
        ("score_high", t.score_high, d.score_high),
        ("score_medium", t.score_medium, d.score_medium),
        ("score_low", t.score_low, d.score_low),
        ("score_info", t.score_info, d.score_info),
    ];
    let lowered: Vec<String> = pairs
        .iter()
        .filter(|(_, proj, def)| proj < def)
        .map(|(name, proj, def)| format!("вес {name}={proj} ниже дефолта {def}"))
        .collect();
    if lowered.is_empty() {
        None
    } else {
        Some(lowered)
    }
}

/// Человекочитаемое имя severity для предупреждений (отдельно от `Display`, который даёт
/// сокращения вида CRIT/HIGH; здесь нужны полные слова политики).
fn sev_name(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Эталонная контрольная сумма из окружения (T33), приведённая к нижнему регистру и без
/// окаймляющих пробелов. `None`, если переменная не задана или пуста.
fn trusted_checksum() -> Option<String> {
    std::env::var(POLICY_SHA256_ENV)
        .ok()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
}

/// Полная сверка пакета политики проекта с организационным дефолтом, включая веса (T33).
/// Возвращает единое предупреждение для вердикта или `None`. Публична, чтобы вызывающие
/// пути (гейт, оркестратор) могли при необходимости пересобрать заметку из уже
/// загруженного пакета, не перечитывая файл (см. T38, единый PolicyPack).
pub fn weakness_warning(pp: &PolicyPack) -> Option<String> {
    let mut reasons = Vec::new();
    if let Some(mut r) = weaker_than_default(&pp.gate, &PolicyPack::default()) {
        reasons.append(&mut r);
    }
    if let Some(mut r) = weights_weaker_than_default(pp) {
        reasons.append(&mut r);
    }
    if reasons.is_empty() {
        None
    } else {
        Some(format!(
            "⚠ политика проекта слабее организационного дефолта: {}",
            reasons.join("; ")
        ))
    }
}

/// SHA-256 в шестнадцатеричной строке нижнего регистра. Самодостаточная реализация без
/// внешних зависимостей: контрольная сумма политики не должна тащить криптокрейт в ядро,
/// а сверка с эталоном из доверенного окружения целостности соответствует этой задаче.
fn sha256_hex(data: &[u8]) -> String {
    let h = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for b in h {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// Минимальная реализация SHA-256 (FIPS 180-4) без внешних зависимостей. Используется
/// только для сверки контрольной суммы файла политики с эталоном из доверенного
/// окружения, поэтому достаточно одноразового вычисления над буфером в памяти.
struct Sha256;

impl Sha256 {
    fn digest(data: &[u8]) -> [u8; 32] {
        // Начальные значения хеша (дробные части корней первых восьми простых).
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        // Константы раундов (дробные части кубических корней первых 64 простых).
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        // Дополнение сообщения по FIPS 180-4: бит 1, нули, 64-битная длина в битах.
        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in msg.chunks_exact(64) {
            let mut w = [0u32; 64];
            for (i, word) in w.iter_mut().enumerate().take(16) {
                let j = i * 4;
                *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let mut v = h;
            for i in 0..64 {
                let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
                let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
                let t1 = v[7]
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
                let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                let t2 = s0.wrapping_add(maj);
                v[7] = v[6];
                v[6] = v[5];
                v[5] = v[4];
                v[4] = v[3].wrapping_add(t1);
                v[3] = v[2];
                v[2] = v[1];
                v[1] = v[0];
                v[0] = t1.wrapping_add(t2);
            }
            for (hi, vi) in h.iter_mut().zip(v.iter()) {
                *hi = hi.wrapping_add(*vi);
            }
        }

        let mut out = [0u8; 32];
        for (i, word) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ailc_contracts::Family;

    /// Создать уникальный временный корень с заданным содержимым файла политики (или без
    /// него). Файловая система потокобезопасна, процессное окружение тут НЕ трогается:
    /// ядро `load_with` принимает доверенный путь и контрольную сумму явными аргументами,
    /// поэтому тесты детерминированы и не гоняются друг с другом за переменные.
    fn root_with_policy(body: Option<&str>) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ailc-policy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        if let Some(b) = body {
            std::fs::write(p.join(POLICY_FILE), b).unwrap();
        }
        p
    }

    /// Эталонный вектор SHA-256 для пустого ввода (FIPS): реализация корректна.
    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Отсутствие файла политики даёт безопасный дефолт без шумной заметки.
    #[test]
    fn missing_file_is_silent_default() {
        let root = root_with_policy(None);
        let (pp, note) = load_with(&root, None, None);
        assert_eq!(pp.gate.block_at, Severity::High);
        assert!(note.is_none(), "нет файла означает штатный дефолт без предупреждения");
    }

    /// Битый TOML: дефолт плюс ЯВНОЕ предупреждение (T34, инвариант «нет молчаливых
    /// пропусков»).
    #[test]
    fn broken_toml_warns_and_defaults() {
        let root = root_with_policy(Some("это = [не валидный toml"));
        let (pp, note) = load_with(&root, None, None);
        assert_eq!(pp.gate.block_at, Severity::High, "применён дефолт");
        let note = note.expect("должна быть заметка о битом файле");
        assert!(note.contains("битый"), "заметка обязана называть проблему: {note}");
    }

    /// Невалидные значения (отрицательный вес, нулевой порог) отвергаются с заметкой,
    /// применяется дефолт (T34).
    #[test]
    fn invalid_values_rejected_with_default() {
        let root = root_with_policy(Some(
            "name = \"bad\"\n[thresholds]\nscore_high = -5.0\nmax_lines = 0\n",
        ));
        let (pp, note) = load_with(&root, None, None);
        assert_eq!(pp.thresholds.score_high, 10.0, "вернулся дефолтный вес");
        let note = note.expect("должна быть заметка о невалидных значениях");
        assert!(
            note.contains("вне допустимых диапазонов"),
            "заметка обязана объяснить нарушение: {note}"
        );
    }

    /// Политика слабее дефолта (block_at выше, families обрезаны) загружается, но
    /// сопровождается ЯВНЫМ предупреждением (T33).
    #[test]
    fn weaker_policy_loads_with_warning() {
        let root = root_with_policy(Some(
            "name = \"weak\"\n[gate]\nblock_at = \"critical\"\nfamilies = [\"security\"]\n",
        ));
        let (pp, note) = load_with(&root, None, None);
        assert_eq!(pp.gate.block_at, Severity::Critical, "политика всё же применена");
        let note = note.expect("ослабление обязано дать предупреждение");
        assert!(note.contains("СЛАБЕЕ"), "видимое предупреждение: {note}");
    }

    /// Заниженный вес штрафа тоже распознаётся как ослабление (T33): даже при block_at и
    /// families на уровне дефолта.
    #[test]
    fn lowered_weight_triggers_weakness_warning() {
        let root = root_with_policy(Some(
            "name = \"low-weight\"\n[gate]\nblock_at = \"high\"\n\
             families = [\"security\", \"quality\", \"spec\"]\n\
             [thresholds]\nscore_high = 1.0\n",
        ));
        let (_pp, note) = load_with(&root, None, None);
        let note = note.expect("источник всегда называется");
        assert!(note.contains("СЛАБЕЕ"), "занижен вес должно дать предупреждение: {note}");
        assert!(note.contains("score_high"), "назван конкретный вес: {note}");
    }

    /// Политика НЕ слабее дефолта (block_at=high, families включают дефолтные) проходит
    /// без предупреждения об ослаблении (T33, негатив).
    #[test]
    fn at_least_default_policy_no_weakness_warning() {
        let root = root_with_policy(Some(
            "name = \"ok\"\n[gate]\nblock_at = \"high\"\n\
             families = [\"security\", \"quality\", \"spec\", \"verify\"]\n",
        ));
        let (_pp, note) = load_with(&root, None, None);
        let note = note.expect("источник всегда называется");
        assert!(!note.contains("СЛАБЕЕ"), "политика не слабее дефолта: {note}");
    }

    /// Доверенный источник вне дерева имеет приоритет над файлом проекта (T33).
    #[test]
    fn trusted_overrides_project_file() {
        // В проекте лежит слабая политика.
        let root = root_with_policy(Some(
            "name = \"weak-project\"\n[gate]\nblock_at = \"critical\"\n",
        ));
        // Доверенный источник вне дерева строже.
        let trusted_root = root_with_policy(None);
        let trusted = trusted_root.join("org.policy.toml");
        std::fs::write(&trusted, "name = \"org\"\n[gate]\nblock_at = \"medium\"\n").unwrap();
        let (pp, note) = load_with(&root, Some(&trusted), None);
        assert_eq!(pp.name, "org", "приоритет у доверенного источника");
        assert_eq!(pp.gate.block_at, Severity::Medium);
        let note = note.expect("источник назван");
        assert!(note.contains("org"), "заметка ссылается на доверенный файл: {note}");
        // Доверенный источник не помечается как «СЛАБЕЕ», даже если он слабее дефолта.
        assert!(!note.contains("СЛАБЕЕ"), "доверенный авторитетен: {note}");
    }

    /// Нечитаемый доверенный файл даёт дефолт с предупреждением (T33, негатив).
    #[test]
    fn trusted_unreadable_warns_and_defaults() {
        let root = root_with_policy(None);
        let missing = root.join("нет-такого-файла.toml");
        let (pp, note) = load_with(&root, Some(&missing), None);
        assert_eq!(pp.name, "default", "нечитаемый доверенный файл означает дефолт");
        let note = note.expect("нечитаемость обязана дать предупреждение");
        assert!(note.contains("не читается"), "видимое предупреждение: {note}");
    }

    /// Несовпадение контрольной суммы файла проекта с эталоном отвергает файл как
    /// подменённый и применяет дефолт с предупреждением (T33).
    #[test]
    fn checksum_mismatch_rejects_project_file() {
        let root = root_with_policy(Some(
            "name = \"tampered\"\n[gate]\nblock_at = \"critical\"\n",
        ));
        let (pp, note) = load_with(&root, None, Some("0".repeat(64)));
        assert_eq!(pp.name, "default", "подменённый файл отвергнут, взят дефолт");
        let note = note.expect("несовпадение суммы обязано дать предупреждение");
        assert!(note.contains("контрольная сумма"), "видимое предупреждение: {note}");
    }

    /// Совпадение контрольной суммы пропускает файл проекта (T33, позитив).
    #[test]
    fn checksum_match_accepts_project_file() {
        let body = "name = \"signed\"\n[gate]\nblock_at = \"high\"\n\
                    families = [\"security\", \"quality\", \"spec\", \"verify\"]\n";
        let root = root_with_policy(Some(body));
        let sum = sha256_hex(body.as_bytes());
        let (pp, _note) = load_with(&root, None, Some(sum));
        assert_eq!(pp.name, "signed", "верная сумма пропускает файл");
    }

    /// `weakness_warning` собирает и пороговое, и весовое ослабление в единое сообщение.
    #[test]
    fn weakness_warning_covers_thresholds_and_weights() {
        let mut pp = PolicyPack::default();
        pp.gate.block_at = Severity::Critical; // строже-блокирующее = ослабление порога
        pp.gate.families = vec![Family::Security]; // обрезаны quality/spec
        pp.thresholds.score_high = 1.0; // занижен вес High (дефолт 10)
        let w = weakness_warning(&pp).expect("ослабление обнаружено");
        assert!(w.contains("block_at"), "порог в предупреждении: {w}");
        assert!(w.contains("обрезаны семейства"), "охват в предупреждении: {w}");
        assert!(w.contains("score_high"), "веса в предупреждении: {w}");
        // Дефолт сам по себе не слабее себя.
        assert!(weakness_warning(&PolicyPack::default()).is_none());
    }

    /// Пустой список families НЕ считается ослаблением охвата (пусто = все семейства).
    #[test]
    fn empty_families_is_not_weaker() {
        let mut pp = PolicyPack::default();
        pp.gate.families = vec![];
        assert!(
            weaker_than_default(&pp.gate, &PolicyPack::default()).is_none(),
            "пустой families = все семейства, не ослабление"
        );
    }
}
