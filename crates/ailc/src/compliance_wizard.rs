//! Интерактивный мастер комплаенса РФ: `ailc compliance-ru [путь-вывода]`.
//!
//! Задаёт ~11 вопросов о сервисе → выдаёт ПЕРСОНАЛЬНЫЙ список обязанностей (только
//! применимые законы со штрафами) и генерирует настроенный под профиль `constitution.md`
//! + `МОЙ-ЧЕК-ЛИСТ.md`. Цель — джун видит не «20 законов вообще», а «вот ваши 6».
//!
//! ОРИЕНТИР, не юрконсультация: финально проверяет юрист (см. compliance-ru/).

use std::fs;
use std::io::{self, BufRead, Write};

#[derive(Default)]
struct Profile {
    pdn: bool,
    ru_users: bool,
    foreign_infra: bool,
    registration: bool,
    ads: bool,
    payments: bool,
    biometrics: bool,
    recommender: bool,
    minors: bool,
    large_audience: bool,
    foreign_company: bool,
}

struct Ob {
    risk: u8, // 2 = высокий, 1 = средний
    law: &'static str,
    what: &'static str,
    fine: &'static str,
    hint: &'static str,
}

pub fn run(args: &[String]) {
    let out_dir = args.get(2).cloned().unwrap_or_else(|| ".".to_string());

    println!("\nМАСТЕР КОМПЛАЕНСА РФ — ответьте да/нет, и я соберу ваши обязанности.");
    println!("⚠ Ориентир, НЕ юридическая консультация — финально проверяет юрист.\n");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let mut ask = |q: &str| -> bool {
        print!("  {q} (да/нет): ");
        io::stdout().flush().ok();
        match lines.next() {
            Some(Ok(l)) => {
                let l = l.trim().to_lowercase();
                matches!(l.as_str(), "да" | "д" | "y" | "yes" | "1" | "ага" | "+" | "true")
            }
            _ => false,
        }
    };

    // `&&` короткозамыкает: вопросы 2–4 задаются только при «да» на ПДн.
    let pdn = ask("1. Собираете персональные данные (имя, email, телефон, адрес, фото)?");
    let ru_users = pdn && ask("2. Среди пользователей есть граждане РФ?");
    let foreign_infra = pdn
        && ask("3. Используете зарубежные облака/аналитику/CRM/рассылки (AWS, GA, Mailchimp)?");
    let biometrics = pdn && ask("4. Собираете биометрию (лицо/голос/отпечаток)?");
    let registration = ask("5. Есть регистрация пользователей с аккаунтами?");
    let ads = ask("6. Размещаете рекламу (баннеры, интеграции, продвижение)?");
    let payments = ask("7. Принимаете платежи от физлиц?");
    let recommender = ask("8. Есть рекомендательная лента/алгоритмы подбора контента?");
    let minors = ask("9. Сервис доступен несовершеннолетним или есть пользовательский контент?");
    let large_audience =
        ask("10. Аудитория >500 тыс/сутки ИЛИ это соцсеть/мессенджер/видеохостинг?");
    let foreign_company = ask("11. Юрлицо зарегистрировано за пределами РФ?");

    let p = Profile {
        pdn,
        ru_users,
        foreign_infra,
        registration,
        ads,
        payments,
        biometrics,
        recommender,
        minors,
        large_audience,
        foreign_company,
    };
    let obs = obligations(&p);
    print_report(&p, &obs);
    write_outputs(&out_dir, &p, &obs);
}

fn obligations(p: &Profile) -> Vec<Ob> {
    let mut o = Vec::new();
    if p.pdn {
        o.push(Ob { risk: 2, law: "152-ФЗ", what: "Уведомить РКН об обработке ПДн ДО старта; политика конфиденциальности; согласие активным opt-in; уведомление об утечке 24ч/72ч", fine: "без согласия до 700 тыс; утечка 3–15 млн; повтор — оборотный", hint: "[КОД] consent + дизайн (уведомление РКН)" });
        o.push(Ob { risk: 2, law: "152-ФЗ ст.19", what: "Защита ПДн: не логировать в открытом виде, не хранить пароли в plaintext/MD5", fine: "входит в составы утечки", hint: "[КОД] pdn-logs, secret, owasp" });
    }
    if p.pdn && p.ru_users {
        o.push(Ob { risk: 2, law: "242-ФЗ", what: "Локализация: первичная запись/хранение ПДн граждан РФ — на серверах в РФ", fine: "1–6 / повтор 6–18 млн", hint: "[КОД] localization" });
    }
    if p.pdn && p.foreign_infra {
        o.push(Ob { risk: 2, law: "152-ФЗ ст.12", what: "Трансгранична: уведомить РКН ДО передачи ПДн за рубеж; отдельное согласие", fine: "УК ст.272.1 ч.4 до 8 лет", hint: "[КОД] cross-border" });
    }
    if p.biometrics {
        o.push(Ob { risk: 2, law: "572-ФЗ", what: "Биометрию обрабатывать только через ЕБС; собственные биометрические системы запрещены", fine: "до 15–20 млн", hint: "дизайн" });
    }
    if p.registration && p.ru_users {
        o.push(Ob { risk: 1, law: "ФЗ о связи", what: "Идентификация пользователей по номеру телефона РФ; запрет анонимной регистрации", fine: "блокировка/штраф", hint: "дизайн" });
    }
    if p.ads {
        o.push(Ob { risk: 2, law: "38-ФЗ", what: "Маркировка рекламы: токен erid через ОРД, пометка «Реклама», отчёт в ЕРИР, 3% сбор", fine: "до 700 тыс за нарушение", hint: "[КОД] erid (частично) + дизайн" });
    }
    if p.recommender {
        o.push(Ob { risk: 1, law: "149-ФЗ ст.10.2-1", what: "Уведомить пользователей о применении рекомендательных технологий; правила на сайте", fine: "до блокировки", hint: "дизайн" });
    }
    if p.payments {
        o.push(Ob { risk: 1, law: "54-ФЗ", what: "ККТ/онлайн-касса, фискальные чеки через ОФД", fine: "% от суммы расчёта", hint: "дизайн" });
    }
    if p.minors {
        o.push(Ob { risk: 1, law: "436-ФЗ", what: "Возрастная маркировка (0+/6+/12+/16+/18+); защита детей от вредной информации", fine: "до 1 млн", hint: "дизайн" });
    }
    if p.large_audience {
        o.push(Ob { risk: 1, law: "РКН-реестры", what: "Регистрация в реестре (соцсети 500к+, каналы 10к+ с 01.11.2024)", fine: "запрет рекламы/блокировка", hint: "дизайн" });
    }
    if p.foreign_company && p.large_audience {
        o.push(Ob { risk: 2, law: "236-ФЗ", what: "«Приземление»: филиал/представительство в РФ + личный кабинет в РКН", fine: "оборотный, мин 6 млн", hint: "дизайн" });
    }
    o.sort_by(|a, b| b.risk.cmp(&a.risk));
    o
}

fn print_report(p: &Profile, obs: &[Ob]) {
    println!("\n══════════════════════════════════════════════════════════");
    println!("ВАШ ПРОФИЛЬ → применяется {} норм(ы):\n", obs.len());
    if obs.is_empty() {
        println!("  По ответам прямых обязанностей не выявлено. Это не гарантия —");
        println!("  при сомнениях сверьтесь с юристом и compliance-ru/ЧЕК-ЛИСТ-ДЖУНА.md.\n");
        return;
    }
    for o in obs {
        let mark = if o.risk == 2 { "⚠ ВЫСОКИЙ" } else { "•  средний" };
        println!("  [{mark}] {} — {}", o.law, o.what);
        println!("      штраф: {} | проверка: {}\n", o.fine, o.hint);
    }
    let code = obs.iter().filter(|o| o.hint.contains("[КОД]")).count();
    println!("Из них ailc поможет автоматически проверить ~{code} в коде.");
    let _ = p;
}

fn write_outputs(dir: &str, p: &Profile, obs: &[Ob]) {
    let const_path = format!("{}/constitution.md", dir.trim_end_matches('/'));
    let list_path = format!("{}/МОЙ-ЧЕК-ЛИСТ.md", dir.trim_end_matches('/'));

    if let Err(e) = fs::write(&const_path, tailored_constitution(p)) {
        eprintln!("не удалось записать {const_path}: {e}");
    }
    if let Err(e) = fs::write(&list_path, personal_checklist(obs)) {
        eprintln!("не удалось записать {list_path}: {e}");
    }
    println!("\nСоздано:");
    println!("  {const_path}  — правила для ailc под ваш профиль");
    println!("  {list_path}  — персональный чек-лист");
    println!("\nПроверить код: ailc cap quality.check/constitution {dir}");
    println!("Или: ailc {dir} \"проверь на соответствие 152-ФЗ\"");
}

/// Данные правил вынесены в файл, чтобы детекторы ailc не ловили токены в .rs.
const RULES_DATA: &str = include_str!("compliance_rules.dat");

fn tailored_constitution(p: &Profile) -> String {
    let mut s = String::from(
        "# КОНСТИТУЦИЯ комплаенса РФ (сгенерировано мастером под ваш профиль)\n\
         # Ориентир, не юрконсультация. FORBID/REQUIRE = подстрочный поиск ailc.\n\n",
    );
    // Какие секции включить по профилю.
    let want = |cond: &str| match cond {
        "pdn" => p.pdn,
        "pdn_ru" => p.pdn && p.ru_users,
        "pdn_foreign" => p.pdn && p.foreign_infra,
        "biometrics" => p.biometrics,
        "ads" => p.ads,
        _ => false,
    };
    let mut active = false;
    for line in RULES_DATA.lines() {
        if let Some(cond) = line.strip_prefix('@') {
            active = want(cond.trim());
            continue;
        }
        if active {
            s.push_str(line);
            s.push('\n');
        }
    }
    s.push_str("\n# Полный набор и пояснения: compliance-ru/constitution.md\n");
    s
}

fn personal_checklist(obs: &[Ob]) -> String {
    let mut s = String::from(
        "# МОЙ ЧЕК-ЛИСТ КОМПЛАЕНСА РФ\n\n\
         > ⚠ Сгенерировано мастером ailc как ОРИЕНТИР. НЕ юрконсультация — \
         проверьте у юриста по pravo.gov.ru/КоАП.\n\n",
    );
    if obs.is_empty() {
        s.push_str("Прямых обязанностей по ответам не выявлено. Сверьтесь с юристом.\n");
        return s;
    }
    s.push_str("| Риск | Закон | Что сделать | Штраф если забыть | Проверка |\n");
    s.push_str("|---|---|---|---|---|\n");
    for o in obs {
        let r = if o.risk == 2 { "⚠ высокий" } else { "средний" };
        s.push_str(&format!(
            "| {r} | {} | {} | {} | {} |\n",
            o.law, o.what, o.fine, o.hint
        ));
    }
    s.push_str("\n`[КОД]` — ailc проверит автоматически. Остальное — дизайн/процесс/юрист.\n");
    s
}
