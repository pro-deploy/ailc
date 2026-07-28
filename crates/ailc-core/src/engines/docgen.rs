//! Сборка документа по декларации стандарта.
//!
//! Документ собирается ЦЕЛИКОМ из трёх источников: декларации разделов (что и в каком
//! порядке обязано быть в документе по стандарту), модели проекта (что установлено из
//! кода) и реестра ответов (что сообщил человек). Ни один раздел не подменяется
//! заглушкой вида «заполни»: раздел либо содержит ответ, либо несёт честную запись об
//! отсутствии сведений с указанием, какой именно вопрос нужно закрыть.
//!
//! ЗОНЫ СВОБОДНОЙ ПРОЗЫ. Человек вправе дописать в документ абзац по месту, и такой
//! абзац переживает регенерацию: он живёт в размеченной зоне, которую сборщик переносит
//! из прежней редакции. Зона помечается состоянием истории изменений, на котором она была
//! написана, чтобы позже можно было честно сказать, что человеческий текст мог устареть.
//! Без этого утверждение «документация всегда актуальна» было бы неверным ровно в
//! человеческой части, которую машина проверить не умеет.
//!
//! ИДЕМПОТЕНТНОСТЬ. В теле документа намеренно нет ни текущей даты, ни отпечатка
//! состояния истории: иначе документ менялся бы от каждого коммита и от смены суток,
//! регенерация всякий раз объявляла бы его обновлённым, а блокировка по расхождению
//! документа с кодом потеряла бы смысл. Даты и отпечатки живут в листе регистрации
//! изменений, который меняется только вместе с содержанием.

use crate::answers::Answers;
use crate::model::ProjectModel;
use crate::profile::ProjectProfile;
use crate::standards::{self, Completeness, Document, Section, Source};
use std::collections::BTreeMap;

/// Метка начала зоны свободной прозы.
///
/// Пустая зона отметки состояния истории не несёт намеренно: иначе документ, в который
/// человек ничего не дописывал, менялся бы от каждого коммита, и блокировка по
/// расхождению документа с кодом потеряла бы смысл. Отметка появляется в тот момент,
/// когда в зоне впервые оказывается человеческий текст.
fn free_start(id: &str, commit: &str) -> String {
    if commit.is_empty() {
        format!("<!-- ailc:free:start {id} -->")
    } else {
        format!("<!-- ailc:free:start {id} коммит={commit} -->")
    }
}

/// Метка конца зоны свободной прозы.
const FREE_END: &str = "<!-- ailc:free:end -->";

/// Собранный документ вместе с оценкой его полноты по стандарту.
pub struct RenderedDocument {
    pub text: String,
    pub completeness: Completeness,
}

/// Прежнее содержимое зоны свободной прозы: текст и отпечаток состояния истории, на
/// котором он был написан.
struct FreeZone {
    text: String,
    commit: String,
}

/// Вынуть зоны свободной прозы из прежней редакции документа.
///
/// Разбор намеренно устойчив к правкам человека вокруг меток: берётся содержимое строго
/// между меткой начала своей зоны и ближайшей меткой конца.
fn extract_free_zones(previous: &str) -> BTreeMap<String, FreeZone> {
    let mut zones: BTreeMap<String, FreeZone> = BTreeMap::new();
    let mut rest = previous;
    while let Some(start) = rest.find("<!-- ailc:free:start ") {
        let after = &rest[start + "<!-- ailc:free:start ".len()..];
        let Some(head_end) = after.find("-->") else {
            break;
        };
        let head = &after[..head_end];
        let mut parts = head.split_whitespace();
        let id = parts.next().unwrap_or_default().to_string();
        let commit = parts
            .find_map(|p| p.strip_prefix("коммит="))
            .unwrap_or_default()
            .to_string();
        let body_start = start + "<!-- ailc:free:start ".len() + head_end + "-->".len();
        let body = &rest[body_start..];
        let Some(end) = body.find(FREE_END) else {
            break;
        };
        let text = body[..end].trim().to_string();
        if !id.is_empty() && !text.is_empty() {
            zones.insert(id, FreeZone { text, commit });
        }
        rest = &body[end + FREE_END.len()..];
    }
    zones
}

/// Собрать документ по декларации.
///
/// `previous` это прежняя редакция файла, если она есть: из неё переносятся зоны
/// свободной прозы. `commit` это текущее состояние истории изменений, которым метятся
/// вновь созданные зоны.
pub fn render(
    doc: &Document,
    m: &ProjectModel,
    answers: &Answers,
    profile: &ProjectProfile,
    previous: Option<&str>,
    commit: &str,
    changes: &[crate::changes::ChangeRecord],
) -> RenderedDocument {
    let zones = previous.map(extract_free_zones).unwrap_or_default();
    let completeness = standards::completeness(doc, m, profile, &|id| answers.is_filled(id));

    let mut s = String::new();
    s.push_str(&title_page(doc, m, &completeness));
    s.push_str(&contents(doc, m, profile));

    for sec in doc.sections {
        s.push_str(&section(sec, doc, m, answers, profile, &zones, commit));
    }

    s.push_str(&change_sheet(changes));
    s.push_str(&footer(doc, &completeness));

    RenderedDocument {
        text: s,
        completeness,
    }
}

/// Титульный лист с обязательными реквизитами.
///
/// Состав реквизитов отвечает требованиям к оформлению: наименование документа,
/// обозначение, наименование изделия, к которому документ относится, и указание
/// стандарта, по которому документ построен.
fn title_page(doc: &Document, m: &ProjectModel, c: &Completeness) -> String {
    let name = m
        .identity
        .name
        .as_ref()
        .map(|f| f.value.as_str())
        .unwrap_or("наименование не установлено");
    let version = m
        .identity
        .version
        .as_ref()
        .map(|f| f.value.clone())
        .unwrap_or_else(|| "не установлена".to_string());

    let mut s = String::new();
    s.push_str(&format!("# {}\n\n", doc.title));
    s.push_str("<!-- ЭТОТ ДОКУМЕНТ СОБИРАЕТСЯ АВТОМАТИЧЕСКИ. Правки вносите ответами на\n");
    s.push_str("     вопросы (spec/answer) либо в зонах свободной прозы ailc:free. Всё\n");
    s.push_str("     остальное будет перезаписано при следующей сборке. -->\n\n");
    s.push_str("| Реквизит | Значение |\n|---|---|\n");
    s.push_str(&format!("| Наименование изделия | {name} |\n"));
    s.push_str(&format!("| Версия изделия | {version} |\n"));
    s.push_str(&format!(
        "| Обозначение документа | {} |\n",
        doc.designation
    ));
    s.push_str(&format!("| Наименование документа | {} |\n", doc.title));
    s.push_str(&format!(
        "| Документ построен по | {} |\n",
        doc.standard.title()
    ));
    s.push_str(&format!(
        "| Полнота по стандарту | {} процентов ({} из {} обязательных разделов) |\n",
        c.percent(),
        c.filled,
        c.required
    ));
    if let Some(l) = &m.identity.license {
        s.push_str(&format!("| Условия использования | {} |\n", l.value));
    }
    s.push('\n');
    s
}

/// Оглавление документа.
fn contents(doc: &Document, m: &ProjectModel, p: &ProjectProfile) -> String {
    let mut s = String::from("## Содержание\n\n");
    for sec in doc.sections {
        let mark = if sec.source == Source::Heading {
            String::new()
        } else if standards::is_required(sec, m, p) {
            " (обязательный)".to_string()
        } else {
            " (при необходимости)".to_string()
        };
        let indent = "  ".repeat(sec.number.matches('.').count());
        s.push_str(&format!("{indent}- {} {}{mark}\n", sec.number, sec.title));
    }
    s.push('\n');
    s
}

/// Один раздел документа.
fn section(
    sec: &Section,
    doc: &Document,
    m: &ProjectModel,
    answers: &Answers,
    p: &ProjectProfile,
    zones: &BTreeMap<String, FreeZone>,
    commit: &str,
) -> String {
    // Глубина заголовка по глубине номера, но не глубже шестого уровня разметки.
    let depth = (sec.number.matches('.').count() + 2).min(6);
    let mut s = format!("{} {} {}\n\n", "#".repeat(depth), sec.number, sec.title);

    if sec.source != Source::Heading {
        s.push_str(&body(sec, doc, m, answers, p));
        s.push('\n');
    }

    // Зона свободной прозы: прежний текст переносится, отметка о возможном устаревании
    // ставится, если состояние истории изменилось с момента её написания.
    let zone = zones.get(sec.id);
    let (text, zone_commit) = match zone {
        // Текст есть, а отметки нет: значит человек дописал его после прошлой сборки.
        // Ставим действующее состояние истории, то есть текст описывает именно его.
        Some(z) if z.commit.is_empty() => (z.text.clone(), commit.to_string()),
        Some(z) => (z.text.clone(), z.commit.clone()),
        None => (String::new(), String::new()),
    };
    s.push_str(&free_start(sec.id, &zone_commit));
    s.push('\n');
    if !text.is_empty() {
        s.push_str(&text);
        s.push('\n');
        if !zone_commit.is_empty() && zone_commit != commit {
            s.push_str(&format!(
                "\n> Примечание ailc: текст выше написан человеком на состоянии истории {zone_commit}, \
                 с тех пор код изменялся. Машина проверить его актуальность не может, требуется подтверждение.\n"
            ));
        }
    }
    s.push_str(FREE_END);
    s.push_str("\n\n");
    s
}

/// Содержание раздела: ответ, вывод из кода либо честная запись об отсутствии.
fn body(
    sec: &Section,
    doc: &Document,
    m: &ProjectModel,
    answers: &Answers,
    p: &ProjectProfile,
) -> String {
    // Диаграммы модели C4 строит движок диаграмм: раздел этого документа является
    // диаграммой, а не перечнем фактов, и подменять её списком значило бы выпустить
    // документ, не отвечающий модели.
    if doc.standard == crate::standards::Standard::C4 {
        if let Some(d) = c4_section(sec.id, m) {
            return d;
        }
    }
    let draft = standards::draft_text(sec.draft, m);
    let answer = answers.get(sec.id).filter(|a| !a.value.trim().is_empty());

    match sec.source {
        Source::Heading => String::new(),
        Source::FromModel => match draft {
            Some(d) => d,
            None => absent(sec, m, p),
        },
        Source::FromInterview => match answer {
            Some(a) => format!(
                "{}\n\n*Источник сведений: {}.*",
                a.value.trim(),
                a.source.label()
            ),
            None => absent(sec, m, p),
        },
        Source::Mixed => match answer {
            Some(a) => {
                let mut s = format!(
                    "{}\n\n*Источник сведений: {}.*",
                    a.value.trim(),
                    a.source.label()
                );
                if let Some(d) = draft {
                    s.push_str(&format!("\n\nУстановлено из кода:\n\n{d}"));
                }
                s
            }
            None => {
                let mut s = absent(sec, m, p);
                if let Some(d) = draft {
                    s.push_str(&format!("\n\nУстановлено из кода:\n\n{d}"));
                }
                s
            }
        },
    }
    .trim_end()
    .to_string()
}

/// Раздел документа модели C4 как диаграмма с обязательными элементами нотации.
///
/// Заголовок с указанием типа диаграммы и области охвата обязателен по требованиям
/// модели, поэтому он входит в текст раздела, а не подразумевается.
fn c4_section(id: &str, m: &ProjectModel) -> Option<String> {
    use crate::engines::diagram::DiagramEngine;
    let name = m
        .identity
        .name
        .as_ref()
        .map(|f| f.value.clone())
        .unwrap_or_else(|| "система".to_string());
    let (заголовок, тело) = match id {
        "c4.контекст" => (
            format!("Диаграмма контекста системы для «{name}»"),
            DiagramEngine::c4_context(m),
        ),
        "c4.контейнеры" => (
            format!("Диаграмма контейнеров для «{name}»"),
            DiagramEngine::c4_containers(m),
        ),
        "c4.компоненты" => (
            format!("Диаграмма компонентов наиболее крупного контейнера системы «{name}»"),
            DiagramEngine::c4_components(m),
        ),
        "c4.динамика" => (
            format!("Динамическая диаграмма запуска системы «{name}»"),
            DiagramEngine::c4_dynamic(m),
        ),
        "c4.развёртывание" => (
            format!("Диаграмма развертывания системы «{name}»"),
            DiagramEngine::c4_deployment(m),
        ),
        _ => return None,
    };
    Some(format!("**{заголовок}**\n\n```mermaid\n{тело}```"))
}

/// Запись об отсутствии сведений.
///
/// Стандарт прямо предписывает сохранять раздел и приводить в нём запись об отсутствии
/// требований, а не выбрасывать раздел из документа. Запись всегда указывает, чем именно
/// её закрыть, поэтому она является не отговоркой, а поручением.
fn absent(sec: &Section, m: &ProjectModel, p: &ProjectProfile) -> String {
    let обязателен = standards::is_required(sec, m, p);
    let mut s = if обязателен {
        "Сведения не определены.".to_string()
    } else {
        "Требования не предъявляются.".to_string()
    };
    if let Some(q) = sec.question {
        s.push_str(&format!(
            " Чтобы закрыть раздел, ответьте на вопрос: {q} Ответ записывается вызовом `spec/answer` с идентификатором `{}`.",
            sec.id
        ));
    } else if обязателен {
        s.push_str(" Модель проекта сведений для этого раздела не содержит.");
    }
    s
}

/// Лист регистрации изменений.
///
/// Строки листа заполняет журнал изменений: каждое, даже мелкое изменение оставляет в нём
/// запись, а затронутые документы получают строку с номером изменения и перечнем
/// изменённых разделов.
fn change_sheet(changes: &[crate::changes::ChangeRecord]) -> String {
    let mut s = String::from("## Лист регистрации изменений\n\n");
    if changes.is_empty() {
        s.push_str(
            "Изменений после первого выпуска документа не зарегистрировано. Записи вносит журнал \
             изменений: каждое, даже мелкое изменение кода оставляет в нём запись, а лист \
             регистрации сводит эти записи здесь.\n\n",
        );
        return s;
    }
    s.push_str(
        "| Изменение | Дата | Класс | Затронуто файлов | Основание |\n|---|---|---|---|---|\n",
    );
    // Показываются последние записи: лист регистрации изменений это сводка, а полный
    // журнал живёт в служебном каталоге и никуда не девается.
    let tail = changes.iter().rev().take(50).collect::<Vec<_>>();
    for r in tail.into_iter().rev() {
        let основание = if r.intent.trim().is_empty() {
            "не указано".to_string()
        } else {
            r.intent.replace('|', "/")
        };
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            r.number,
            r.date,
            r.class.label(),
            r.files.len(),
            основание
        ));
    }
    s.push('\n');
    s
}

/// Заключительная отметка о полноте с перечнем незакрытых разделов.
fn footer(doc: &Document, c: &Completeness) -> String {
    let mut s = String::from("## Отметка о полноте\n\n");
    if c.complete() {
        s.push_str(&format!(
            "Все обязательные разделы документа закрыты: {} из {}. Документ соответствует требованиям к составу разделов, установленным стандартом {}.\n",
            c.filled,
            c.required,
            doc.standard.title()
        ));
        return s;
    }
    s.push_str(&format!(
        "Закрыто {} из {} обязательных разделов ({} процентов). До полного соответствия требованиям к составу разделов не закрыты:\n\n",
        c.filled,
        c.required,
        c.percent()
    ));
    for (n, t) in &c.missing {
        s.push_str(&format!("- {n} {t}\n"));
    }
    s.push_str("\nОчередь вопросов по незакрытым разделам выдаёт `spec/questions`.\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::answers::{Answer, AnswerSource};
    use crate::standards::gost19_201;

    fn пустая_модель() -> ProjectModel {
        ProjectModel {
            schema_version: crate::model::SCHEMA_VERSION,
            ..Default::default()
        }
    }

    /// В документе не остаётся заглушек вида «заполни»: незакрытый раздел несёт честную
    /// запись об отсутствии сведений и указание, чем именно её закрыть.
    #[test]
    fn незакрытый_раздел_несёт_запись_об_отсутствии() {
        let m = пустая_модель();
        let r = render(
            &gost19_201::DOCUMENT,
            &m,
            &Answers::default(),
            &ProjectProfile::default(),
            None,
            "abc1234",
            &[],
        );
        assert!(
            r.text.contains("Сведения не определены."),
            "незакрытый обязательный раздел обязан нести запись об отсутствии"
        );
        assert!(
            !r.text.contains("заполни"),
            "заглушек в документе быть не должно"
        );
        assert!(
            r.text.contains("spec/answer"),
            "запись об отсутствии обязана указывать, чем её закрыть"
        );
        assert!(!r.completeness.complete());
    }

    /// Ответ человека попадает в документ вместе с указанием происхождения: читатель
    /// обязан различать подтверждённое человеком и выведенное из кода.
    #[test]
    fn ответ_попадает_в_документ_с_происхождением() {
        let m = пустая_модель();
        let mut a = Answers::default();
        a.set(
            "тз.основания",
            Answer {
                value: "Разработка ведётся инициативно.".into(),
                source: AnswerSource::Human,
                date: "2026-07-26".into(),
                commit: None,
                question: "На основании какого документа ведётся разработка?".into(),
            },
        );
        let r = render(
            &gost19_201::DOCUMENT,
            &m,
            &a,
            &ProjectProfile::default(),
            None,
            "abc1234",
            &[],
        );
        assert!(r.text.contains("Разработка ведётся инициативно."));
        assert!(
            r.text.contains("подтверждено человеком"),
            "происхождение ответа обязано быть видно в документе"
        );
    }

    /// Дописанный человеком абзац переживает регенерацию, а при изменении состояния
    /// истории получает отметку о возможном устаревании: машина не умеет проверять
    /// человеческую прозу и обязана сказать об этом прямо.
    #[test]
    fn свободная_проза_переживает_регенерацию_и_метится_при_устаревании() {
        let m = пустая_модель();
        let первый = render(
            &gost19_201::DOCUMENT,
            &m,
            &Answers::default(),
            &ProjectProfile::default(),
            None,
            "коммит1",
            &[],
        );

        // Человек дописал абзац в отведённую зону.
        let правленый = первый.text.replace(
            &format!("{}\n{}", free_start("тз.основания", ""), FREE_END),
            &format!(
                "{}\nСогласовано на совещании двенадцатого марта.\n{}",
                free_start("тз.основания", ""),
                FREE_END
            ),
        );
        assert!(правленый.contains("Согласовано на совещании"));

        // Первая сборка после приписки: текст описывает действующее состояние истории,
        // отметка ставится, предупреждать не о чем.
        let второй = render(
            &gost19_201::DOCUMENT,
            &m,
            &Answers::default(),
            &ProjectProfile::default(),
            Some(&правленый),
            "коммит1",
            &[],
        );
        assert!(
            второй
                .text
                .contains("Согласовано на совещании двенадцатого марта."),
            "текст человека обязан пережить регенерацию"
        );
        assert!(
            !второй.text.contains("требуется подтверждение"),
            "пока код не менялся, предупреждать об устаревании не о чем"
        );

        // Код изменился: машина не умеет проверить человеческую прозу и обязана прямо
        // сказать, что та могла устареть.
        let третий = render(
            &gost19_201::DOCUMENT,
            &m,
            &Answers::default(),
            &ProjectProfile::default(),
            Some(&второй.text),
            "коммит2",
            &[],
        );
        assert!(
            третий
                .text
                .contains("Согласовано на совещании двенадцатого марта."),
            "текст человека обязан сохраняться и дальше"
        );
        assert!(
            третий.text.contains("требуется подтверждение"),
            "при изменении состояния истории человеческий текст обязан помечаться как возможно устаревший"
        );
    }

    /// Сборка идемпотентна: два прогона подряд дают побайтово одинаковый документ.
    /// Иначе регенерация всякий раз объявляла бы документ обновлённым, и блокировка по
    /// расхождению документа с кодом потеряла бы смысл.
    #[test]
    fn сборка_документа_идемпотентна() {
        let m = пустая_модель();
        let a = Answers::default();
        let p = ProjectProfile::default();
        let первый = render(&gost19_201::DOCUMENT, &m, &a, &p, None, "коммит1", &[]);
        let второй = render(
            &gost19_201::DOCUMENT,
            &m,
            &a,
            &p,
            Some(&первый.text),
            "коммит1",
            &[],
        );
        assert_eq!(
            первый.text, второй.text,
            "повторная сборка без изменений обязана давать тот же документ"
        );
    }

    /// В теле документа нет ни текущей даты, ни отпечатка истории: иначе документ менялся
    /// бы от каждого коммита и от смены суток.
    #[test]
    fn тело_документа_не_зависит_от_даты_и_коммита() {
        let m = пустая_модель();
        let a = Answers::default();
        let p = ProjectProfile::default();
        let первый = render(&gost19_201::DOCUMENT, &m, &a, &p, None, "коммит1", &[]);
        let второй = render(&gost19_201::DOCUMENT, &m, &a, &p, None, "коммит2", &[]);
        assert_eq!(
            первый.text, второй.text,
            "смена состояния истории не должна менять документ без изменения содержания"
        );
    }
}
