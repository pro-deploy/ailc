//! Реестр ответов — протокол интервью, а не форма для заполнения.
//!
//! Сведения, которых код не содержит в принципе (основания для разработки, допустимое
//! время простоя, порядок приёмки), добываются опросом: ailc детерминированно знает, какие
//! разделы стандарта не закрыты и какой вопрос по каждому задать, агент задаёт вопрос
//! человеку обычным языком, ответ возвращается сюда. Гарантию по-прежнему даёт не
//! нейросеть: модель отвечает за формулировку вопроса и за перевод реплики в значение
//! поля, а решение о том, что раздел закрыт, принимает детерминированная проверка.
//!
//! Ключом ответа служит идентификатор раздела стандарта, а не место в файле. Из этого
//! следуют два свойства. Первое: один ответ автоматически попадает во все документы
//! комплекта, где встречается соответствующий раздел, и его не приходится переписывать
//! по десять раз. Второе: при смене применяемого стандарта ответы переносятся, поскольку
//! переносится не текст документа, а содержание раздела.
//!
//! У каждого ответа хранится происхождение. Документ обязан честно показывать, что
//! именно подтвердил человек, а что выведено из кода и лишь принято без возражений.

use ailc_contracts::{CapError, Ctx, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Файл реестра в служебном каталоге проекта.
const FILE: &str = "требования.toml";

/// Происхождение ответа.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnswerSource {
    /// Ответ дал человек своими словами.
    Human,
    /// Черновик выведен из кода, человек его подтвердил.
    Confirmed,
    /// Значение принято из кода без участия человека (для разделов, где это допустимо).
    Derived,
}

impl AnswerSource {
    /// Человекочитаемое обозначение для примечания в документе.
    pub fn label(&self) -> &'static str {
        match self {
            AnswerSource::Human => "подтверждено человеком",
            AnswerSource::Confirmed => "выведено из кода и подтверждено человеком",
            AnswerSource::Derived => "выведено из кода",
        }
    }
}

/// Один ответ реестра.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    /// Содержание раздела в том виде, в каком оно попадёт в документ.
    #[serde(rename = "значение")]
    pub value: String,
    #[serde(rename = "происхождение")]
    pub source: AnswerSource,
    /// Дата получения ответа в виде «ГГГГ-ММ-ДД».
    #[serde(rename = "дата")]
    pub date: String,
    /// Состояние истории изменений на момент ответа: позволяет позже определить,
    /// не устарел ли ответ относительно изменившегося кода.
    #[serde(rename = "коммит", skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Формулировка заданного вопроса. Хранится намеренно: без неё невозможно понять,
    /// на что именно человек отвечал, а значит невозможно и перепроверить ответ.
    #[serde(rename = "вопрос")]
    pub question: String,
}

/// Реестр ответов проекта.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Answers {
    /// Ответы по идентификатору раздела стандарта.
    #[serde(rename = "раздел", default)]
    pub sections: BTreeMap<String, Answer>,
}

impl Answers {
    /// Загрузить реестр. Отсутствующий файл означает пустой реестр, а не ошибку:
    /// до первого интервью реестра нет и быть не должно.
    pub fn load(ctx: &Ctx) -> Answers {
        let path = ctx.root.join(format!(".ailc/{FILE}"));
        let Ok(text) = std::fs::read_to_string(path) else {
            return Answers::default();
        };
        toml::from_str(&text).unwrap_or_default()
    }

    /// Записать реестр. Возвращает относительный путь.
    pub fn save(&self, ctx: &Ctx) -> Result<String> {
        let body = toml::to_string_pretty(self)
            .map_err(|e| CapError(format!("реестр ответов не сериализуется: {e}")))?;
        let text = format!(
            "# Реестр ответов ailc: протокол интервью по разделам стандартов.\n\
             # Файл ведёт сервер: ответы поступают из диалога с агентом. Ручная правка\n\
             # возможна, но не является предполагаемым способом работы.\n\n{body}"
        );
        // Реестр лежит в корне служебного каталога рядом с паспортом и конституцией,
        // поэтому пишется здесь, а не через хранилище с пространствами имён. Запись
        // двухстадийная: читатель никогда не должен увидеть наполовину записанный файл.
        let dir = ctx.root.join(".ailc");
        std::fs::create_dir_all(&dir)?;
        let tmp = dir.join(format!(".{FILE}.tmp{}", std::process::id()));
        std::fs::write(&tmp, text.as_bytes())?;
        if let Err(e) = std::fs::rename(&tmp, dir.join(FILE)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        Ok(format!(".ailc/{FILE}"))
    }

    /// Закрыт ли раздел ответом.
    pub fn is_filled(&self, id: &str) -> bool {
        self.sections
            .get(id)
            .is_some_and(|a| !a.value.trim().is_empty())
    }

    pub fn get(&self, id: &str) -> Option<&Answer> {
        self.sections.get(id)
    }

    /// Записать ответ на раздел. Повторный ответ заменяет прежний: интервью уточняет
    /// сведения, а не накапливает их редакции.
    pub fn set(&mut self, id: &str, answer: Answer) {
        self.sections.insert(id.to_string(), answer);
    }
}

/// Текущая дата в виде «ГГГГ-ММ-ДД».
///
/// Считается из системных часов без внешних зависимостей по общеизвестному алгоритму
/// перевода числа дней от эпохи в календарную дату.
pub fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Календарная дата по числу дней от 1 января 1970 года.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> Ctx {
        let root = std::env::temp_dir().join(format!(
            "ailc-answers-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Ctx::new(root.to_str().unwrap())
    }

    fn ответ(value: &str) -> Answer {
        Answer {
            value: value.to_string(),
            source: AnswerSource::Human,
            date: today(),
            commit: Some("abc1234".into()),
            question: "Каково назначение продукта?".into(),
        }
    }

    /// Реестр переживает запись и чтение вместе с происхождением ответа: без
    /// происхождения документ не сможет честно показать, что подтверждал человек.
    #[test]
    fn ответ_переживает_запись_и_чтение() {
        let ctx = tmp("кругооборот");
        let mut a = Answers::default();
        a.set("тз.назначение", ответ("Учёт заявок подразделения."));
        let rel = a.save(&ctx).unwrap();
        assert_eq!(rel, ".ailc/требования.toml");

        let b = Answers::load(&ctx);
        let got = b.get("тз.назначение").expect("ответ обязан читаться");
        assert_eq!(got.value, "Учёт заявок подразделения.");
        assert_eq!(got.source, AnswerSource::Human);
        assert_eq!(got.commit.as_deref(), Some("abc1234"));
        assert!(
            !got.question.trim().is_empty(),
            "вопрос сохраняется вместе с ответом"
        );
        assert!(b.is_filled("тз.назначение"));
        assert!(!b.is_filled("тз.основания"));
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Отсутствие файла означает пустой реестр, а не ошибку: до первого интервью
    /// реестра не существует.
    #[test]
    fn отсутствующий_реестр_читается_как_пустой() {
        let ctx = tmp("пустой");
        let a = Answers::load(&ctx);
        assert!(a.sections.is_empty());
        assert!(!a.is_filled("что-угодно"));
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Пустой ответ разделом не закрывает: иначе пробел выдавался бы за содержание.
    #[test]
    fn пустой_ответ_раздел_не_закрывает() {
        let ctx = tmp("пусто");
        let mut a = Answers::default();
        a.set("тз.назначение", ответ("   "));
        a.save(&ctx).unwrap();
        assert!(!Answers::load(&ctx).is_filled("тз.назначение"));
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Перевод числа дней в календарную дату проверяется по опорным точкам.
    #[test]
    fn календарная_дата_считается_верно() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(19_784), (2024, 3, 2)); // после високосного дня
    }
}
