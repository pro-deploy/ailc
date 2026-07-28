//! Журнал работ: что запланировано, что в работе, что сделано, что отложено и что
//! решено не делать.
//!
//! ЗАЧЕМ. След выполненных проверок и след изменений кода сервер вёл и раньше, но ни то,
//! ни другое не отвечает на вопрос человека, вернувшегося к проекту после перерыва:
//! «что из задуманного уже сделано, что осталось и почему часть отложена». Список задач
//! агента живёт в его сеансе и исчезает вместе с ним: обрыв связи, перезапуск среды
//! разработки или отключение электричества стирают состояние работ целиком, и
//! восстановить его человеку неоткуда. Журнал работ переносит это состояние в проект,
//! где оно переживает любой обрыв.
//!
//! ПОЧЕМУ ПРИЧИНА ОБЯЗАТЕЛЬНА. Отложенная задача без причины неотличима от забытой, а
//! отклонённая без причины неотличима от невыполненной. Именно в этих двух случаях
//! человек и теряет понимание происходящего, поэтому статусы «отложено» и «отклонено»
//! принимаются только вместе с объяснением.
//!
//! ЧТО ЭТО НЕ ЗАМЕНЯЕТ. Журнал изменений отвечает на вопрос «что поменялось в коде»,
//! журнал решений отвечает на вопрос «почему выбрано именно так», а этот журнал отвечает
//! на вопрос «где мы находимся в работе». Три журнала не пересекаются и связываются
//! ссылками.

use crate::engines::store::Store;
use ailc_contracts::{CapError, Ctx, Result};
use serde::{Deserialize, Serialize};

/// Пространство журнала работ в служебном каталоге проекта.
const NS: &str = "tasks";

/// Состояние задачи.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskStatus {
    /// Запланирована, к ней ещё не приступали.
    Planned,
    /// В работе прямо сейчас.
    InProgress,
    /// Выполнена.
    Done,
    /// Отложена на следующую итерацию. Требует причины.
    Deferred,
    /// Решено не делать. Требует причины.
    Rejected,
}

impl TaskStatus {
    /// Человекочитаемое обозначение для сводки и для активного контекста.
    pub fn label(&self) -> &'static str {
        match self {
            TaskStatus::Planned => "запланирована",
            TaskStatus::InProgress => "в работе",
            TaskStatus::Done => "сделана",
            TaskStatus::Deferred => "отложена",
            TaskStatus::Rejected => "решено не делать",
        }
    }

    /// Требует ли статус объяснения. Без него запись бесполезна: отложенная задача без
    /// причины неотличима от забытой, а отклонённая от невыполненной.
    pub fn needs_reason(&self) -> bool {
        matches!(self, TaskStatus::Deferred | TaskStatus::Rejected)
    }

    /// Разобрать статус из слова человека либо из машинного написания.
    pub fn parse(s: &str) -> Option<TaskStatus> {
        let l = s.trim().to_lowercase();
        match l.as_str() {
            "planned" | "запланирована" | "запланировано" | "план" => {
                Some(TaskStatus::Planned)
            }
            "in-progress" | "in_progress" | "в работе" | "работаю" | "начал" => {
                Some(TaskStatus::InProgress)
            }
            "done" | "сделана" | "сделано" | "готово" | "выполнено" => {
                Some(TaskStatus::Done)
            }
            "deferred" | "отложена" | "отложено" | "потом" => {
                Some(TaskStatus::Deferred)
            }
            "rejected" | "отклонена" | "отклонено" | "не делать" | "отказ" => {
                Some(TaskStatus::Rejected)
            }
            _ => None,
        }
    }
}

/// Одна задача журнала работ.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub number: u32,
    pub title: String,
    pub status: TaskStatus,
    /// Объяснение статуса. Обязательно для отложенных и отклонённых задач.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Намерение, в рамках которого задача появилась. Позволяет позже понять, зачем
    /// вообще эта работа затевалась.
    pub intent: String,
    /// Связанные записи: спека, архитектурное решение, запись журнала изменений.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<String>,
    pub created: String,
    pub updated: String,
}

/// Прочитать все задачи, упорядоченные по номеру.
pub fn all(ctx: &Ctx) -> Vec<Task> {
    let mut out: Vec<Task> = Store::read_all(ctx, NS)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(_, body)| toml::from_str::<Task>(&body).ok())
        .collect();
    out.sort_by_key(|t| t.number);
    out
}

/// Записать задачу на диск.
fn save(ctx: &Ctx, t: &Task) -> Result<String> {
    let body =
        toml::to_string_pretty(t).map_err(|e| CapError(format!("задача не сериализуется: {e}")))?;
    let name = format!("{:04}.toml", t.number);
    Store::write(ctx, NS, &name, &body)?;
    Ok(format!(".ailc/{NS}/{name}"))
}

/// Добавить задачу в состоянии «запланирована».
///
/// Повторное добавление задачи с тем же заголовком новой записи не создаёт: план
/// перестраивают многократно, и дубли превратили бы журнал в свалку.
pub fn add(ctx: &Ctx, title: &str, intent: &str) -> Result<Option<Task>> {
    let title = title.trim();
    if title.is_empty() {
        return Ok(None);
    }
    let existing = all(ctx);
    if existing.iter().any(|t| t.title == title) {
        return Ok(None);
    }
    let today = crate::answers::today();
    let t = Task {
        number: existing.iter().map(|t| t.number).max().unwrap_or(0) + 1,
        title: title.to_string(),
        status: TaskStatus::Planned,
        reason: None,
        intent: intent.trim().to_string(),
        links: Vec::new(),
        created: today.clone(),
        updated: today,
    };
    save(ctx, &t)?;
    Ok(Some(t))
}

/// Сменить состояние задачи. Возвращает обновлённую задачу либо причину отказа.
pub fn update(
    ctx: &Ctx,
    number: u32,
    status: TaskStatus,
    reason: Option<&str>,
) -> Result<std::result::Result<Task, String>> {
    let reason = reason.map(str::trim).filter(|r| !r.is_empty());
    if status.needs_reason() && reason.is_none() {
        return Ok(Err(format!(
            "статус «{}» принимается только с объяснением: без причины такая запись \
             неотличима от забытой задачи",
            status.label()
        )));
    }
    let Some(mut t) = all(ctx).into_iter().find(|t| t.number == number) else {
        return Ok(Err(format!(
            "задачи с номером {number} в журнале работ нет"
        )));
    };
    t.status = status;
    // Причина сохраняется, даже когда статус её не требует: пояснение к выполненной
    // задаче тоже бывает полезным, а вот затирать прежнее объяснение молча нельзя.
    if let Some(r) = reason {
        t.reason = Some(r.to_string());
    }
    t.updated = crate::answers::today();
    save(ctx, &t)?;
    Ok(Ok(t))
}

/// Привязать к задаче связанную запись (спеку, решение, изменение).
pub fn link(ctx: &Ctx, number: u32, target: &str) -> Result<bool> {
    let Some(mut t) = all(ctx).into_iter().find(|t| t.number == number) else {
        return Ok(false);
    };
    let target = target.trim().to_string();
    if target.is_empty() || t.links.contains(&target) {
        return Ok(false);
    }
    t.links.push(target);
    t.links.sort();
    t.updated = crate::answers::today();
    save(ctx, &t)?;
    Ok(true)
}

/// Сводка состояния работ: сколько задач в каждом состоянии.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub planned: usize,
    pub in_progress: usize,
    pub done: usize,
    pub deferred: usize,
    pub rejected: usize,
}

impl Summary {
    pub fn total(&self) -> usize {
        self.planned + self.in_progress + self.done + self.deferred + self.rejected
    }
}

pub fn summary(tasks: &[Task]) -> Summary {
    let mut s = Summary::default();
    for t in tasks {
        match t.status {
            TaskStatus::Planned => s.planned += 1,
            TaskStatus::InProgress => s.in_progress += 1,
            TaskStatus::Done => s.done += 1,
            TaskStatus::Deferred => s.deferred += 1,
            TaskStatus::Rejected => s.rejected += 1,
        }
    }
    s
}

/// Раздел активного контекста о состоянии работ.
///
/// Именно этот текст видит человек, открывший проект после перерыва, поэтому порядок
/// изложения выбран от насущного к отложенному: сначала то, что брошено на середине,
/// затем очередь, затем отложенное и отклонённое с причинами, и лишь потом сделанное.
pub fn active_context_block(tasks: &[Task]) -> String {
    if tasks.is_empty() {
        return "## Состояние работ (ведётся сервером)\n\n\
                _Журнал работ пуст. Задачи попадают сюда вызовом `task/plan`, состояние \
                меняется вызовом `task/update`._\n"
            .to_string();
    }
    let s = summary(tasks);
    let mut out = String::from("## Состояние работ (ведётся сервером)\n\n");
    out.push_str(&format!(
        "Всего задач {}: сделано {}, в работе {}, запланировано {}, отложено {}, решено не делать {}.\n",
        s.total(),
        s.done,
        s.in_progress,
        s.planned,
        s.deferred,
        s.rejected
    ));

    let mut section = |заголовок: &str, статус: TaskStatus, with_reason: bool| {
        let items: Vec<&Task> = tasks.iter().filter(|t| t.status == статус).collect();
        if items.is_empty() {
            return;
        }
        out.push_str(&format!("\n### {заголовок}\n"));
        for t in items {
            out.push_str(&format!("- [{}] {}", t.number, t.title));
            if with_reason {
                if let Some(r) = &t.reason {
                    out.push_str(&format!(". Причина: {r}"));
                }
            }
            if !t.links.is_empty() {
                out.push_str(&format!(". См.: {}", t.links.join(", ")));
            }
            out.push('\n');
        }
    };

    section("В работе прямо сейчас", TaskStatus::InProgress, false);
    section("Очередь", TaskStatus::Planned, false);
    section("Отложено на следующую итерацию", TaskStatus::Deferred, true);
    section("Решено не делать", TaskStatus::Rejected, true);
    section("Сделано", TaskStatus::Done, false);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> Ctx {
        let root = std::env::temp_dir().join(format!(
            "ailc-tasks-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join(".ailc")).unwrap();
        Ctx::new(root.to_str().unwrap())
    }

    /// Задача переживает запись и чтение, а состояние работ восстанавливается целиком:
    /// именно ради этого журнал и существует, поскольку список задач агента исчезает
    /// вместе с его сеансом.
    #[test]
    fn состояние_работ_переживает_потерю_сеанса() {
        let ctx = tmp("кругооборот");
        add(&ctx, "Починить извлечение фактов", "внедрить документы").unwrap();
        add(&ctx, "Описать декларации стандартов", "внедрить документы").unwrap();
        add(&ctx, "Выпустить руководство", "внедрить документы").unwrap();

        update(&ctx, 1, TaskStatus::Done, None).unwrap().unwrap();
        update(&ctx, 2, TaskStatus::InProgress, None)
            .unwrap()
            .unwrap();
        update(
            &ctx,
            3,
            TaskStatus::Deferred,
            Some("ждём ответов на вопросы интервью"),
        )
        .unwrap()
        .unwrap();

        // Новое чтение, как после перезапуска среды: состояние на месте.
        let tasks = all(&ctx);
        let s = summary(&tasks);
        assert_eq!(s.done, 1);
        assert_eq!(s.in_progress, 1);
        assert_eq!(s.deferred, 1);
        assert_eq!(
            tasks[2].reason.as_deref(),
            Some("ждём ответов на вопросы интервью"),
            "причина отсрочки обязана сохраняться"
        );
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Отложенная задача без причины неотличима от забытой, поэтому такой статус без
    /// объяснения не принимается.
    #[test]
    fn отсрочка_без_причины_отвергается() {
        let ctx = tmp("причина");
        add(&ctx, "Задача", "намерение").unwrap();
        let r = update(&ctx, 1, TaskStatus::Deferred, None).unwrap();
        assert!(r.is_err(), "отсрочка без причины принята быть не должна");
        let r = update(&ctx, 1, TaskStatus::Rejected, Some("   ")).unwrap();
        assert!(r.is_err(), "пробелы объяснением не являются");
        // Состояние при этом не изменилось.
        assert_eq!(all(&ctx)[0].status, TaskStatus::Planned);
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// План перестраивают многократно, поэтому повторное добавление той же задачи новой
    /// записи не создаёт: иначе журнал превратился бы в свалку дублей.
    #[test]
    fn повторное_добавление_не_плодит_дубли() {
        let ctx = tmp("дубли");
        assert!(add(&ctx, "Одна и та же", "намерение").unwrap().is_some());
        assert!(add(&ctx, "Одна и та же", "намерение").unwrap().is_none());
        assert_eq!(all(&ctx).len(), 1);
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Раздел активного контекста ставит насущное впереди: человек, вернувшийся к
    /// проекту, первым делом обязан увидеть брошенное на середине, а не список сделанного.
    #[test]
    fn активный_контекст_начинается_с_насущного() {
        let ctx = tmp("контекст");
        add(&ctx, "Сделанная", "н").unwrap();
        add(&ctx, "Текущая", "н").unwrap();
        add(&ctx, "Отклонённая", "н").unwrap();
        update(&ctx, 1, TaskStatus::Done, None).unwrap().unwrap();
        update(&ctx, 2, TaskStatus::InProgress, None)
            .unwrap()
            .unwrap();
        update(
            &ctx,
            3,
            TaskStatus::Rejected,
            Some("дешевле купить готовое"),
        )
        .unwrap()
        .unwrap();

        let block = active_context_block(&all(&ctx));
        let текущая = block.find("Текущая").expect("текущая задача видна");
        let сделанная = block.find("Сделанная").expect("сделанная задача видна");
        assert!(
            текущая < сделанная,
            "в работе показывается раньше сделанного"
        );
        assert!(
            block.contains("дешевле купить готовое"),
            "причина отказа обязана быть видна: {block}"
        );
        let _ = std::fs::remove_dir_all(&ctx.root);
    }

    /// Статус понимается и по-русски, и в машинном написании: агент передаёт машинное,
    /// человек говорит своими словами.
    #[test]
    fn статус_разбирается_из_слова_человека() {
        assert_eq!(TaskStatus::parse("в работе"), Some(TaskStatus::InProgress));
        assert_eq!(TaskStatus::parse("done"), Some(TaskStatus::Done));
        assert_eq!(TaskStatus::parse("отложено"), Some(TaskStatus::Deferred));
        assert_eq!(TaskStatus::parse("не делать"), Some(TaskStatus::Rejected));
        assert_eq!(TaskStatus::parse("нечто"), None);
    }
}
