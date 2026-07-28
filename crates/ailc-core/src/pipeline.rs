//! Движок пайплайна: шаги-как-данные плюс направленный ациклический граф (DAG) плюс
//! параллелизм на чистом std.
//!
//! Пайплайн описывается ДАННЫМИ (список шагов с зависимостями), а не зашит в код.
//! Исполнение идёт «волнами»: на каждой волне параллельно запускаются все шаги, чьи
//! зависимости уже выполнены, поэтому независимые проверки идут одновременно, а
//! зависимые: после своих предшественников.
//!
//! ФАКТИЧЕСКОЕ ПОЛОЖЕНИЕ ДЕЛ С ЯВНЫМИ ЗАВИСИМОСТЯМИ (сказано прямо, чтобы описание не
//! расходилось с кодом). Движок УМЕЕТ упорядочивать шаги по явно заданным зависимостям
//! (конструктор `Step::with_deps` и поле `Step::deps`), включая обнаружение неразрешимых
//! и циклических связей, однако НИ ОДНО рабочее место построения пайплайна их пока не
//! задаёт. Обе точки сборки в планировщике (`orchestrator.rs`) и построитель пайплайна
//! агента (`agent.rs`) создают шаги исключительно через `Step::of`, то есть с пустым
//! списком зависимостей. Следовательно, в продукте разбиение на волны определяется не
//! явным графом, а исключительно НЕЯВНОЙ сериализацией мутаторов (описана ниже и в
//! `PipelineEngine::execute_with_timeout`), а любой набор немутирующих проверок
//! сворачивается ровно в одну параллельную волну. Это утверждение не декларативное:
//! оно закреплено тестом `шаги_без_зависимостей_исполняются_одной_волной`, который
//! сравнивает фактическое число волн с ожидаемым.
//!
//! Механизм явных зависимостей сохранён намеренно, а не удалён «для опрятности», по трём
//! проверяемым причинам. Во-первых, он входит в зафиксированную базовую линию открытого
//! программного интерфейса (запись `rust fn with_deps` в файле `.ailc/api/baseline.txt`),
//! поэтому его изъятие было бы ломающим изменением интерфейса, которое сам же инструмент
//! обязан пометить нарушением. Во-вторых, удаление почти ничего не упростило бы: цикл
//! волн нужен движку в любом случае ради неявной сериализации мутаторов, ибо отложенные
//! мутатором шаги возвращаются в очередь и переоцениваются ТЕМ ЖЕ условием готовности;
//! исчезли бы лишь один предикат готовности и одна ветвь диагностики. В-третьих, вместе
//! с полем `deps` пропала бы защитная ветвь, сообщающая о неразрешимых и циклических
//! зависимостях, то есть механизм, страхующий будущего планировщика (в том числе
//! планировщика на языковой модели) от молчаливого зависания на противоречивом плане.
//!
//! Модель потоков (честно, без приукрашивания). Каждый шаг волны исполняется в
//! ОТСОЕДИНЁННОМ потоке (std::thread::spawn, не std::thread::scope). Поток нельзя
//! безопасно прервать извне, поэтому изоляция строится на трёх опорах. Во-первых, тело
//! потока обёрнуто в std::panic::catch_unwind: паника одного шага НЕ роняет процесс, а
//! превращается в ошибку шага (это работает только при panic = "unwind"; в релизном
//! профиле с panic = "abort" катить нечего, см. ниже про Cargo.toml). Во-вторых, у
//! волны есть общий дедлайн: по нему recv_timeout помечает зависший шаг как
//! «превысил лимит», и пайплайн идёт дальше, не дожидаясь зависшего потока. В-третьих,
//! при наступлении дедлайна поднимается общий кооперативный флаг отмены (см.
//! `cancellation_requested`): долгие capability, которые его опрашивают (например в
//! колбэке обхода файлов между файлами), могут досрочно и аккуратно завершиться,
//! освободив CPU и память, вместо того чтобы дорабатывать обход вхолостую.
//!
//! Ширина волны ОГРАНИЧЕНА: одновременно ИСПОЛНЯЕТСЯ не больше capability, чем выдаёт
//! std::thread::available_parallelism (число доступных ядер). Это исключает работу
//! десятков тяжёлых capability разом, каждая из которых независимо держит в памяти своё
//! дерево/индекс; остальные готовые шаги ждут освобождения «пропуска» (семафор на
//! Mutex плюс Condvar, чистый std, без внешних зависимостей).
//!
//! Существенная деталь: пропуск захватывается ВНУТРИ рабочего потока, поэтому потоки
//! порождаются сразу для всех готовых шагов, а ждут места уже они, а не главный поток.
//! Ожидание в главном потоке было бы неограниченным по времени: у захвата пропуска нет
//! таймаута, и при числе зависших шагов, равном числу ядер, весь прогон вставал бы
//! навсегда. Ограничение по памяти при этом сохраняется, поскольку его даёт именно
//! семафор, а не число живых потоков.
//!
//! Планировщик (см. orchestrator::Planner) лишь СОБИРАЕТ Pipeline под намерение; сюда
//! позже встанет LLM-планировщик, не меняя движок исполнения.

use crate::registry::Registry;
use ailc_contracts::{CapabilityOutput, Ctx, RunInput};
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Жёсткий потолок одного шага. Выше таймаута Runner (120с на внешний процесс),
/// чтобы не убивать легитимные долгие прогоны тестов; страхует пайплайн от
/// зависшей capability: без него один зависший шаг блокирует весь прогон.
const STEP_TIMEOUT: Duration = Duration::from_secs(180);

thread_local! {
    /// Кооперативный флаг отмены ТЕКУЩЕГО шага. Пайплайн выставляет его в рабочем потоке
    /// перед вызовом `cap.run` и поднимает по общему дедлайну волны. Capability,
    /// исполняющая долгий обход, опрашивает его через `cancellation_requested` между
    /// файлами и может аккуратно прерваться. По умолчанию (вне рабочего потока пайплайна
    /// либо в обычном вызове) флаг отсутствует, и опрос всегда возвращает «не отменено».
    ///
    /// Хранится КЛОН `Arc<AtomicBool>`, а не сырой указатель: владение самим thread-local
    /// гарантирует живость аллокации на всё время, пока флаг установлен, поэтому никакого
    /// `unsafe` и рассуждений о времени жизни указателя не требуется.
    static CANCEL: RefCell<Option<Arc<AtomicBool>>> = const { RefCell::new(None) };
}

/// Опросить кооперативный флаг отмены текущего шага. Возвращает `true`, если пайплайн
/// попросил досрочно завершить текущую capability (наступил общий дедлайн волны). Долгие
/// движки (например обход файлов) должны вызывать это между единицами работы и при `true`
/// аккуратно прекращать работу, выставляя `skipped`/частичный результат, вместо того
/// чтобы вхолостую дорабатывать обход уже «просроченного» шага. Вне рабочего потока
/// пайплайна всегда возвращает `false`, поэтому безопасно вызывать из любого кода.
pub fn cancellation_requested() -> bool {
    CANCEL.with(|c| {
        c.borrow()
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
    })
}

/// Установить клон флага отмены для текущего потока на время вызова `f`, а после
/// гарантированно снять его. Гарантия снятия (через guard, срабатывающий и при панике
/// внутри `f`) не оставляет чужой флаг переиспользуемому потоку.
fn with_cancel<R>(flag: &Arc<AtomicBool>, f: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CANCEL.with(|c| *c.borrow_mut() = None);
        }
    }
    CANCEL.with(|c| *c.borrow_mut() = Some(Arc::clone(flag)));
    let _reset = Reset;
    f()
}

/// Простой счётный семафор на std (Mutex плюс Condvar), чтобы ограничить число
/// одновременно исполняемых потоков волны числом ядер. Внешних зависимостей не вводим.
struct Semaphore {
    state: Mutex<usize>,
    cv: Condvar,
}

impl Semaphore {
    fn new(permits: usize) -> Self {
        Self {
            state: Mutex::new(permits.max(1)),
            cv: Condvar::new(),
        }
    }

    /// Захватить один пропуск, при необходимости дождавшись освобождения.
    fn acquire(&self) {
        let mut avail = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while *avail == 0 {
            avail = self.cv.wait(avail).unwrap_or_else(|e| e.into_inner());
        }
        *avail -= 1;
    }

    /// Вернуть один пропуск и разбудить ожидающего.
    fn release(&self) {
        let mut avail = self.state.lock().unwrap_or_else(|e| e.into_inner());
        *avail += 1;
        self.cv.notify_one();
    }
}

/// Узел DAG: какой capability запустить и от каких шагов он зависит.
pub struct Step {
    pub id: String,
    pub capability: String,
    pub deps: Vec<String>,
}

impl Step {
    /// Независимый шаг (без явных зависимостей), id = id capability.
    ///
    /// Внимание. «Без явных зависимостей» НЕ означает «можно гнать параллельно с чем
    /// угодно». Движок исполнения дополнительно вычисляет НЕЯВНЫЕ зависимости по признаку
    /// мутации (см. `Step::with_deps` и логику волн в `PipelineEngine::execute`): шаг
    /// мутирующей capability никогда не попадёт в одну волну с читателями того же
    /// состояния, иначе читатель мог бы увидеть наполовину записанный снимок (см. T74).
    pub fn of(capability: &str) -> Self {
        Self {
            id: capability.to_string(),
            capability: capability.to_string(),
            deps: Vec::new(),
        }
    }

    /// Шаг с явно заданными зависимостями (id предшественников). Аддитивный конструктор
    /// для планировщиков, которые хотят выстроить порядок руками; существующие вызовы
    /// `Step::of` остаются рабочими.
    ///
    /// ЧЕСТНОЕ ЗАМЕЧАНИЕ О ПРИМЕНЕНИИ. На сегодняшний день у этого конструктора нет ни
    /// одного вызова в продуктовом коде: все три места сборки пайплайна (две в
    /// `orchestrator.rs` и одна в `agent.rs`) пользуются `Step::of`. Он вызывается только
    /// из тестов настоящего модуля, которые проверяют сам движок упорядочивания. Причины,
    /// по которым механизм тем не менее сохранён (обязательство по базовой линии
    /// открытого интерфейса, неустранимость цикла волн и защита от циклических планов),
    /// изложены в документации модуля.
    pub fn with_deps(capability: &str, deps: Vec<String>) -> Self {
        Self {
            id: capability.to_string(),
            capability: capability.to_string(),
            deps,
        }
    }
}

pub struct Pipeline {
    pub name: String,
    pub steps: Vec<Step>,
}

/// Результат одного шага.
pub struct StepResult {
    pub step: String,
    pub capability: String,
    pub output: CapabilityOutput,
    pub error: Option<String>,
}

pub struct PipelineEngine;

impl PipelineEngine {
    /// Выполнить пайплайн, уважая зависимости; независимые шаги: параллельно, но не шире
    /// числа ядер и с разделением мутаторов и читателей по разным волнам.
    ///
    /// Напоминание о фактическом режиме работы: поскольку ни одно рабочее место не задаёт
    /// явных зависимостей (см. документацию модуля), для продуктовых пайплайнов уважать
    /// здесь нечего, кроме неявного разделения мутаторов и читателей, и набор проверок
    /// исполняется одной волной.
    pub fn execute(
        reg: &Registry,
        ctx: &Ctx,
        input: &RunInput,
        pipeline: &Pipeline,
    ) -> Vec<StepResult> {
        Self::execute_with_timeout(reg, ctx, input, pipeline, STEP_TIMEOUT)
    }

    /// Тот же прогон с явным бюджетом одной волны. Существует ради проверяемости: поведение
    /// по истечении бюджета (кооперативная отмена, честное сообщение о неначавшемся шаге,
    /// отсутствие блокировки главного потока) иначе проверялось бы тестом длительностью в
    /// продуктовый бюджет, то есть три минуты, и потому не проверялось бы вовсе.
    pub(crate) fn execute_with_timeout(
        reg: &Registry,
        ctx: &Ctx,
        input: &RunInput,
        pipeline: &Pipeline,
        step_timeout: Duration,
    ) -> Vec<StepResult> {
        Self::execute_counting_waves(reg, ctx, input, pipeline, step_timeout).0
    }

    /// Тот же прогон, дополнительно возвращающий ЧИСЛО ФАКТИЧЕСКИ ИСПОЛНЕННЫХ ВОЛН.
    ///
    /// Счётчик существует ради проверяемости утверждений документации. В модуле прямо
    /// сказано, что явные зависимости в продукте не задаются и что набор немутирующих
    /// проверок сворачивается в одну волну, а мутатор отделяется от читателей. Такое
    /// утверждение обязано быть измеримым, иначе оно со временем разойдётся с кодом так
    /// же незаметно, как разошлось прежнее. Число волн выбрано наблюдаемой величиной
    /// потому, что оно определяется исключительно решением планировщика волн и не зависит
    /// ни от числа ядер, ни от таймингов: наблюдение через фактический параллелизм было бы
    /// неустойчивым на машине с одним доступным ядром, где семафор выдаёт единственный
    /// пропуск и шаги одной волны исполняются последовательно.
    fn execute_counting_waves(
        reg: &Registry,
        ctx: &Ctx,
        input: &RunInput,
        pipeline: &Pipeline,
        step_timeout: Duration,
    ) -> (Vec<StepResult>, usize) {
        // Ширина волны: не больше числа доступных ядер. Если запросить не удалось
        // (экзотическая платформа), берём 1, то есть последовательное исполнение, что
        // корректно и безопасно по памяти.
        let permits = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let sem = Arc::new(Semaphore::new(permits));

        // Признак мутирующей capability: нужен, чтобы НЕ ставить мутатор в одну волну с
        // читателями (T74). Берём из манифеста реестра; неизвестный id трактуем как
        // немутирующий (он всё равно завершится ошибкой «нет capability»).
        let is_mutating = |cap_id: &str| -> bool {
            reg.get(cap_id)
                .map(|c| c.manifest().mutates)
                .unwrap_or(false)
        };

        let mut done: HashSet<String> = HashSet::new();
        // Шаги, завершившиеся сбоем (ошибка, паника, таймаут) либо пропущенные из-за
        // такого сбоя. В `done` они НЕ попадают: «выполнен» означает «результат есть»,
        // и зависимый шаг не должен запускаться поверх отсутствующего результата.
        let mut failed: HashSet<String> = HashSet::new();
        let mut results: Vec<StepResult> = Vec::new();
        let mut remaining: Vec<&Step> = pipeline.steps.iter().collect();
        // Число исполненных волн: наблюдаемая величина для тестов (см. пояснение выше).
        let mut waves_executed: usize = 0;

        while !remaining.is_empty() {
            // Шаги, среди зависимостей которых есть провалившийся или пропущенный шаг,
            // получают ЯВНЫЙ пропуск с причиной, а не запуск поверх отсутствующего
            // результата и не молчаливое исчезновение. Пропуск транзитивен: пропущенный
            // шаг сам считается невыполненным для своих зависимых, поэтому отсев
            // повторяется до неподвижной точки.
            loop {
                let (dead, alive): (Vec<&Step>, Vec<&Step>) = remaining
                    .into_iter()
                    .partition(|s| s.deps.iter().any(|d| failed.contains(d)));
                remaining = alive;
                if dead.is_empty() {
                    break;
                }
                for s in dead {
                    let cause = s
                        .deps
                        .iter()
                        .find(|d| failed.contains(*d))
                        .cloned()
                        .unwrap_or_default();
                    results.push(StepResult {
                        step: s.id.clone(),
                        capability: s.capability.clone(),
                        output: CapabilityOutput::default(),
                        error: Some(format!(
                            "шаг пропущен: зависимость «{cause}» не выполнилась"
                        )),
                    });
                    failed.insert(s.id.clone());
                }
            }
            if remaining.is_empty() {
                break;
            }

            let (ready, not_ready): (Vec<&Step>, Vec<&Step>) = remaining
                .into_iter()
                .partition(|s| s.deps.iter().all(|d| done.contains(d)));

            if ready.is_empty() {
                // Нет готовых, но что-то осталось: неразрешимые/циклические зависимости.
                for s in not_ready {
                    results.push(StepResult {
                        step: s.id.clone(),
                        capability: s.capability.clone(),
                        output: CapabilityOutput::default(),
                        error: Some("неразрешимые зависимости шага".into()),
                    });
                }
                break;
            }

            // НЕЯВНАЯ сериализация мутаторов (T74). Даже если deps пусты (шаги собраны
            // через Step::of, как в build_pipeline агента), мутирующий шаг не должен идти
            // в одной волне с читателями того же состояния: читатель мог бы прочитать
            // наполовину записанный снимок (Store::write теперь атомарна через
            // tmp+rename, но порядок «сначала записали, потом читаем» всё равно обязателен
            // для детерминизма). Правило простое и безопасное: на каждой волне допускаем
            // ЛИБО только немутирующие шаги, ЛИБО ровно один мутатор. Так читатели всегда
            // идут отдельной волной ПОСЛЕ завершившихся мутаторов (готовность волны
            // считается по `done`), а мутаторы не конкурируют друг с другом за состояние.
            let (this_wave, deferred): (Vec<&Step>, Vec<&Step>) = {
                let any_mut = ready.iter().any(|s| is_mutating(&s.capability));
                if !any_mut {
                    // Чистая волна читателей: запускаем всех готовых.
                    (ready, Vec::new())
                } else {
                    // Есть хотя бы один мутатор: пускаем ровно ОДИН мутатор этой волной,
                    // всё остальное (другие мутаторы и любые читатели) откладываем на
                    // следующие волны, чтобы читатели гарантированно увидели результат
                    // мутатора, а мутаторы не пересекались между собой.
                    let mut taken = false;
                    let mut wave: Vec<&Step> = Vec::new();
                    let mut rest: Vec<&Step> = Vec::new();
                    for s in ready {
                        if is_mutating(&s.capability) && !taken {
                            taken = true;
                            wave.push(s);
                        } else {
                            rest.push(s);
                        }
                    }
                    (wave, rest)
                }
            };

            // Состав волны окончательно определён: учитываем её в счётчике. Считаем именно
            // здесь, а не в начале итерации, чтобы аварийный выход по неразрешимым
            // зависимостям (шаги не исполнялись вовсе) не засчитывался как волна.
            waves_executed += 1;

            // Волна: готовые шаги параллельно, но не шире числа ядер (семафор) и каждый
            // в отсоединённом потоке с общим дедлайном и кооперативным флагом отмены.
            let deadline = Instant::now() + step_timeout;
            // Кооперативная отмена волны: атомарный флаг (его опрашивают capability) плюс
            // Condvar, чтобы СТОРОЖ мог проснуться досрочно, как только волна собрана, и
            // НЕ держать поток спящим до самого дедлайна (иначе join сторожа завис бы на
            // весь STEP_TIMEOUT даже после быстрой волны).
            let cancel = Arc::new(AtomicBool::new(false));
            let wave_finished = Arc::new((Mutex::new(false), Condvar::new()));

            // Сторож дедлайна (T60): ждёт ЛИБО наступления общего дедлайна волны, ЛИБО
            // сигнала «волна собрана» (через Condvar). По дедлайну поднимает кооперативный
            // флаг отмены, чтобы опрашивающие его capability могли досрочно завершиться, не
            // дожидаясь конца обхода уже «просроченного» шага. По раннему сигналу выходит
            // сразу, поэтому его join не блокирует пайплайн на весь STEP_TIMEOUT.
            //
            // ПОРОЖДАЕТСЯ ДО ЦИКЛА СПАВНА, а не после него. Прежде сторож создавался после
            // того, как все шаги волны были поставлены, и при этом главный поток мог
            // застрять внутри цикла (см. ниже про захват пропуска). Пока он там стоял,
            // сторожа не существовало, дедлайн проходил незамеченным и кооперативный флаг
            // отмены не поднимался вовсе.
            let cancel_watch = Arc::clone(&cancel);
            let finished_watch = Arc::clone(&wave_finished);
            let watchdog = std::thread::spawn(move || {
                let (lock, cv) = &*finished_watch;
                let mut done_flag = lock.lock().unwrap_or_else(|e| e.into_inner());
                while !*done_flag {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        // Дедлайн наступил: просим capability кооперативно отмениться.
                        cancel_watch.store(true, Ordering::Relaxed);
                        break;
                    }
                    let (g, timeout) = cv
                        .wait_timeout(done_flag, left)
                        .unwrap_or_else(|e| e.into_inner());
                    done_flag = g;
                    if timeout.timed_out() && !*done_flag {
                        cancel_watch.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            });

            let mut pending = Vec::with_capacity(this_wave.len());
            for &s in &this_wave {
                // Признак «шаг реально начал исполняться» (то есть получил пропуск).
                // Нужен, чтобы по истечении бюджета волны сообщить ПРАВДУ: превысил ли шаг
                // лимит времени или вообще не запускался. Прежде оба случая давали
                // одинаковое сообщение «шаг превысил лимит времени (180с)», что для шага,
                // не выполнившего ни одной инструкции, является ложным утверждением.
                let started = Arc::new(AtomicBool::new(false));
                let slot = match reg.get_arc(&s.capability) {
                    None => Err(format!("нет capability `{}`", s.capability)),
                    Some(cap) => {
                        let (tx, rx) = mpsc::channel();
                        let (ctx2, input2) = (ctx.clone(), input.clone());
                        let sem2 = Arc::clone(&sem);
                        let cancel2 = Arc::clone(&cancel);
                        let started2 = Arc::clone(&started);
                        std::thread::spawn(move || {
                            // ПРОПУСК ЗАХВАТЫВАЕТСЯ ЗДЕСЬ, В РАБОЧЕМ ПОТОКЕ, а не в главном
                            // перед порождением.
                            //
                            // Прежний порядок давал два независимых дефекта. Во-первых, при
                            // числе готовых шагов больше числа ядер главный поток блокировался
                            // на захвате, и у этого ожидания НЕ БЫЛО таймаута: если столько
                            // шагов зависало, сколько есть ядер, пропусков не возвращал никто,
                            // а потоки отсоединены и не прерываются, поэтому процесс вставал
                            // навсегда. Во-вторых, пока главный поток стоял на захвате, он не
                            // успевал ни поставить остальные шаги, ни породить сторожа.
                            //
                            // Ограничение по памяти при этом СОХРАНЯЕТСЯ: семафор по-прежнему
                            // допускает одновременное исполнение не более чем `permits`
                            // capability, поэтому десятки тяжёлых разборов разом в память не
                            // попадут. Меняется лишь то, ГДЕ происходит ожидание: в своём
                            // рабочем потоке вместо главного.
                            sem2.acquire();
                            // Гарантируем возврат пропуска и при панике (catch_unwind ниже
                            // её ловит, но страхуемся guard-ом на случай иных путей).
                            struct Permit(Arc<Semaphore>);
                            impl Drop for Permit {
                                fn drop(&mut self) {
                                    self.0.release();
                                }
                            }
                            let _permit = Permit(sem2);
                            // Дождались места, но бюджет волны уже истёк: работу не начинаем.
                            // Результат этого шага главный поток всё равно не ждёт, а полный
                            // разбор дерева вхолостую занял бы процессор и память.
                            if cancel2.load(Ordering::Relaxed) {
                                return;
                            }
                            started2.store(true, Ordering::Relaxed);
                            // T59: ловим панику шага, чтобы один упавший детектор не ронял
                            // процесс, а превращался в ошибку шага. Отдаём Result, явно
                            // отличающий панику от обычной ошибки capability.
                            let outcome =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    with_cancel(&cancel2, || cap.run(&ctx2, &input2))
                                }));
                            let _ = tx.send(outcome);
                        });
                        Ok(rx)
                    }
                };
                pending.push((s, slot, started));
            }

            let wave: Vec<StepResult> = pending
                .into_iter()
                .map(|(s, slot, started)| {
                    let mut res = StepResult {
                        step: s.id.clone(),
                        capability: s.capability.clone(),
                        output: CapabilityOutput::default(),
                        error: None,
                    };
                    match slot {
                        Err(e) => res.error = Some(e),
                        Ok(rx) => {
                            let left = deadline.saturating_duration_since(Instant::now());
                            match rx.recv_timeout(left) {
                                Ok(Ok(Ok(out))) => res.output = out,
                                Ok(Ok(Err(e))) => res.error = Some(e.to_string()),
                                Ok(Err(panic)) => {
                                    // T59: поток шага паниковал, но процесс жив (поймали
                                    // через catch_unwind). Достаём сообщение паники.
                                    res.error = Some(panic_message(panic.as_ref()));
                                }
                                Err(mpsc::RecvTimeoutError::Timeout) => {
                                    // Различаем «работал и не успел» от «не начинал работать»:
                                    // второе означает, что бюджет волны истёк, пока шаг ждал
                                    // освобождения места, и утверждать про него «превысил
                                    // лимит времени» было бы неправдой.
                                    res.error = Some(if started.load(Ordering::Relaxed) {
                                        format!(
                                            "шаг превысил лимит времени ({}с)",
                                            step_timeout.as_secs()
                                        )
                                    } else {
                                        format!(
                                            "шаг не запускался: бюджет волны ({}с) истёк, пока шаг \
                                             ждал освобождения места (одновременно исполняется не \
                                             более {permits} проверок)",
                                            step_timeout.as_secs()
                                        )
                                    });
                                }
                                Err(mpsc::RecvTimeoutError::Disconnected) => {
                                    // Канал закрыт без значения: при panic = "abort" поток
                                    // уносит процесс ещё до этой ветки, поэтому сюда мы
                                    // попадаем лишь при крайне редком обрыве (например,
                                    // отправитель уронен мимо catch_unwind). Помечаем шаг,
                                    // не роняя пайплайн.
                                    res.error = Some("шаг прерван без результата".into());
                                }
                            }
                        }
                    }
                    res
                })
                .collect();

            // Волна собрана: будим сторожа (Condvar), чтобы он вышел немедленно и его join
            // не ждал дедлайна. Флаг отмены при штатном завершении поднимать НЕ нужно: все
            // рабочие потоки уже отдали результат, опрашивать его больше некому.
            {
                let (lock, cv) = &*wave_finished;
                let mut g = lock.lock().unwrap_or_else(|e| e.into_inner());
                *g = true;
                cv.notify_one();
            }
            let _ = watchdog.join();

            // В `done` идут ТОЛЬКО успешно завершившиеся шаги: у шага со сбоем результата
            // нет, и считать его «выполненным» для зависимых означало бы запускать их
            // поверх пустоты. Сбойные шаги уходят в `failed`, и их зависимые получат явный
            // пропуск с причиной на следующей итерации (см. отсев в начале цикла).
            for r in &wave {
                if r.error.is_none() {
                    done.insert(r.step.clone());
                } else {
                    failed.insert(r.step.clone());
                }
            }
            results.extend(wave);

            // Отложенные на следующие волны (мутаторы/читатели) плюс ещё не готовые.
            remaining = deferred.into_iter().chain(not_ready).collect();
        }

        (results, waves_executed)
    }
}

/// Извлечь человекочитаемое сообщение из payload пойманной паники.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        format!("шаг паниковал: {s}")
    } else if let Some(s) = payload.downcast_ref::<String>() {
        format!("шаг паниковал: {s}")
    } else {
        "шаг паниковал".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Capability;
    use ailc_contracts::{CapabilityManifest, EngineKind, Family, Finding, Result, Severity, Tier};
    use std::sync::atomic::{AtomicUsize, Ordering as AtOrd};

    // ── Тестовые capability ────────────────────────────────────────────────────

    /// Capability, которая просто отдаёт находку и помечает «выполнено» в общем счётчике.
    struct Ok1 {
        manifest: CapabilityManifest,
    }
    impl Capability for Ok1 {
        fn manifest(&self) -> &CapabilityManifest {
            &self.manifest
        }
        fn run(&self, _ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
            let mut out = CapabilityOutput::default();
            out.findings.push(Finding::new(
                "demo",
                Severity::Low,
                "ок",
                None,
                None,
                false,
                self.manifest.id,
            ));
            Ok(out)
        }
    }

    /// Capability, которая паникует: проверяем изоляцию (T59).
    struct Panicker {
        manifest: CapabilityManifest,
    }
    impl Capability for Panicker {
        fn manifest(&self) -> &CapabilityManifest {
            &self.manifest
        }
        fn run(&self, _ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
            panic!("намеренная паника шага");
        }
    }

    /// Capability, которая возвращает обычную ошибку (не панику).
    struct Failer {
        manifest: CapabilityManifest,
    }
    impl Capability for Failer {
        fn manifest(&self) -> &CapabilityManifest {
            &self.manifest
        }
        fn run(&self, _ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
            Err(ailc_contracts::CapError("обычная ошибка".into()))
        }
    }

    // Глобальные счётчики наблюдения за порядком и параллелизмом мутатора и читателя.
    static MUT_RUNNING: AtomicUsize = AtomicUsize::new(0);
    static READER_SAW_MUT: AtomicUsize = AtomicUsize::new(0);
    static MUT_DONE_BEFORE_READER: AtomicUsize = AtomicUsize::new(0);
    static MUT_FINISHED: AtomicBool = AtomicBool::new(false);

    /// Мутатор: на входе поднимает флаг «мутатор работает», держит его ненадолго, затем
    /// опускает и помечает «мутатор завершён».
    struct Mutator {
        manifest: CapabilityManifest,
    }
    impl Capability for Mutator {
        fn manifest(&self) -> &CapabilityManifest {
            &self.manifest
        }
        fn run(&self, _ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
            MUT_RUNNING.fetch_add(1, AtOrd::SeqCst);
            std::thread::sleep(Duration::from_millis(40));
            MUT_RUNNING.fetch_sub(1, AtOrd::SeqCst);
            MUT_FINISHED.store(true, AtOrd::SeqCst);
            Ok(CapabilityOutput::default())
        }
    }

    /// Читатель: фиксирует, видел ли он работающего мутатора и завершился ли мутатор к
    /// моменту его старта.
    struct Reader {
        manifest: CapabilityManifest,
    }
    impl Capability for Reader {
        fn manifest(&self) -> &CapabilityManifest {
            &self.manifest
        }
        fn run(&self, _ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
            if MUT_RUNNING.load(AtOrd::SeqCst) > 0 {
                READER_SAW_MUT.fetch_add(1, AtOrd::SeqCst);
            }
            if MUT_FINISHED.load(AtOrd::SeqCst) {
                MUT_DONE_BEFORE_READER.fetch_add(1, AtOrd::SeqCst);
            }
            Ok(CapabilityOutput::default())
        }
    }

    fn manifest(id: &'static str, mutates: bool) -> CapabilityManifest {
        CapabilityManifest {
            id,
            family: if mutates {
                Family::Generate
            } else {
                Family::Verify
            },
            engine: EngineKind::Scan,
            when_to_use: "тест",
            input_schema: "{}",
            tier: Tier::Core,
            deterministic: true,
            mutates,
        }
    }

    fn ctx() -> Ctx {
        Ctx::new(std::env::temp_dir())
    }

    #[test]
    fn panic_isolated_does_not_kill_others() {
        // T59: паника одного шага не роняет процесс и не мешает соседним шагам.
        let mut reg = Registry::new();
        reg.register(Box::new(Ok1 {
            manifest: manifest("ok.a", false),
        }));
        reg.register(Box::new(Panicker {
            manifest: manifest("boom", false),
        }));
        reg.register(Box::new(Ok1 {
            manifest: manifest("ok.b", false),
        }));

        let pipeline = Pipeline {
            name: "t".into(),
            steps: vec![Step::of("ok.a"), Step::of("boom"), Step::of("ok.b")],
        };
        let res = PipelineEngine::execute(&reg, &ctx(), &RunInput::default(), &pipeline);

        assert_eq!(res.len(), 3);
        let boom = res.iter().find(|r| r.step == "boom").unwrap();
        assert!(
            boom.error.as_deref().unwrap_or("").contains("паниковал"),
            "паника должна быть помечена как ошибка шага, а не уронить процесс: {:?}",
            boom.error
        );
        // Соседи отработали штатно.
        for id in ["ok.a", "ok.b"] {
            let r = res.iter().find(|r| r.step == id).unwrap();
            assert!(r.error.is_none(), "{id} не должен иметь ошибки");
            assert_eq!(r.output.findings.len(), 1, "{id} должен дать находку");
        }
    }

    #[test]
    fn ordinary_error_is_distinguished_from_panic() {
        // T59 (негатив): обычная ошибка capability не маркируется как паника.
        let mut reg = Registry::new();
        reg.register(Box::new(Failer {
            manifest: manifest("fail", false),
        }));
        let pipeline = Pipeline {
            name: "t".into(),
            steps: vec![Step::of("fail")],
        };
        let res = PipelineEngine::execute(&reg, &ctx(), &RunInput::default(), &pipeline);
        let e = res[0].error.as_deref().unwrap_or("");
        assert!(e.contains("обычная ошибка"), "ожидали обычную ошибку: {e}");
        assert!(
            !e.contains("паниковал"),
            "не должно быть пометки паники: {e}"
        );
    }

    #[test]
    fn missing_capability_reported() {
        let reg = Registry::new();
        let pipeline = Pipeline {
            name: "t".into(),
            steps: vec![Step::of("нет.такого")],
        };
        let res = PipelineEngine::execute(&reg, &ctx(), &RunInput::default(), &pipeline);
        assert_eq!(res.len(), 1);
        assert!(res[0]
            .error
            .as_deref()
            .unwrap_or("")
            .contains("нет capability"));
    }

    #[test]
    fn cyclic_deps_reported_not_hung() {
        // Шаги с взаимной зависимостью не вешают движок, а помечаются ошибкой.
        let mut reg = Registry::new();
        reg.register(Box::new(Ok1 {
            manifest: manifest("a", false),
        }));
        reg.register(Box::new(Ok1 {
            manifest: manifest("b", false),
        }));
        let pipeline = Pipeline {
            name: "t".into(),
            steps: vec![
                Step::with_deps("a", vec!["b".into()]),
                Step::with_deps("b", vec!["a".into()]),
            ],
        };
        let res = PipelineEngine::execute(&reg, &ctx(), &RunInput::default(), &pipeline);
        assert_eq!(res.len(), 2);
        for r in &res {
            assert!(r
                .error
                .as_deref()
                .unwrap_or("")
                .contains("неразрешимые зависимости"));
        }
    }

    #[test]
    fn explicit_deps_respected() {
        // Явные deps: зависимый шаг видит результат предшественника как «выполнено».
        let mut reg = Registry::new();
        reg.register(Box::new(Ok1 {
            manifest: manifest("first", false),
        }));
        reg.register(Box::new(Ok1 {
            manifest: manifest("second", false),
        }));
        let pipeline = Pipeline {
            name: "t".into(),
            steps: vec![
                Step::with_deps("second", vec!["first".into()]),
                Step::of("first"),
            ],
        };
        let res = PipelineEngine::execute(&reg, &ctx(), &RunInput::default(), &pipeline);
        assert_eq!(res.len(), 2);
        assert!(res.iter().all(|r| r.error.is_none()));
    }

    /// РЕГРЕССИЯ. Шаг со сбоем не попадает в «выполненные», а его зависимые не
    /// запускаются поверх отсутствующего результата: они получают ЯВНЫЙ пропуск с
    /// причиной, причём транзитивно по цепочке зависимостей.
    #[test]
    fn зависимые_от_сбойного_шага_пропускаются_с_причиной() {
        let mut reg = Registry::new();
        reg.register(Box::new(Failer {
            manifest: manifest("база", false),
        }));
        reg.register(Box::new(Ok1 {
            manifest: manifest("зависимый", false),
        }));
        reg.register(Box::new(Ok1 {
            manifest: manifest("внук", false),
        }));
        reg.register(Box::new(Ok1 {
            manifest: manifest("независимый", false),
        }));
        let pipeline = Pipeline {
            name: "t".into(),
            steps: vec![
                Step::of("база"),
                Step::with_deps("зависимый", vec!["база".into()]),
                Step::with_deps("внук", vec!["зависимый".into()]),
                Step::of("независимый"),
            ],
        };
        let res = PipelineEngine::execute(&reg, &ctx(), &RunInput::default(), &pipeline);
        assert_eq!(res.len(), 4, "результат есть по каждому шагу");
        let by = |id: &str| res.iter().find(|r| r.step == id).unwrap();
        assert!(by("база").error.is_some(), "базовый шаг провалился");
        let dep = by("зависимый").error.clone().unwrap_or_default();
        assert!(
            dep.contains("пропущен") && dep.contains("база"),
            "зависимый шаг пропущен с указанием причины: {dep}"
        );
        let grand = by("внук").error.clone().unwrap_or_default();
        assert!(
            grand.contains("пропущен"),
            "пропуск транзитивен по цепочке: {grand}"
        );
        assert!(
            by("независимый").error.is_none(),
            "независимый шаг выполняется штатно"
        );
    }

    /// ЗАКРЕПЛЕНИЕ ФАКТИЧЕСКОГО ПОВЕДЕНИЯ, заявленного в документации модуля. Там прямо
    /// сказано, что явные зависимости движком поддержаны, но ни одно рабочее место их не
    /// задаёт, а значит продуктовый пайплайн из немутирующих проверок вырождается в одну
    /// параллельную волну. Утверждение документации должно быть измеримым, поэтому тест
    /// сравнивает фактическое число волн с ожидаемым и заодно показывает, что эта величина
    /// действительно различает режимы: явные зависимости и присутствие мутатора дают
    /// больше одной волны.
    #[test]
    fn шаги_без_зависимостей_исполняются_одной_волной() {
        let mut reg = Registry::new();
        for id in ["одна", "вторая", "третья"] {
            reg.register(Box::new(Ok1 {
                manifest: manifest(id, false),
            }));
        }
        // Мутирующая capability для контрольного сравнения: сама по себе она ничего не
        // пишет, важен лишь признак `mutates` в манифесте, по которому движок разводит
        // мутаторов и читателей по разным волнам.
        reg.register(Box::new(Ok1 {
            manifest: manifest("мутатор", true),
        }));

        // Основной случай: ровно то, что строят orchestrator.rs и agent.rs, то есть шаги
        // через `Step::of` без единой зависимости.
        let plain = Pipeline {
            name: "как в продукте".into(),
            steps: vec![Step::of("одна"), Step::of("вторая"), Step::of("третья")],
        };
        let (res, waves) = PipelineEngine::execute_counting_waves(
            &reg,
            &ctx(),
            &RunInput::default(),
            &plain,
            STEP_TIMEOUT,
        );
        assert_eq!(res.len(), 3, "результат есть по каждому шагу");
        assert!(
            res.iter().all(|r| r.error.is_none()),
            "ошибок быть не должно"
        );
        assert_eq!(
            waves, 1,
            "шаги без явных зависимостей и без мутаторов обязаны исполниться одной волной"
        );

        // Контроль первый: явные зависимости всё ещё работают и дают две волны, то есть
        // измеряемая величина не является константой.
        let chained = Pipeline {
            name: "с явными зависимостями".into(),
            steps: vec![
                Step::with_deps("вторая", vec!["одна".into()]),
                Step::of("одна"),
            ],
        };
        let (_, waves_chained) = PipelineEngine::execute_counting_waves(
            &reg,
            &ctx(),
            &RunInput::default(),
            &chained,
            STEP_TIMEOUT,
        );
        assert_eq!(
            waves_chained, 2,
            "явно заданная зависимость обязана развести шаги по двум волнам"
        );

        // Контроль второй: неявная сериализация мутаторов действует и при пустых deps,
        // поэтому единственной волной такой набор не обходится.
        let with_mutator = Pipeline {
            name: "с мутатором".into(),
            steps: vec![Step::of("одна"), Step::of("мутатор"), Step::of("вторая")],
        };
        let (_, waves_mut) = PipelineEngine::execute_counting_waves(
            &reg,
            &ctx(),
            &RunInput::default(),
            &with_mutator,
            STEP_TIMEOUT,
        );
        assert_eq!(
            waves_mut, 2,
            "мутатор обязан идти отдельной волной, а читатели следующей"
        );
    }

    #[test]
    fn mutator_never_shares_wave_with_readers() {
        // T74: даже когда deps пусты (Step::of), мутатор не идёт в одной волне с
        // читателями. Читатель не должен застать мутатора работающим и должен видеть
        // его уже завершившимся (записанный снимок готов к чтению).
        MUT_RUNNING.store(0, AtOrd::SeqCst);
        READER_SAW_MUT.store(0, AtOrd::SeqCst);
        MUT_DONE_BEFORE_READER.store(0, AtOrd::SeqCst);
        MUT_FINISHED.store(false, AtOrd::SeqCst);

        let mut reg = Registry::new();
        reg.register(Box::new(Mutator {
            manifest: manifest("gen.baseline", true),
        }));
        reg.register(Box::new(Reader {
            manifest: manifest("verify.r1", false),
        }));
        reg.register(Box::new(Reader {
            manifest: manifest("verify.r2", false),
        }));

        let pipeline = Pipeline {
            name: "t".into(),
            steps: vec![
                Step::of("verify.r1"),
                Step::of("gen.baseline"),
                Step::of("verify.r2"),
            ],
        };
        let res = PipelineEngine::execute(&reg, &ctx(), &RunInput::default(), &pipeline);
        assert_eq!(res.len(), 3);
        assert!(
            res.iter().all(|r| r.error.is_none()),
            "ошибок быть не должно"
        );

        assert_eq!(
            READER_SAW_MUT.load(AtOrd::SeqCst),
            0,
            "ни один читатель не должен застать мутатора работающим (гонка на снимке)"
        );
        assert_eq!(
            MUT_DONE_BEFORE_READER.load(AtOrd::SeqCst),
            2,
            "оба читателя должны стартовать ПОСЛЕ завершения мутатора"
        );
    }

    #[test]
    fn semaphore_caps_concurrency() {
        // T61: семафор не выпускает в работу больше потоков, чем выдано пропусков.
        let sem = Semaphore::new(2);
        sem.acquire();
        sem.acquire();
        // Третий acquire должен блокироваться, пока не будет release. Проверяем через
        // отдельный поток с таймаутом ожидания.
        let sem2 = Arc::new(sem);
        let s3 = Arc::clone(&sem2);
        let (tx, rx) = mpsc::channel();
        let h = std::thread::spawn(move || {
            s3.acquire();
            let _ = tx.send(());
        });
        // Пропусков нет: третий поток ещё не должен пройти.
        assert!(
            rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "при исчерпанных пропусках acquire обязан блокироваться"
        );
        // Освобождаем один пропуск: теперь третий поток проходит.
        sem2.release();
        assert!(
            rx.recv_timeout(Duration::from_millis(500)).is_ok(),
            "после release ожидающий acquire обязан пройти"
        );
        let _ = h.join();
    }

    /// Capability, которая держит поток заметно дольше, чем длится тест: изображает
    /// зависший детектор, не опрашивающий флаг отмены.
    struct Hanger {
        manifest: CapabilityManifest,
    }
    impl Capability for Hanger {
        fn manifest(&self) -> &CapabilityManifest {
            &self.manifest
        }
        fn run(&self, _ctx: &Ctx, _input: &RunInput) -> Result<CapabilityOutput> {
            std::thread::sleep(Duration::from_secs(30));
            Ok(CapabilityOutput::default())
        }
    }

    /// РЕГРЕССИЯ на устранённое зависание. Шагов в волне заведомо больше, чем пропусков
    /// семафора, и все они зависают. Прежде главный поток блокировался на захвате пропуска
    /// БЕЗ таймаута: пропусков не возвращал никто, потоки отсоединены и не прерываются,
    /// поэтому прогон вставал навсегда. Теперь ожидание места происходит в рабочих потоках,
    /// главный поток ограничен бюджетом волны и обязан вернуться.
    ///
    /// Тест проверяет именно ВОЗВРАТ управления, а не время: он завершается, только если
    /// зависания нет. Результаты шагов при этом суть ошибки, и это правильно.
    #[test]
    fn зависшие_шаги_не_блокируют_главный_поток_навсегда() {
        let mut reg = Registry::new();
        let permits = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        // Вдвое больше зависающих шагов, чем пропусков, плюс запас.
        let count = permits * 2 + 2;
        let ids: Vec<String> = (0..count).map(|i| format!("hang.{i}")).collect();
        for id in &ids {
            let leaked: &'static str = Box::leak(id.clone().into_boxed_str());
            reg.register(Box::new(Hanger {
                manifest: manifest(leaked, false),
            }));
        }
        let steps: Vec<Step> = ids.iter().map(|id| Step::of(id)).collect();
        let pipeline = Pipeline {
            name: "тест зависаний".to_string(),
            steps,
        };

        // Короткий бюджет волны: тест обязан проверять ПОВЕДЕНИЕ, а не ждать продуктовые
        // три минуты. Ключевое утверждение здесь одно: управление возвращается. При прежнем
        // порядке захвата пропуска этот вызов не вернулся бы никогда, и тест завис бы.
        let budget = Duration::from_secs(1);
        let started = Instant::now();
        let results = PipelineEngine::execute_with_timeout(
            &reg,
            &ctx(),
            &RunInput::default(),
            &pipeline,
            budget,
        );
        assert_eq!(results.len(), count, "результат есть по каждому шагу");
        assert!(
            results.iter().all(|r| r.error.is_some()),
            "зависшие шаги дают ошибку, а не молчаливый чистый результат: {:?}",
            results.iter().map(|r| r.error.clone()).collect::<Vec<_>>()
        );
        // Шаг, не получивший места, не должен утверждать, что «превысил лимит времени»:
        // он не выполнил ни одной инструкции, и об этом сообщается отдельной формулировкой.
        assert!(
            results.iter().any(|r| r
                .error
                .as_deref()
                .is_some_and(|e| e.contains("не запускался"))),
            "неначавшиеся шаги сообщаются честно: {:?}",
            results.iter().map(|r| r.error.clone()).collect::<Vec<_>>()
        );
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "прогон уложился в бюджет волны с запасом, а не завис: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn cancellation_flag_false_outside_pipeline() {
        // T60: вне рабочего потока пайплайна опрос флага безопасен и даёт «не отменено».
        assert!(!cancellation_requested());
    }

    #[test]
    fn cancellation_flag_visible_inside_worker() {
        // T60: внутри области with_cancel опрос видит общий флаг отмены.
        let flag = Arc::new(AtomicBool::new(false));
        with_cancel(&flag, || {
            assert!(!cancellation_requested(), "сначала отмены нет");
            flag.store(true, Ordering::Relaxed);
            assert!(
                cancellation_requested(),
                "после поднятия флага видна отмена"
            );
        });
        // После выхода из области указатель снят: опрос снова даёт false.
        assert!(!cancellation_requested());
    }
}
