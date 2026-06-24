//! Движок пайплайна: шаги-как-данные плюс направленный ациклический граф (DAG) плюс
//! параллелизм на чистом std.
//!
//! Пайплайн описывается ДАННЫМИ (список шагов с зависимостями), а не зашит в код.
//! Исполнение идёт «волнами»: на каждой волне параллельно запускаются все шаги, чьи
//! зависимости уже выполнены, поэтому независимые проверки идут одновременно, а
//! зависимые: после своих предшественников.
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
//! Ширина волны ОГРАНИЧЕНА: одновременно исполняется не больше потоков, чем выдаёт
//! std::thread::available_parallelism (число доступных ядер). Это исключает спавн
//! десятков тяжёлых capability разом, каждая из которых независимо держит в памяти своё
//! дерево/индекс; остальные готовые шаги ждут освобождения «пропуска» (семафор на
//! Mutex плюс Condvar, чистый std, без внешних зависимостей).
//!
//! Планировщик (см. orchestrator::Planner) лишь СОБИРАЕТ Pipeline под намерение; сюда
//! позже встанет LLM-планировщик, не меняя движок исполнения.

use crate::registry::Registry;
use ailc_contracts::{CapabilityOutput, Ctx, RunInput};
use std::cell::Cell;
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
    static CANCEL: Cell<Option<*const AtomicBool>> = const { Cell::new(None) };
}

/// Опросить кооперативный флаг отмены текущего шага. Возвращает `true`, если пайплайн
/// попросил досрочно завершить текущую capability (наступил общий дедлайн волны). Долгие
/// движки (например обход файлов) должны вызывать это между единицами работы и при `true`
/// аккуратно прекращать работу, выставляя `skipped`/частичный результат, вместо того
/// чтобы вхолостую дорабатывать обход уже «просроченного» шага. Вне рабочего потока
/// пайплайна всегда возвращает `false`, поэтому безопасно вызывать из любого кода.
///
/// БЕЗОПАСНОСТЬ. Хранимый указатель действителен ровно на время жизни рабочего потока.
/// Флаг отмены живёт в куче внутри `Arc<AtomicBool>`; каждый рабочий поток держит
/// собственный клон этого `Arc` на всё время исполнения шага (поле `cancel2` в замыкании
/// потока). Поэтому, даже если пайплайн по таймауту шага идёт дальше и роняет свой клон
/// `Arc`, аллокация остаётся жива до конца рабочего потока, а указатель в его thread-local
/// остаётся валидным. Указатель снимается (`None`) гарантированно до возврата из тела
/// потока (см. guard в `with_cancel`), поэтому разыменование всегда происходит при живой
/// аллокации.
pub fn cancellation_requested() -> bool {
    CANCEL.with(|c| match c.get() {
        // SAFETY: указатель установлен пайплайном на `AtomicBool`, живущий не короче
        // рабочего потока (его держит клон `Arc` в этом же потоке, см. контракт выше).
        // Снимается (`None`) до завершения потока.
        Some(ptr) => unsafe { (*ptr).load(Ordering::Relaxed) },
        None => false,
    })
}

/// Установить указатель на флаг отмены для текущего потока на время вызова `f`, а после
/// гарантированно снять его. Гарантия снятия (через guard, срабатывающий и при панике
/// внутри `f`) не даёт «висячему» указателю пережить рабочий поток.
fn with_cancel<R>(flag: &Arc<AtomicBool>, f: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CANCEL.with(|c| c.set(None));
        }
    }
    let ptr: *const AtomicBool = Arc::as_ptr(flag);
    CANCEL.with(|c| c.set(Some(ptr)));
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
    pub fn execute(
        reg: &Registry,
        ctx: &Ctx,
        input: &RunInput,
        pipeline: &Pipeline,
    ) -> Vec<StepResult> {
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
            reg.get(cap_id).map(|c| c.manifest().mutates).unwrap_or(false)
        };

        let mut done: HashSet<String> = HashSet::new();
        let mut results: Vec<StepResult> = Vec::new();
        let mut remaining: Vec<&Step> = pipeline.steps.iter().collect();

        while !remaining.is_empty() {
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

            // Волна: готовые шаги параллельно, но не шире числа ядер (семафор) и каждый
            // в отсоединённом потоке с общим дедлайном и кооперативным флагом отмены.
            let deadline = Instant::now() + STEP_TIMEOUT;
            // Кооперативная отмена волны: атомарный флаг (его опрашивают capability) плюс
            // Condvar, чтобы СТОРОЖ мог проснуться досрочно, как только волна собрана, и
            // НЕ держать поток спящим до самого дедлайна (иначе join сторожа завис бы на
            // весь STEP_TIMEOUT даже после быстрой волны).
            let cancel = Arc::new(AtomicBool::new(false));
            let wave_finished = Arc::new((Mutex::new(false), Condvar::new()));
            let mut pending = Vec::with_capacity(this_wave.len());
            for &s in &this_wave {
                let slot = match reg.get_arc(&s.capability) {
                    None => Err(format!("нет capability `{}`", s.capability)),
                    Some(cap) => {
                        let (tx, rx) = mpsc::channel();
                        let (ctx2, input2) = (ctx.clone(), input.clone());
                        let sem2 = Arc::clone(&sem);
                        let cancel2 = Arc::clone(&cancel);
                        // Захватываем пропуск ДО спавна: число живых рабочих потоков не
                        // превышает число ядер; лишние готовые шаги ждут здесь.
                        sem2.acquire();
                        std::thread::spawn(move || {
                            // Гарантируем возврат пропуска и при панике (catch_unwind ниже
                            // её ловит, но страхуемся guard-ом на случай иных путей).
                            struct Permit(Arc<Semaphore>);
                            impl Drop for Permit {
                                fn drop(&mut self) {
                                    self.0.release();
                                }
                            }
                            let _permit = Permit(sem2);
                            // T59: ловим панику шага, чтобы один упавший детектор не ронял
                            // процесс, а превращался в ошибку шага. Отдаём Result, явно
                            // отличающий панику от обычной ошибки capability.
                            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                                || with_cancel(&cancel2, || cap.run(&ctx2, &input2)),
                            ));
                            let _ = tx.send(outcome);
                        });
                        Ok(rx)
                    }
                };
                pending.push((s, slot));
            }

            // Сторож дедлайна (T60): ждёт ЛИБО наступления общего дедлайна волны, ЛИБО
            // сигнала «волна собрана» (через Condvar). По дедлайну поднимает кооперативный
            // флаг отмены, чтобы опрашивающие его capability могли досрочно завершиться, не
            // дожидаясь конца обхода уже «просроченного» шага. По раннему сигналу выходит
            // сразу, поэтому его join не блокирует пайплайн на весь STEP_TIMEOUT.
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

            let wave: Vec<StepResult> = pending
                .into_iter()
                .map(|(s, slot)| {
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
                                    res.error = Some(format!(
                                        "шаг превысил лимит времени ({}с)",
                                        STEP_TIMEOUT.as_secs()
                                    ));
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

            for r in &wave {
                done.insert(r.step.clone());
            }
            results.extend(wave);

            // Отложенные на следующие волны (мутаторы/читатели) плюс ещё не готовые.
            remaining = deferred.into_iter().chain(not_ready).collect();
        }

        results
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
    use ailc_contracts::{
        CapabilityManifest, EngineKind, Family, Finding, Result, Severity, Tier,
    };
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
        assert!(!e.contains("паниковал"), "не должно быть пометки паники: {e}");
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
        assert!(res.iter().all(|r| r.error.is_none()), "ошибок быть не должно");

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
            assert!(cancellation_requested(), "после поднятия флага видна отмена");
        });
        // После выхода из области указатель снят: опрос снова даёт false.
        assert!(!cancellation_requested());
    }
}
