//! Замер времени исполнения проверок.
//!
//! Включается переменной окружения `AILC_TIMINGS`. Пока она не задана, [`record`] ничего
//! не делает и не захватывает замок, поэтому в обычном прогоне замер не стоит ничего.
//! При включённом замере каждая точка исполнения capability (гейт и прямой прогон осей
//! в Definition of Done) сообщает длительность, а вызывающий забирает накопленное через
//! [`take`] и печатает таблицу. Длительность меряется со стороны вызывающего, то есть
//! включает ожидание отсоединённого потока: для тяжёлого анализа, превысившего бюджет,
//! в таблицу попадает именно время, на которое он задержал вердикт.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Одна запись замера.
#[derive(Debug, Clone)]
pub struct Timing {
    /// Где исполнялась проверка (например «гейт» или «прямая ось»), либо «фаза».
    pub phase: &'static str,
    pub id: String,
    pub elapsed: Duration,
}

static TIMINGS: Mutex<Vec<Timing>> = Mutex::new(Vec::new());

/// Включён ли замер.
pub fn enabled() -> bool {
    crate::env::is_set("AILC_TIMINGS")
}

/// Записать длительность. Вне режима замера ничего не делает.
pub fn record(phase: &'static str, id: &str, elapsed: Duration) {
    if !enabled() {
        return;
    }
    TIMINGS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(Timing {
            phase,
            id: id.to_string(),
            elapsed,
        });
}

/// Исполнить `f` и записать его длительность.
pub fn measure<T>(phase: &'static str, id: &str, f: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let out = f();
    record(phase, id, started.elapsed());
    out
}

/// Забрать накопленные замеры, отсортированные по убыванию длительности.
pub fn take() -> Vec<Timing> {
    let mut v = std::mem::take(&mut *TIMINGS.lock().unwrap_or_else(|e| e.into_inner()));
    v.sort_by(|a, b| b.elapsed.cmp(&a.elapsed));
    v
}
