//! Сборочный шаг: сжатие снимка базы уязвимостей.
//!
//! Снимок хранится в репозитории построчным текстом (`assets/osv/snapshot.tsv`), потому
//! что он обновляется регулярно и текстовый формат с устойчивым порядком даёт системе
//! контроля версий маленькие разностные объекты. В бинарь же встраивать девять с лишним
//! мегабайт текста расточительно, поэтому здесь он сжимается один раз при сборке, и
//! бинарь несёт около полутора мегабайт, распаковывая их лениво при первой проверке
//! зависимостей.

use std::io::Write;
use std::path::Path;

fn main() {
    let src = Path::new("assets/osv/snapshot.tsv");
    println!("cargo:rerun-if-changed={}", src.display());

    let raw = std::fs::read(src).unwrap_or_else(|e| {
        panic!(
            "снимок базы уязвимостей {} не читается: {e}. Пересоберите его командой \
             `python3 tools/update-osv.py`",
            src.display()
        )
    });

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR задаётся сборочной системой");
    let dst = Path::new(&out_dir).join("snapshot.tsv.gz");

    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(&raw).expect("сжатие снимка не должно падать");
    let packed = enc.finish().expect("завершение сжатия не должно падать");
    std::fs::write(&dst, packed).expect("запись сжатого снимка в OUT_DIR");
}
