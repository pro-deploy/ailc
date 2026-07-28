//! Паспорт проекта — детерминированное «что перед нами», без LLM и без вопросов.
//!
//! По манифестам, расширениям и дешёвым признакам содержимого профиль определяет:
//! стек, есть ли интерфейс, мобильная часть, признаки персональных данных, русскоязычная
//! ли кодовая база (вероятная юрисдикция РФ) и есть ли обращения к LLM. От паспорта
//! зависят умолчания: какие семейства гнать без указаний и какие оси Definition of Done
//! считать жёсткими. Человек ничего не настраивает; паспорт виден в `.ailc/profile.md`.
//!
//! Обход ограничен по числу файлов и объёму чтения: паспорт обязан быть дешёвым,
//! чтобы вычисляться на каждый прогон без кэша и не устаревать.

use crate::engines::generator::Generator;
use crate::engines::walk;
use crate::stack;
use ailc_contracts::Ctx;
use std::path::Path;

/// Сколько файлов максимум сканируем по содержимому (дешевизна паспорта важнее полноты:
/// глубокую правду дают сами сканеры, паспорт лишь включает уместные).
const MAX_CONTENT_FILES: usize = 240;
/// Сколько байт читаем из файла для признаков содержимого.
const MAX_READ: usize = 64 * 1024;

/// Детерминированный паспорт проекта.
#[derive(Debug, Default, Clone)]
pub struct ProjectProfile {
    /// Метки стека по манифестам (`stack::detect`).
    pub stacks: Vec<&'static str>,
    /// Есть пользовательский интерфейс (веб-разметка, фронтенд-компоненты, мобильные экраны).
    pub has_ui: bool,
    /// Есть мобильная часть (Flutter, Android, iOS).
    pub has_mobile: bool,
    /// Признаки работы с персональными данными (паспорт, СНИЛС, ИНН, ПДн-поля).
    pub has_pdn: bool,
    /// Русскоязычная кодовая база или документация: вероятна юрисдикция РФ.
    pub ru_locale: bool,
    /// Обращения к нейросетям (LLM-SDK в зависимостях или вызовы в коде).
    pub has_llm: bool,
}

impl ProjectProfile {
    /// Семейства, которые стоит гнать по умолчанию СВЕРХ базового набора
    /// (Security+Quality+Spec). Отдаём строками осей политики: Compliance при признаках
    /// РФ и ПДн (иначе комплаенс-шум на нерелевантных проектах).
    pub fn extra_families(&self) -> Vec<ailc_contracts::Family> {
        let mut fams = Vec::new();
        if self.ru_locale && self.has_pdn {
            fams.push(ailc_contracts::Family::Compliance);
        }
        fams
    }

    /// Однострочная сводка для журналов и вердикта.
    pub fn summary(&self) -> String {
        let mut tags: Vec<&str> = Vec::new();
        if self.has_ui {
            tags.push("UI");
        }
        if self.has_mobile {
            tags.push("mobile");
        }
        if self.has_pdn {
            tags.push("ПДн");
        }
        if self.ru_locale {
            tags.push("RU");
        }
        if self.has_llm {
            tags.push("LLM");
        }
        format!(
            "стек: {} · признаки: {}",
            if self.stacks.is_empty() {
                "не распознан".to_string()
            } else {
                self.stacks.join(", ")
            },
            if tags.is_empty() {
                "нет".to_string()
            } else {
                tags.join(", ")
            }
        )
    }
}

/// Построить паспорт проекта. Дёшево и детерминированно: манифесты, расширения,
/// ограниченный по числу файлов и объёму скан содержимого.
pub fn detect(root: &Path) -> ProjectProfile {
    let mut p = ProjectProfile {
        stacks: stack::detect(root),
        ..Default::default()
    };

    // Мобильная часть по манифестам.
    p.has_mobile = root.join("pubspec.yaml").exists()
        || root.join("android/app").is_dir()
        || root.join("ios").is_dir() && root.join("Podfile").exists()
        || stack::has_ext(root, &[".xcodeproj"]);

    // LLM по зависимостям: дешёвый и надёжный признак (SDK в манифесте).
    p.has_llm = manifest_mentions(
        root,
        &[
            "anthropic",
            "openai",
            "langchain",
            "llama",
            "ollama",
            "mistralai",
            "google-generativeai",
            "genai",
            "cohere",
        ],
    );

    // Признаки по файлам: расширения UI и содержимое (кириллица, ПДн, LLM-вызовы).
    let mut scanned = 0usize;
    let _ = walk::walk(root, &mut |path: &Path| {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        match ext.as_str() {
            "html" | "htm" | "jsx" | "tsx" | "vue" | "svelte" | "storyboard" | "xib" => {
                p.has_ui = true
            }
            "xml" if path.to_string_lossy().contains("res/layout") => p.has_ui = true,
            _ => {}
        }
        // Содержимое смотрим только у исходников и доков, ограниченно по числу и объёму.
        let content_ext = matches!(
            ext.as_str(),
            "md" | "rs"
                | "py"
                | "js"
                | "ts"
                | "tsx"
                | "jsx"
                | "go"
                | "java"
                | "kt"
                | "rb"
                | "php"
                | "cs"
                | "swift"
                | "dart"
                | "scala"
                | "c"
                | "cpp"
                | "h"
                | "sql"
                | "html"
                | "vue"
                | "svelte"
        );
        if !content_ext || scanned >= MAX_CONTENT_FILES {
            return;
        }
        scanned += 1;
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let slice = &bytes[..bytes.len().min(MAX_READ)];
        let text = String::from_utf8_lossy(slice);
        // Русскоязычность проекта определяется не единственной кириллической буквой, а
        // заметным объёмом кириллицы: одно случайное слово в комментарии не должно
        // включать профильные оси комплаенса на нерелевантном проекте.
        if !p.ru_locale && cyrillic_count(&text, MIN_CYRILLIC) >= MIN_CYRILLIC {
            p.ru_locale = true;
        }
        if !p.has_pdn && has_pdn_marker(&text) {
            p.has_pdn = true;
        }
        if !p.has_llm && has_llm_call(&text) {
            p.has_llm = true;
        }
    });

    if p.has_mobile {
        p.has_ui = true;
    }
    p
}

/// Сколько кириллических букв в просмотренной части файла считается признаком
/// русскоязычного проекта. Порог отсекает единичное русское слово в комментарии и при
/// этом заведомо перекрывается любым реальным русским текстом (одна фраза длиннее).
const MIN_CYRILLIC: usize = 60;

/// Число кириллических букв в первых 20 000 символах текста; подсчёт прекращается по
/// достижении `limit`, поэтому стоимость ограничена.
fn cyrillic_count(text: &str, limit: usize) -> usize {
    let mut n = 0usize;
    for c in text.chars().take(20_000) {
        if ('а'..='я').contains(&c.to_lowercase().next().unwrap_or(c)) || c == 'ё' || c == 'Ё' {
            n += 1;
            if n >= limit {
                return n;
            }
        }
    }
    n
}

/// Однозначные маркеры персональных данных: встречаются только в соответствующем
/// смысле, поэтому ищутся как подстрока.
const PDN_EXACT: &[&str] = &[
    "снилс",
    "passport_number",
    "passport_series",
    "personal_data",
    "person_data",
    "birth_date",
    "date_of_birth",
    "персональные данные",
    "персональных данных",
    "паспортные данные",
    "паспортных данных",
    "номер паспорта",
    "серия паспорта",
];

/// Многозначные маркеры: ищутся ТОЛЬКО как отдельные слова. Подстрочный поиск здесь
/// недопустим, поскольку сочетание «инн» входит в обычные слова («длинный»,
/// «старинный», «инновация»), а слово «паспорт» вне сочетания с данными означает в том
/// числе паспорт проекта, и подстрочный поиск объявлял бы обработкой персональных
/// данных проекты, которые к ним отношения не имеют.
const PDN_WORDS: &[&str] = &["инн", "снилс", "snils", "inn"];

/// Признаки персональных данных в тексте файла (поля и термины, по которым работает
/// и семейство compliance.ru; здесь только дешёвый сигнал «тема присутствует»).
fn has_pdn_marker(text: &str) -> bool {
    let lower = text.to_lowercase();
    if PDN_EXACT.iter().any(|m| lower.contains(m)) {
        return true;
    }
    PDN_WORDS.iter().any(|w| contains_word(&lower, w))
}

/// Входит ли `word` в `text` как отдельное слово. Границей слова считается любой символ,
/// не являющийся буквой, цифрой или знаком подчёркивания; учитываются в том числе
/// кириллические буквы, поэтому «инн» не совпадает внутри слова «инновация».
fn contains_word(text: &str, word: &str) -> bool {
    let is_part = |c: char| c.is_alphanumeric() || c == '_';
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(word) {
        let start = from + rel;
        let end = start + word.len();
        let before_ok = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_part(c));
        let after_ok = text[end..].chars().next().is_none_or(|c| !is_part(c));
        if before_ok && after_ok {
            return true;
        }
        // Сдвигаемся на один символ вперёд, сохраняя корректность границ UTF-8.
        from = start + text[start..].chars().next().map_or(1, char::len_utf8);
        if from >= text.len() {
            break;
        }
    }
    false
}

/// Признак обращения к LLM в коде (когда SDK не виден в манифесте: прямые HTTP-вызовы).
fn has_llm_call(text: &str) -> bool {
    [
        "api.openai.com",
        "api.anthropic.com",
        "chat/completions",
        "createMessage",
        "generativelanguage.googleapis",
    ]
    .iter()
    .any(|m| text.contains(m))
}

/// Упомянут ли любой из маркеров в манифестах зависимостей корня.
fn manifest_mentions(root: &Path, markers: &[&str]) -> bool {
    const MANIFESTS: &[&str] = &[
        "package.json",
        "requirements.txt",
        "pyproject.toml",
        "Cargo.toml",
        "go.mod",
        "composer.json",
        "Gemfile",
        "build.gradle",
        "pubspec.yaml",
    ];
    for m in MANIFESTS {
        if let Ok(text) = std::fs::read_to_string(root.join(m)) {
            let lower = text.to_lowercase();
            if markers.iter().any(|k| lower.contains(k)) {
                return true;
            }
        }
    }
    false
}

/// Идемпотентно записать паспорт в `.ailc/profile.md` (управляемый авто-блок; ручные
/// приписки человека вне блока сохраняются). Возвращает свежий профиль.
pub fn ensure(ctx: &Ctx) -> ProjectProfile {
    let p = detect(&ctx.root);
    let yes = |b: bool| if b { "да" } else { "нет" };
    let content = format!(
        "# Паспорт проекта\n\n\
         Автоматически определён AILC; от него зависят умолчания проверок и жёсткость\n\
         осей вердикта. Пересчитывается сам, править не нужно.\n\n\
         - Стек: {}\n\
         - Интерфейс (UI): {}\n\
         - Мобильная часть: {}\n\
         - Признаки персональных данных: {}\n\
         - Русскоязычная база (юрисдикция РФ вероятна): {}\n\
         - Обращения к нейросетям (LLM): {}\n",
        if p.stacks.is_empty() {
            "не распознан".to_string()
        } else {
            p.stacks.join(", ")
        },
        yes(p.has_ui),
        yes(p.has_mobile),
        yes(p.has_pdn),
        yes(p.ru_locale),
        yes(p.has_llm),
    );
    let _ = Generator::write_block(ctx, ".ailc/profile.md", "profile", &content);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ailc-profile-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ui_detected_by_markup() {
        let d = tmp("ui");
        std::fs::write(d.join("index.html"), "<html></html>").unwrap();
        let p = detect(&d);
        assert!(p.has_ui);
        assert!(!p.has_llm);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn llm_detected_by_manifest_and_ru_pdn_by_content() {
        let d = tmp("llm");
        std::fs::write(
            d.join("package.json"),
            r#"{ "dependencies": { "@anthropic-ai/sdk": "^1.0.0" } }"#,
        )
        .unwrap();
        std::fs::write(
            d.join("main.py"),
            "# Проверка СНИЛС клиента перед сохранением анкеты в базу данных.\n\
             # Значение приходит из формы регистрации и подлежит маскированию в журнале.\n",
        )
        .unwrap();
        let p = detect(&d);
        assert!(p.has_llm);
        assert!(p.ru_locale);
        assert!(p.has_pdn);
        assert_eq!(p.extra_families(), vec![ailc_contracts::Family::Compliance]);
        std::fs::remove_dir_all(&d).ok();
    }

    /// T-09: слова «старинный» и «инновация» содержат сочетание «инн», но признаком
    /// обработки персональных данных не являются.
    #[test]
    fn inn_inside_ordinary_words_is_not_pdn() {
        assert!(!has_pdn_marker(
            "Длинный старинный алгоритм, инновация в вычислениях. Невинный комментарий."
        ));
        assert!(has_pdn_marker("поле inn заполняется из анкеты"));
        assert!(has_pdn_marker("ИНН: 7701234567"));
        assert!(has_pdn_marker("значение passport_number маскируется"));
    }

    /// T-09: паспорт проекта не превращает проект в обработчика персональных данных.
    #[test]
    fn project_passport_is_not_personal_data() {
        assert!(!has_pdn_marker(
            "Паспорт проекта определяется автоматически и хранится в .ailc/profile.md"
        ));
        assert!(has_pdn_marker(
            "серия паспорта и номер паспорта не логируются"
        ));
    }

    /// T-10: единственное русское слово не делает проект русскоязычным.
    #[test]
    fn single_russian_word_is_not_ru_locale() {
        let d = tmp("ru-thin");
        std::fs::write(d.join("a.rs"), "// хак\nfn main() {}\n").unwrap();
        assert!(!detect(&d).ru_locale);
        std::fs::remove_dir_all(&d).ok();

        let d = tmp("ru-full");
        std::fs::write(
            d.join("a.rs"),
            "// Этот модуль отвечает за разбор входящих сообщений и проверку подписи.\n\
             // Ошибки разбора возвращаются вызывающему коду без паники.\nfn main() {}\n",
        )
        .unwrap();
        assert!(detect(&d).ru_locale);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn profile_written_idempotently() {
        let d = tmp("idem");
        std::fs::create_dir_all(d.join(".ailc")).unwrap();
        std::fs::write(d.join("index.html"), "<html></html>").unwrap();
        let ctx = Ctx::new(d.to_str().unwrap());
        let p1 = ensure(&ctx);
        let first = std::fs::read_to_string(d.join(".ailc/profile.md")).unwrap();
        let _p2 = ensure(&ctx);
        let second = std::fs::read_to_string(d.join(".ailc/profile.md")).unwrap();
        assert!(p1.has_ui);
        assert_eq!(first, second, "повторная запись не меняет файл");
        assert!(first.contains("Интерфейс (UI): да"));
        std::fs::remove_dir_all(&d).ok();
    }
}
