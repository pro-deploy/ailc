//! Экспорт capability как agentskills.io-совместимого пака (SKILL.md + plugin.json).
//!
//! Замыкает разрыв с библиотеками навыков: у них есть формат-дистрибуция, но нет
//! исполняемых движков; у ailc — наоборот. Здесь каждая capability реестра
//! превращается в навык с frontmatter, который любой agentskills.io-совместимый агент
//! (Claude Code, Cursor, …) обнаружит и сможет вызвать через MCP-сервер ailc.
//!
//! Генерация ЧИСТАЯ (реестр-манифесты → файлы в памяти) — запись на диск делает CLI.

use ailc_contracts::CapabilityManifest;
use serde_json::json;

/// Один файл будущего пака: относительный путь + содержимое.
pub struct SkillFile {
    pub path: String,
    pub content: String,
}

/// id capability → slug для имени папки навыка: `security.scan/secret` → `security-scan-secret`.
fn slug(id: &str) -> String {
    id.chars()
        .map(|c| if c == '/' || c == '.' { '-' } else { c })
        .collect::<String>()
        .to_lowercase()
}

/// Сгенерировать пак: `.claude-plugin/plugin.json` + `skills/<slug>/SKILL.md` на каждую capability.
pub fn generate(manifests: &[&CapabilityManifest], version: &str) -> Vec<SkillFile> {
    let mut files = Vec::with_capacity(manifests.len() + 1);
    files.push(SkillFile {
        path: ".claude-plugin/plugin.json".to_string(),
        content: plugin_json(manifests.len(), version),
    });
    for m in manifests {
        files.push(SkillFile {
            path: format!("skills/{}/SKILL.md", slug(m.id)),
            content: skill_md(m),
        });
    }
    files
}

fn plugin_json(count: usize, version: &str) -> String {
    let doc = json!({
        "name": "ailc",
        "version": version,
        "description": format!(
            "Офлайновый оркестратор качества и безопасности кода — {count} возможностей (SAST · taint-анализ · OSV · секреты · web/API · AI-безопасность · комплаенс РФ), экспонированных как навыки. Один бинарь, без внешних сервисов; находки верифицируются состязательным проходом.",
        ),
        "category": "security",
        "keywords": [
            "security", "sast", "taint-analysis", "dependency-audit", "secrets",
            "compliance", "devsecops", "code-quality", "offline", "mcp"
        ],
        "mcp": { "command": "ailc", "args": ["serve"] }
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

fn skill_md(m: &CapabilityManifest) -> String {
    // description в frontmatter — JSON-строка: безопасно для YAML при любых символах в when_to_use.
    let desc = serde_json::to_string(m.when_to_use).unwrap_or_else(|_| "\"\"".to_string());
    format!(
        "---\n\
         name: {slug}\n\
         description: {desc}\n\
         license: Apache-2.0\n\
         metadata:\n  \
         family: {family}\n  \
         engine: {engine}\n  \
         tier: {tier}\n  \
         mutates: {mutates}\n\
         ---\n\
         \n\
         # {id}\n\
         \n\
         {when}\n\
         \n\
         ## Как запустить\n\
         \n\
         Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):\n\
         \n\
         - `run {{ \"id\": \"{id}\", \"path\": \"<путь к проекту>\" }}`\n\
         - семантический подбор под намерение: `find_capability {{ \"query\": \"...\" }}`\n\
         \n\
         Через CLI:\n\
         \n\
         ```\n\
         ailc cap {id} <путь>\n\
         ```\n\
         \n\
         Находки возвращаются структурно (file:line + severity) и проходят состязательную \
         верификацию — в балл и гейт идут только подтверждённые. Семейство `{family}`, \
         движок `{engine}`, тир `{tier}`.\n",
        slug = slug(m.id),
        desc = desc,
        family = m.family,
        engine = m.engine,
        tier = m.tier,
        mutates = m.mutates,
        id = m.id,
        when = m.when_to_use,
    )
}
