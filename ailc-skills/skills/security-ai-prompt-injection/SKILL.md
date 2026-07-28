---
name: security-ai-prompt-injection
description: "Промпт-инъекция (OWASP LLM01): промпт для LLM собирается из недоверенного пользовательского ввода интерполяцией/конкатенацией (f-строки, ${...}, .format, склейка, а также push_str/format! на Rust/Go)."
license: Apache-2.0
metadata:
  family: security
  engine: scan
  tier: core
  mutates: false
---

# security.ai/prompt-injection

Промпт-инъекция (OWASP LLM01): промпт для LLM собирается из недоверенного пользовательского ввода интерполяцией/конкатенацией (f-строки, ${...}, .format, склейка, а также push_str/format! на Rust/Go).

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "security.ai/prompt-injection", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap security.ai/prompt-injection <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `security`, движок `scan`, тир `core`.
