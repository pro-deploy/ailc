---
name: security-ai-insecure-output
description: "Небезопасная обработка вывода LLM (OWASP LLM02): ответ модели исполняется (eval/exec/Function/vm/os.system/subprocess) или вставляется как сырой HTML (innerHTML/outerHTML/document.write/insertAdjacentHTML) без проверки."
license: Apache-2.0
metadata:
  family: security
  engine: scan
  tier: core
  mutates: false
---

# security.ai/insecure-output

Небезопасная обработка вывода LLM (OWASP LLM02): ответ модели исполняется (eval/exec/Function/vm/os.system/subprocess) или вставляется как сырой HTML (innerHTML/outerHTML/document.write/insertAdjacentHTML) без проверки.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "security.ai/insecure-output", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap security.ai/insecure-output <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `security`, движок `scan`, тир `core`.
