---
name: security-ai-insecure-output-taint
description: "Небезопасная обработка вывода LLM через переменную (OWASP LLM02): результат вызова модели присвоен переменной, которая ниже в той же функции попадает в сток исполнения (eval/exec/Function/vm/shell) или рендера (innerHTML/outerHTML/document.write/insertAdjacentHTML)."
license: Apache-2.0
metadata:
  family: security
  engine: scan
  tier: core
  mutates: false
---

# security.ai/insecure-output-taint

Небезопасная обработка вывода LLM через переменную (OWASP LLM02): результат вызова модели присвоен переменной, которая ниже в той же функции попадает в сток исполнения (eval/exec/Function/vm/shell) или рендера (innerHTML/outerHTML/document.write/insertAdjacentHTML).

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "security.ai/insecure-output-taint", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap security.ai/insecure-output-taint <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `security`, движок `scan`, тир `core`.
