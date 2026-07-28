---
name: code-intel-find_usages
description: "Найти все использования символа по имени — оценить влияние ПЕРЕД изменением."
license: Apache-2.0
metadata:
  family: code.intel
  engine: codeintel
  tier: core
  mutates: false
---

# code.intel/find_usages

Найти все использования символа по имени — оценить влияние ПЕРЕД изменением.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "code.intel/find_usages", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap code.intel/find_usages <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `code.intel`, движок `codeintel`, тир `core`.
