---
name: memory-update
description: "Сохранить рабочий контекст в память проекта (имя файла — target, содержимое — query)."
license: Apache-2.0
metadata:
  family: memory
  engine: store
  tier: core
  mutates: true
---

# memory/update

Сохранить рабочий контекст в память проекта (имя файла — target, содержимое — query).

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "memory/update", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap memory/update <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `memory`, движок `store`, тир `core`.
