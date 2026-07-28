---
name: memory-decision-log
description: "Записать принятое решение строкой в журнал решений проекта (текст — query)."
license: Apache-2.0
metadata:
  family: memory
  engine: store
  tier: core
  mutates: true
---

# memory/decision-log

Записать принятое решение строкой в журнал решений проекта (текст — query).

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "memory/decision-log", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap memory/decision-log <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `memory`, движок `store`, тир `core`.
