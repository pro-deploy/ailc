---
name: memory-read
description: "Прочитать рабочую память проекта (контекст, заметки) перед началом работы."
license: Apache-2.0
metadata:
  family: memory
  engine: store
  tier: core
  mutates: false
---

# memory/read

Прочитать рабочую память проекта (контекст, заметки) перед началом работы.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "memory/read", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap memory/read <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `memory`, движок `store`, тир `core`.
