---
name: backlog-add
description: "Добавить задачу в бэклог проекта (описание задачи — query); id выдаётся автоматически."
license: Apache-2.0
metadata:
  family: backlog
  engine: store
  tier: core
  mutates: true
---

# backlog/add

Добавить задачу в бэклог проекта (описание задачи — query); id выдаётся автоматически.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "backlog/add", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap backlog/add <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `backlog`, движок `store`, тир `core`.
