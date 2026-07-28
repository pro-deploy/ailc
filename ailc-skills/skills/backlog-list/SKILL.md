---
name: backlog-list
description: "Перечислить задачи бэклога проекта с их заголовками."
license: Apache-2.0
metadata:
  family: backlog
  engine: store
  tier: core
  mutates: false
---

# backlog/list

Перечислить задачи бэклога проекта с их заголовками.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "backlog/list", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap backlog/list <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `backlog`, движок `store`, тир `core`.
