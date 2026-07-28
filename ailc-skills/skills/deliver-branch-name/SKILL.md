---
name: deliver-branch-name
description: "Собрать корректное имя git-ветки из описания задачи (описание — query)."
license: Apache-2.0
metadata:
  family: deliver
  engine: store
  tier: core
  mutates: false
---

# deliver/branch-name

Собрать корректное имя git-ветки из описания задачи (описание — query).

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "deliver/branch-name", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap deliver/branch-name <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `deliver`, движок `store`, тир `core`.
