---
name: quality-ui-focus-visible
description: "Видимость фокуса клавиатуры: стиль убирает контур фокуса (outline: none/0), но во всём файле нет восстановления видимого фокуса через :focus-visible или :focus."
license: Apache-2.0
metadata:
  family: quality
  engine: scan
  tier: core
  mutates: false
---

# quality.ui/focus-visible

Видимость фокуса клавиатуры: стиль убирает контур фокуса (outline: none/0), но во всём файле нет восстановления видимого фокуса через :focus-visible или :focus.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.ui/focus-visible", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.ui/focus-visible <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `scan`, тир `core`.
