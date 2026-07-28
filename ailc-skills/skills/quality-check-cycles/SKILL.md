---
name: quality-check-cycles
description: "Найти циклические зависимости между модулями — архитектурный запах."
license: Apache-2.0
metadata:
  family: quality
  engine: codeintel
  tier: core
  mutates: false
---

# quality.check/cycles

Найти циклические зависимости между модулями — архитектурный запах.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.check/cycles", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.check/cycles <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `codeintel`, тир `core`.
