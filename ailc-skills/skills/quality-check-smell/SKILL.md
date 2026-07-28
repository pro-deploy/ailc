---
name: quality-check-smell
description: "Запахи корректности: проглоченные ошибки, panic/unwrap, маркеры техдолга."
license: Apache-2.0
metadata:
  family: quality
  engine: scan
  tier: core
  mutates: false
---

# quality.check/smell

Запахи корректности: проглоченные ошибки, panic/unwrap, маркеры техдолга.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.check/smell", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.check/smell <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `scan`, тир `core`.
