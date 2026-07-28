---
name: quality-check-layers
description: "Проверить архитектурные слои: какие модули кому разрешено зависеть (правила из .ailc/layers.txt)."
license: Apache-2.0
metadata:
  family: quality
  engine: codeintel
  tier: core
  mutates: false
---

# quality.check/layers

Проверить архитектурные слои: какие модули кому разрешено зависеть (правила из .ailc/layers.txt).

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.check/layers", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.check/layers <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `codeintel`, тир `core`.
