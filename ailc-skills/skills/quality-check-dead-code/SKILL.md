---
name: quality-check-dead-code
description: "Найти экспортируемые символы без использований — кандидаты в мёртвый код."
license: Apache-2.0
metadata:
  family: quality
  engine: codeintel
  tier: core
  mutates: false
---

# quality.check/dead-code

Найти экспортируемые символы без использований — кандидаты в мёртвый код.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.check/dead-code", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.check/dead-code <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `codeintel`, тир `core`.
