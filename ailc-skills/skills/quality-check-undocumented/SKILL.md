---
name: quality-check-undocumented
description: "Найти публичные функции/типы/классы без описания — пропущенная документация внешнего API."
license: Apache-2.0
metadata:
  family: quality
  engine: codeintel
  tier: core
  mutates: false
---

# quality.check/undocumented

Найти публичные функции/типы/классы без описания — пропущенная документация внешнего API.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.check/undocumented", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.check/undocumented <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `codeintel`, тир `core`.
