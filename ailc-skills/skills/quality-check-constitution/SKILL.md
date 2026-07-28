---
name: quality-check-constitution
description: "Проверить код на соответствие конституции проекта (правила FORBID/REQUIRE/REQUIRE_EACH из .ailc/constitution.md)."
license: Apache-2.0
metadata:
  family: quality
  engine: scan
  tier: core
  mutates: false
---

# quality.check/constitution

Проверить код на соответствие конституции проекта (правила FORBID/REQUIRE/REQUIRE_EACH из .ailc/constitution.md).

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.check/constitution", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.check/constitution <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `scan`, тир `core`.
