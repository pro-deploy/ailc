---
name: quality-check-complexity
description: "Найти слишком длинные и слишком сложные файлы — кандидаты на разбиение перед изменением."
license: Apache-2.0
metadata:
  family: quality
  engine: metric
  tier: core
  mutates: false
---

# quality.check/complexity

Найти слишком длинные и слишком сложные файлы — кандидаты на разбиение перед изменением.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.check/complexity", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.check/complexity <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `metric`, тир `core`.
