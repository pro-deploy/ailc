---
name: verify-test
description: "Реально прогнать тесты проекта (cargo/go/npm/pytest) и проверить, что код работает."
license: Apache-2.0
metadata:
  family: verify
  engine: runner
  tier: core
  mutates: false
---

# verify/test

Реально прогнать тесты проекта (cargo/go/npm/pytest) и проверить, что код работает.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "verify/test", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap verify/test <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `verify`, движок `runner`, тир `core`.
