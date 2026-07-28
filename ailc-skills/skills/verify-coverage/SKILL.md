---
name: verify-coverage
description: "Посчитать покрытие тестами (go test -cover / cargo llvm-cov / jest / pytest-cov) реальным прогоном."
license: Apache-2.0
metadata:
  family: verify
  engine: runner
  tier: core
  mutates: false
---

# verify/coverage

Посчитать покрытие тестами (go test -cover / cargo llvm-cov / jest / pytest-cov) реальным прогоном.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "verify/coverage", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap verify/coverage <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `verify`, движок `runner`, тир `core`.
