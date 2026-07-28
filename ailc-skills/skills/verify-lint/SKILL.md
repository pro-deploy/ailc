---
name: verify-lint
description: "Запустить линтер проекта (clippy/golangci-lint/eslint/ruff) с фолбэком."
license: Apache-2.0
metadata:
  family: verify
  engine: runner
  tier: core
  mutates: false
---

# verify/lint

Запустить линтер проекта (clippy/golangci-lint/eslint/ruff) с фолбэком.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "verify/lint", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap verify/lint <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `verify`, движок `runner`, тир `core`.
