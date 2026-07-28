---
name: security-scan-deps
description: "Проверить зависимости проекта на известные уязвимости (cargo audit / npm audit / pip-audit / govulncheck)."
license: Apache-2.0
metadata:
  family: security
  engine: runner
  tier: core
  mutates: false
---

# security.scan/deps

Проверить зависимости проекта на известные уязвимости (cargo audit / npm audit / pip-audit / govulncheck).

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "security.scan/deps", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap security.scan/deps <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `security`, движок `runner`, тир `core`.
