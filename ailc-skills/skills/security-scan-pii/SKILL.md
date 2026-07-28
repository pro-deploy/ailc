---
name: security-scan-pii
description: "Персональные данные в коде/логах: SSN, карты, email, логирование чувствительных полей."
license: Apache-2.0
metadata:
  family: security
  engine: scan
  tier: core
  mutates: false
---

# security.scan/pii

Персональные данные в коде/логах: SSN, карты, email, логирование чувствительных полей.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "security.scan/pii", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap security.scan/pii <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `security`, движок `scan`, тир `core`.
