---
name: security-scan-licenses
description: "Проверить лицензии зависимостей: копилефт (GPL/AGPL/LGPL) в проприетарном проекте, неуказанные лицензии. Офлайн из package-lock.json."
license: Apache-2.0
metadata:
  family: security
  engine: scan
  tier: core
  mutates: false
---

# security.scan/licenses

Проверить лицензии зависимостей: копилефт (GPL/AGPL/LGPL) в проприетарном проекте, неуказанные лицензии. Офлайн из package-lock.json.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "security.scan/licenses", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap security.scan/licenses <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `security`, движок `scan`, тир `core`.
