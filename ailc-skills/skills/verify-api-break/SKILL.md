---
name: verify-api-break
description: "Проверить, не сломан ли публичный контракт: удалённые/переименованные публичные символы относительно снимка .ailc/api/baseline.txt."
license: Apache-2.0
metadata:
  family: verify
  engine: codeintel
  tier: core
  mutates: false
---

# verify/api-break

Проверить, не сломан ли публичный контракт: удалённые/переименованные публичные символы относительно снимка .ailc/api/baseline.txt.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "verify/api-break", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap verify/api-break <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `verify`, движок `codeintel`, тир `core`.
