---
name: generate-adr
description: "Зафиксировать принятое архитектурное решение отдельной записью (заголовок решения — query)."
license: Apache-2.0
metadata:
  family: generate
  engine: generator
  tier: core
  mutates: true
---

# generate/adr

Зафиксировать принятое архитектурное решение отдельной записью (заголовок решения — query).

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "generate/adr", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap generate/adr <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `generate`, движок `generator`, тир `core`.
