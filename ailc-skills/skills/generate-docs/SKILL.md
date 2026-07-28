---
name: generate-docs
description: "Создать обзор проекта живым русским языком: из каких частей он состоит и как они связаны."
license: Apache-2.0
metadata:
  family: generate
  engine: generator
  tier: core
  mutates: true
---

# generate/docs

Создать обзор проекта живым русским языком: из каких частей он состоит и как они связаны.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "generate/docs", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap generate/docs <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `generate`, движок `generator`, тир `core`.
