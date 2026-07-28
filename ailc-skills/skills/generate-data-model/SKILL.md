---
name: generate-data-model
description: "Собрать модель данных из кода (ORM-модели, Prisma, SQL CREATE TABLE). Идемпотентно."
license: Apache-2.0
metadata:
  family: generate
  engine: generator
  tier: core
  mutates: true
---

# generate/data-model

Собрать модель данных из кода (ORM-модели, Prisma, SQL CREATE TABLE). Идемпотентно.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "generate/data-model", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap generate/data-model <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `generate`, движок `generator`, тир `core`.
