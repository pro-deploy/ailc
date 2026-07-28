---
name: generate-glossary
description: "Собрать глоссарий из кода: публичные типы/классы/интерфейсы как термины предметной области. Идемпотентно."
license: Apache-2.0
metadata:
  family: generate
  engine: generator
  tier: core
  mutates: true
---

# generate/glossary

Собрать глоссарий из кода: публичные типы/классы/интерфейсы как термины предметной области. Идемпотентно.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "generate/glossary", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap generate/glossary <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `generate`, движок `generator`, тир `core`.
