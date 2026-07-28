---
name: generate-api-baseline
description: "Зафиксировать снимок публичного API в .ailc/api/baseline.txt — эталон, против которого verify/api-break ловит слом контракта."
license: Apache-2.0
metadata:
  family: generate
  engine: generator
  tier: core
  mutates: true
---

# generate/api-baseline

Зафиксировать снимок публичного API в .ailc/api/baseline.txt — эталон, против которого verify/api-break ловит слом контракта.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "generate/api-baseline", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap generate/api-baseline <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `generate`, движок `generator`, тир `core`.
