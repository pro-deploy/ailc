---
name: code-intel-symbols
description: "Перечислить функции/типы/классы проекта на любом языке — карта кода перед изменением."
license: Apache-2.0
metadata:
  family: code.intel
  engine: codeintel
  tier: core
  mutates: false
---

# code.intel/symbols

Перечислить функции/типы/классы проекта на любом языке — карта кода перед изменением.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "code.intel/symbols", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap code.intel/symbols <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `code.intel`, движок `codeintel`, тир `core`.
