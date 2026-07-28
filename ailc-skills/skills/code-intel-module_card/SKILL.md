---
name: code-intel-module_card
description: "Сводка по частям проекта: сколько определений и публичного API в каждой папке-пакете."
license: Apache-2.0
metadata:
  family: code.intel
  engine: codeintel
  tier: core
  mutates: false
---

# code.intel/module_card

Сводка по частям проекта: сколько определений и публичного API в каждой папке-пакете.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "code.intel/module_card", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap code.intel/module_card <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `code.intel`, движок `codeintel`, тир `core`.
