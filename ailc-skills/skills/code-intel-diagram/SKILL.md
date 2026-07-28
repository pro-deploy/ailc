---
name: code-intel-diagram
description: "Показать связи частей проекта диаграммой Mermaid — наглядная карта зависимостей без записи на диск."
license: Apache-2.0
metadata:
  family: code.intel
  engine: diagram
  tier: core
  mutates: false
---

# code.intel/diagram

Показать связи частей проекта диаграммой Mermaid — наглядная карта зависимостей без записи на диск.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "code.intel/diagram", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap code.intel/diagram <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `code.intel`, движок `diagram`, тир `core`.
