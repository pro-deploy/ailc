---
name: generate-diagram
description: "Записать диаграмму связей частей проекта (Mermaid) в документацию docs/ДИАГРАММА.md."
license: Apache-2.0
metadata:
  family: generate
  engine: diagram
  tier: core
  mutates: true
---

# generate/diagram

Записать диаграмму связей частей проекта (Mermaid) в документацию docs/ДИАГРАММА.md.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "generate/diagram", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap generate/diagram <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `generate`, движок `diagram`, тир `core`.
