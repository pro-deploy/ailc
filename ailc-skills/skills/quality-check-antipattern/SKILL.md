---
name: quality-check-antipattern
description: "Найти структурные антипаттерны: перегруженные файлы (God-файл) и чрезмерно глубокую вложенность."
license: Apache-2.0
metadata:
  family: quality
  engine: codeintel
  tier: core
  mutates: false
---

# quality.check/antipattern

Найти структурные антипаттерны: перегруженные файлы (God-файл) и чрезмерно глубокую вложенность.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.check/antipattern", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.check/antipattern <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `codeintel`, тир `core`.
