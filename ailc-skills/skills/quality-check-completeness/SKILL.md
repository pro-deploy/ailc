---
name: quality-check-completeness
description: "Найти недоделанное, что ИИ мог пропустить: заглушки (unimplemented/TODO/NotImplementedError), пустые обработчики ошибок, пустые функции."
license: Apache-2.0
metadata:
  family: quality
  engine: scan
  tier: core
  mutates: false
---

# quality.check/completeness

Найти недоделанное, что ИИ мог пропустить: заглушки (unimplemented/TODO/NotImplementedError), пустые обработчики ошибок, пустые функции.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.check/completeness", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.check/completeness <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `scan`, тир `core`.
