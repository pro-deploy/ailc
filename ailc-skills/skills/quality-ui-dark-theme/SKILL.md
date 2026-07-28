---
name: quality-ui-dark-theme
description: "Поддержка предпочитаемой цветовой схемы (тёмная тема): файл стилей задаёт фон и цвет текста явными значениями, но во всём файле нет медиазапроса prefers-color-scheme."
license: Apache-2.0
metadata:
  family: quality
  engine: scan
  tier: core
  mutates: false
---

# quality.ui/dark-theme

Поддержка предпочитаемой цветовой схемы (тёмная тема): файл стилей задаёт фон и цвет текста явными значениями, но во всём файле нет медиазапроса prefers-color-scheme.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.ui/dark-theme", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.ui/dark-theme <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `scan`, тир `core`.
