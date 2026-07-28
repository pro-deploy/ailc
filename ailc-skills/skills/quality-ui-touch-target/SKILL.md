---
name: quality-ui-touch-target
description: "Размер цели нажатия меньше минимума доступности: для веба явные width/height меньше 44px, для Android android:layout_height/width меньше 48dp, для iOS размер кадра кнопки меньше 44pt."
license: Apache-2.0
metadata:
  family: quality
  engine: scan
  tier: core
  mutates: false
---

# quality.ui/touch-target

Размер цели нажатия меньше минимума доступности: для веба явные width/height меньше 44px, для Android android:layout_height/width меньше 48dp, для iOS размер кадра кнопки меньше 44pt.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.ui/touch-target", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.ui/touch-target <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `scan`, тир `core`.
