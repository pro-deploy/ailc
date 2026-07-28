---
name: quality-ui-responsive
description: "Адаптивность веб-страницы: корневой HTML без метатега области просмотра (viewport) и блокировка масштабирования (user-scalable=no либо maximum-scale=1), мешающая увеличению страницы."
license: Apache-2.0
metadata:
  family: quality
  engine: scan
  tier: core
  mutates: false
---

# quality.ui/responsive

Адаптивность веб-страницы: корневой HTML без метатега области просмотра (viewport) и блокировка масштабирования (user-scalable=no либо maximum-scale=1), мешающая увеличению страницы.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.ui/responsive", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.ui/responsive <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `scan`, тир `core`.
