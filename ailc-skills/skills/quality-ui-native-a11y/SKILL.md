---
name: quality-ui-native-a11y
description: "Доступность нативного мобильного интерфейса: изображение/иконка в XML-макете Android без contentDescription, виджет Image во Flutter без semanticLabel и обёртки Semantics, элемент iOS с отключённой доступностью (isAccessibilityElement=false)."
license: Apache-2.0
metadata:
  family: quality
  engine: scan
  tier: core
  mutates: false
---

# quality.ui/native-a11y

Доступность нативного мобильного интерфейса: изображение/иконка в XML-макете Android без contentDescription, виджет Image во Flutter без semanticLabel и обёртки Semantics, элемент iOS с отключённой доступностью (isAccessibilityElement=false).

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.ui/native-a11y", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.ui/native-a11y <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `scan`, тир `core`.
