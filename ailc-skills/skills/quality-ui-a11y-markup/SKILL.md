---
name: quality-ui-a11y-markup
description: "Барьеры доступности в разметке (HTML/JSX/TSX/Vue/Svelte): изображение без текстовой альтернативы (alt), поле ввода без программной подписи (label/aria-label/aria-labelledby), интерактив на неинтерактивном теге (div/span с onClick) без роли и клавиатурного обработчика."
license: Apache-2.0
metadata:
  family: quality
  engine: scan
  tier: core
  mutates: false
---

# quality.ui/a11y-markup

Барьеры доступности в разметке (HTML/JSX/TSX/Vue/Svelte): изображение без текстовой альтернативы (alt), поле ввода без программной подписи (label/aria-label/aria-labelledby), интерактив на неинтерактивном теге (div/span с onClick) без роли и клавиатурного обработчика.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "quality.ui/a11y-markup", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap quality.ui/a11y-markup <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `scan`, тир `core`.
