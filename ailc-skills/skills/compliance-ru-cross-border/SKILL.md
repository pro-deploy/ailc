---
name: compliance-ru-cross-border
description: "Иностранная аналитика/трекинг/рассылки (Google Analytics, Meta Pixel, Amplitude, Sentry, SendGrid и др.) — СИГНАЛ возможной трансграничной передачи ПДн (152-ФЗ ст.12), а не доказанная передача: какие данные уходят, решает ревью."
license: Apache-2.0
metadata:
  family: compliance
  engine: scan
  tier: core
  mutates: false
---

# compliance.ru/cross-border

Иностранная аналитика/трекинг/рассылки (Google Analytics, Meta Pixel, Amplitude, Sentry, SendGrid и др.) — СИГНАЛ возможной трансграничной передачи ПДн (152-ФЗ ст.12), а не доказанная передача: какие данные уходят, решает ревью.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "compliance.ru/cross-border", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap compliance.ru/cross-border <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `compliance`, движок `scan`, тир `core`.
