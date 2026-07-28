---
name: compliance-ru-localization
description: "Зарубежная инфраструктура хранения данных (AWS RDS/Mongo Atlas/Firebase/Supabase/иностранные регионы) — СИГНАЛ для проверки локализации ПДн граждан РФ (242-ФЗ), а не доказанное нарушение: что именно там хранится, решает ревью."
license: Apache-2.0
metadata:
  family: compliance
  engine: scan
  tier: core
  mutates: false
---

# compliance.ru/localization

Зарубежная инфраструктура хранения данных (AWS RDS/Mongo Atlas/Firebase/Supabase/иностранные регионы) — СИГНАЛ для проверки локализации ПДн граждан РФ (242-ФЗ), а не доказанное нарушение: что именно там хранится, решает ревью.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "compliance.ru/localization", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap compliance.ru/localization <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `compliance`, движок `scan`, тир `core`.
