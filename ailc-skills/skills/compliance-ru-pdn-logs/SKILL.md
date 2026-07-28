---
name: compliance-ru-pdn-logs
description: "Логирование персональных данных граждан РФ (паспорт/СНИЛС/ИНН и т.п.) — нарушение 152-ФЗ. Покрывает logger/console/print/log/zap/slog на всех стеках; построчно и многострочно (аргумент перенесён на следующую строку)."
license: Apache-2.0
metadata:
  family: compliance
  engine: scan
  tier: core
  mutates: false
---

# compliance.ru/pdn-logs

Логирование персональных данных граждан РФ (паспорт/СНИЛС/ИНН и т.п.) — нарушение 152-ФЗ. Покрывает logger/console/print/log/zap/slog на всех стеках; построчно и многострочно (аргумент перенесён на следующую строку).

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "compliance.ru/pdn-logs", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap compliance.ru/pdn-logs <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `compliance`, движок `scan`, тир `core`.
