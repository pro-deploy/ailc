---
name: governance-rule-add
description: "Добавить правило в конституцию проекта одной строкой (FORBID/REQUIRE/REQUIRE_EACH, опционально [warn] и [in: путь]) и сразу узнать, сколько мест ему противоречит."
license: Apache-2.0
metadata:
  family: quality
  engine: store
  tier: core
  mutates: true
---

# governance/rule-add

Добавить правило в конституцию проекта одной строкой (FORBID/REQUIRE/REQUIRE_EACH, опционально [warn] и [in: путь]) и сразу узнать, сколько мест ему противоречит.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "governance/rule-add", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap governance/rule-add <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `quality`, движок `store`, тир `core`.
