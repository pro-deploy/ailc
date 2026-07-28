---
name: spec-check-trace
description: "Проверить, что текущее изменение (git) прослеживается к спеке или задаче бэклога."
license: Apache-2.0
metadata:
  family: spec
  engine: codeintel
  tier: core
  mutates: false
---

# spec.check/trace

Проверить, что текущее изменение (git) прослеживается к спеке или задаче бэклога.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "spec.check/trace", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap spec.check/trace <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `spec`, движок `codeintel`, тир `core`.
