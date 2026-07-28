---
name: deliver-commit-draft
description: "Подготовить черновик сообщения коммита по подготовленным изменениям (git diff --cached). Сам не коммитит."
license: Apache-2.0
metadata:
  family: deliver
  engine: runner
  tier: core
  mutates: false
---

# deliver/commit-draft

Подготовить черновик сообщения коммита по подготовленным изменениям (git diff --cached). Сам не коммитит.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "deliver/commit-draft", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap deliver/commit-draft <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `deliver`, движок `runner`, тир `core`.
