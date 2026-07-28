---
name: setup-init
description: "Развернуть скелет среды ailc в проекте (конституция, слои, рабочая память). Идемпотентно."
license: Apache-2.0
metadata:
  family: setup
  engine: generator
  tier: core
  mutates: true
---

# setup/init

Развернуть скелет среды ailc в проекте (конституция, слои, рабочая память). Идемпотентно.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "setup/init", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap setup/init <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `setup`, движок `generator`, тир `core`.
