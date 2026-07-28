---
name: setup-cicd
description: "Сгенерировать GitHub Actions workflow, который гоняет ailc dod + sarif в CI — внедрить гейт в один шаг."
license: Apache-2.0
metadata:
  family: setup
  engine: generator
  tier: core
  mutates: true
---

# setup/cicd

Сгенерировать GitHub Actions workflow, который гоняет ailc dod + sarif в CI — внедрить гейт в один шаг.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "setup/cicd", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap setup/cicd <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `setup`, движок `generator`, тир `core`.
