---
name: generate-release-notes
description: "Собрать changelog из conventional-commits (feat/fix/...) с последнего тега — заметки к релизу в docs/RELEASE-NOTES.md."
license: Apache-2.0
metadata:
  family: generate
  engine: generator
  tier: core
  mutates: true
---

# generate/release-notes

Собрать changelog из conventional-commits (feat/fix/...) с последнего тега — заметки к релизу в docs/RELEASE-NOTES.md.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "generate/release-notes", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap generate/release-notes <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `generate`, движок `generator`, тир `core`.
