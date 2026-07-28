---
name: code-intel-diff-scope
description: "Радиус влияния текущей правки: какие функции затронуты изменением через граф вызовов (что задело это изменение перед сдачей)."
license: Apache-2.0
metadata:
  family: code.intel
  engine: codeintel
  tier: core
  mutates: false
---

# code.intel/diff-scope

Радиус влияния текущей правки: какие функции затронуты изменением через граф вызовов (что задело это изменение перед сдачей).

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "code.intel/diff-scope", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap code.intel/diff-scope <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `code.intel`, движок `codeintel`, тир `core`.
