---
name: code-intel-metrics
description: "Числовая карта кода: размеры и сложность файлов, топ самых сложных — где сосредоточен риск."
license: Apache-2.0
metadata:
  family: code.intel
  engine: metric
  tier: core
  mutates: false
---

# code.intel/metrics

Числовая карта кода: размеры и сложность файлов, топ самых сложных — где сосредоточен риск.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "code.intel/metrics", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap code.intel/metrics <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `code.intel`, движок `metric`, тир `core`.
