---
name: code-intel-map
description: "Карта незнакомого проекта одним вызовом: дерево папок (языки, файлы, строки, символы) и точки входа."
license: Apache-2.0
metadata:
  family: code.intel
  engine: codeintel
  tier: core
  mutates: false
---

# code.intel/map

Карта незнакомого проекта одним вызовом: дерево папок (языки, файлы, строки, символы) и точки входа.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "code.intel/map", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap code.intel/map <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `code.intel`, движок `codeintel`, тир `core`.
