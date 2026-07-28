---
name: verify-desktop
description: "Проверить десктопный проект (.NET/Tauri/Electron/C++): небезопасная конфигурация Electron/Tauri детерминированным сканом плюс сборка/тесты всех обнаруженных стеков."
license: Apache-2.0
metadata:
  family: verify
  engine: runner
  tier: core
  mutates: false
---

# verify/desktop

Проверить десктопный проект (.NET/Tauri/Electron/C++): небезопасная конфигурация Electron/Tauri детерминированным сканом плюс сборка/тесты всех обнаруженных стеков.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "verify/desktop", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap verify/desktop <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `verify`, движок `runner`, тир `core`.
