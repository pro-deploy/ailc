---
name: verify-mobile
description: "Собрать и прогнать тесты мобильного или нативного проекта (Flutter/Dart, React Native/Expo, Android через ./gradlew, Swift/iOS), запустить доступные анализаторы (flutter/dart analyze, swiftlint, ktlint, detekt) и статически разобрать Info.plist/entitlements. Поддерживает мульти-стек без раннего пропуска."
license: Apache-2.0
metadata:
  family: verify
  engine: runner
  tier: core
  mutates: false
---

# verify/mobile

Собрать и прогнать тесты мобильного или нативного проекта (Flutter/Dart, React Native/Expo, Android через ./gradlew, Swift/iOS), запустить доступные анализаторы (flutter/dart analyze, swiftlint, ktlint, detekt) и статически разобрать Info.plist/entitlements. Поддерживает мульти-стек без раннего пропуска.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "verify/mobile", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap verify/mobile <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `verify`, движок `runner`, тир `core`.
