---
name: security-scan-mobile-config
description: "Статический анализ мобильных конфигураций (AndroidManifest.xml, Info.plist, entitlements, build.gradle, network security config, assetlinks/apple-app-site-association): экспортируемые компоненты без разрешения, открытый текст по сети, отладка и резервное копирование в проде, ослабленная транспортная безопасность iOS, мобильные секреты и небезопасное хранение токенов, небезопасные диплинки."
license: Apache-2.0
metadata:
  family: security
  engine: scan
  tier: core
  mutates: false
---

# security.scan/mobile-config

Статический анализ мобильных конфигураций (AndroidManifest.xml, Info.plist, entitlements, build.gradle, network security config, assetlinks/apple-app-site-association): экспортируемые компоненты без разрешения, открытый текст по сети, отладка и резервное копирование в проде, ослабленная транспортная безопасность iOS, мобильные секреты и небезопасное хранение токенов, небезопасные диплинки.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "security.scan/mobile-config", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap security.scan/mobile-config <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `security`, движок `scan`, тир `core`.
