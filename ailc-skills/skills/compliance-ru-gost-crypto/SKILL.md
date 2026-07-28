---
name: compliance-ru-gost-crypto
description: "Иностранная криптография (AES/RSA/ECDSA/SHA/bcrypt) на объекте КИИ — 187-ФЗ и импортозамещение требуют ГОСТ-криптографии (Магма/Кузнечик/Стрибог). Проверка применима, только если система — значимый объект КИИ."
license: Apache-2.0
metadata:
  family: compliance
  engine: scan
  tier: enterprise
  mutates: false
---

# compliance.ru/gost-crypto

Иностранная криптография (AES/RSA/ECDSA/SHA/bcrypt) на объекте КИИ — 187-ФЗ и импортозамещение требуют ГОСТ-криптографии (Магма/Кузнечик/Стрибог). Проверка применима, только если система — значимый объект КИИ.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "compliance.ru/gost-crypto", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap compliance.ru/gost-crypto <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `compliance`, движок `scan`, тир `enterprise`.
