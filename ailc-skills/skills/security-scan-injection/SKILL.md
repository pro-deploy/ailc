---
name: security-scan-injection
description: "Инъекции в HTML/шаблоны на клиенте (межсайтовый скриптинг, XSS): запись сырого HTML из данных — innerHTML, outerHTML, insertAdjacentHTML, dangerouslySetInnerHTML, v-html, обход санитайзера Angular, document.write, сборка HTML и SQL конкатенацией или шаблонным литералом."
license: Apache-2.0
metadata:
  family: security
  engine: scan
  tier: core
  mutates: false
---

# security.scan/injection

Инъекции в HTML/шаблоны на клиенте (межсайтовый скриптинг, XSS): запись сырого HTML из данных — innerHTML, outerHTML, insertAdjacentHTML, dangerouslySetInnerHTML, v-html, обход санитайзера Angular, document.write, сборка HTML и SQL конкатенацией или шаблонным литералом.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "security.scan/injection", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap security.scan/injection <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `security`, движок `scan`, тир `core`.
