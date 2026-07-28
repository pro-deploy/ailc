---
name: security-scan-taint
description: "Taint-анализ потока данных на всех 15 языках движка (Python/JS/TS/Go/Java/Ruby/PHP/C#/Rust/Kotlin/Scala/C/C++/Swift/Dart): недоверенный ввод (request/getParameter/$_GET/env::var/getenv/argv/fgets/req.query), достигающий стока исполнения/SQL/файла/копирования через цепочку присваиваний и границы функций — межпроцедурное внедрение команд/SQL/обход пути/переполнение буфера, с учётом санитайзеров. Видит то, что одно-операторный анализ и regex пропускают. Тяжёлый — для полного пентеста."
license: Apache-2.0
metadata:
  family: security
  engine: codeintel
  tier: enterprise
  mutates: false
---

# security.scan/taint

Taint-анализ потока данных на всех 15 языках движка (Python/JS/TS/Go/Java/Ruby/PHP/C#/Rust/Kotlin/Scala/C/C++/Swift/Dart): недоверенный ввод (request/getParameter/$_GET/env::var/getenv/argv/fgets/req.query), достигающий стока исполнения/SQL/файла/копирования через цепочку присваиваний и границы функций — межпроцедурное внедрение команд/SQL/обход пути/переполнение буфера, с учётом санитайзеров. Видит то, что одно-операторный анализ и regex пропускают. Тяжёлый — для полного пентеста.

## Как запустить

Через MCP-сервер ailc (один офлайновый бинарь, без внешних сервисов):

- `run { "id": "security.scan/taint", "path": "<путь к проекту>" }`
- семантический подбор под намерение: `find_capability { "query": "..." }`

Через CLI:

```
ailc cap security.scan/taint <путь>
```

Находки возвращаются структурно (file:line + severity) и проходят состязательную верификацию — в балл и гейт идут только подтверждённые. Семейство `security`, движок `codeintel`, тир `enterprise`.
