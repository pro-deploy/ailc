#!/usr/bin/env python3
"""Пересборка встроенного снимка базы уязвимостей OSV.

Назначение. Проверка зависимостей в ailc работает офлайн по снимку, вшитому в бинарь.
Снимок обязан быть настоящим и свежим, иначе результат «уязвимых 0» не значит ничего.
Настоящий скрипт скачивает официальные выгрузки OSV.dev по экосистемам, сводит их к
компактному виду, который нужен движку (экосистема, пакет, границы версий, важность,
краткое описание), и перезаписывает `crates/ailc-core/assets/osv/snapshot.tsv`.

Запуск вручную:

    python3 tools/update-osv.py

Регулярно скрипт выполняется рабочим процессом `.github/workflows/osv-update.yml`,
который коммитит обновлённый снимок в репозиторий. Поэтому обычному пользователю
достаточно обновить репозиторий и пересобрать бинарь.

Зависимостей за пределами стандартной библиотеки Python нет намеренно: скрипт обязан
запускаться на чистом раннере без установки пакетов.
"""

from __future__ import annotations

import io
import json
import os
import sys
import urllib.request
import zipfile
from datetime import date
from pathlib import Path

BASE = "https://osv-vulnerabilities.storage.googleapis.com"

# Экосистемы, для которых движок умеет разбирать файлы блокировок. Имена совпадают с
# именами каталогов выгрузки OSV и со значениями поля `ecosystem` в снимке.
ECOSYSTEMS = [
    "npm",
    "PyPI",
    "crates.io",
    "Go",
    "Maven",
    "Packagist",
    "RubyGems",
    "NuGet",
    "Pub",
    "Hex",
]

# Записи о ВРЕДОНОСНЫХ пакетах (идентификатор с префиксом MAL-) исключаются. Их в одной
# только экосистеме npm сотни тысяч, они раздули бы бинарь на порядки, а практическая
# польза для проверки собственных зависимостей проекта невелика: вредоносный пакет
# обычно снимают с реестра до того, как он попадёт в файл блокировок.
SKIP_ID_PREFIXES = ("MAL-",)

# Верхняя граница длины описания. Полные тексты OSV достигают тысяч символов и в снимок
# не нужны: человеку показывается краткая суть, подробности он смотрит по идентификатору.
MAX_SUMMARY = 120

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "crates" / "ailc-core" / "assets" / "osv" / "snapshot.tsv"


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def fetch(ecosystem: str) -> bytes:
    # Имя экосистемы обязано принадлежать закрытому списку. Оно может прийти из переменной
    # окружения `AILC_OSV_ONLY`, то есть извне, и подстановка произвольной строки в адрес
    # означала бы обращение по неконтролируемому пути. Проверка по списку снимает этот
    # класс риска целиком и заодно ловит опечатку в имени экосистемы сразу, а не по факту
    # пустой выгрузки.
    if ecosystem not in ECOSYSTEMS:
        raise ValueError(f"неизвестная экосистема: {ecosystem!r}, допустимы {ECOSYSTEMS}")
    url = f"{BASE}/{ecosystem}/all.zip"
    log(f"скачиваю {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "ailc-osv-updater"})
    with urllib.request.urlopen(req, timeout=600) as resp:
        return resp.read()


def severity_of(entry: dict) -> str:
    """Важность записи в терминах ailc.

    OSV не гарантирует единого поля важности, поэтому берётся, в порядке убывания
    надёжности: явная категория из `database_specific`, затем оценка CVSS из `severity`.
    При отсутствии данных возвращается MEDIUM: неизвестная важность не должна выглядеть
    безобидно, но и завышать её до критической без оснований нельзя.
    """
    ds = entry.get("database_specific") or {}
    raw = str(ds.get("severity") or "").upper()
    if raw in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        return "MEDIUM" if raw == "MODERATE" else raw

    for sev in entry.get("severity") or []:
        score = str(sev.get("score") or "")
        # Формат CVSS-вектора не разбираем: берём числовую оценку, если она есть.
        try:
            value = float(score)
        except ValueError:
            continue
        if value >= 9.0:
            return "CRITICAL"
        if value >= 7.0:
            return "HIGH"
        if value >= 4.0:
            return "MEDIUM"
        return "LOW"
    return "MEDIUM"


def ranges_of(affected: dict) -> list[tuple[str, str]]:
    """Пары (введено, исправлено) из диапазонов записи.

    Берутся диапазоны типов ECOSYSTEM и SEMVER: именно они выражены версиями пакета, а
    не хешами коммитов. Диапазон без границы `fixed` пропускается: движок сверяет версию
    по полуинтервалу, и запись без верхней границы применить нельзя, о чём он сообщает
    отдельно как о подозрительной записи.
    """
    out: list[tuple[str, str]] = []
    for rng in affected.get("ranges") or []:
        if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        introduced = "0"
        for event in rng.get("events") or []:
            if "introduced" in event:
                introduced = str(event["introduced"])
            elif "fixed" in event:
                out.append((introduced, str(event["fixed"])))
            elif "last_affected" in event:
                # Верхняя граница включительная: движок работает с исключающей, поэтому
                # такие записи пропускаем, чтобы не объявить исправленную версию уязвимой.
                continue
    return out


def preferred_id(entry: dict) -> str:
    """Идентификатор записи для показа человеку.

    Предпочитается номер CVE из списка синонимов: именно им пользуются в отчётах,
    политиках и переписке с поставщиками, тогда как внутренние номера GHSA и GO знакомы
    далеко не всем. Побочная польза в том, что записи одной и той же уязвимости из разных
    источников (GHSA и GO для одной CVE) схлопываются при устранении повторов, и снимок
    становится меньше. Если синонима CVE нет, берётся собственный номер записи.
    """
    for alias in entry.get("aliases") or []:
        a = str(alias)
        if a.startswith("CVE-"):
            return a
    return str(entry.get("id") or "")


def compact(entry: dict, ecosystem: str) -> list[dict]:
    vid = preferred_id(entry)
    native = str(entry.get("id") or "")
    if not vid or native.startswith(SKIP_ID_PREFIXES):
        return []
    if entry.get("withdrawn"):
        return []

    summary = (entry.get("summary") or entry.get("details") or "").strip().replace("\n", " ")
    if len(summary) > MAX_SUMMARY:
        summary = summary[: MAX_SUMMARY - 1].rstrip() + "…"
    severity = severity_of(entry)

    rows: list[dict] = []
    for affected in entry.get("affected") or []:
        pkg = affected.get("package") or {}
        name = str(pkg.get("name") or "")
        eco = str(pkg.get("ecosystem") or ecosystem)
        # Экосистема в записи может нести уточнение через двоеточие (например
        # «Alpine:v3.16»); движок сверяет по базовому имени.
        eco = eco.split(":", 1)[0]
        if not name or eco not in ECOSYSTEMS:
            continue
        for introduced, fixed in ranges_of(affected):
            rows.append(
                {
                    "id": vid,
                    "ecosystem": eco,
                    "package": name,
                    "introduced": introduced,
                    "fixed": fixed,
                    "severity": severity,
                    "summary": summary,
                }
            )
    return rows


def main() -> int:
    only = os.environ.get("AILC_OSV_ONLY")
    ecosystems = only.split(",") if only else ECOSYSTEMS

    seen: set[tuple[str, str, str, str, str]] = set()
    vulns: list[dict] = []
    for eco in ecosystems:
        try:
            blob = fetch(eco)
        except Exception as exc:  # сеть недоступна или выгрузка временно отсутствует
            log(f"ОШИБКА: {eco}: {exc}")
            return 2
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            before = len(vulns)
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    entry = json.loads(zf.read(name))
                except Exception:
                    continue
                for row in compact(entry, eco):
                    key = (
                        row["id"],
                        row["ecosystem"],
                        row["package"],
                        row["introduced"],
                        row["fixed"],
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    vulns.append(row)
            log(f"{eco}: записей {len(vulns) - before}")

    # Устойчивый порядок: снимок обязан быть побайтово воспроизводимым, иначе каждый
    # прогон обновления давал бы бессмысленный диф и шумные коммиты.
    vulns.sort(key=lambda r: (r["ecosystem"], r["package"], r["id"], r["introduced"]))

    # Формат снимка: строчный TSV, а не JSON. Причины две. Во-первых, он вдвое компактнее
    # при том же содержании. Во-вторых, снимок хранится в репозитории и обновляется
    # регулярно, а построчный формат с устойчивым порядком даёт системе контроля версий
    # маленькие разностные объекты вместо переписывания всего файла при каждом обновлении.
    # Первая строка это метаданные, начинающиеся с решётки; далее по записи на строку.
    lines = [
        f"# ailc-osv-snapshot\tgenerated_at={date.today().isoformat()}\tcount={len(vulns)}",
        "# поля: id\tecosystem\tpackage\tintroduced\tfixed\tseverity\tsummary",
        "# источник: официальные выгрузки OSV.dev, сборка tools/update-osv.py, "
        "записи о вредоносных пакетах (MAL-*) исключены",
    ]
    for r in vulns:
        summary = r["summary"].replace("\t", " ").replace("\n", " ")
        lines.append(
            "\t".join(
                [
                    r["id"],
                    r["ecosystem"],
                    r["package"],
                    r["introduced"],
                    r["fixed"],
                    r["severity"],
                    summary,
                ]
            )
        )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"записано {len(vulns)} записей в {OUT} ({OUT.stat().st_size} байт)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
