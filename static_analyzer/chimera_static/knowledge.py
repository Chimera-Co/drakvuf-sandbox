"""Lazy, process-local lookups for the bundled analyst reference tables."""

from functools import lru_cache
from importlib.resources import files


@lru_cache(maxsize=4)
def load(name: str) -> dict:
    import json

    if name not in {"winapi", "libraries", "linux_symbols", "strings_rules"}:
        raise ValueError("unknown knowledge table")
    return json.loads(files("chimera_static").joinpath("knowledge", name + ".json").read_text(encoding="utf-8"))


def normalize_api(name: str) -> str:
    """Only strip a terminal A/W if the resulting base is known; preserve Ex."""
    table = load("winapi")
    if name in table:
        return name
    if name.endswith(("A", "W")) and name[:-1] in table:
        return name[:-1]
    return name


def api(name: str) -> dict:
    return load("winapi").get(normalize_api(name), {})


def library(name: str) -> dict:
    return load("libraries").get(name.lower(), {})


def symbol(name: str) -> dict:
    return load("linux_symbols").get(name.split("@", 1)[0], {})


def annotation(record: dict) -> dict:
    return {key: record.get(key, default) for key, default in (
        ("category", "misc"), ("description", ""), ("attacker_use", ""), ("severity", 0), ("attack", []))}


def imports_summary(functions: list[dict], total: int | None = None) -> dict:
    from collections import Counter

    flagged = [f for f in functions if f["severity"]]
    return {"categories": dict(Counter(f["category"] for f in functions)),
            "severities": dict(Counter(str(f["severity"]) for f in functions)),
            "flagged_count": len(flagged), "annotated_count": len(functions),
            "total_count": len(functions) if total is None else total,
            "truncated": total is not None and total > len(functions),
            "top_flagged": sorted(flagged, key=lambda f: (-f["severity"], f["name"] or ""))[:100]}
