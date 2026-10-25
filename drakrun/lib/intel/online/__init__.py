"""Online observable providers, independent of classifier features."""

from importlib import import_module

IDS = (
    "virustotal",
    "malwarebazaar",
    "threatfox",
    "urlhaus",
    "otx",
    "abuseipdb",
    "greynoise",
    "hashlookup",
    "hybridanalysis",
    "urlscan",
)


def providers():
    return [import_module(f"{__name__}.{name}").Adapter() for name in IDS]


def inventory(config):
    from .base import key_exists

    return [
        dict(
            id=p.id,
            label=p.label,
            configured=p.optional_key or key_exists(p, config),
            enabled=config.providers.get(p.id, True),
            observable_types=list(p.types),
        )
        for p in providers()
    ]
