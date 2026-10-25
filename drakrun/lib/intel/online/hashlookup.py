"""CIRCL hashlookup observable lookup adapter."""

from urllib.parse import quote

from .base import Provider


class Adapter(Provider):
    id = "hashlookup"
    label = "CIRCL hashlookup"
    host = "hashlookup.circl.lu"
    types = ("sha256",)
    header = None
    optional_key = True

    def request(self, kind, value):

        return f"https://{self.host}/lookup/sha256/{quote(value)}", None, {}

    def parse(self, doc, kind, value):

        if not doc.get("SHA-256") and not doc.get("FileName"):
            return {"status": "not_found"}
        return dict(
            verdict="unknown" if doc.get("KnownMalicious") else "harmless",
            permalink=f"https://hashlookup.circl.lu/lookup/sha256/{value}",
            details={
                k: doc.get(k)
                for k in (
                    "source",
                    "ProductCode",
                    "ProductName",
                    "FileName",
                    "KnownMalicious",
                )
            },
        )
