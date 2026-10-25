"""Bounded, host-only observable queries. There is no sample upload interface."""

import json
import socket
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

HASHES = ("sha256", "sha1", "md5")
NETWORK = ("domain", "ip", "url")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("redirect refused")


def probe(host):
    try:
        with socket.create_connection((host, 443), timeout=3):
            return True
    except OSError:
        return False


def key_path(provider, config):
    return Path(
        config.abusech_key_file
        if provider.id in {"malwarebazaar", "threatfox", "urlhaus"}
        else Path(config.keys_dir) / provider.id
    )


def key_exists(provider, config):
    try:
        return key_path(provider, config).is_file()
    except OSError:
        return False


def read_key(provider, config):
    try:
        return key_path(provider, config).read_text().strip()
    except OSError:
        return ""


def bounded(value, depth=0):
    if depth > 4:
        return None
    if isinstance(value, dict):
        return {
            str(k)[:100]: bounded(v, depth + 1) for k, v in list(value.items())[:20]
        }
    if isinstance(value, list):
        return [bounded(v, depth + 1) for v in value[:20]]
    if isinstance(value, str):
        return value[:500]
    return value if value is None or isinstance(value, (int, float, bool)) else None


# Longest a single lookup waits for its provider's request spacing.
MAX_WAIT_S = 20


class Provider:
    optional_key = False
    interval = 1
    daily_cap = 500
    # Observables looked up per analysis (sample hash first, then observed network indicators, then strings).
    max_lookups = 20
    header = None
    # Larger details are dropped (only `truncated` kept) so one provider cannot bloat the report.
    max_details_bytes = 8192

    def result(self, kind, value, status="ok", **fields):
        return dict(
            provider=self.id,
            observable=value,
            type=kind,
            status=status,
            verdict="unknown",
            family=None,
            tags=[],
            first_seen=None,
            last_seen=None,
            permalink=None,
            details={},
            **fields
        )

    def lookup(self, kind, value, config, cache):
        result = self.result(kind, value)
        if kind not in self.types:
            return {**result, "status": "unsupported"}
        key = read_key(self, config)
        if not key and not self.optional_key:
            return {**result, "status": "not_configured"}
        hit = cache.get(self.id, kind, value)
        if hit is not None:
            return hit
        try:
            url, data, headers = self.request(kind, value)
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or parsed.hostname != self.host
                or parsed.username
                or parsed.password
            ):
                raise ValueError("invalid endpoint")
            if not probe(self.host):
                return {**result, "status": "offline"}
            # Wait out the provider's spacing (e.g. 15 s for VirusTotal's public API) rather than skipping the
            # lookup; give up only when the daily budget is spent or the wait would be too long.
            deadline = time.monotonic() + MAX_WAIT_S
            while not cache.reserve(self.id, self.interval, self.daily_cap):
                wait = cache.delay(self.id, self.interval, self.daily_cap)
                if wait is None or time.monotonic() + wait > deadline:
                    return {**result, "status": "rate_limited"}
                time.sleep(max(wait, 0.05))
            if key and self.header:
                headers[self.header] = key
            opener = urllib.request.build_opener(
                NoRedirect(),
                urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            )
            with opener.open(
                urllib.request.Request(url, data=data, headers=headers),
                timeout=min(config.request_timeout_s, 10),
            ) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError("response too large")
            result.update(bounded(self.parse(json.loads(raw), kind, value)))
            if len(json.dumps(result.get("details", {}))) > self.max_details_bytes:
                result["details"] = {"truncated": True}
            # Reject provider echoes before either the cache or report receives them.
            if key and key in json.dumps(result, ensure_ascii=False):
                raise ValueError("credential echo")
        except urllib.error.HTTPError as error:
            result["status"] = (
                "not_found"
                if error.code == 404
                else "rate_limited" if error.code == 429 else "error"
            )
            result["details"] = {
                "reason": (
                    "bad key"
                    if error.code in (401, 403)
                    else "not in the provider's data" if error.code == 404 else "HTTP failure"
                ),
                "http_status": error.code,
            }
        except (TimeoutError, socket.timeout):
            result.update(status="error", details={"reason": "timeout"})
        except Exception:
            result = self.result(kind, value, "error")
            result["details"] = {"reason": "request or parse failed"}
        if result["status"] in {"ok", "not_found"}:
            cache.put(self.id, kind, value, result)
        return result
