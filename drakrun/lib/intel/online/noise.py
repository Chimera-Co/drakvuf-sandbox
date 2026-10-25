"""Names not worth an online lookup.

Domain reputation for Windows' own background traffic (update, telemetry, certificate revocation) and for XML
namespace strings found in nearly every PE says nothing about the sample, and spends provider quota. Full URLs
from the sample's own processes are still looked up even on these hosts (malware hosts payloads on shared
services). Non-public names (localhost, .local, single labels) are never sent anywhere.
"""

NON_PUBLIC_SUFFIXES = (
    "localhost", "local", "localdomain", "lan", "home", "internal", "intranet", "corp", "arpa", "invalid",
)

BACKGROUND_SUFFIXES = (
    # Windows and Microsoft services the guest contacts on its own
    "microsoft.com", "windowsupdate.com", "windows.com", "live.com", "live.net", "msftncsi.com",
    "msftconnecttest.com", "msedge.net", "bing.com", "bing.net", "msn.com", "office.com", "office.net",
    "office365.com", "skype.com", "xboxlive.com", "microsoftonline.com", "msocsp.com",
    # certificate revocation and CA infrastructure
    "digicert.com", "lencr.org", "letsencrypt.org", "sectigo.com", "usertrust.com", "globalsign.com",
    "globalsign.net", "entrust.net", "comodoca.com", "symcd.com", "symcb.com", "verisign.com",
    # Azure AD sign-in (Windows itself) and the run's own network simulator
    "login.windows.net", "inetsim.org",
    # XML and schema namespaces that appear as strings in ordinary files
    "w3.org", "xmlsoap.org", "openxmlformats.org", "purl.org", "ns.adobe.com", "schemas.android.com",
)


def _matches(host, suffixes):
    host = (host or "").lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in suffixes)


def non_public(host):
    host = (host or "").lower().rstrip(".")
    return "." not in host or _matches(host, NON_PUBLIC_SUFFIXES)


def background(host):
    return _matches(host, BACKGROUND_SUFFIXES)


def string_artifact(kind, host):
    """Values that string extraction finds in ordinary files but that are almost never real indicators:
    version numbers read as IPs (1.9.16.1), dotted settings keys read as domains, one-letter names (e.com)."""
    if kind == "ip":
        try:
            return all(int(part) <= 32 for part in host.split("."))
        except ValueError:
            return False
    labels = (host or "").lower().rstrip(".").split(".")
    return len(labels) > 4 or len(labels) < 2 or len(labels[-2]) < 2
