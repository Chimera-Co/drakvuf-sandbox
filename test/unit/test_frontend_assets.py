"""Top-level frontend assets and the SPA fallback, using an offline dist."""

import importlib
import sys

import pytest


@pytest.fixture
def frontend_client(monkeypatch, base_config, tmp_path):
    monkeypatch.setattr("drakrun.lib.config.load_config", lambda: base_config)
    monkeypatch.setattr("rq_dashboard.web.setup_rq_connection", lambda app: None)
    sys.modules.pop("drakrun.web.app", None)
    module = importlib.import_module("drakrun.web.app")
    monkeypatch.setattr(module.app, "root_path", str(tmp_path))
    dist = tmp_path / "frontend" / "dist"
    dist.mkdir(parents=True)
    (dist / "index.html").write_text("<html>SPA</html>")
    for name in ("favicon.ico", "favicon-32x32.png", "apple-touch-icon.png",
                 "android-chrome-192x192.png", "android-chrome-512x512.png",
                 "favicon.svg", "site.webmanifest"):
        (dist / name).write_bytes(b"asset")
    (dist / "nested").mkdir()
    (dist / "nested" / "secret.png").write_bytes(b"not public")
    yield module.app.test_client()
    sys.modules.pop("drakrun.web.app", None)


@pytest.mark.parametrize("name,mimetype", [
    ("favicon.ico", "image/vnd.microsoft.icon"),
    ("favicon-32x32.png", "image/png"),
    ("apple-touch-icon.png", "image/png"),
    ("android-chrome-192x192.png", "image/png"),
    ("android-chrome-512x512.png", "image/png"),
    ("favicon.svg", "image/svg+xml"),
    ("site.webmanifest", "application/manifest+json"),
])
def test_top_level_assets(frontend_client, name, mimetype):
    response = frontend_client.get(f"/{name}")
    assert response.status_code == 200
    assert response.data == b"asset"
    assert response.mimetype == mimetype


@pytest.mark.parametrize("path", [
    "/", "/upload", "/analysis/example", "/missing.png", "/nested/secret.png",
    "/../secret.png", "/nested%5Csecret.png",
])
def test_spa_fallback(frontend_client, path):
    response = frontend_client.get(path)
    assert response.status_code == 200
    assert response.mimetype == "text/html"
    assert response.data == b"<html>SPA</html>"
