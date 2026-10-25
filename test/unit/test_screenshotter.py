import asyncio
import json
import types

import numpy as np

from drakrun.analyzer import screenshotter as mod


class FakeClient:
    def __init__(self, frames):
        self.frames = iter(frames)

    async def screenshot(self):
        return next(self.frames)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def run(tmp_path, monkeypatch, frames, times, **kwargs):
    monkeypatch.setattr(mod.asyncvnc, "connect", lambda **_: FakeClient(frames))
    clock = iter(times)
    monkeypatch.setattr(mod, "time", types.SimpleNamespace(time=lambda: next(clock)))

    async def no_sleep(_):
        return None

    monkeypatch.setattr(mod.asyncio, "sleep", no_sleep)
    shot = mod.Screenshotter(tmp_path, "localhost", 5901, "x", **kwargs)
    try:
        asyncio.run(shot.perform())
    except Exception:
        pass
    lines = (tmp_path / "screenshots.json").read_text().splitlines()
    return [json.loads(line) for line in lines]


def frame(value):
    img = np.zeros((64, 64, 3), dtype=np.uint8)
    img[: value * 8, :, :] = 255
    return img


def test_unchanged_screen_keeps_only_heartbeat_frames(tmp_path, monkeypatch):
    same = [frame(2)] * 6
    log = run(tmp_path, monkeypatch, same, [0, 10, 20, 31, 40, 62],
              max_screenshots=10, diff_threshold=0.02, heartbeat_interval=30)
    assert [e["index"] for e in log] == [1, 2, 3]
    assert [e.get("heartbeat", False) for e in log] == [False, True, True]


def test_changed_screen_is_kept_and_cap_respected(tmp_path, monkeypatch):
    frames = [frame(i) for i in range(8)]
    log = run(tmp_path, monkeypatch, frames, list(range(8)),
              max_screenshots=3, diff_threshold=0.02, heartbeat_interval=0)
    assert len(log) == 3
    assert not any(e.get("heartbeat") for e in log)
    assert len(list((tmp_path / "screenshots").iterdir())) == 3
