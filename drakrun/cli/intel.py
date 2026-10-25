"""Offline threat intelligence administration."""

import json
import sqlite3
from datetime import datetime, timezone

import click

from drakrun.lib.config import load_config
from drakrun.lib.intel import import_bundle


@click.group()
def intel():
    """Import and inspect offline indicator snapshots."""


@intel.command("import")
@click.argument("bundle", type=click.Path(exists=True, dir_okay=False))
def import_command(bundle):
    config = load_config().intel
    try:
        manifest = import_bundle(bundle, config.db_path, config.max_bundle_bytes)
    except (ValueError, OSError, KeyError, sqlite3.Error) as exc:
        raise click.ClickException("Invalid bundle or inaccessible database") from exc
    click.echo(f"Imported {len(manifest['feeds'])} feeds")


@intel.command()
def status():
    path = load_config().intel.db_path
    if not path.exists():
        click.echo("Offline intel unavailable: database missing")
        return
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        for name, raw in db.execute("SELECT name,metadata FROM feeds ORDER BY name"):
            feed = json.loads(raw)
            now = datetime.now(timezone.utc)
            fetched = datetime.fromisoformat(feed["fetched_at"].replace("Z", "+00:00"))
            stale = (
                datetime.fromisoformat(feed["expires_at"].replace("Z", "+00:00")) < now
            )
            count = db.execute(
                "SELECT count(*) FROM indicators WHERE feed=?", (name,)
            ).fetchone()[0]
            click.echo(
                f"{name}: {count} indicators; age {(now-fetched).days} days; expires {feed['expires_at']}; {'expired/stale' if stale else 'fresh'}"
            )
        latest = json.loads(
            db.execute(
                "SELECT manifest FROM imports ORDER BY rowid DESC LIMIT 1"
            ).fetchone()[0]
        )
        for failure in latest.get("failures", []):
            click.echo(f"{failure['name']}: missing; fetch or parse failed")
