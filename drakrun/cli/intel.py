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


@intel.command("providers")
@click.option("--test", "test_lookup", is_flag=True)
def providers_command(test_lookup):
    """Show key presence and optionally query the EICAR hash."""
    from drakrun.lib.intel.online import inventory, providers
    from drakrun.lib.intel.online.base import key_exists
    from drakrun.lib.intel.online.cache import Cache

    config = load_config().intel
    cache = Cache(config.cache_path) if test_lookup else None
    for provider, info in zip(providers(), inventory(config)):
        message = f"{provider.id}: key_file={'yes' if key_exists(provider, config) else 'no'} configured={'yes' if info['configured'] else 'no'} enabled={'yes' if info['enabled'] else 'no'}"
        if test_lookup and info["configured"] and info["enabled"]:
            result = provider.lookup(
                "sha256",
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                config,
                cache,
            )
            message += f" status={result['status']}"
        click.echo(message)


@intel.command("trails-sync")
@click.option("--log", "log_path", type=click.Path(dir_okay=False), default=None)
def trails_sync_command(log_path):
    """Pull github.com/stamparm/trails, log the diff and rebuild the attribution index."""
    from drakrun.lib.intel.trails import sync

    config = load_config().intel
    if config.trails_db_path is None:
        raise click.ClickException("Set [intel] trails_db_path to enable Maltrail attribution")
    log_path = log_path or config.trails_checkout.parent / "trails-changes.jsonl"
    record = sync(config.trails_checkout, config.trails_db_path, log_path)
    click.echo(
        f"trails {str(record['to'])[:12]} ({record['committed_at']}): {record['status']}"
        + (
            f"; {record['files_changed']} files changed, +{record['added']}/-{record['removed']} lines"
            if "files_changed" in record
            else ""
        )
        + ("; LICENCE CHANGED, review it" if record.get("license_changed") else "")
    )


@intel.command("trails-status")
def trails_status_command():
    from drakrun.lib.intel.trails import read_meta

    path = load_config().intel.trails_db_path
    if path is None or not path.exists():
        click.echo("Maltrail attribution unavailable: index missing (run drakrun intel trails-sync)")
        return
    meta = read_meta(path)
    click.echo(
        f"trails {meta['commit'][:12]} committed {meta['committed_at']}, built {meta['built_at']}: "
        f"{meta['trails']} trails ({meta['apt_trails']} APT), "
        + ", ".join(f"{k} {v}" for k, v in meta["counts"].items())
    )
