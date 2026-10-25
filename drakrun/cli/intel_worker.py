"""Worker for host-only observable intelligence."""

import click


@click.command()
@click.option("--burst", is_flag=True)
def intel_worker(burst):
    from redis import Redis
    from rq import Worker

    from drakrun.analyzer.static.worker import INTEL_QUEUE_NAME
    from drakrun.lib.config import load_config

    config = load_config()
    Worker(
        [INTEL_QUEUE_NAME],
        connection=Redis(
            host=config.redis.host,
            port=config.redis.port,
            username=config.redis.username,
            password=config.redis.password,
        ),
    ).work(burst=burst)
