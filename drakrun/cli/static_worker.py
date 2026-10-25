import click

from .check_root import check_root


@click.command(
    help="Start the static-analysis worker (runs chimera_static in a locked-down container)"
)
@click.option(
    "--burst", is_flag=True, default=False, help="Process queued jobs then exit"
)
@click.option(
    "--deep",
    is_flag=True,
    default=False,
    help="Run the deep pass (capa + FLOSS) queue instead",
)
@check_root
def static_worker(burst: bool, deep: bool):
    from drakrun.analyzer.static.worker import static_worker_main

    static_worker_main(burst=burst, deep=deep)
