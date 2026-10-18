import click

from .check_root import check_root


@click.command(help="Start drakrun evasion-verification worker")
@click.option(
    "--vm-id",
    "vm_id",
    default=1,
    type=int,
    show_default=True,
    help="VM id to use for running evasion verification scans",
)
@click.option(
    "--burst",
    is_flag=True,
    default=False,
    help="Process currently queued jobs then exit, instead of running forever",
)
@check_root
def evasion_worker(vm_id: int, burst: bool):
    from drakrun.evasion.worker import evasion_worker_main

    evasion_worker_main(vm_id, burst=burst)
