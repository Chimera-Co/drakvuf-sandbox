import click

from drakrun.lib.config import load_config

from .check_root import check_root


@click.command(help="Shut the static-analysis VM down when it has been idle (run by a timer)")
@check_root
def static_vm_idle():
    from drakrun.analyzer.static.vm_backend import stop_if_idle

    click.echo(stop_if_idle(load_config().static))
