import sys

import click

from .check_root import check_root


@click.command(
    help=(
        "Run a harmless Xen/DRAKVUF guest-lifecycle smoke test "
        "(diagnostic only, NOT a verification scan)"
    )
)
@click.option(
    "--vm-id",
    "vm_id",
    default=2,
    type=int,
    show_default=True,
    help="VM id to use for the disposable smoke-test overlay (must not be 0)",
)
@check_root
def evasion_smoke_test(vm_id: int):
    from drakrun.evasion.smoke_test import run_guest_smoke_test

    result = run_guest_smoke_test(vm_id)

    click.echo(f"[smoke-test] vm_id={result.vm_id}")
    click.echo(
        f"[smoke-test] command probe: {'OK' if result.probe_ok else 'FAIL'}"
        f" - {result.probe_detail}"
    )
    upload_line = f"[smoke-test] upload: {'OK' if result.upload_ok else 'FAIL'}"
    if result.upload_error:
        upload_line += f" - {result.upload_error}"
    click.echo(upload_line)
    retrieval_line = (
        f"[smoke-test] retrieval: {'OK' if result.retrieval_ok else 'FAIL'}"
    )
    if result.retrieval_error:
        retrieval_line += f" - {result.retrieval_error}"
    click.echo(retrieval_line)
    click.echo(
        f"[smoke-test] byte comparison: {'MATCH' if result.bytes_match else 'MISMATCH'}"
    )
    click.echo(f"[smoke-test] overall: {'PASS' if result.success else 'FAIL'}")

    if not result.success:
        sys.exit(1)
