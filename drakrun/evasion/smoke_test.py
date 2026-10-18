"""Diagnostic-only smoke test for the real Xen/DRAKVUF guest lifecycle.

Exercises run_vm -> restore -> boot -> Injector -> Drakshell -> GuestSession
-> harmless guest command -> file upload -> file retrieval -> byte
comparison -> run_vm's own teardown, WITHOUT performing any evasion
verification: no verifier adapter runs, no EvasionScanMetadata is
constructed, no CHIMERA score is computed, and neither evasion.json nor
report.html is written. This is a Phase-G infrastructure check only, not a
scan, and must never be mistaken for one by anything reading scan storage.

Every Xen/DRAKVUF-only import is local to run_guest_smoke_test's body, for
the same reason drakrun.evasion.worker.worker_verify does it: this module
must stay importable on a plain Windows checkout with no Xen installed.
"""

from __future__ import annotations

import logging
import pathlib
import tempfile
from dataclasses import dataclass

logger = logging.getLogger(__name__)

SMOKE_TEST_PAYLOAD = b"CHIMERA-PHASE-G-SMOKE-TEST-0123456789\n"
GUEST_REMOTE_PATH = r"C:\Windows\Temp\chimera_smoke_test.txt"
PROBE_TIMEOUT_SECONDS = 30.0
PROBE_COMMAND = ["cmd", "/c", "ver"]


@dataclass
class SmokeTestResult:
    """Plain diagnostic result, deliberately not an EvasionScanMetadata/
    EvasionScore - this never gets written to EVASION_DIR or the scan
    listing, only logged/printed by the CLI command that calls this."""

    vm_id: int
    probe_ok: bool = False
    probe_detail: str = ""
    upload_ok: bool = False
    upload_error: str = ""
    retrieval_ok: bool = False
    retrieval_error: str = ""
    bytes_match: bool = False

    @property
    def success(self) -> bool:
        return (
            self.probe_ok and self.upload_ok and self.retrieval_ok and self.bytes_match
        )


def run_guest_smoke_test(vm_id: int) -> SmokeTestResult:
    """Restore vm_id's disposable overlay, connect a real GuestSession, run
    one harmless command probe and one file upload/retrieval round-trip,
    then let run_vm's own context manager destroy the VM on the way out -
    regardless of whether every step above passed or failed."""
    if vm_id == 0:
        raise ValueError(
            "vm_id=0 is the golden/template image and must never be used "
            "for the smoke test"
        )

    from drakrun.analyzer.run_tools import run_vm
    from drakrun.evasion.guest_runner import connect_guest_session
    from drakrun.lib.config import NetworkConfigSection, load_config
    from drakrun.lib.injector import Injector
    from drakrun.lib.install_info import InstallInfo
    from drakrun.lib.libvmi import VmiInfo
    from drakrun.lib.paths import (
        INSTALL_INFO_PATH,
        VMI_INFO_PATH,
        VMI_KERNEL_PROFILE_PATH,
    )

    result = SmokeTestResult(vm_id=vm_id)

    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    vmi_info = VmiInfo.load(VMI_INFO_PATH)
    kernel_profile_path = VMI_KERNEL_PROFILE_PATH.as_posix()
    network_conf = NetworkConfigSection(
        out_interface=config.network.out_interface,
        dns_server=config.network.dns_server,
        net_enable=config.network.net_enable,
    )

    logger.info("[smoke-test] phase=restore vm_id=%s", vm_id)
    with run_vm(vm_id, install_info, network_conf) as vm:
        logger.info("[smoke-test] phase=booted vm_name=%s", vm.vm_name)

        injector = Injector(vm.vm_name, vmi_info, kernel_profile_path)
        session = connect_guest_session(vm.vm_name, injector)
        logger.info("[smoke-test] phase=connected vm_name=%s", vm.vm_name)

        logger.info("[smoke-test] phase=probe command=%s", PROBE_COMMAND)
        result.probe_ok, result.probe_detail = session.probe_command(
            PROBE_COMMAND, PROBE_TIMEOUT_SECONDS
        )
        logger.info(
            "[smoke-test] phase=probe ok=%s detail=%s",
            result.probe_ok,
            result.probe_detail,
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            local_upload_path = pathlib.Path(tmp_dir) / "smoke_test_upload.txt"
            local_upload_path.write_bytes(SMOKE_TEST_PAYLOAD)

            logger.info("[smoke-test] phase=upload remote_path=%s", GUEST_REMOTE_PATH)
            try:
                session.put_file(local_upload_path, GUEST_REMOTE_PATH)
                result.upload_ok = True
            except Exception as exc:  # noqa: BLE001 - diagnostic result, not re-raised
                result.upload_error = str(exc)
                logger.exception("[smoke-test] phase=upload failed")

            if result.upload_ok:
                local_retrieved_path = (
                    pathlib.Path(tmp_dir) / "smoke_test_retrieved.txt"
                )
                logger.info(
                    "[smoke-test] phase=retrieve remote_path=%s", GUEST_REMOTE_PATH
                )
                try:
                    session.get_file(GUEST_REMOTE_PATH, local_retrieved_path)
                    result.retrieval_ok = True
                except (
                    Exception
                ) as exc:  # noqa: BLE001 - diagnostic result, not re-raised
                    result.retrieval_error = str(exc)
                    logger.exception("[smoke-test] phase=retrieve failed")

                if result.retrieval_ok:
                    retrieved_bytes = local_retrieved_path.read_bytes()
                    result.bytes_match = retrieved_bytes == SMOKE_TEST_PAYLOAD
                    logger.info(
                        "[smoke-test] phase=compare match=%s", result.bytes_match
                    )

        logger.info("[smoke-test] phase=teardown vm_name=%s", vm.vm_name)
    # run_vm's own finally: vm.destroy() has already run by this point,
    # whether the block above completed normally or raised.

    logger.info(
        "[smoke-test] phase=done vm_id=%s overall=%s",
        vm_id,
        "PASS" if result.success else "FAIL",
    )
    return result


__all__ = ["SmokeTestResult", "run_guest_smoke_test"]
