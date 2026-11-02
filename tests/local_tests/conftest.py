"""Local-vm kernel test fixtures.

Opt-in: tests here only run when the VM (192.168.52.129 by default) is
reachable via the OpenSSH client. Everything (WDK build of the payload +
loader, peor CLI chain build) still happens on the host without the VM.

Configuration environment variables:
  PEOR_VM_HOST  (default 192.168.52.129; empty disables entirely)
  PEOR_VM_PORT  (default 22)  PEOR_VM_USER  (ssh identity)  PEOR_VM_SSH_KEY
"""
from __future__ import annotations

import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent       # tests/local_tests
REPO_ROOT = HERE.parents[1]                          # peor repo root

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(HERE))

import _kernel_chain_build as kb                     # noqa: E402
import _vmharness                                    # noqa: E402
from _wdk import WdkError, find_wdk                  # noqa: E402


@pytest.fixture(scope="session")
def wdk():
    """WDK toolchain (cl/link over the WDK km headers/ntoskrnl.lib)."""
    try:
        toolchain = find_wdk()
    except WdkError as e:
        pytest.skip(f"WDK toolchain unavailable: {e}")
    return toolchain


@pytest.fixture(scope="session")
def vm(wdk):
    """VM harness; skips the test when the machine cannot be reached.

    Also trusts the local test-signing certificate in the VM's
    Root/TrustedPeople stores, so sc start can load signed drivers.
    """
    try:
        harness = _vmharness.VmHarness.from_env()
    except _vmharness.VmError as e:
        pytest.skip(f"VM harness unavailable: {e}")
    if not harness.reachable():
        pytest.skip(
            f"VM {harness._target} unreachable; boot it / start OpenSSH"
        )
    import _signing
    _signing.ensure_cert()
    _signing.install_on_vm(harness)
    return harness


@pytest.fixture()
def chain_build():
    """Small facade on _kernel_chain_build for the tests."""
    return kb


@pytest.fixture()
def clean_vm_markers(vm, chain_build):
    """Delete every marker file this suite writes before the test runs."""
    for path in (chain_build.PEOR_CHAIN_RESULT_PATH,
                 chain_build.PEOR_CALC_RESULT_PATH,
                 chain_build.PEOR_SPAWN_STATUS_PATH,
                 chain_build.PEOR_SPAWN_CMDS_PATH):
        vm.cleanup_marker(path)
    yield
