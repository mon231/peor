"""Real ring-0 peor kernel64 chain: calc payload on the Windows VM.

Pipeline exercised (all on the host except the VM execution step):
  WDK-compile kernelsrc/calc.c -> calc_payload.sys,
  `python -m peor -i calc_payload.sys --platform kernel64` -> chain blob,
  WDK-compile SCM loader embedding the blob -> peor_load_calc.sys,
  push to VM, `sc create`/`sc start`, read markers back via ssh.
"""
import pathlib
import uuid

import pytest

import _signing

pytest.importorskip("peor")          # repo root is on sys.path via conftest

pytestmark = pytest.mark.usefixtures("clean_vm_markers")


def _build(wdk, kb, work: pathlib.Path) -> pathlib.Path:
    """host-side build: payload sys -> worst chain blob -> loader sys."""
    work.mkdir(parents=True, exist_ok=True)
    payload_sys = wdk.compile_sys(
        [kb.KNSRC / "calc.c"],
        work / "calc_payload.sys",
        include_dirs=[str(kb.KNSRC)],
    )
    blob = kb.build_chain(payload_sys, work)
    return kb.compile_loader(wdk, blob, work, chain_name="calc")


def test_real_kernel_calc_on_vm(wdk, vm, chain_build, tmp_path):
    """calc a+b==5 executes on the VM's real kernel via the peor chain."""
    kb = chain_build
    loader = _build(wdk, kb, tmp_path)
    _signing.sign(wdk, loader)

    # VM prep: stale artifacts out of the way.
    remote_sys = rf"C:\Windows\Temp\{loader.name}"
    remote_svc = "peorCalcLoader" + uuid.uuid4().hex[:6]
    vm.cleanup_marker(kb.PEOR_CHAIN_RESULT_PATH)
    vm.cleanup_marker(kb.PEOR_CALC_RESULT_PATH)
    vm.push(loader, remote_sys)
    vm.service_create(remote_svc, remote_sys)
    try:
        vm.service_start(remote_svc)
    finally:
        chain_text = vm.read_text(kb.PEOR_CHAIN_RESULT_PATH)
        calc_text = vm.read_text(kb.PEOR_CALC_RESULT_PATH)
        vm.service_stop(remote_svc)
        vm.service_remove(remote_svc)
        for p in (kb.PEOR_CHAIN_RESULT_PATH, kb.PEOR_CALC_RESULT_PATH,
                  remote_sys):
            vm.cleanup_marker(p)

    # Load failures (DSE, missing service, etc.) surface through the
    # markers rather than the ssh return code.
    assert chain_text is not None, (
        "loader did not write peor_chain_result.txt; "
        "sc start output: check VM event log, driver may have failed "
        "to load (driver signing / bcdedit testsigning?)")
    assert "PEOR_CHAIN_RESULT=0x" in chain_text
    assert "PEOR_CHAIN_RESULT=0x00000000" in chain_text, chain_text
    assert calc_text is not None, "calc payload returned but wrote no marker"
    assert "PEOR_CALC=0x00000005" in calc_text, calc_text
