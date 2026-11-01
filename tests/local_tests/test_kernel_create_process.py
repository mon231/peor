"""Real ring-0 peor kernel64 chain: CREATE a real user-mode process on the VM.

This is the mandatory execution test: the spawn payload (kernelsrc/spawn.c)
runs on the VM's real kernel through the peor kernel64 chain and from
ring-0 creates a REAL user-mode process running cmd.exe. The proof is
third-party: the child itself writes C:/Windows/Temp/peor_spawn_cmds.txt
via `dir C:/ > that file`, so the test only counts as passed when
something outside our own code wrote that file.
"""
import pathlib
import uuid

import pytest

pytest.importorskip("peor")

pytestmark = pytest.mark.usefixtures("clean_vm_markers")


def _build(wdk, kb, work: pathlib.Path) -> pathlib.Path:
    work.mkdir(parents=True, exist_ok=True)
    payload_sys = wdk.compile_sys(
        [kb.KNSRC / "spawn.c"],
        work / "spawn_payload.sys",
        include_dirs=[str(kb.KNSRC)],
    )
    blob = kb.build_chain(payload_sys, work)
    return kb.compile_loader(wdk, blob, work, chain_name="spawn")


def test_real_process_run_on_vm(wdk, vm, chain_build, tmp_path):
    """A real process runs for real on the VM because of the peor chain."""
    kb = chain_build
    loader = _build(wdk, kb, tmp_path)

    remote_sys = rf"C:\Windows\Temp\{loader.name}"
    remote_svc = "peorSpawnLoader" + uuid.uuid4().hex[:6]
    for p in (kb.PEOR_CHAIN_RESULT_PATH, kb.PEOR_SPAWN_STATUS_PATH,
              kb.PEOR_SPAWN_CMDS_PATH):
        vm.cleanup_marker(p)
    vm.push(loader, remote_sys)
    vm.service_create(remote_svc, remote_sys)
    try:
        vm.service_start(remote_svc)
    finally:
        chain_text = vm.read_text(kb.PEOR_CHAIN_RESULT_PATH)
        spawn_text = vm.read_text(kb.PEOR_SPAWN_STATUS_PATH)
        cmds_text = vm.read_text(kb.PEOR_SPAWN_CMDS_PATH)
        vm.service_stop(remote_svc)
        vm.service_remove(remote_svc)
        for p in (kb.PEOR_CHAIN_RESULT_PATH, kb.PEOR_SPAWN_STATUS_PATH,
                  remote_sys):
            vm.cleanup_marker(p)

    assert chain_text is not None, (
        "loader did not write peor_chain_result.txt - sc start likely "
        "failed to load the driver (check driver signing / testsigning)")
    assert "PEOR_CHAIN_RESULT=0x00000000" in chain_text, chain_text

    assert spawn_text is not None, (
        "spawn payload did not write peor_spawn_status.txt; the chain "
        "returned non-zero or crashed the VM (inspect chain result)")
    assert "PEOR_SPAWN=" in spawn_text
    assert "MISSING_ROUTINE" not in spawn_text, spawn_text
    assert "PEOR_SPAWN=process-was-real" in spawn_text, spawn_text

    # Third-party proof: the child cmd.exe itself redirected `dir C:\`
    # into this file. Only a running process can have written it.
    assert cmds_text is not None, (
        f"child process never wrote {kb.PEOR_SPAWN_CMDS_PATH!r}; "
        f"spawn payload status:\n{spawn_text}")
    assert cmds_text.strip() != "", (
        f"child wrote an empty dir listing; spawn status:\n{spawn_text}")
    assert "Directory of C:" in cmds_text or \
           " Volume in drive C" in cmds_text or \
           "<DIR>" in cmds_text, cmds_text[:400]
