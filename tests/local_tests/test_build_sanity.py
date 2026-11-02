"""Build-only sanity checks for the local VM test suite (no VM needed).

Catches toolchain/pipeline errors early on any Windows host that has the
WDK installed: WDK-compile every kernelsrc payload, run `python -m peor`
on it, embed into the loader, and verify the output .sys/.bin shapes.
Runtime assertions (things needing the VM) live in the other modules.
"""
import pathlib

import pytest

pytest.importorskip("peor")


def test_wdk_toolchain_located(wdk):
    assert wdk.cl.exists()
    assert wdk.link.exists()


def test_compile_and_chain_calc(wdk, chain_build, tmp_path):
    kb = chain_build
    payload = wdk.compile_sys([kb.KNSRC / "calc.c"],
                              tmp_path / "calc_payload.sys",
                              include_dirs=[str(kb.KNSRC)])
    blob = kb.build_chain(payload, tmp_path)
    assert len(blob) > 4096
    assert blob[:4] == b"\x53\x55\x56\x57"    # kernel64 push rbx/rbp/rsi/rdi
    loader = kb.compile_loader(wdk, blob, tmp_path, chain_name="calc")
    assert loader.exists() and loader.stat().st_size > 1024


def test_compile_and_chain_spawn(wdk, chain_build, tmp_path):
    kb = chain_build
    payload = wdk.compile_sys([kb.KNSRC / "spawn.c"],
                              tmp_path / "spawn_payload.sys",
                              include_dirs=[str(kb.KNSRC)])
    blob = kb.build_chain(payload, tmp_path)
    assert blob[:4] == b"\x53\x55\x56\x57"
    loader = kb.compile_loader(wdk, blob, tmp_path, chain_name="spawn")
    assert loader.exists() and loader.stat().st_size > 1024
