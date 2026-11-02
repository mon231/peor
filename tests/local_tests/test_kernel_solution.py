"""Visual Studio solution build of the local kernel drivers.

The whole local_tests driver project set (loader + per-test payloads) MUST
build through the real WDK kernel-mode MSBuild targets. This test pins the
build matrix ({Debug, Release} x {x64, Win32}) and, for every payload, the
peor post-build chain artifact whose conformance is checked via the same
arch prologue bytes the peor CLI always emits.
"""
from __future__ import annotations

import pytest

import _solution
import _kernel_chain_build as kb

pytest.importorskip("peor")


@pytest.fixture(scope="session")
def solution():
    try:
        return _solution.Solution()
    except _solution.SolutionError as e:
        pytest.skip(f"solution toolchain unavailable: {e}")


@pytest.mark.parametrize("platform", ["x64", "Win32"])
@pytest.mark.parametrize("config", ["Release", "Debug"])
def test_solution_build_produces_drivers_and_chains(config, platform, solution):
    """Every config builds all 3 drivers and the peor post-build chain bins."""
    kb.ensure_shellcodes()
    built = solution.build(config, platform)
    for name in ("loader", "calc", "spawn"):
        built.sys(name)
    for name in ("calc", "spawn"):
        blob = built.chain_bin(name).read_bytes()
        _solution.verify_kernel_chain_prologue(blob, platform)

    release_bin = solution.build("Release", platform).chain_bin("calc")
    debug_bin = solution.build("Debug", platform).chain_bin("calc")
    assert release_bin != debug_bin  # per-config OutDir, no shared artifact
