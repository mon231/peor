"""Visual Studio solution build of the local kernel drivers.

The whole local_tests driver project set (loader + per-test payloads) MUST
build through the real WDK kernel-mode MSBuild targets. This test pins the
build matrix ({Debug, Release} x {x64, Win32}) and, for every payload, the
peor post-build chain artifact whose conformance is checked via the same
arch prologue bytes the peor CLI always emits.
"""
from __future__ import annotations

import re

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


@pytest.mark.parametrize("name", ["loader", "calc", "spawn"])
def test_win32_stub_def_covers_x64_kernel_imports(solution, name):
    """ntoskrnl_x86.def must cover every ntoskrnl import the x64 build makes.

    The x86 stubs are hand-maintained (WKD ships no km\\x86 anymore); a
    payload growing an import the .def misses would break the Win32 link for
    a driver that still links on x64.
    """
    pefile = pytest.importorskip("pefile")
    built = solution.build("Release", "x64")
    sys_imports = set()
    pe = pefile.PE(str(built.sys(name)), fast_load=True)
    pe.parse_data_directories(
        [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        sys_imports.update(
            imp.name.decode() for imp in entry.imports)

    def_names = set()
    in_exports = False
    for line in _solution._DEF_PATH.read_text(encoding="utf-8").splitlines():
        token = line.strip()
        if not token or token.startswith(";"):
            continue
        if token == "EXPORTS":
            in_exports = True
            continue
        if not in_exports:
            continue
        m = re.match(r"^@?([A-Za-z_][A-Za-z0-9_$]*?)(?:@\d+)?$", token)
        if m:
            def_names.add(m.group(1))
    missing = sys_imports - def_names
    assert not missing, f"ntoskrnl_x86.def missing: {sorted(missing)}"
