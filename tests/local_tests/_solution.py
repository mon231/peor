"""MSBuild facade for the local kernel test Visual Studio solution.

The three driver projects (loader + per-test payloads) live in
tests/local_tests/solution and MUST build through the real WDK kernel-mode
MSBuild targets (PlatformToolset WindowsKernelModeDriver10.0 over the
Windows Kits build\\<ver> compiler config), not through hand-rolled
cl/link. The payload projects run the peor CLI as MSBuild post-build and
emit the peor chain shellcode next to their .sys:

    <solution>\\out\\<config>\\<arch>\\peor_<name>_chain_<arch>.bin

which the loader driver reads from C:\\shellcode on the VM at run time.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess


class SolutionError(RuntimeError):
    """MSBuild location, or a solution build, failed."""


_MSBUILD_DEFAULT = (
    pathlib.Path(r"C:\Program Files\Microsoft Visual Studio\18\Community")
    / "MSBuild" / "Current" / "Bin" / "MSBuild.exe"
)
_SOLUTION_NAME = "peor_kernel_tests.sln"
_OUT_DIRNAME = "out"

# The worst chain prologue peor emits, per target platform. km64: the
# chain saves the full callee-saved set (push rbx, rbp, rsi, rdi, then
# r12..r15); km32 the 32-bit mirror (push ebx/ebp/esi/edi).
_CHAIN_PROLOGUE = {
    "x64": bytes.fromhex("5355565741544155415641 57".replace(" ", "")),
    "Win32": bytes.fromhex("53555657"),
}


def find_msbuild() -> pathlib.Path:
    """Locate MSBuild.exe: known path first, vswhere second."""
    if _MSBUILD_DEFAULT.is_file():
        return _MSBUILD_DEFAULT
    vswhere = shutil.which("vswhere") or (
        pathlib.Path(r"C:\Program Files (x86)\Microsoft Visual Studio"
                     r"\Installer\vswhere.exe"))
    if pathlib.Path(vswhere).is_file():
        out = subprocess.run(
            [str(vswhere), "-latest", "-products", "*",
             "-find", r"**\MSBuild\Current\Bin\MSBuild.exe"],
            capture_output=True, text=True, timeout=60,
        ).stdout.strip().splitlines()
        if out:
            path = pathlib.Path(out[0])
            if path.is_file():
                return path
    raise SolutionError(
        "MSBuild.exe not found: install Visual Studio with the C++ "
        "toolset and the WDK")


def verify_kernel_chain_prologue(blob: bytes, platform: str) -> None:
    """Assert `blob` is the peor chain for `platform` (x64 | Win32)."""
    try:
        prologue = _CHAIN_PROLOGUE[platform]
    except KeyError:
        raise SolutionError(f"unknown platform {platform!r}") from None
    if not blob.startswith(prologue):
        raise SolutionError(
            f"peor chain output unexpected prologue: {blob[:8].hex()}")


class SolutionBuild:
    """Artifacts of one solution build (config x platform)."""

    def __init__(self, solution: "Solution", config: str, platform: str):
        self.config = config
        self.platform = platform
        self._solution = solution

    @property
    def out_dir(self) -> pathlib.Path:
        return self._solution.root / _OUT_DIRNAME / self.config / self.platform

    def sys(self, name: str) -> pathlib.Path:
        return self.out_dir / f"peor_{name}.sys"

    def chain_bin(self, name: str) -> pathlib.Path:
        return self.out_dir / f"peor_{name}_chain_{self.platform}.bin"


class Solution:
    """The local kernel tests' VS solution, built per config x platform."""

    def __init__(self):
        self.msbuild = find_msbuild()
        self.root = pathlib.Path(__file__).resolve().parent / "solution"
        self.sln = self.root / _SOLUTION_NAME
        if not self.sln.is_file():
            raise SolutionError(f"solution file missing: {self.sln}")

    def build(self, config: str, platform: str) -> SolutionBuild:
        if config not in ("Release", "Debug"):
            raise SolutionError(f"unknown config {config!r}")
        if platform not in _CHAIN_PROLOGUE:
            raise SolutionError(f"unknown platform {platform!r}")
        proc = subprocess.run(
            [str(self.msbuild), str(self.sln),
             "/p:Configuration=" + config, "/p:Platform=" + platform,
             "/p:BuildProjectReferences=true",
             "/m", "/v:minimal", "/nologo"],
            capture_output=True, text=True, timeout=1800,
        )
        if proc.returncode != 0:
            raise SolutionError(
                f"msbuild {config}|{platform} failed rc={proc.returncode}\n"
                f"{proc.stdout[-3000:]}\n{proc.stderr[-1500:]}")
        return SolutionBuild(self, config, platform)
