"""Locate Visual Studio + WDK (km headers/libs) and compile drivers/exes with cl/link.

The local kernel tests need real WDK-built driver PEs:

* payloads (calc/spawn) are built as NATIVE-subsystem .sys linked against
  the WDK's ``km\\ntoskrnl.lib``;
* the loader driver (embedded peor chain blob) is a normal kernel-mode
  driver built the same way - it is what Windows' Service Control Manager
  loads on the VM;
* the child .exe for the create-process test is a plain user-mode console
  image linked against kernel32.lib.

No CRT is linked: payloads and the child stay away from CRT helpers and
format statuses by hand (hex via table) inside the sources.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess


class WdkError(RuntimeError):
    """Toolchain location or compilation failure."""


_DEFAULT_VS_ROOTS = (
    r"C:\Program Files\Microsoft Visual Studio\18\Community",
    r"C:\Program Files\Microsoft Visual Studio\18\Professional",
    r"C:\Program Files\Microsoft Visual Studio\18\Enterprise",
    r"C:\Program Files\Microsoft Visual Studio\2022\Community",
    r"C:\Program Files\Microsoft Visual Studio\2022\Professional",
    r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise",
)


def _find_visual_studio() -> pathlib.Path:
    for cand in _DEFAULT_VS_ROOTS:
        msvc = pathlib.Path(cand) / "VC" / "Tools" / "MSVC"
        if msvc.is_dir() and any(msvc.iterdir()):
            return pathlib.Path(cand)
    where = shutil.which("vswhere")
    if where:
        out = subprocess.run(
            [where, "-latest", "-products", "*", "-requires",
             "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
             "-property", "installationPath"],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip()
        if out and (pathlib.Path(out) / "VC" / "Tools" / "MSVC").is_dir():
            return pathlib.Path(out)
    raise WdkError(
        "Visual Studio C++ toolset not found: install VS with the "
        "'Desktop development with C++' workload"
    )


def _find_kit() -> tuple[pathlib.Path, str]:
    """Windows Kits\\10 root + newest version whose km headers AND libs exist."""
    kit_root = pathlib.Path(r"C:\Program Files (x86)\Windows Kits\10")
    if not kit_root.is_dir():
        raise WdkError("Windows Kits\\10 root not found")
    best = None
    for inc in (kit_root / "Include").iterdir():
        if not inc.is_dir():
            continue
        version = inc.name
        hdr = inc / "km" / "wdm.h"
        lib = kit_root / "Lib" / version / "km" / "x64" / "ntoskrnl.lib"
        if hdr.exists() and lib.exists():
            best = (version, inc, lib)
    if best is None:
        raise WdkError(
            "WDK km headers/libraries not found (Include\\<ver>\\km + "
            "Lib\\<ver>\\km\\x64\\ntoskrnl.lib). Install: "
            "winget install --id Microsoft.WindowsWDK.10.0.28000 "
            "and the matching WindowsSDK (10.0.28000)"
        )
    return kit_root, best[0]


class WdkToolchain:
    """cl.exe / link.exe with WDK kernel (km) include+lib environments."""

    def __init__(self, arch: str = "x64"):
        if arch != "x64":
            raise WdkError("local tests are x64-only for now")
        self.arch = arch
        self.vs_root = _find_visual_studio()
        msvc_root = self.vs_root / "VC" / "Tools" / "MSVC"
        self.msvc = sorted(d for d in msvc_root.iterdir() if d.is_dir())[-1]
        self.kit_root, self.kit_version = _find_kit()
        self.kit_inc = self.kit_root / "Include" / self.kit_version
        self.kit_lib = self.kit_root / "Lib" / self.kit_version
        host = "Hostx64\\x64"
        self.cl = self.msvc / "bin" / host / "cl.exe"
        self.link = self.msvc / "bin" / host / "link.exe"
        # SDK (um/ucrt) may be a separate version (SDK 28000 vs 26100); prefer
        # the same version, else fall back to the newest installed one.
        self.sdk_inc, self.sdk_lib = self._find_sdk()

    # ------------------------------------------------------------------
    def _find_sdk(self) -> tuple[pathlib.Path, pathlib.Path]:
        same = self.kit_root / "Include" / self.kit_version / "um"
        if same.is_dir() or (self.kit_inc / "shared" / "ntdef.h").exists():
            return self.kit_inc, self.kit_lib
        cands = []
        for d in (self.kit_root / "Include").iterdir():
            if d.is_dir() and d.name != self.kit_version and (d / "shared" / "ntdef.h").exists():
                cands.append(d)
        if not cands:
            raise WdkError(
                f"No Windows SDK matching WDK {self.kit_version}: need "
                "Include\\<ver>\\shared\\ntdef.h. Install "
                "winget install --id Microsoft.WindowsSDK.10.0.28000"
            )
        sdk = sorted(cands)[-1]
        return sdk, self.kit_root / "Lib" / sdk.name

    # ------------------------------------------------------------------
    @property
    def description(self) -> str:
        return (f"WDK {self.kit_version} @ {self.kit_root}, "
                f"MSVC {self.msvc.name} @ {self.vs_root}")

    def _env(self, kernel: bool) -> dict:
        include_dirs = [
            str(self.kit_inc / "km"),
            str(self.sdk_inc / "shared"),
            str(self.sdk_inc / "um"),
            str(self.sdk_inc / "ucrt"),
            str(self.msvc / "include"),
            str(self.msvc / "include" / "vcruntime"),
        ]
        lib_dirs = [
            str(self.kit_lib / "km" / "x64"),
            str(self.sdk_lib / "um" / "x64"),
            str(self.sdk_lib / "ucrt" / "x64"),
            str(self.msvc / "lib" / "x64"),
        ]
        return {"INCLUDE": ";".join(include_dirs),
                "LIB": ";".join(lib_dirs)}

    # ------------------------------------------------------------------
    def compile_sys(self, sources, out_sys: pathlib.Path,
                    defines=(), extra_libs=(), include_dirs=()) -> pathlib.Path:
        """NATIVE-subsystem kernel driver (.sys, no CRT)."""
        return self._compile(sources, out_path := pathlib.Path(out_sys),
                             is_kernel=True, entry="DriverEntry",
                             subsystem="native", libs=("ntoskrnl.lib",),
                             extra_libs=tuple(extra_libs),
                             defines=defines, include_dirs=include_dirs)

    def compile_exe(self, sources, out_exe: pathlib.Path,
                    entry: str, defines=(), include_dirs=()) -> pathlib.Path:
        """Plain console user-mode exe without CRT."""
        return self._compile(sources, pathlib.Path(out_exe), is_kernel=False,
                             entry=entry, subsystem="console",
                             libs=("kernel32.lib",),
                             defines=defines, include_dirs=include_dirs)

    # ------------------------------------------------------------------
    def _compile(self, sources, out_path, is_kernel, entry, subsystem,
                 libs, defines=(), include_dirs=(),
                 extra_libs=(), workdir: pathlib.Path | None = None) -> pathlib.Path:
        workdir = workdir or out_path.parent
        workdir = pathlib.Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        out_path = pathlib.Path(out_path)
        env_incl = self._env(is_kernel)
        cl = [str(self.cl), "/nologo", "/c", "/W3", "/Zl", "/Od",
              "/GR-", "/GS-", "/EHsc-"]
        if is_kernel:
            cl += ["/kernel"]
        cl += ["/D_WIN64", "/D_AMD64_", "/DAMD64"]
        for d in defines:
            cl.append(f"/D{d}")
        cl += ["/I" + str(pathlib.Path(d).resolve()) for d in include_dirs]
        srcs = [str(pathlib.Path(s).resolve()) for s in sources]
        cl += srcs
        proc = subprocess.run(
            cl, capture_output=True, text=True, timeout=300,
            cwd=str(workdir), env={**dict(os.environ), **env_incl},
        )
        objs = [pathlib.Path(workdir) / (pathlib.Path(s).stem + ".obj")
                for s in sources]
        missing = [o for o in objs if not o.exists()]
        if proc.returncode != 0 or missing:
            raise WdkError(f"cl failed rc={proc.returncode} missing={[str(m) for m in missing]}\n"
                           f"{proc.stdout}\n{proc.stderr}")
        link = [
            str(self.link), "/nologo", f"/OUT:{out_path}",
            f"/SUBSYSTEM:{subsystem}", f"/ENTRY:{entry}", "/MACHINE:X64",
            "/NODEFAULTLIB", "/DYNAMICBASE", "/NXCOMPAT",
        ] + [str(o) for o in objs] + list(libs) + list(extra_libs) + \
            ["/LIBPATH:" + p for p in env_incl["LIB"].split(";") if p]
        proc = subprocess.run(
            link, capture_output=True, text=True, timeout=300,
            cwd=str(workdir), env={**dict(os.environ), **env_incl},
        )
        if proc.returncode != 0 or not out_path.exists():
            raise WdkError(f"link failed rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}")
        return out_path


def find_wdk() -> WdkToolchain:
    try:
        return WdkToolchain()
    except WdkError:
        raise
