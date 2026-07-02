#!/usr/bin/env python3
"""Build every test artifact tests/pytest/test_shellcode.py needs — that file contains
no build logic at all; every fixture it reads must already exist on disk before pytest
runs, or the corresponding test fails with a message pointing back here.

Run this before `pytest tests/pytest` (peor must already be `pip install -e .`d — this
script doesn't do that itself). CI does the same (see .github/workflows/test.yml), using
--target to build only what each job needs:

    python tests/build_tests.py                 # everything this host's toolchains support
    python tests/build_tests.py --target linux   # Linux test loaders + Linux-platform PEs
    python tests/build_tests.py --target efi     # EFI test-source PEs (all 4 archs) + x64/x86 loader templates
    python tests/build_tests.py --target windows # mingw/clang-cl Windows-usermode test PEs

Populates:
  tests/test_loader_linux/test_loader_linux{,_32}.pe        (native gcc Linux loaders)
  tests/Linux_x64/*.pe, tests/Linux_x86/*.pe                 (mingw-w64 Linux test PEs)
  tests/Win_x64_EFI/*.efi, tests/Win_x86_EFI/*.efi            (mingw-w64 EFI test PEs)
  tests/Win_ARM64/*.efi,   tests/Win_ARM32/*.efi              (clang/lld EFI test PEs)
  tests/Win_x64_EFI/efi_loader.efi, ... (one per arch)        (EFI loader w/ placeholder
                                                                 shellcode blob, see
                                                                 tests/EFI/efi_loader/main.c)
  tests/Win_x64_MinGW/*.exe, tests/Win_x86_MinGW/*.exe        (mingw-w64 Windows test PEs,
                                                                 plus the clang-cl static-CRT
                                                                 PE when run on Windows)

NOT built here — needs MSBuild, see tests/tests.sln:
  - Windows-native MSVC .exe test binaries
"""
import sys
import importlib.util
import subprocess
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent

# Load test_shellcode.py by explicit file path (not sys.path + import) so this script
# works regardless of invocation style (`python tests/build_tests.py`, `python -m
# tests.build_tests`, run from any cwd) and never collides with an unrelated top-level
# "tests" or "pytest" package that might already be installed in site-packages.
_spec = importlib.util.spec_from_file_location("peor_test_shellcode", TESTS_DIR / "pytest" / "test_shellcode.py")
ts = importlib.util.module_from_spec(_spec)
sys.modules["peor_test_shellcode"] = ts
_spec.loader.exec_module(ts)

_SIMPLE_EFI_TESTS = ["01_efi_hello", "02_efi_print", "03_efi_simple_calc", "05_efi_memory_services"]

_FAILURES = []


def _report(label: str, ok: bool, detail: str = "") -> None:
    status = "OK" if ok else "FAIL"
    print(f"[build_tests] {status:4} {label}")
    if not ok:
        _FAILURES.append(f"{label}: {detail}")
        if detail:
            print(f"             {detail}")


def build_linux_loaders() -> None:
    """Build the native (this-host) Linux test loaders directly with gcc.

    Mirrors .github/workflows/test.yml's build-linux-mingw job exactly. This runs on
    the Linux/WSL host itself (not cross-compiled), so it always uses plain native gcc.
    """
    loader_dir = TESTS_DIR / "test_loader_linux"
    src = loader_dir / "main.c"

    loader64 = loader_dir / "test_loader_linux.pe"
    if loader64.exists():
        _report("linux loader x64 (already built)", True)
    else:
        cmd = (["gcc", "-O2"] + ts._LINUX_LOADER_CFLAGS
               + ["-o", str(loader64), str(src), "-ldl"])
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=30)
            _report("linux loader x64", r.returncode == 0, r.stderr.decode(errors="replace"))
        except FileNotFoundError:
            _report("linux loader x64", False, "gcc not found")

    loader32 = loader_dir / "test_loader_linux_32.pe"
    if loader32.exists():
        _report("linux loader x86 (-m32, already built)", True)
    else:
        cmd = ["gcc"] + ts._LINUX_LOADER_CFLAGS_32 + ["-o", str(loader32), str(src)]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=30)
            _report("linux loader x86 (-m32)", r.returncode == 0, r.stderr.decode(errors="replace"))
        except FileNotFoundError:
            _report("linux loader x86 (-m32)", False, "gcc-multilib not found")


def build_efi_source_pes() -> None:
    """Compile the fixed-source EFI test PEs (01,02,03,05 + 04's C++ variant) once per arch."""
    efi_dir = TESTS_DIR / "EFI"
    gcc64_cmd, gcc64_wsl = ts._find_mingw_gcc()
    gcc32_cmd, gcc32_wsl = ts._find_mingw_gcc_32()
    gpp64_cmd, gpp64_wsl = ts._find_mingw_gpp_posix()
    gpp32_cmd, gpp32_wsl = ts._find_mingw_gpp_posix_32()
    clang64, clang64_wsl = ts._find_clang_arm64_wsl()
    clang32, clang32_wsl = ts._find_clang_arm32_wsl()

    targets = [
        ("x64", ts._EFI_PREBUILT_X64, gcc64_cmd, "x86_64-w64-mingw32-gcc",
         lambda src, out: ts._compile_efi_pe(src, out, None, "efi_main", gcc64_wsl, arch="x64")),
        ("x86", ts._EFI_PREBUILT_X86, gcc32_cmd, "i686-w64-mingw32-gcc",
         lambda src, out: ts._compile_efi_pe(src, out, None, "efi_main", gcc32_wsl, arch="x86")),
        ("arm64", ts._EFI_PREBUILT_ARM64, clang64, "clang (aarch64-w64-mingw32)",
         lambda src, out: ts._compile_efi_pe_arm64(src, out, None, "efi_main")),
        ("arm32", ts._EFI_PREBUILT_ARM32, clang32, "clang (armv7-w64-mingw32)",
         lambda src, out: ts._compile_efi_pe_arm32(src, out, None, "efi_main")),
    ]

    for arch, prebuilt_dir, toolchain, toolchain_name, compile_fn in targets:
        if toolchain is None:
            for test_name in _SIMPLE_EFI_TESTS:
                _report(f"efi {arch}/{test_name}", False, f"{toolchain_name} not found (native or WSL)")
            continue
        for test_name in _SIMPLE_EFI_TESTS:
            src = efi_dir / test_name / "main.c"
            if not src.exists():
                continue
            out = prebuilt_dir / f"{test_name}.efi"
            prebuilt_dir.mkdir(parents=True, exist_ok=True)
            cc = compile_fn(src, out)
            ok = cc.returncode == 0
            detail = cc.stderr.decode(errors="replace") if not ok else ""
            _report(f"efi {arch}/{test_name}", ok, detail)

    # 04_cpp_exceptions: x64/x86 via g++-posix (DWARF/SJLJ EH), arm32 via clang + sjlj_arm32.c
    cpp_targets = [
        ("x64", ts._EFI_PREBUILT_X64, gpp64_cmd, "x86_64-w64-mingw32-g++-posix",
         lambda out: ts._compile_cpp_pe(ts._EFI_CPP_EXCEPTIONS_SRC, out, gpp64_wsl, "efi_main", "10", arch="x64")),
        ("x86", ts._EFI_PREBUILT_X86, gpp32_cmd, "i686-w64-mingw32-g++-posix",
         lambda out: ts._compile_cpp_pe(ts._EFI_CPP_EXCEPTIONS_SRC, out, gpp32_wsl, "efi_main", "10", arch="x86")),
        ("arm32", ts._EFI_PREBUILT_ARM32, clang32, "clang (armv7-w64-mingw32)",
         lambda out: ts._compile_efi_pe_arm32(
             ts._EFI_CPP_EXCEPTIONS_SRC, out, None, "efi_main",
             extra_srcs=[ts._CPP_EH_SUPPORT_DIR / "sjlj_arm32.c"])),
    ]
    for arch, prebuilt_dir, toolchain, toolchain_name, compile_fn in cpp_targets:
        label = f"efi {arch}/04_cpp_exceptions"
        if toolchain is None:
            _report(label, False, f"{toolchain_name} not found (native or WSL)")
            continue
        prebuilt_dir.mkdir(parents=True, exist_ok=True)
        cc = compile_fn(prebuilt_dir / "04_cpp_exceptions.efi")
        ok = cc.returncode == 0
        _report(label, ok, cc.stderr.decode(errors="replace") if not ok else "")


def build_efi_loader_templates() -> None:
    """Compile efi_loader.efi once per arch with its placeholder shellcode blob.

    x64/x86 only: tests/pytest/test_shellcode.py byte-patches a copy of this at test
    time (see _embed_shellcode_in_loader) — no compiler runs there. ARM64/ARM32 loaders
    are compiled per-test instead (see the PEOR_ARM_LEGACY_SHELLCODE comment in
    tests/EFI/efi_loader/main.c for why) so there's nothing to prebuild for them here.
    """
    gcc64_cmd, gcc64_wsl = ts._find_mingw_gcc()
    gcc32_cmd, gcc32_wsl = ts._find_mingw_gcc_32()

    targets = [
        ("x64", gcc64_cmd, "x86_64-w64-mingw32-gcc",
         lambda out: ts._compile_efi_pe(ts._EFI_LOADER_SRC, out, None, "efi_loader_main", gcc64_wsl, arch="x64")),
        ("x86", gcc32_cmd, "i686-w64-mingw32-gcc",
         lambda out: ts._compile_efi_pe(ts._EFI_LOADER_SRC, out, None, "efi_loader_main", gcc32_wsl, arch="x86")),
    ]
    for arch, toolchain, toolchain_name, compile_fn in targets:
        label = f"efi_loader/{arch}"
        if toolchain is None:
            _report(label, False, f"{toolchain_name} not found (native or WSL)")
            continue
        out = ts._EFI_LOADER_PREBUILT[arch]
        out.parent.mkdir(parents=True, exist_ok=True)
        cc = compile_fn(out)
        ok = cc.returncode == 0
        if ok:
            # Sanity-check the magic is present & unique, exactly like the test-time patcher will.
            data = out.read_bytes()
            ok = data.count(ts._EFI_LOADER_SHELLCODE_MAGIC) == 1
            detail = "" if ok else "shellcode magic missing or not unique in compiled loader"
        else:
            detail = cc.stderr.decode(errors="replace")
        _report(label, ok, detail)


def build_linux_test_pes() -> None:
    """Build the 5 Linux-platform test PEs (x64 + x86) via their existing _build_* helpers
    (01/03/04) or _compile_cpp_pe directly (02/05, which have no dedicated helper)."""
    import tempfile
    tmp_path = Path(tempfile.mkdtemp(prefix="peor_build_"))

    gcc64_cmd, gcc64_wsl = ts._find_mingw_gcc()
    gcc32_cmd, gcc32_wsl = ts._find_mingw_gcc_32()
    gpp64_cmd, gpp64_wsl = ts._find_mingw_gpp_posix()
    gpp32_cmd, gpp32_wsl = ts._find_mingw_gpp_posix_32()

    def _use_wsl_or(cmd, wsl):
        return bool(wsl) if cmd is not None else None

    # 01: dedicated helpers already exist for both arches.
    if gcc64_cmd is not None:
        exe = ts._build_linux_write_pe(tmp_path, _use_wsl_or(gcc64_cmd, gcc64_wsl))
        _report("linux x64/01_linux_write", exe is not None, "compile failed")
    else:
        _report("linux x64/01_linux_write", False, "x86_64-w64-mingw32-gcc not found (native or WSL)")
    if gcc32_cmd is not None:
        exe = ts._build_linux_write_pe_32(tmp_path, _use_wsl_or(gcc32_cmd, gcc32_wsl))
        _report("linux x86/01_linux_write", exe is not None, "compile failed")
    else:
        _report("linux x86/01_linux_write", False, "i686-w64-mingw32-gcc not found (native or WSL)")

    # 02, 05: no dedicated helper — compile straight to the prebuilt path via _compile_cpp_pe.
    cpp_targets = [
        ("02_linux_cpp_exceptions", ts._LINUX_CPP_EXCEPTIONS_SRC),
        ("05_linux_global_ctor", ts._LINUX_GLOBAL_CTOR_SRC),
    ]
    for name, src in cpp_targets:
        for arch, gpp_cmd, gpp_wsl, prebuild_dir in [
            ("x64", gpp64_cmd, gpp64_wsl, ts._LINUX_PREBUILD_X64),
            ("x86", gpp32_cmd, gpp32_wsl, ts._LINUX_PREBUILD_X86),
        ]:
            label = f"linux {arch}/{name}"
            out = prebuild_dir / f"{name}_{arch}.pe"
            if out.exists():
                _report(f"{label} (already built)", True)
                continue
            if gpp_cmd is None:
                _report(label, False, "g++-posix not found (native or WSL)")
                continue
            prebuild_dir.mkdir(parents=True, exist_ok=True)
            cc = ts._compile_cpp_pe(src, out, gpp_wsl, "main", "posix", arch=arch)
            _report(label, cc.returncode == 0, cc.stderr.decode(errors="replace"))

    # 03, 04: dedicated helpers, parameterised by arch.
    for arch, gcc_cmd, gcc_wsl in [("x64", gcc64_cmd, gcc64_wsl), ("x86", gcc32_cmd, gcc32_wsl)]:
        label3 = f"linux {arch}/03_linux_with_crt"
        label4 = f"linux {arch}/04_linux_signal"
        if gcc_cmd is None:
            _report(label3, False, "mingw-gcc not found (native or WSL)")
            _report(label4, False, "mingw-gcc not found (native or WSL)")
            continue
        exe3 = ts._build_linux_crt_pe(tmp_path, _use_wsl_or(gcc_cmd, gcc_wsl), arch=arch)
        _report(label3, exe3 is not None, "compile failed")
        exe4 = ts._build_linux_signal_pe(tmp_path, _use_wsl_or(gcc_cmd, gcc_wsl), arch=arch)
        _report(label4, exe4 is not None, "compile failed")


def build_mingw_windows_pes() -> None:
    """Build the MinGW-compiled Windows-target test PEs (run via test_loader.exe)."""
    for arch, out_dir in ts._MINGW_WIN_PREBUILT.items():
        out_dir.mkdir(parents=True, exist_ok=True)

    gcc64_cmd, gcc64_wsl = ts._find_mingw_gcc()
    out = ts._MINGW_WIN_PREBUILT["x64"] / "01_simple_calc_mingw.exe"
    if gcc64_cmd is None:
        _report("mingw/01_simple_calc", False, "x86_64-w64-mingw32-gcc not found (native or WSL)")
    else:
        src = TESTS_DIR / "01_simple_calc" / "main.c"
        stub_c = "void __main(void) {}"
        if gcc64_wsl:
            src_wsl = ts._win_path_to_wsl(src)
            out_wsl = ts._win_path_to_wsl(out)
            cmd = (f"echo '{stub_c}' | x86_64-w64-mingw32-gcc "
                   + " ".join(ts._MINGW_CFLAGS)
                   + f" -x c - {src_wsl} -Wl,-e,main -o {out_wsl}")
            cc = ts._wsl_bash_run(cmd, capture_output=True, timeout=30)
        else:
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False) as f:
                f.write(stub_c)
                stub_file = f.name
            try:
                cc = subprocess.run(
                    gcc64_cmd + ts._MINGW_CFLAGS
                    + ["-x", "c", stub_file, str(src), "-Wl,-e,main", "-o", str(out)],
                    capture_output=True, timeout=30,
                )
            finally:
                Path(stub_file).unlink(missing_ok=True)
        _report("mingw/01_simple_calc", cc.returncode == 0, cc.stderr.decode(errors="replace") if cc.returncode else "")

    gpp64_cmd, gpp64_wsl = ts._find_mingw_gpp_posix()
    gpp32_cmd, gpp32_wsl = ts._find_mingw_gpp_posix_32()
    src17 = TESTS_DIR / "Windows" / "17_mingw_cpp_exceptions" / "main.cpp"
    for arch, gpp_cmd, gpp_wsl in [("x64", gpp64_cmd, gpp64_wsl), ("x86", gpp32_cmd, gpp32_wsl)]:
        label = f"mingw {arch}/17_mingw_cpp_exceptions"
        out17 = ts._MINGW_WIN_PREBUILT[arch] / "17_mingw_cpp_exceptions.exe"
        if gpp_cmd is None:
            _report(label, False, "g++-posix not found (native or WSL)")
            continue
        cc = ts._compile_cpp_pe(src17, out17, gpp_wsl, "WinMain", "windows", arch=arch)
        _report(label, cc.returncode == 0, cc.stderr.decode(errors="replace") if cc.returncode else "")


def build_clangcl_pe() -> None:
    """Windows-only: clang-cl /MT static-CRT test PE."""
    import platform as _platform
    if _platform.system() != "Windows":
        _report("clangcl/01_simple_calc", True, "")  # not applicable on this host
        return
    clangcl = ts._find_clangcl()
    out_dir = ts._MINGW_WIN_PREBUILT["x64"]
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "01_simple_calc_clangcl.exe"
    if clangcl is None:
        _report("clangcl/01_simple_calc", False, "clang-cl not found (install LLVM or VS with Clang component)")
        return
    src = TESTS_DIR / "01_simple_calc" / "main.c"
    cc = subprocess.run([clangcl, "/MT", "/Ox", f"/Fe{out}", str(src)], capture_output=True, timeout=120)
    _report("clangcl/01_simple_calc", cc.returncode == 0, cc.stderr.decode(errors="replace") if cc.returncode else "")


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--target", choices=["all", "linux", "efi", "windows"], default="all",
        help="which fixture group to build (default: all)",
    )
    args = parser.parse_args()

    if args.target in ("all", "linux"):
        build_linux_loaders()
        build_linux_test_pes()
    if args.target in ("all", "efi"):
        build_efi_source_pes()
        build_efi_loader_templates()
    if args.target in ("all", "windows"):
        build_mingw_windows_pes()
        build_clangcl_pe()

    if _FAILURES:
        print(f"\n[build_tests] {len(_FAILURES)} build step(s) failed (toolchain not installed on this host):")
        for f in _FAILURES:
            print(f"  - {f}")
        print("[build_tests] pytest will still run; unbuilt tests fail loudly instead of skipping.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
