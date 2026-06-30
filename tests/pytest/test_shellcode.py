import os
import re
import sys
import time
import pytest
import struct
import shutil
import ctypes
import platform
import subprocess
from pathlib import Path
from typing import Optional

from pefile import PE
from pefile import OPTIONAL_HEADER_MAGIC_PE_PLUS

from peor.__main__ import (
    dump_memory_layout,
    _build_shellcode_chain,
    _find_export_rva,
    _SHELLCODES,
    _PLATFORM_LINUX,
    _PLATFORM_EFI,
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
)

TESTS_DIR = Path(__file__).parent.parent

ARCH_DIRS = {
    "x86": TESTS_DIR / "Win_x86",
    "x64": TESTS_DIR / "Win_x64",
}

# Pre-built Linux PE directories (populated by build-linux-mingw CI job or first local run).
# Tests check these dirs first; compilation only happens when the PE is absent.
_LINUX_PREBUILD_X64 = TESTS_DIR / "Linux_x64"
_LINUX_PREBUILD_X86 = TESTS_DIR / "Linux_x86"

MINGW_CPP_EH_RETURN_CODE = 42
LINUX_CRT_RETURN_CODE = 73
LINUX_SIGNAL_RETURN_CODE = 77
LINUX_GLOBAL_CTOR_RETURN_CODE = 99

# v1 and v2: importless, verified by exit code
_EXIT_CODE_CASES = [
    ("01_simple_calc", 4950),     # sum(0..99)
    ("02_relocs_functions", 90),  # accumulate([10,20,30,40])=100 → g_array[0]=120 → g_value=120-30
]

# v3 MessageBox constants (from 03_winapi_messagebox/main.c)
_MSGBOX_TITLE = "PEOR Test"
_MSGBOX_TEXT = "Hello from PEOR!"
_WM_COMMAND = 0x0111
_IDOK = 1


def _skip_if_missing(loader_path: Path, pe_path: Path) -> None:
    if not loader_path.exists():
        pytest.skip(f"test_loader.exe not found — build tests/tests.sln first")
    if not pe_path.exists():
        pytest.skip(f"{pe_path.name} not found at {pe_path}")


def _shellcodify(pe_path: Path, output_path: Path, *,
                 ignore_imports: bool = False, no_imports: bool = False,
                 override_ep_rva: int | None = None) -> None:
    """Shellcodify pe_path to output_path and assert the output is deterministic."""
    dump_memory_layout(PE(str(pe_path)), output_path,
                       ignore_imports=ignore_imports, no_imports=no_imports,
                       override_ep_rva=override_ep_rva)
    det_path = output_path.parent / (output_path.stem + '_det' + output_path.suffix)
    dump_memory_layout(PE(str(pe_path)), det_path,
                       ignore_imports=ignore_imports, no_imports=no_imports,
                       override_ep_rva=override_ep_rva)
    assert output_path.read_bytes() == det_path.read_bytes(), \
        f"Non-deterministic shellcode output for {pe_path.name}"


def _poll_and_dismiss_msgbox(title: str, timeout: float = 10.0) -> dict:
    """Poll for a MessageBox with the given title, capture its message text, then dismiss it."""
    user32 = ctypes.windll.user32
    result = {"found": False, "text": None}
    deadline = time.monotonic() + timeout

    hwnd = None
    while time.monotonic() < deadline:
        hwnd = user32.FindWindowA(None, title.encode())
        if hwnd:
            break
        time.sleep(0.05)

    if not hwnd:
        return result

    result["found"] = True

    # Small delay so the dialog finishes creating child controls before we query them.
    time.sleep(0.15)

    # Iterate Static children to find the message text (skip blank icon placeholder)
    hwnd_child = user32.FindWindowExA(hwnd, None, b"Static", None)
    while hwnd_child:
        buf = ctypes.create_unicode_buffer(1024)
        user32.GetWindowTextW(hwnd_child, buf, len(buf))
        text = buf.value.strip()
        if text:
            result["text"] = text
            break
        hwnd_child = user32.FindWindowExA(hwnd, hwnd_child, b"Static", None)

    # PostMessageA+BM_CLICK avoids cross-architecture SendMessage hangs (64-bit Python →
    # 32-bit WOW64 dialog). After posting, poll until the window disappears.
    hwnd_ok = user32.FindWindowExA(hwnd, None, b"Button", None)
    if hwnd_ok:
        user32.PostMessageA(hwnd_ok, 0x00F5, 0, 0)  # BM_CLICK
    else:
        user32.PostMessageA(hwnd, _WM_COMMAND, _IDOK, 0)

    dismiss_deadline = time.monotonic() + 5.0
    while time.monotonic() < dismiss_deadline:
        if not user32.IsWindow(hwnd):
            break
        time.sleep(0.05)

    return result


@pytest.mark.parametrize("arch", ["x86", "x64"])
@pytest.mark.parametrize("test_name,expected", _EXIT_CODE_CASES, ids=[t[0] for t in _EXIT_CODE_CASES])
def test_shellcode_exit_code(arch, test_name, expected, tmp_path):
    win_dir = ARCH_DIRS[arch]
    pe_path = win_dir / f"{test_name}.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"{test_name}_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True,
    )

    assert result.returncode == expected, (
        f"[{arch}] {test_name}: expected exit code {expected}, got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.skipif(bool(os.getenv("CI")), reason="MessageBox requires an interactive desktop, skipped in CI")
@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_03_winapi_messagebox(arch, tmp_path):
    win_dir = ARCH_DIRS[arch]
    pe_path = win_dir / "03_winapi_messagebox.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"03_winapi_messagebox_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    # The loader blocks on MessageBoxA — start it without waiting
    proc = subprocess.Popen([str(loader_path), str(shellcode_path)])

    try:
        msgbox = _poll_and_dismiss_msgbox(_MSGBOX_TITLE)

        if not msgbox["found"]:
            pytest.fail(f"[{arch}] MessageBox '{_MSGBOX_TITLE}' did not appear within timeout")

        # ExitProcess from inside the shellcode triggers full DLL teardown; 30s is sufficient.
        proc.wait(timeout=30)
    finally:
        if proc.returncode is None:
            proc.kill()

    assert msgbox["text"] == _MSGBOX_TEXT, (
        f"[{arch}] MessageBox text: expected {_MSGBOX_TEXT!r}, got {msgbox['text']!r}"
    )
    assert proc.returncode == 0, f"[{arch}] expected exit code 0, got {proc.returncode}"


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_04_crt_printf_rand(arch, tmp_path):
    win_dir = ARCH_DIRS[arch]
    pe_path = win_dir / "04_crt_printf_rand.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"04_crt_printf_rand_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True,
        timeout=10,
    )

    stdout = result.stdout.decode(errors="replace").strip()
    assert result.returncode == 0, (
        f"[{arch}] expected exit code 0, got {result.returncode}\n"
        f"stdout: {stdout}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )
    assert re.fullmatch(r"Random: \d+", stdout), (
        f"[{arch}] unexpected stdout: {stdout!r}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_05_dll_entry(arch, tmp_path):
    """DLL shellcode: DllMain calls ExitProcess(42) on DLL_PROCESS_ATTACH."""
    win_dir = ARCH_DIRS[arch]
    pe_path = win_dir / "05_dll_entry.dll"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"05_dll_entry_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 42, (
        f"[{arch}] expected exit code 42 from DllMain, got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_06_stripped_relocs(arch, tmp_path):
    """EXE with /FIXED (no .reloc section): reloc resolver must skip relocation and jump to OEP."""
    win_dir = ARCH_DIRS[arch]
    pe_path = win_dir / "06_stripped_relocs.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"06_stripped_relocs_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 99, (
        f"[{arch}] expected exit code 99, got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_07_cpp_exceptions(arch, tmp_path):
    """C++ EXE with try/catch: x64 requires RtlAddFunctionTable for SEH unwind tables."""
    win_dir = ARCH_DIRS[arch]
    pe_path = win_dir / "07_cpp_exceptions.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"07_cpp_exceptions_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True,
        timeout=30,  # x86 WER processing takes 6-9s on unhandled exceptions
    )

    assert result.returncode == 77, (
        f"[{arch}] expected exit code 77, got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_08_cpp_thread(arch, tmp_path):
    """C++ EXE with std::thread: thread sets result=42, main returns it."""
    win_dir = ARCH_DIRS[arch]
    pe_path = win_dir / "08_cpp_thread.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"08_cpp_thread_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 42, (
        f"[{arch}] expected exit code 42, got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_09_resources(arch, tmp_path):
    """C++ EXE with embedded string resource: reads via __ImageBase HMODULE, returns 42 on match."""
    win_dir = ARCH_DIRS[arch]
    pe_path = win_dir / "09_resources.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"09_resources_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 42, (
        f"[{arch}] expected exit code 42 (resource read OK), got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


def _sign_pe(source_path: Path, dest_path: Path) -> bool:
    """Append a dummy WIN_CERTIFICATE to a PE copy to exercise the security directory.

    Uses only Python stdlib so the test runs on any OS without PowerShell.
    DataDir[4] (IMAGE_DIRECTORY_ENTRY_SECURITY) stores a file offset (not an RVA);
    we append a minimal WIN_CERTIFICATE structure past the last section and record it.
    """
    shutil.copy2(source_path, dest_path)
    try:
        pe_bytes = bytearray(dest_path.read_bytes())
        e_lfanew = struct.unpack_from('<I', pe_bytes, 0x3c)[0]
        pe_magic = struct.unpack_from('<H', pe_bytes, e_lfanew + 24)[0]
        # DataDirectory array starts at: e_lfanew + 4 (sig) + 20 (file hdr) + 96 or 112 (opt hdr fields)
        dir_array_off = e_lfanew + 24 + (96 if pe_magic == 0x10b else 112)
        sec_dir_off   = dir_array_off + 4 * 8  # DataDir[4]

        # Minimal WIN_CERTIFICATE: dwLength | wRevision=0x0200 | wCertificateType=0x0002 | data
        dummy_data = b'\x00' * 16
        win_cert   = struct.pack('<IHH', 8 + len(dummy_data), 0x0200, 0x0002) + dummy_data

        cert_file_offset = len(pe_bytes)           # security dir stores a file offset, not RVA
        pe_bytes.extend(win_cert)
        struct.pack_into('<II', pe_bytes, sec_dir_off, cert_file_offset, len(win_cert))
        dest_path.write_bytes(bytes(pe_bytes))

        dirs = PE(str(dest_path)).OPTIONAL_HEADER.DATA_DIRECTORY
        return len(dirs) > 4 and dirs[4].VirtualAddress != 0
    except Exception:
        return False


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_certificate_signed_pe(arch, tmp_path):
    """peor must produce correct shellcode from an Authenticode-signed PE."""
    win_dir = ARCH_DIRS[arch]
    pe_path = win_dir / "02_relocs_functions.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    signed_path = tmp_path / f"02_relocs_functions_signed_{arch}.exe"
    assert _sign_pe(pe_path, signed_path), 'failed singing the PE file'

    shellcode_path = tmp_path / f"02_relocs_signed_{arch}.bin"
    _shellcodify(signed_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 90, (
        f"[{arch}] signed PE: expected exit code 90, got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_10_tls_callbacks(arch, tmp_path):
    """C++ EXE with TLS callback: callback sets g_result=88, main returns it via a C++ static-local."""
    win_dir = ARCH_DIRS[arch]
    pe_path = win_dir / "10_tls_callbacks.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"10_tls_callbacks_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 88, (
        f"[{arch}] expected exit code 88 (TLS callback ran), got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_11_cpp_exceptions(arch, tmp_path):
    """C++ EXE with typed throw/catch: typed catch must return 123; catch(...) returns 456; no-catch 789."""
    win_dir = ARCH_DIRS[arch]
    pe_path = win_dir / "11_cpp_exceptions.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"11_cpp_exceptions_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 123, (
        f"[{arch}] expected exit code 123 (typed catch fired), got {result.returncode}\n"
        f"  456 = catch(...) fired (type matching broken)\n"
        f"  789 = no exception caught at all\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_12_seh_exceptions(arch, tmp_path):
    """C++ EXE compiled with /EHa (SEH-integrated): typed catch must fire and return 123."""
    win_dir = ARCH_DIRS[arch]
    pe_path = win_dir / "12_seh_exceptions.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"12_seh_exceptions_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 123, (
        f"[{arch}] expected exit code 123 (typed catch fired), got {result.returncode}\n"
        f"  456 = catch(...) fired (type matching broken — cxx_eh_fixer not working with /EHa)\n"
        f"  789 = no exception caught at all\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_clr_rejection(arch, tmp_path):
    """peor must raise ValueError when DataDir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR] is non-zero."""
    pe_path = ARCH_DIRS[arch] / "01_simple_calc.exe"
    if not pe_path.exists():
        pytest.skip("test binaries not built")

    pe   = PE(str(pe_path))
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    assert len(dirs) > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, \
        "PE has too few DATA_DIRECTORY entries to set COM_DESCRIPTOR"
    dirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = 0x1000

    with pytest.raises(ValueError, match="CLR"):
        dump_memory_layout(pe, tmp_path / "clr_rejected.bin")


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_stdout_output(arch, tmp_path):
    """`peor -o -` must write exactly the same bytes as dump_memory_layout to a file."""
    pe_path = ARCH_DIRS[arch] / "01_simple_calc.exe"
    if not pe_path.exists():
        pytest.skip("test binaries not built")

    file_path = tmp_path / f"01_simple_calc_{arch}.bin"
    dump_memory_layout(PE(str(pe_path)), file_path)

    result = subprocess.run(
        [sys.executable, "-m", "peor", "-i", str(pe_path), "-o", "-"],
        capture_output=True, timeout=30,
    )
    assert result.returncode == 0, f"peor -o - exited with {result.returncode}: {result.stderr}"
    assert result.stdout == file_path.read_bytes(), \
        f"[{arch}] stdout bytes differ from file bytes"


@pytest.mark.parametrize("arch", ["x64"])
def test_info_mode(arch, tmp_path):
    """`peor --info` must print cxx_eh and seh rows (x64 + resolve-imports) without writing a file."""
    pe_path = ARCH_DIRS[arch] / "11_cpp_exceptions.exe"
    if not pe_path.exists():
        pytest.skip("test binaries not built")

    result = subprocess.run(
        [sys.executable, "-m", "peor", "--info", "-i", str(pe_path)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"peor --info exited with {result.returncode}: {result.stderr}"
    assert "cxx_eh"   in result.stdout, f"'cxx_eh' not in --info output:\n{result.stdout}"
    assert "seh"      in result.stdout, f"'seh' not in --info output:\n{result.stdout}"
    assert "total"    in result.stdout, f"'total' not in --info output:\n{result.stdout}"
    assert "PE image" in result.stdout, f"'PE image' not in --info output:\n{result.stdout}"
    assert not list(tmp_path.iterdir()), "--info must not write any output files"


# ── P2 tests ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_bound_imports(arch, tmp_path):
    """Shellcode from a PE with a non-zero DataDir[BOUND_IMPORT] must still execute correctly."""
    pe_path     = ARCH_DIRS[arch] / "04_crt_printf_rand.exe"
    loader_path = ARCH_DIRS[arch] / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    # Patch DataDir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] VirtualAddress to non-zero.
    pe_bytes  = bytearray(pe_path.read_bytes())
    e_lfanew  = struct.unpack_from('<I', pe_bytes, 0x3C)[0]
    pe_magic  = struct.unpack_from('<H', pe_bytes, e_lfanew + 24)[0]
    dir_off   = e_lfanew + 24 + (96 if pe_magic == 0x10B else 112)
    bound_off = dir_off + IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT * 8
    struct.pack_into('<II', pe_bytes, bound_off, 0x1000, 0)
    patched_path = tmp_path / f"04_bound_{arch}.exe"
    patched_path.write_bytes(bytes(pe_bytes))

    shellcode_path = tmp_path / f"04_bound_{arch}.bin"
    _shellcodify(patched_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True, timeout=10,
    )
    stdout = result.stdout.decode(errors="replace").strip()
    assert result.returncode == 0, \
        f"[{arch}] expected exit code 0, got {result.returncode}\nstdout: {stdout}"
    assert re.fullmatch(r"Random: \d+", stdout), \
        f"[{arch}] unexpected stdout: {stdout!r}"


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_13_tls_multi_callbacks(arch, tmp_path):
    """Five ordered TLS callbacks accumulate g = g*10 + i (i=1..5); main returns g == 12345."""
    win_dir     = ARCH_DIRS[arch]
    pe_path     = win_dir / "13_tls_multi_callbacks.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"13_tls_multi_callbacks_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True, timeout=10,
    )
    assert result.returncode == 12345, (
        f"[{arch}] expected exit code 12345 (callbacks ran in order 1-5), got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_14_global_ctors(arch, tmp_path):
    """File-scope C++ object constructor runs before main; sets g_value=42, main returns it."""
    win_dir     = ARCH_DIRS[arch]
    pe_path     = win_dir / "14_global_ctors.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"14_global_ctors_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True, timeout=10,
    )
    assert result.returncode == 42, (
        f"[{arch}] expected exit code 42 (global ctor ran), got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_15_nested_exceptions(arch, tmp_path):
    """Nested try/rethrow: inner catch rethrows, outer catch must fire and return 55."""
    win_dir     = ARCH_DIRS[arch]
    pe_path     = win_dir / "15_nested_exceptions.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"15_nested_exceptions_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True, timeout=30,
    )
    assert result.returncode == 55, (
        f"[{arch}] expected exit code 55 (outer catch fired after rethrow), got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


# ── P2-15 ─────────────────────────────────────────────────────────────────────


def test_large_pe_disp32_guard():
    """_build_shellcode_chain raises ValueError when the computed disp32 would overflow signed 32-bit."""
    pe_path = ARCH_DIRS["x64"] / "01_simple_calc.exe"
    if not pe_path.exists():
        pytest.skip("test binaries not built")

    # Craft an entry dict whose relocs already has disp32 = 0x7FFFFFFF.
    # Any non-zero extra (entrypoint resolver) will push it over the limit.
    entry = dict(_SHELLCODES[OPTIONAL_HEADER_MAGIC_PE_PLUS])
    relocs_bytes = bytearray(entry['relocs'])
    off = entry['disp32_off']
    relocs_bytes[off:off + 4] = (0x7FFFFFFF).to_bytes(4, 'little')
    entry = dict(entry, relocs=bytes(relocs_bytes))

    pe = PE(str(pe_path))
    with pytest.raises(ValueError, match="disp32"):
        _build_shellcode_chain(pe, entry, skip_imports=True)


# ── P2-14 ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_16_delay_load(arch, tmp_path):
    """Delay-loaded GetTickCount must be resolved before the entry point; returns 1..250."""
    win_dir     = ARCH_DIRS[arch]
    pe_path     = win_dir / "16_delay_load.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"16_delay_load_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True, timeout=10,
    )
    assert 1 <= result.returncode <= 250, (
        f"[{arch}] expected exit code 1..250 (GetTickCount resolved), got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


# ── P3-17 ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("arch", ["x64"])
def test_custom_entry(arch, tmp_path):
    """--entry selects a named export (DllMain) instead of OEP; must return 42."""
    win_dir     = ARCH_DIRS[arch]
    pe_path     = win_dir / "05_dll_entry.dll"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    pe = PE(str(pe_path))
    override_ep_rva = _find_export_rva(pe, "DllMain")

    shellcode_path = tmp_path / f"custom_entry_{arch}.bin"
    _shellcodify(pe_path, shellcode_path, override_ep_rva=override_ep_rva)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True, timeout=10,
    )
    assert result.returncode == 42, (
        f"[{arch}] --entry DllMain: expected exit code 42, got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


def _shellcodify_platform(pe_path: Path, output_path: Path, platform: str) -> None:
    """Shellcodify with an explicit --platform override (determinism-checked)."""
    dump_memory_layout(PE(str(pe_path)), output_path, platform=platform)
    det_path = output_path.parent / (output_path.stem + '_det' + output_path.suffix)
    dump_memory_layout(PE(str(pe_path)), det_path, platform=platform)
    assert output_path.read_bytes() == det_path.read_bytes(), \
        f"Non-deterministic shellcode output for {pe_path.name}"


def _win_path_to_wsl(p: Path) -> str:
    """Convert an absolute Windows path to its WSL /mnt/<drive>/... form."""
    s = str(p).replace("\\", "/")
    if len(s) >= 2 and s[1] == ":":
        return f"/mnt/{s[0].lower()}{s[2:]}"
    return s


def _find_git_bash() -> "str | None":
    """Return path to Git Bash's bash.exe on Windows, or None."""
    candidates = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return shutil.which("bash")


def _wsl_bash_run(cmd_str: str, **kwargs) -> subprocess.CompletedProcess:
    """Run a WSL shell command, routing through Git Bash when wsl.exe fails directly."""
    git_bash = _find_git_bash()
    if git_bash:
        return subprocess.run(
            [git_bash, "-c", f"wsl bash -c {repr(cmd_str)}"],
            **kwargs,
        )
    return subprocess.run(["wsl", "bash", "-c", cmd_str], **kwargs)


def _find_mingw_gcc():
    """Return (use_wsl bool) or (None) if unavailable.

    Returns ([gcc], False) for native, or (["__wsl__"], True) for WSL.
    Callers must check use_wsl and use _wsl_bash_run() to compile.
    """
    gcc = "x86_64-w64-mingw32-gcc"
    if shutil.which(gcc):
        return [gcc], False
    if platform.system() == "Windows":
        try:
            r = _wsl_bash_run(f"which {gcc}", capture_output=True, timeout=60)
            if r.returncode == 0:
                return ["__wsl__"], True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return None, None


_LINUX_LOADER_CFLAGS = [
    "-O2",
    # The shellcode chain sets RBX = PE base and does not restore it, violating the
    # System V callee-saved convention.  -ffixed-<reg> tells GCC not to use these
    # registers in the loader itself, so the clobber is harmless.
    "-ffixed-rbx", "-ffixed-r12", "-ffixed-r13", "-ffixed-r14", "-ffixed-r15",
]


def _ensure_linux_loader(use_wsl: bool) -> "Path | None":
    """Return path to the pre-built test_loader_linux binary.

    Builds it inside WSL if it does not yet exist and WSL is available.
    The binary lands in tests/test_loader_linux/ so subsequent runs reuse it.
    """
    loader = TESTS_DIR / "test_loader_linux" / "test_loader_linux.pe"
    if loader.exists():
        return loader
    src = TESTS_DIR / "test_loader_linux" / "main.c"
    if not use_wsl:
        return None
    cmd = ("gcc " + " ".join(_LINUX_LOADER_CFLAGS)
           + f" -o {_win_path_to_wsl(loader)} {_win_path_to_wsl(src)}")
    r = _wsl_bash_run(cmd, capture_output=True, timeout=30)
    return loader if r.returncode == 0 and loader.exists() else None


def _find_clangcl() -> "str | None":
    """Return path to clang-cl or None if not found or not runnable on this machine."""
    candidates = []
    from_path = shutil.which("clang-cl")
    if from_path:
        candidates.append(from_path)
    candidates += [
        r"C:\Program Files\LLVM\bin\clang-cl.exe",
        r"C:\Program Files (x86)\LLVM\bin\clang-cl.exe",
        r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\Llvm\x64\bin\clang-cl.exe",
        r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin\clang-cl.exe",
    ]
    for p in candidates:
        if not Path(p).exists():
            continue
        try:
            subprocess.run([p, "--version"], capture_output=True, timeout=10)
            return p
        except OSError:
            continue
    return None


# ── P2-16 tests ───────────────────────────────────────────────────────────────

_MINGW_CFLAGS = [
    "-nostdlib", "-nodefaultlibs", "-nostartfiles",
    "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
]


@pytest.mark.parametrize("arch", ["x64"])
def test_mingw_simple_calc(arch, tmp_path):
    """MinGW cross-compiled importless EXE: shellcodify and run via Linux loader.

    Works on native Linux, on Windows+WSL, and on ubuntu-latest CI.
    MinGW emits an empty .idata sentinel; peor must skip the imports resolver
    for such PEs (fixed via _has_imports using pefile's parsed DIRECTORY_ENTRY_IMPORT).
    The Linux loader prints the full int return value to stdout (bypassing the
    8-bit Linux exit code limit).
    """
    mingw_cmd, use_wsl = _find_mingw_gcc()
    if mingw_cmd is None:
        pytest.skip("x86_64-w64-mingw32-gcc not found (native PATH or WSL)")

    src = TESTS_DIR / "01_simple_calc" / "main.c"
    if not src.exists():
        pytest.skip(f"source not found: {src}")

    exe = tmp_path / "simple_calc_mingw.exe"

    # MinGW's GCC injects a call to __main() (global ctor registration) inside
    # main(); provide a no-op stub via stdin so we need no extra source file.
    stub_c = "void __main(void) {}"
    _gcc64 = "x86_64-w64-mingw32-gcc"
    if use_wsl:
        src_wsl = _win_path_to_wsl(src)
        exe_wsl = _win_path_to_wsl(exe)
        cmd = (f"echo '{stub_c}' | {_gcc64} "
               + " ".join(_MINGW_CFLAGS)
               + f" -x c - {src_wsl} -Wl,-e,main -o {exe_wsl}")
        cc = _wsl_bash_run(cmd, capture_output=True, timeout=30)
    else:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False) as f:
            f.write(stub_c)
            stub_file = f.name
        try:
            cc = subprocess.run(
                mingw_cmd + _MINGW_CFLAGS
                + ["-x", "c", stub_file, str(src), "-Wl,-e,main", "-o", str(exe)],
                capture_output=True, timeout=30,
            )
        finally:
            Path(stub_file).unlink(missing_ok=True)

    assert cc.returncode == 0, (
        f"MinGW compile failed:\n{cc.stderr.decode(errors='replace')}"
    )

    sc = tmp_path / "simple_calc_mingw.bin"
    _shellcodify(exe, sc)

    if use_wsl:
        # MinGW was compiled via WSL but the shellcode lives on the Windows
        # filesystem; run the Windows test_loader.exe directly (no WSL layer
        # needed for execution — test_loader.exe is a native Windows PE).
        loader = ARCH_DIRS[arch] / "test_loader.exe"
        _skip_if_missing(loader, sc)
        result = subprocess.run(
            [str(loader), str(sc)], capture_output=True, timeout=10,
        )
        assert result.returncode == 4950, (
            f"[MinGW {arch}] expected 4950, got {result.returncode}\n"
            f"stdout: {result.stdout.decode(errors='replace')}\n"
            f"stderr: {result.stderr.decode(errors='replace')}"
        )
    else:
        # Native Linux or Linux CI: use the Linux test_loader (built with
        # -ffixed-rbx so GCC doesn't rely on callee-saved regs the shellcode clobbers).
        loader = TESTS_DIR / "test_loader_linux" / "test_loader_linux.pe"
        if not loader.exists():
            pytest.skip(
                "Linux test_loader not found — "
                "build with: gcc -O2 -ffixed-rbx -ffixed-r12 -ffixed-r13 "
                "-ffixed-r14 -ffixed-r15 -o tests/test_loader_linux/test_loader_linux.pe "
                "tests/test_loader_linux/main.c"
            )
        result = subprocess.run([str(loader), str(sc)], capture_output=True, timeout=10)
        assert result.returncode == 0, (
            f"[MinGW {arch}] loader crashed with code {result.returncode}\n"
            f"stderr: {result.stderr.decode(errors='replace')}"
        )
        stdout = result.stdout.decode(errors="replace").strip()
        assert stdout == "4950", (
            f"[MinGW {arch}] expected stdout '4950', got {stdout!r}\n"
            f"stderr: {result.stderr.decode(errors='replace')}"
        )


@pytest.mark.parametrize("arch", ["x64"])
def test_clangcl_simple_calc(arch, tmp_path):
    """clang-cl compiled EXE with static CRT must shellcodify and return 4950."""
    if platform.system() != "Windows":
        pytest.skip("clang-cl test is Windows-only")

    clangcl = _find_clangcl()
    if clangcl is None:
        pytest.skip("clang-cl not found (install LLVM or VS with Clang component)")

    src = TESTS_DIR / "01_simple_calc" / "main.c"
    if not src.exists():
        pytest.skip(f"source not found: {src}")

    exe = tmp_path / "simple_calc_clangcl.exe"
    cc = subprocess.run(
        [clangcl, "/MT", "/Ox", f"/Fe{exe}", str(src)],
        capture_output=True, timeout=120,
    )
    assert cc.returncode == 0, (
        f"clang-cl compile failed:\n{cc.stderr.decode(errors='replace')}"
    )

    loader = ARCH_DIRS[arch] / "test_loader.exe"
    _skip_if_missing(loader, exe)

    sc = tmp_path / "simple_calc_clangcl.bin"
    _shellcodify(exe, sc)

    result = subprocess.run([str(loader), str(sc)], capture_output=True, timeout=10)
    assert result.returncode == 4950, (
        f"[clang-cl {arch}] expected 4950, got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


# ── P4-18: Linux user-mode ────────────────────────────────────────────────────

# LIBRARY line omitted: dlltool >=2.41 has a parsing bug with it; use -D flag instead.
_LIBC_DEF_CONTENT = "EXPORTS\nwrite\n"
_LIBC_DLL_NAME    = "libc.so.6"

_MINGW_CFLAGS_LINUX = [
    "-nostdlib", "-nodefaultlibs", "-nostartfiles",
    "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
]


def _build_linux_write_pe(tmp_path: Path, use_wsl: bool) -> "Path | None":
    """Cross-compile tests/Linux/01_linux_write/main.c as a Windows PE with libc.so.6 imports.

    Returns the path to the compiled PE, or None on failure.
    Output goes to the stable tests/Linux_x64/ directory; the pre-built PE is reused on
    subsequent calls so the build-linux-mingw CI job can pre-populate it.
    """
    stable = _LINUX_PREBUILD_X64 / "01_linux_write_x64.pe"
    if stable.exists():
        return stable
    _LINUX_PREBUILD_X64.mkdir(parents=True, exist_ok=True)

    src = TESTS_DIR / "Linux" / "01_linux_write" / "main.c"
    if not src.exists():
        return None

    exe     = stable
    def_file = tmp_path / "libc.so.6.def"
    imp_lib  = tmp_path / "liblibc_import.a"
    def_file.write_text(_LIBC_DEF_CONTENT, encoding="ascii")

    _GCC64 = "x86_64-w64-mingw32-gcc"
    _DLLTOOL64 = "x86_64-w64-mingw32-dlltool"
    # MinGW GCC injects a call to __main() inside main() even with -nostartfiles;
    # provide a no-op stub so the shellcode entry point is pure.
    _MAIN_STUB = "void __main(void) {}"

    if use_wsl:
        def_wsl  = _win_path_to_wsl(def_file)
        imp_wsl  = _win_path_to_wsl(imp_lib)
        src_wsl  = _win_path_to_wsl(src)
        exe_wsl  = _win_path_to_wsl(exe)

        r = _wsl_bash_run(
            f"{_DLLTOOL64} -D {_LIBC_DLL_NAME} -d {def_wsl} -l {imp_wsl}",
            capture_output=True, timeout=30,
        )
        if r.returncode != 0:
            return None

        # Write __main stub to a WSL-side temp file so -x c never sees the .a file.
        cc = _wsl_bash_run(
            f"printf '%s' '{_MAIN_STUB}' > /tmp/_peor_stub64.c"
            f" && {_GCC64} " + " ".join(_MINGW_CFLAGS_LINUX)
            + f" /tmp/_peor_stub64.c {src_wsl} {imp_wsl}"
            f" -Wl,-e,main -Wl,--subsystem,posix -o {exe_wsl}",
            capture_output=True, timeout=30,
        )
    else:
        r = subprocess.run(
            [_DLLTOOL64, "-D", _LIBC_DLL_NAME, "-d", str(def_file), "-l", str(imp_lib)],
            capture_output=True, timeout=30,
        )
        if r.returncode != 0:
            return None

        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False) as f:
            f.write(_MAIN_STUB)
            stub_file = f.name
        try:
            cc = subprocess.run(
                [_GCC64] + _MINGW_CFLAGS_LINUX
                + [stub_file, str(src), str(imp_lib),
                   "-Wl,-e,main", "-Wl,--subsystem,posix", "-o", str(exe)],
                capture_output=True, timeout=30,
            )
        finally:
            Path(stub_file).unlink(missing_ok=True)

    if cc.returncode != 0 or not exe.exists():
        return None
    return exe


@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_01_linux_write(arch, tmp_path):
    """Linux import resolver: PE imports write() from libc.so.6; shellcode writes PEOR to stdout.

    On Windows, both compilation and execution run inside WSL.
    The PE is compiled with --subsystem posix (subsystem 7) so peor auto-selects the Linux chain;
    PE bitness (PE32+ vs PE32) determines whether the x64 or x86 resolver is used.
    Tested for both x64 (x86_64-w64-mingw32-gcc) and x86 (i686-w64-mingw32-gcc).
    """
    if arch == "x64":
        prebuilt = _LINUX_PREBUILD_X64 / "01_linux_write_x64.pe"
        mingw_cmd, use_wsl = _find_mingw_gcc()
        if not prebuilt.exists() and mingw_cmd is None:
            pytest.skip("x86_64-w64-mingw32-gcc not found (native PATH or WSL)")
        if use_wsl is None:
            use_wsl = platform.system() == "Windows"
        loader = _ensure_linux_loader(use_wsl)
        if loader is None:
            pytest.skip("Linux test_loader not found and could not be built via WSL")
        exe = _build_linux_write_pe(tmp_path, use_wsl)
        if exe is None:
            pytest.fail("Failed to build linux_write PE (dlltool or mingw-gcc unavailable)")
    else:
        prebuilt = _LINUX_PREBUILD_X86 / "01_linux_write_x86.pe"
        mingw_cmd, use_wsl = _find_mingw_gcc_32()
        if not prebuilt.exists() and mingw_cmd is None:
            pytest.skip("i686-w64-mingw32-gcc not found (native PATH or WSL)")
        if use_wsl is None:
            use_wsl = platform.system() == "Windows"
        loader = _ensure_linux_loader_32(use_wsl)
        if loader is None:
            pytest.fail("32-bit Linux test_loader not found and could not be built via WSL — run: wsl sudo apt-get install gcc-multilib")
        exe = _build_linux_write_pe_32(tmp_path, use_wsl)
        if exe is None:
            pytest.fail("Failed to build x86 linux_write PE")

    sc = tmp_path / f"linux_write_{arch}.bin"
    _shellcodify_platform(exe, sc, _PLATFORM_LINUX)

    if use_wsl:
        # Use wsl.exe directly (no Git Bash / MSYS2 layer) to avoid MSYS2 converting
        # /mnt/c/ paths to C:/Program Files/Git/mnt/c/ before they reach WSL.
        sc_wsl = _win_path_to_wsl(sc)
        loader_wsl = _win_path_to_wsl(loader)
        result = subprocess.run(
            ["wsl", "--", loader_wsl, sc_wsl], capture_output=True, timeout=15
        )
    else:
        result = subprocess.run([str(loader), str(sc)], capture_output=True, timeout=15)

    assert result.returncode == 0, (
        f"[linux_write {arch}] loader crashed with code {result.returncode}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )
    stdout = result.stdout.decode(errors="replace")
    assert "PEOR\n" in stdout, (
        f"[linux_write {arch}] expected 'PEOR\\n' in stdout, got {stdout!r}"
    )


_LINUX_CPP_EXCEPTIONS_SRC = TESTS_DIR / "Linux" / "02_linux_cpp_exceptions" / "main.cpp"


@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_02_linux_cpp_exceptions(arch, tmp_path):
    """Linux C++ shellcode: throws and catches a custom type; main returns 42.

    The PE is compiled with posix-threading g++ (DWARF-2 or SJLJ) so exceptions
    are self-contained.  peor's ctors runner initialises the GCC EH runtime before
    main runs.  The Linux loader prints the return value; test checks stdout == '42'.
    Tested for x64 and x86.
    """
    prebuild_dir = _LINUX_PREBUILD_X64 if arch == "x64" else _LINUX_PREBUILD_X86
    prebuilt = prebuild_dir / f"02_linux_cpp_exceptions_{arch}.pe"

    if arch == "x64":
        gpp_cmd, use_wsl = _find_mingw_gpp_posix()
        gpp_skip = "x86_64-w64-mingw32-g++-posix not found (install g++-mingw-w64-x86-64)"
        loader = _ensure_linux_loader(use_wsl)
    else:
        gpp_cmd, use_wsl = _find_mingw_gpp_posix_32()
        gpp_skip = "i686-w64-mingw32-g++-posix not found (install g++-mingw-w64-i686)"
        loader = _ensure_linux_loader_32(use_wsl)

    if not prebuilt.exists() and gpp_cmd is None:
        pytest.skip(gpp_skip)
    if use_wsl is None:
        use_wsl = platform.system() == "Windows"
    if loader is None:
        pytest.fail("Linux test_loader not found and could not be built — install gcc-multilib")

    if not prebuilt.exists():
        prebuild_dir.mkdir(parents=True, exist_ok=True)
        cc = _compile_cpp_pe(_LINUX_CPP_EXCEPTIONS_SRC, prebuilt, use_wsl, "main", "posix", arch=arch)
        assert cc.returncode == 0, (
            f"[linux_cpp {arch}] compile failed:\n{cc.stderr.decode(errors='replace')}"
        )
    exe = prebuilt

    sc = tmp_path / f"linux_cpp_except_{arch}.bin"
    _shellcodify_platform(exe, sc, _PLATFORM_LINUX)

    if use_wsl:
        sc_wsl     = _win_path_to_wsl(sc)
        loader_wsl = _win_path_to_wsl(loader)
        result = subprocess.run(["wsl", "--", loader_wsl, sc_wsl], capture_output=True, timeout=15)
    else:
        result = subprocess.run([str(loader), str(sc)], capture_output=True, timeout=15)

    assert result.returncode == 0, (
        f"[linux_cpp {arch}] loader crashed with code {result.returncode}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )
    stdout = result.stdout.decode(errors="replace").strip()
    assert stdout == "42", (
        f"[linux_cpp {arch}] expected stdout '42', got {stdout!r}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


# ── P4-20: EFI via QEMU ───────────────────────────────────────────────────────

_EFI_LOADER_SRC    = TESTS_DIR / "EFI" / "efi_loader" / "main.c"
_EFI_HELLO_SRC     = TESTS_DIR / "EFI" / "01_efi_hello" / "main.c"
_EFI_PREBUILT_ARM64 = TESTS_DIR / "Win_ARM64"

_MINGW_CFLAGS_EFI = [
    "-nostdlib", "-nodefaultlibs", "-nostartfiles",
    "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
]

_CLANG_CFLAGS_EFI_ARM64 = [
    "--target=aarch64-w64-mingw32",
    "-fuse-ld=lld",
    "-nostdlib", "-nodefaultlibs", "-nostartfiles",
    "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
]


def _find_clang_arm64() -> "str | None":
    """Return path to clang supporting aarch64-w64-mingw32 target, or None."""
    for clang in ("clang", "clang-18", "clang-17", "clang-16", "clang-15"):
        path = shutil.which(clang)
        if path:
            r = subprocess.run(
                [path, "--target=aarch64-w64-mingw32", "-print-effective-triple"],
                capture_output=True, timeout=10,
            )
            if r.returncode == 0 and b"aarch64" in r.stdout:
                return path
    return None


def _find_clang_arm64_wsl() -> "tuple[str | None, bool]":
    """Return (clang_path_or_cmd, use_wsl) for aarch64-w64-mingw32 clang, or (None, None)."""
    native = _find_clang_arm64()
    if native:
        return native, False
    if platform.system() == "Windows":
        try:
            r = _wsl_bash_run(
                "clang --target=aarch64-w64-mingw32 -print-effective-triple 2>/dev/null"
                " || clang-18 --target=aarch64-w64-mingw32 -print-effective-triple 2>/dev/null",
                capture_output=True, timeout=15,
            )
            if r.returncode == 0 and b"aarch64" in r.stdout:
                return "__wsl_clang__", True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return None, None


def _compile_efi_pe_arm64(src: Path, out: Path, extra_includes: "Path | None",
                           entry_fn: str) -> subprocess.CompletedProcess:
    """Compile an EFI PE for ARM64 using clang with aarch64-w64-mingw32 target."""
    clang, use_wsl = _find_clang_arm64_wsl()
    assert clang is not None, "clang with aarch64-w64-mingw32 target not found"
    include_flag = [f"-I{extra_includes}"] if extra_includes else []
    if use_wsl:
        inc_flag = f"-I{_win_path_to_wsl(extra_includes)}" if extra_includes else ""
        flags = " ".join(_CLANG_CFLAGS_EFI_ARM64)
        cmd = (f"clang {flags} {inc_flag}"
               f" -Wl,--entry={entry_fn} -Wl,--subsystem=efi_application"
               f" -o {_win_path_to_wsl(out)} {_win_path_to_wsl(src)}")
        return _wsl_bash_run(cmd, capture_output=True, timeout=30)
    return subprocess.run(
        [clang] + _CLANG_CFLAGS_EFI_ARM64
        + include_flag
        + [f"-Wl,--entry={entry_fn}", "-Wl,--subsystem=efi_application",
           "-o", str(out), str(src)],
        capture_output=True, timeout=30,
    )


def _find_qemu_ovmf(arch: str = "x64") -> "tuple[str, str, str] | tuple[None, None, None]":
    """Return (qemu_bin, ovmf_code, ovmf_vars) or (None, None, None) if unavailable."""
    if arch == "arm64":
        qemu_bin_name = "qemu-system-aarch64"
        qemu_win_path = Path(r"C:\Program Files\qemu\qemu-system-aarch64.exe")
        linux_code_candidates = [
            "/usr/share/AAVMF/AAVMF_CODE.fd",             # Ubuntu 24.04+ (split)
            "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",    # Ubuntu (combined)
            "/usr/share/edk2/aarch64/QEMU_EFI.fd",
        ]
        linux_vars_candidates = [
            "/usr/share/AAVMF/AAVMF_VARS.fd",             # Ubuntu 24.04+ (split)
        ]
        qemu = shutil.which(qemu_bin_name)
        if qemu is None and platform.system() == "Windows" and qemu_win_path.exists():
            qemu = str(qemu_win_path)
        if qemu is None:
            return None, None, None
        qemu_share = Path(qemu).parent / "share"
        candidates_code = [str(qemu_share / "edk2-aarch64-code.fd")] + linux_code_candidates
        candidates_vars = linux_vars_candidates + [str(qemu_share / "edk2-aarch64-vars.fd")]
        ovmf_code = next((p for p in candidates_code if Path(p).exists()), None)
        if ovmf_code is None:
            return None, None, None
        ovmf_vars = next((p for p in candidates_vars if Path(p).exists()), None)
        return qemu, ovmf_code, ovmf_vars
    elif arch == "x64":
        qemu_bin_name = "qemu-system-x86_64"
        qemu_win_path = Path(r"C:\Program Files\qemu\qemu-system-x86_64.exe")
        edk2_code = "edk2-x86_64-code.fd"
        edk2_vars = "edk2-x86_64-vars.fd"
        linux_code_candidates = [
            "/usr/share/OVMF/OVMF_CODE_4M.fd",   # Ubuntu 24.04+
            "/usr/share/OVMF/OVMF_CODE.fd",
            "/usr/share/ovmf/OVMF.fd",
            "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        ]
        linux_vars_candidates = [
            "/usr/share/OVMF/OVMF_VARS_4M.fd",   # Ubuntu 24.04+
            "/usr/share/OVMF/OVMF_VARS.fd",
            "/usr/share/ovmf/OVMF_VARS.fd",
            "/usr/share/edk2/ovmf/OVMF_VARS.fd",
        ]
    else:  # IA-32
        qemu_bin_name = "qemu-system-i386"
        qemu_win_path = Path(r"C:\Program Files\qemu\qemu-system-i386.exe")
        edk2_code = "edk2-i386-code.fd"
        edk2_vars = "edk2-i386-vars.fd"
        linux_code_candidates = [
            "/usr/share/OVMF/OVMF32_CODE_4M.fd",
            "/usr/share/edk2/ovmf/OVMF32_CODE_4M.fd",
        ]
        linux_vars_candidates = [
            "/usr/share/OVMF/OVMF32_VARS_4M.fd",
            "/usr/share/edk2/ovmf/OVMF32_VARS_4M.fd",
        ]

    qemu = shutil.which(qemu_bin_name)
    if qemu is None and platform.system() == "Windows" and qemu_win_path.exists():
        qemu = str(qemu_win_path)
    if qemu is None:
        return None, None, None

    qemu_share = Path(qemu).parent / "share"
    candidates_code = [str(qemu_share / edk2_code)] + linux_code_candidates
    candidates_vars = [str(qemu_share / edk2_vars)] + linux_vars_candidates
    ovmf_code = next((p for p in candidates_code if Path(p).exists()), None)
    ovmf_vars = next((p for p in candidates_vars if Path(p).exists()), None)
    if ovmf_code is None:
        return None, None, None
    return qemu, ovmf_code, ovmf_vars


def _compile_efi_pe(gcc_src: Path, out: Path, extra_includes: "Path | None",
                    entry_fn: str, use_wsl: bool,
                    *, arch: str = "x64") -> subprocess.CompletedProcess:
    """Compile an EFI PE using either native or WSL mingw gcc.

    arch="x64" uses x86_64-w64-mingw32-gcc; arch="x86" uses i686-w64-mingw32-gcc.
    Subsystem 10 = EFI_APPLICATION; numeric form avoids older-binutils parsing bugs.
    """
    _gcc = "x86_64-w64-mingw32-gcc" if arch == "x64" else "i686-w64-mingw32-gcc"
    if use_wsl:
        inc = f"-I{_win_path_to_wsl(extra_includes)}" if extra_includes else ""
        flags = " ".join(_MINGW_CFLAGS_EFI)
        cmd = (f"{_gcc} {flags} {inc} -Wl,-e,{entry_fn}"
               f" -Wl,--subsystem,10"
               f" -o {_win_path_to_wsl(out)} {_win_path_to_wsl(gcc_src)}")
        return _wsl_bash_run(cmd, capture_output=True, timeout=30)
    include_flag = [f"-I{extra_includes}"] if extra_includes else []
    return subprocess.run(
        [_gcc] + _MINGW_CFLAGS_EFI
        + include_flag
        + [f"-Wl,-e,{entry_fn}", "-Wl,--subsystem,10",
           "-o", str(out), str(gcc_src)],
        capture_output=True, timeout=30,
    )


def _make_efi_boot_dir(efi_pe: Path, boot_dir: Path, arch: str = "x64") -> None:
    """Populate boot_dir/EFI/BOOT/BOOT*.EFI for QEMU vvfat presentation."""
    efi_boot = boot_dir / "EFI" / "BOOT"
    efi_boot.mkdir(parents=True, exist_ok=True)
    if arch == "x64":
        boot_filename = "BOOTX64.EFI"
    elif arch == "arm64":
        boot_filename = "BOOTAA64.EFI"
    else:
        boot_filename = "BOOTIA32.EFI"
    shutil.copy2(efi_pe, efi_boot / boot_filename)


@pytest.mark.parametrize("arch", ["x64", "x86", "arm64"])
def test_01_efi_hello(arch, tmp_path):
    """EFI shellcode: peor converts an EFI application PE; QEMU+OVMF boots it and shuts down.

    The EFI loader PE (compiled from efi_loader/main.c) embeds the shellcode bytes as a
    C array, calls the shellcode (which returns EFI_SUCCESS=0), then calls ResetSystem.
    QEMU exits 0 on clean UEFI shutdown — that is the success criterion.
    Tested for both x64 (qemu-system-x86_64 + OVMF) and x86 (qemu-system-i386 + OVMF32).
    """
    _build_and_run_efi(tmp_path, _EFI_HELLO_SRC, arch=arch)


# ── P4: EFI QEMU helper ───────────────────────────────────────────────────────


def _build_and_run_efi(tmp_path: Path, efi_src: Path, expected_stdout_substr: str = None,
                        *, arch: str = "x64") -> str:
    """Build an EFI PE, convert to shellcode, embed in loader, boot in QEMU.

    arch="x64"   uses qemu-system-x86_64 + OVMF    + x86_64 MinGW.
    arch="x86"   uses qemu-system-i386   + OVMF32   + i686 MinGW.
    arch="arm64" uses qemu-system-aarch64 + AAVMF   + clang aarch64-w64-mingw32.
    Returns QEMU stdout.  Fails (not skips) if required tools are absent.
    Asserts QEMU exits 0 (ResetSystem called on EFI_SUCCESS).
    """
    if arch == "arm64":
        clang, use_wsl_clang = _find_clang_arm64_wsl()
        assert clang is not None, "clang with aarch64-w64-mingw32 target not found; install clang+lld"
        qemu, ovmf_code, ovmf_vars = _find_qemu_ovmf("arm64")
        assert qemu is not None, "qemu-system-aarch64 not found; install qemu-system-arm"
        assert ovmf_code is not None, "AAVMF firmware not found; install qemu-efi-aarch64"

        prebuilt_pe = _EFI_PREBUILT_ARM64 / (efi_src.parent.name + ".efi")
        if prebuilt_pe.exists():
            efi_pe = prebuilt_pe
        else:
            efi_pe = tmp_path / (efi_src.stem + ".efi")
            cc = _compile_efi_pe_arm64(efi_src, efi_pe, None, "efi_main")
            assert cc.returncode == 0, (
                f"ARM64 EFI PE compile failed:\n{cc.stderr.decode(errors='replace')}"
            )

        sc = tmp_path / (efi_src.stem + ".bin")
        _shellcodify(efi_pe, sc)

        sc_bytes = sc.read_bytes()
        hex_bytes = ", ".join(f"0x{b:02x}" for b in sc_bytes)
        header = (
            f"static const unsigned char SHELLCODE_BYTES[] = {{{hex_bytes}}};\n"
            f"static const unsigned long long SHELLCODE_SIZE = {len(sc_bytes)}ULL;\n"
        )
        (tmp_path / "shellcode_data.h").write_text(header, encoding="ascii")

        loader_efi = tmp_path / "efi_loader.efi"
        cc = _compile_efi_pe_arm64(_EFI_LOADER_SRC, loader_efi, tmp_path, "efi_loader_main")
        assert cc.returncode == 0, (
            f"ARM64 EFI loader compile failed:\n{cc.stderr.decode(errors='replace')}"
        )

        boot_dir = tmp_path / "efi_boot"
        _make_efi_boot_dir(loader_efi, boot_dir, "arm64")

        qemu_cmd = [
            qemu, "-nographic", "-machine", "virt", "-cpu", "cortex-a57",
            "-drive", f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
        ]
        if ovmf_vars:
            aavmf_vars_rw = tmp_path / "AAVMF_VARS.fd"
            shutil.copy2(ovmf_vars, aavmf_vars_rw)
            qemu_cmd += ["-drive", f"if=pflash,format=raw,file={aavmf_vars_rw}"]
        qemu_cmd += [
            "-drive", f"id=boot,if=none,format=vvfat,file=fat:rw:{boot_dir},fat-type=16",
            "-device", "qemu-xhci",
            "-device", "usb-storage,drive=boot",
            "-m", "256M", "-no-reboot",
        ]
        try:
            result = subprocess.run(qemu_cmd, capture_output=True, timeout=300)
        except subprocess.TimeoutExpired:
            pytest.fail("QEMU ARM64 timed out")

        stdout = result.stdout.decode(errors="replace")
        assert result.returncode == 0, (
            f"[arm64 EFI] QEMU exited {result.returncode} (expected 0 = clean shutdown)\n"
            f"stdout: {stdout[:2000]}\nstderr: {result.stderr.decode(errors='replace')[:500]}"
        )
        if expected_stdout_substr is not None:
            assert expected_stdout_substr in stdout, (
                f"[arm64 EFI] Expected {expected_stdout_substr!r} in stdout\nstdout: {stdout[:2000]}"
            )
        return stdout

    if arch == "x64":
        mingw_cmd, use_wsl = _find_mingw_gcc()
        gcc_skip_msg = "x86_64-w64-mingw32-gcc not found (native or WSL)"
        qemu_skip_msg = "qemu-system-x86_64 not found"
    else:
        mingw_cmd, use_wsl = _find_mingw_gcc_32()
        gcc_skip_msg = "i686-w64-mingw32-gcc not found (native or WSL)"
        qemu_skip_msg = "qemu-system-i386 not found"

    if mingw_cmd is None:
        pytest.skip(gcc_skip_msg)

    qemu, ovmf_code, ovmf_vars = _find_qemu_ovmf(arch)
    if qemu is None:
        pytest.skip(qemu_skip_msg)
    if ovmf_code is None:
        pytest.skip(f"OVMF firmware not found for arch={arch} (install ovmf package)")

    # Build the EFI PE from source
    efi_pe = tmp_path / (efi_src.stem + ".efi")
    cc = _compile_efi_pe(efi_src, efi_pe, None, "efi_main", use_wsl, arch=arch)
    assert cc.returncode == 0, (
        f"EFI PE compile failed:\n{cc.stderr.decode(errors='replace')}"
    )

    # Convert to shellcode (auto-detects EFI chain from subsystem 10 + PE bitness)
    sc = tmp_path / (efi_src.stem + ".bin")
    _shellcodify(efi_pe, sc)

    # Generate shellcode_data.h for the EFI loader
    sc_bytes = sc.read_bytes()
    hex_bytes = ", ".join(f"0x{b:02x}" for b in sc_bytes)
    header = (
        f"static const unsigned char SHELLCODE_BYTES[] = {{{hex_bytes}}};\n"
        f"static const unsigned long long SHELLCODE_SIZE = {len(sc_bytes)}ULL;\n"
    )
    header_path = tmp_path / "shellcode_data.h"
    header_path.write_text(header, encoding="ascii")

    # Build the EFI loader with shellcode embedded
    loader_efi = tmp_path / "efi_loader.efi"
    cc = _compile_efi_pe(_EFI_LOADER_SRC, loader_efi, tmp_path, "efi_loader_main", use_wsl, arch=arch)
    assert cc.returncode == 0, (
        f"EFI loader compile failed:\n{cc.stderr.decode(errors='replace')}"
    )

    boot_dir = tmp_path / "efi_boot"
    _make_efi_boot_dir(loader_efi, boot_dir, arch)

    ovmf_vars_rw = tmp_path / "OVMF_VARS.fd"
    if ovmf_vars:
        shutil.copy2(ovmf_vars, ovmf_vars_rw)
    else:
        ovmf_vars_rw.write_bytes(b'\x00' * (540 * 1024))

    qemu_cmd = [
        qemu, "-nographic", "-machine", "q35",
        "-drive", f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
        "-drive", f"if=pflash,format=raw,file={ovmf_vars_rw}",
        "-drive", f"format=vvfat,file=fat:rw:{boot_dir},if=ide,fat-type=16",
        "-m", "256M", "-no-reboot",
    ]
    try:
        result = subprocess.run(qemu_cmd, capture_output=True, timeout=90)
    except subprocess.TimeoutExpired:
        pytest.fail("QEMU timed out")

    stdout = result.stdout.decode(errors="replace")
    assert result.returncode == 0, (
        f"QEMU exited {result.returncode} (expected 0 = clean shutdown)\n"
        f"stdout: {stdout[:2000]}\nstderr: {result.stderr.decode(errors='replace')[:500]}"
    )
    if expected_stdout_substr is not None:
        assert expected_stdout_substr in stdout, (
            f"Expected {expected_stdout_substr!r} in QEMU stdout\nstdout: {stdout[:2000]}"
        )
    return stdout


_EFI_PRINT_SRC       = TESTS_DIR / "EFI" / "02_efi_print"       / "main.c"
_EFI_SIMPLE_CALC_SRC = TESTS_DIR / "EFI" / "03_efi_simple_calc" / "main.c"


@pytest.mark.parametrize("arch", ["x64", "x86", "arm64"])
def test_02_efi_print(arch, tmp_path):
    """EFI shellcode uses ConOut->OutputString to print PEOR_EFI_HELLO.

    The shellcode finds EFI_SYSTEM_TABLE by scanning memory (no runtime params).
    Test checks QEMU stdout for the expected string.  Tested for x64 and x86.
    """
    _build_and_run_efi(tmp_path, _EFI_PRINT_SRC, expected_stdout_substr="PEOR_EFI_HELLO",
                        arch=arch)


@pytest.mark.parametrize("arch", ["x64", "x86", "arm64"])
def test_03_efi_simple_calc(arch, tmp_path):
    """EFI shellcode computes sum(0..99)=4950 and prints PEOR_4950 via ConOut.

    The shellcode finds EFI_SYSTEM_TABLE by scanning memory (no runtime params).
    Test checks QEMU stdout for PEOR_4950.  Tested for x64 and x86.
    """
    _build_and_run_efi(tmp_path, _EFI_SIMPLE_CALC_SRC, expected_stdout_substr="PEOR_4950",
                        arch=arch)


_EFI_CPP_EXCEPTIONS_SRC = TESTS_DIR / "EFI" / "04_cpp_exceptions" / "main.cpp"


@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_04_efi_cpp_exceptions(arch, tmp_path):
    """EFI C++ shellcode: throws and catches a custom type; prints PEOR_CPP_EH_OK on success.

    Requires g++-posix (DWARF-2 or SJLJ exceptions) and peor's ctors runner to initialise
    the GCC EH runtime before efi_main runs.  Tested for x64 and x86.
    """
    if arch == "x64":
        gpp_cmd, use_wsl = _find_mingw_gpp_posix()
        gpp_skip = "x86_64-w64-mingw32-g++-posix not found (install g++-mingw-w64-x86-64)"
    else:
        gpp_cmd, use_wsl = _find_mingw_gpp_posix_32()
        gpp_skip = "i686-w64-mingw32-g++-posix not found (install g++-mingw-w64-i686)"

    if gpp_cmd is None:
        pytest.skip(gpp_skip)

    qemu, ovmf_code, ovmf_vars = _find_qemu_ovmf(arch)
    if qemu is None:
        pytest.skip(f"qemu not found for arch={arch}")
    if ovmf_code is None:
        pytest.skip(f"OVMF firmware not found for arch={arch}")

    efi_pe = tmp_path / "04_efi_cpp.efi"
    cc = _compile_cpp_pe(_EFI_CPP_EXCEPTIONS_SRC, efi_pe, use_wsl, "efi_main", "10", arch=arch)
    assert cc.returncode == 0, (
        f"EFI C++ PE compile failed:\n{cc.stderr.decode(errors='replace')}"
    )

    sc = tmp_path / "04_efi_cpp.bin"
    _shellcodify(efi_pe, sc)

    sc_bytes = sc.read_bytes()
    hex_bytes = ", ".join(f"0x{b:02x}" for b in sc_bytes)
    header = (
        f"static const unsigned char SHELLCODE_BYTES[] = {{{hex_bytes}}};\n"
        f"static const unsigned long long SHELLCODE_SIZE = {len(sc_bytes)}ULL;\n"
    )
    header_path = tmp_path / "shellcode_data.h"
    header_path.write_text(header, encoding="ascii")

    loader_efi = tmp_path / "efi_loader.efi"
    cc = _compile_efi_pe(_EFI_LOADER_SRC, loader_efi, tmp_path, "efi_loader_main", use_wsl, arch=arch)
    assert cc.returncode == 0, (
        f"EFI loader compile failed:\n{cc.stderr.decode(errors='replace')}"
    )

    boot_dir = tmp_path / "efi_boot"
    _make_efi_boot_dir(loader_efi, boot_dir, arch)

    ovmf_vars_rw = tmp_path / "OVMF_VARS.fd"
    if ovmf_vars:
        shutil.copy2(ovmf_vars, ovmf_vars_rw)
    else:
        ovmf_vars_rw.write_bytes(b'\x00' * (540 * 1024))

    qemu_cmd = [
        qemu, "-nographic", "-machine", "q35",
        "-drive", f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
        "-drive", f"if=pflash,format=raw,file={ovmf_vars_rw}",
        "-drive", f"format=vvfat,file=fat:rw:{boot_dir},if=ide,fat-type=16",
        "-m", "256M", "-no-reboot",
    ]
    try:
        result = subprocess.run(qemu_cmd, capture_output=True, timeout=90)
    except subprocess.TimeoutExpired:
        pytest.fail("QEMU timed out for EFI C++ exceptions test")

    stdout = result.stdout.decode(errors="replace")
    assert result.returncode == 0, (
        f"[efi_cpp {arch}] QEMU exited {result.returncode} (expected 0 = clean shutdown)\n"
        f"stdout: {stdout[:2000]}\nstderr: {result.stderr.decode(errors='replace')[:500]}"
    )
    assert "PEOR_CPP_EH_OK" in stdout, (
        f"[efi_cpp {arch}] PEOR_CPP_EH_OK not in QEMU stdout — exception not caught\n"
        f"stdout: {stdout[:2000]}"
    )


# ── P4: x86 Linux user-mode ───────────────────────────────────────────────────


_LINUX_LOADER_CFLAGS_32 = [
    "-m32", "-O2",
    # _FILE_OFFSET_BITS=64: fstat() on DrvFs (/mnt/c/...) fails on 32-bit Linux
    # without this flag (old 32-bit fstat syscall not supported for Windows mounts).
    "-D_FILE_OFFSET_BITS=64",
    # -no-pie -fno-pic: x86-32 PIE uses EBX as the GOT base register; every PLT
    # stub emits "jmp [ebx+N]".  The shellcode's relocs-resolver sets EBX=PE_base
    # and never restores it, so the first PLT call after the shellcode returns
    # (munmap, fprintf, …) would dereference PE_base+N → SIGSEGV.
    # Building as a plain non-PIE executable changes PLT stubs to absolute-address
    # JMPs.
    # -ffixed-{ebx,esi,edi}: even in non-PIE, GCC uses EBX/ESI/EDI as callee-saved
    # scratch registers (e.g. stores the "return 0" value in one of them, then
    # emits "mov eax,<reg>" at the epilogue, relying on callee-save semantics that
    # the shellcode breaks).  The relocs-resolver clobbers EBX=PE_base and ESI=past-
    # reloc; entrypoint-resolver further sets ESI=NT_headers.  EDI gets the reloc
    # delta.  Fixing all three makes the clobbers harmless.
    "-fno-pie", "-no-pie", "-fno-pic", "-ffixed-ebx", "-ffixed-esi", "-ffixed-edi",
    "-ldl",
]

# LIBRARY line omitted: dlltool >=2.41 has a parsing bug with it; use -D flag instead.
_LIBC_DEF_CONTENT_32 = "EXPORTS\nwrite\n"


def _find_mingw_gcc_32():
    """Return ([cmd...], use_wsl) for i686-w64-mingw32-gcc, or (None, None)."""
    gcc = "i686-w64-mingw32-gcc"
    if shutil.which(gcc):
        return [gcc], False
    if platform.system() == "Windows":
        try:
            r = _wsl_bash_run(f"which {gcc}", capture_output=True, timeout=60)
            if r.returncode == 0:
                return ["__wsl__"], True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return None, None


def _find_mingw_gpp_posix() -> "tuple[list | None, bool | None]":
    """Return ([cmd], use_wsl) for x86_64-w64-mingw32-g++-posix, or (None, None)."""
    gpp = "x86_64-w64-mingw32-g++-posix"
    if shutil.which(gpp):
        return [gpp], False
    if platform.system() == "Windows":
        try:
            r = _wsl_bash_run(f"which {gpp}", capture_output=True, timeout=60)
            if r.returncode == 0:
                return ["__wsl__"], True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return None, None


def _find_mingw_gpp_posix_32() -> "tuple[list | None, bool | None]":
    """Return ([cmd], use_wsl) for i686-w64-mingw32-g++-posix, or (None, None)."""
    gpp = "i686-w64-mingw32-g++-posix"
    if shutil.which(gpp):
        return [gpp], False
    if platform.system() == "Windows":
        try:
            r = _wsl_bash_run(f"which {gpp}", capture_output=True, timeout=60)
            if r.returncode == 0:
                return ["__wsl__"], True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return None, None


_CPP_EH_SUPPORT_DIR = TESTS_DIR / "cpp_eh_support"
_LIBC_CPP_DEF_CONTENT = (
    "EXPORTS\n"
    "strlen\nstrncmp\nstrcmp\nmemcpy\nmemset\nmemcmp\nmemmove\nstrchr\nstrtoul\n"
    "free\nmalloc\ncalloc\nrealloc\natexit\nabort\ngetenv\n"
)
_LIBPTHREAD_CPP_DEF_CONTENT = (
    "EXPORTS\n"
    "pthread_mutex_init\npthread_mutex_destroy\npthread_mutex_lock\npthread_mutex_unlock\n"
    "pthread_once\npthread_key_create\npthread_key_delete\npthread_getspecific\npthread_setspecific\n"
)
_LIBPTHREAD_DLL_NAME = "libpthread.so.0"

_MINGW_CPP_EH_FLAGS = ["-fexceptions", "-nostartfiles", "-nodefaultlibs"]
# EFI / Linux: only toolchain libs (no OS runtime)
_MINGW_CPP_STATIC_LIBS = ["-Wl,--start-group", "-lgcc_eh", "-lsupc++", "-lgcc", "-Wl,--end-group"]
# Windows: toolchain libs + Windows DLL stubs all inside one group.
# __mingw_vsprintf is stubbed in freestanding.c so libmingwex is NOT needed.
_MINGW_CPP_STATIC_LIBS_WINDOWS = [
    "-Wl,--start-group",
    "-lgcc_eh", "-lsupc++", "-lgcc",
    "-lmsvcrt", "-lkernel32",
    "-Wl,--end-group",
]


def _compile_cpp_pe(gcc_src: Path, out: Path, use_wsl: Optional[bool],
                    entry: str, subsystem: str, *, arch: str = "x64") -> subprocess.CompletedProcess:
    """Compile a C++ source file to a Windows PE with GCC DWARF exception support.

    Uses peor_crtbegin.c / peor_crtend.c (from tests/cpp_eh_support/) instead of the system
    crtbegin.o / crtend.o.  For EFI targets (subsystem '10' or entry 'efi_main'),
    freestanding.c is also compiled and linked to supply libsupc++/libgcc_eh symbol deps.
    For Linux targets (subsystem 'posix'), libc.so.6 and libpthread.so.0 import libs are
    generated with dlltool and linked so those symbols are resolved at runtime via dlopen.
    """
    gpp = ("x86_64-w64-mingw32-g++-posix" if arch == "x64"
           else "i686-w64-mingw32-g++-posix")
    dlltool = ("x86_64-w64-mingw32-dlltool" if arch == "x64"
               else "i686-w64-mingw32-dlltool")

    is_efi   = (subsystem == "10" or entry == "efi_main")
    is_linux = (subsystem == "posix")

    crtbegin_src     = _CPP_EH_SUPPORT_DIR / "peor_crtbegin.c"
    crtend_src       = _CPP_EH_SUPPORT_DIR / "peor_crtend.c"
    freestanding_src = _CPP_EH_SUPPORT_DIR / "freestanding.c"
    seh_linux64_src  = _CPP_EH_SUPPORT_DIR / "seh_linux64.c"

    arch_tag = arch  # "x64" or "x86" — used in temp file names to avoid conflicts
    use_wsl = use_wsl or False

    # On i686 MinGW COFF, C symbols get a leading underscore prefix, so the
    # linker entry point name must include it.  x64 COFF has no such prefix.
    coff_entry = f"_{entry}" if arch == "x86" else entry

    if use_wsl:
        crtbegin_wsl     = _win_path_to_wsl(crtbegin_src)
        crtend_wsl       = _win_path_to_wsl(crtend_src)
        freestanding_wsl = _win_path_to_wsl(freestanding_src)
        src_wsl = _win_path_to_wsl(gcc_src)
        out_wsl = _win_path_to_wsl(out)

        crtbegin_o      = f"/tmp/peor_crtbegin_{arch_tag}.o"
        crtend_o        = f"/tmp/peor_crtend_{arch_tag}.o"
        freestanding_o  = f"/tmp/peor_freestanding_{arch_tag}.o"
        seh_linux64_o   = f"/tmp/peor_seh_linux64_{arch_tag}.o"

        compile_flags = " ".join(_MINGW_CPP_EH_FLAGS)
        # Windows chain needs kernel32/msvcrt/mingwex inside the group for circular deps
        _libs_list  = _MINGW_CPP_STATIC_LIBS_WINDOWS if not (is_efi or is_linux) else _MINGW_CPP_STATIC_LIBS
        static_libs = " ".join(_libs_list)

        # Step 1: compile crtbegin and crtend (-x c forces C mode so g++ doesn't mangle names)
        cmds = [
            f"{gpp} -x c -fexceptions -c {crtbegin_wsl} -o {crtbegin_o}",
            f"{gpp} -x c -fexceptions -c {crtend_wsl} -o {crtend_o}",
        ]

        if is_efi:
            if arch == "x64":
                # x64 EFI uses Windows SEH exceptions (same as Linux x64).
                # seh_linux64.c with -DPEOR_EFI_SEH provides all runtime symbols
                # (malloc, pthread, kernel32 IAT stubs) using a static heap.
                seh_wsl = _win_path_to_wsl(seh_linux64_src)
                cmds.append(
                    f"{gpp} -x c -fexceptions -DPEOR_EFI_SEH -c {seh_wsl} -o {seh_linux64_o}"
                )
                middle = f"{seh_linux64_o} {src_wsl}"
            else:
                # x86 EFI uses DWARF exceptions — freestanding.c stubs suffice.
                cmds.append(
                    f"{gpp} -x c -fexceptions -DPEOR_EFI -c {freestanding_wsl} -o {freestanding_o}"
                )
                middle = f"{freestanding_o} {src_wsl}"
            extra_libs = ""
        elif is_linux:
            if arch == "x64":
                # x64: seh_linux64.c supplies freestanding Windows-ABI implementations of ALL
                # libc.so.6 / libpthread.so.0 symbols via __imp_* variables so that
                # libsupc++/libgcc_eh (compiled with Windows x64 ABI) don't need to call
                # glibc (which uses SysV ABI).  No import stubs needed.
                seh_wsl = _win_path_to_wsl(seh_linux64_src)
                cmds.append(
                    f"{gpp} -x c -fexceptions -DPEOR_LINUX_SEH -c {seh_wsl} -o {seh_linux64_o}"
                )
                middle = f"{seh_linux64_o} {src_wsl}"
                extra_libs = ""
            else:
                # x86 Linux: libsupc++.a(vterminate.o) references Windows CRT symbols
                # (fwrite, fputs, fputc, _imp____acrt_iob_func, __mingw_vsprintf) that
                # don't exist in libc.so.6 with those names.  Use freestanding.c with
                # -DPEOR_EFI to provide all stubs (pthread, malloc/free, stdio no-ops),
                # just like the x86 EFI path.  No import stubs needed.
                cmds.append(
                    f"{gpp} -x c -fexceptions -DPEOR_EFI -c {freestanding_wsl} -o {freestanding_o}"
                )
                middle = f"{freestanding_o} {src_wsl}"
                extra_libs = ""
        else:
            # Windows: use freestanding stubs (without -DPEOR_EFI) and link Windows CRT/kernel32
            cmds.append(f"{gpp} -x c -fexceptions -c {freestanding_wsl} -o {freestanding_o}")
            middle = f"{freestanding_o} {src_wsl}"
            extra_libs = ""

        # Final link command (use coff_entry for x86 underscore convention)
        if is_linux:
            # x64: seh_linux64.o provides all libc/pthread direct and __imp_* exports, so
            # --disable-auto-import prevents ld from generating pseudo-reloc objects that
            # would reference _pei386_runtime_relocator (unavailable in -nodefaultlibs).
            extra_auto_import = "-Wl,--disable-auto-import" if arch == "x64" else ""
            link_cmd = (
                f"{gpp} {compile_flags} {extra_auto_import} {crtbegin_o} {middle}"
                f" -Wl,--start-group {extra_libs} -lgcc_eh -lsupc++ -lgcc -Wl,--end-group"
                f" {crtend_o}"
                f" -Wl,-e,{coff_entry} -Wl,--subsystem,{subsystem}"
                f" -o {out_wsl}"
            )
        elif is_efi:
            extra_auto_import_efi = "-Wl,--disable-auto-import" if arch == "x64" else ""
            link_cmd = (
                f"{gpp} {compile_flags} {extra_auto_import_efi} {crtbegin_o} {middle}"
                f" {static_libs}"
                f" {crtend_o}"
                f" -Wl,-e,{coff_entry} -Wl,--subsystem,{subsystem}"
                f" -o {out_wsl}"
            )
        else:
            # Windows: static_libs already includes kernel32/msvcrt/mingwex in --start-group
            link_cmd = (
                f"{gpp} {compile_flags} {crtbegin_o} {middle}"
                f" {static_libs}"
                f" {crtend_o}"
                f" -Wl,-e,{coff_entry} -Wl,--subsystem,{subsystem}"
                f" -o {out_wsl}"
            )
        cmds.append(link_cmd)
        full_cmd = " && ".join(cmds)
        return _wsl_bash_run(full_cmd, capture_output=True, timeout=120)
    else:
        # Native (Linux CI): use temp dir for intermediate objects
        import tempfile, os
        tmp_dir = Path(tempfile.gettempdir())
        crtbegin_o     = tmp_dir / f"peor_crtbegin_{arch_tag}.o"
        crtend_o       = tmp_dir / f"peor_crtend_{arch_tag}.o"
        freestanding_o = tmp_dir / f"peor_freestanding_{arch_tag}.o"
        seh_linux64_o  = tmp_dir / f"peor_seh_linux64_{arch_tag}.o"

        def _run(args, **kw):
            return subprocess.run(args, capture_output=True, timeout=60)

        r = _run([gpp, "-x", "c", "-fexceptions", "-c", str(crtbegin_src), "-o", str(crtbegin_o)])
        if r.returncode != 0:
            return r
        r = _run([gpp, "-x", "c", "-fexceptions", "-c", str(crtend_src), "-o", str(crtend_o)])
        if r.returncode != 0:
            return r

        if is_efi:
            if arch == "x64":
                r = _run([gpp, "-x", "c", "-fexceptions", "-DPEOR_EFI_SEH",
                          "-c", str(seh_linux64_src), "-o", str(seh_linux64_o)])
                if r.returncode != 0:
                    return r
                middle_files = [str(seh_linux64_o), str(gcc_src)]
            else:
                r = _run([gpp, "-x", "c", "-fexceptions", "-DPEOR_EFI",
                          "-c", str(freestanding_src), "-o", str(freestanding_o)])
                if r.returncode != 0:
                    return r
                middle_files = [str(freestanding_o), str(gcc_src)]
            extra_libs = []
        elif is_linux:
            libc_def      = tmp_dir / f"libc_cpp_{arch_tag}.def"
            libpthread_def = tmp_dir / f"libpthread_cpp_{arch_tag}.def"
            liblibc_a     = tmp_dir / f"liblibc_cpp_{arch_tag}.a"
            libpthread_a  = tmp_dir / f"libpthread_cpp_{arch_tag}.a"
            libc_def.write_text(_LIBC_CPP_DEF_CONTENT, encoding="ascii")
            libpthread_def.write_text(_LIBPTHREAD_CPP_DEF_CONTENT, encoding="ascii")
            r = _run([dlltool, "-D", _LIBC_DLL_NAME, "-d", str(libc_def), "-l", str(liblibc_a)])
            if r.returncode != 0:
                return r
            r = _run([dlltool, "-D", _LIBPTHREAD_DLL_NAME, "-d", str(libpthread_def), "-l", str(libpthread_a)])
            if r.returncode != 0:
                return r
            if arch == "x64":
                r = _run([gpp, "-x", "c", "-fexceptions", "-DPEOR_LINUX_SEH",
                          "-c", str(seh_linux64_src), "-o", str(seh_linux64_o)])
                if r.returncode != 0:
                    return r
                middle_files = [str(seh_linux64_o), str(gcc_src)]
                extra_libs = [str(liblibc_a), str(libpthread_a)]
            else:
                # x86 Linux: use freestanding.c with -DPEOR_EFI (same as x86 EFI).
                # libsupc++.a(vterminate.o) references Windows CRT symbols that
                # don't exist in libc.so.6; freestanding.c provides all stubs.
                r = _run([gpp, "-x", "c", "-fexceptions", "-DPEOR_EFI",
                          "-c", str(freestanding_src), "-o", str(freestanding_o)])
                if r.returncode != 0:
                    return r
                middle_files = [str(freestanding_o), str(gcc_src)]
                extra_libs = []
        else:
            r = _run([gpp, "-x", "c", "-fexceptions", "-c", str(freestanding_src), "-o", str(freestanding_o)])
            if r.returncode != 0:
                return r
            middle_files = [str(freestanding_o), str(gcc_src)]
            extra_libs = []

        # Windows chain uses the larger group that includes kernel32/msvcrt/mingwex.
        # Linux: extra_libs (libc/libpthread stubs) go inside --start-group so the linker
        # rescans them when libgcc_eh/libsupc++ pull in emutls.o / eh_alloc.o.
        if is_linux:
            auto_import_linux = ["-Wl,--disable-auto-import"] if arch == "x64" else []
            cmd = (
                [gpp] + _MINGW_CPP_EH_FLAGS
                + auto_import_linux
                + [str(crtbegin_o)]
                + middle_files
                + ["-Wl,--start-group"] + extra_libs + ["-lgcc_eh", "-lsupc++", "-lgcc", "-Wl,--end-group"]
                + [str(crtend_o)]
                + [f"-Wl,-e,{coff_entry}", f"-Wl,--subsystem,{subsystem}", "-o", str(out)]
            )
        else:
            native_libs = _MINGW_CPP_STATIC_LIBS_WINDOWS if not is_efi else _MINGW_CPP_STATIC_LIBS
            auto_import = ["-Wl,--disable-auto-import"] if is_efi and arch == "x64" else []
            cmd = (
                [gpp] + _MINGW_CPP_EH_FLAGS
                + auto_import
                + [str(crtbegin_o)]
                + middle_files
                + extra_libs
                + native_libs
                + [str(crtend_o)]
                + [f"-Wl,-e,{coff_entry}", f"-Wl,--subsystem,{subsystem}", "-o", str(out)]
            )
        return subprocess.run(cmd, capture_output=True, timeout=120)


def _ensure_linux_loader_32(use_wsl: bool) -> "Path | None":
    """Build a 32-bit Linux test loader (reuses main.c with -m32).

    Auto-installs gcc-multilib via apt if the compiler is not available.
    """
    loader = TESTS_DIR / "test_loader_linux" / "test_loader_linux_32.pe"
    if loader.exists():
        return loader
    src = TESTS_DIR / "test_loader_linux" / "main.c"
    if not use_wsl:
        return None
    # Ensure gcc-multilib is available; install it if missing.
    probe = _wsl_bash_run(
        "echo 'int main(){}' | gcc -m32 -x c -o /dev/null - 2>/dev/null",
        capture_output=True, timeout=20,
    )
    if probe.returncode != 0:
        _wsl_bash_run(
            "DEBIAN_FRONTEND=noninteractive sudo -n apt-get install -y gcc-multilib",
            capture_output=True, timeout=120,
        )
    flags = " ".join(_LINUX_LOADER_CFLAGS_32)
    cmd = (
        f"gcc {flags}"
        f" -o {_win_path_to_wsl(loader)} {_win_path_to_wsl(src)}"
    )
    r = _wsl_bash_run(cmd, capture_output=True, timeout=60)
    return loader if r.returncode == 0 and loader.exists() else None


def _build_linux_write_pe_32(tmp_path: Path, use_wsl: bool) -> "Path | None":
    """Cross-compile tests/Linux/01_linux_write/main.c as a PE32 with libc.so.6 import."""
    stable = _LINUX_PREBUILD_X86 / "01_linux_write_x86.pe"
    if stable.exists():
        return stable
    _LINUX_PREBUILD_X86.mkdir(parents=True, exist_ok=True)

    src = TESTS_DIR / "Linux" / "01_linux_write" / "main.c"
    if not src.exists():
        return None

    exe      = stable
    def_file = tmp_path / "libc.so.6.def"
    imp_lib  = tmp_path / "liblibc_import32.a"
    def_file.write_text(_LIBC_DEF_CONTENT_32, encoding="ascii")

    _GCC32 = "i686-w64-mingw32-gcc"
    _DLLTOOL32 = "i686-w64-mingw32-dlltool"
    _MAIN_STUB = "void __main(void) {}"

    if use_wsl:
        def_wsl = _win_path_to_wsl(def_file)
        imp_wsl = _win_path_to_wsl(imp_lib)
        src_wsl = _win_path_to_wsl(src)
        exe_wsl = _win_path_to_wsl(exe)
        r = _wsl_bash_run(
            f"{_DLLTOOL32} -D {_LIBC_DLL_NAME} -d {def_wsl} -l {imp_wsl}",
            capture_output=True, timeout=30,
        )
        if r.returncode != 0:
            return None
        cc = _wsl_bash_run(
            f"printf '%s' '{_MAIN_STUB}' > /tmp/_peor_stub32.c"
            f" && {_GCC32} " + " ".join(_MINGW_CFLAGS_LINUX)
            + f" /tmp/_peor_stub32.c {src_wsl} {imp_wsl}"
            f" -Wl,-e,_main -Wl,--subsystem,posix -o {exe_wsl}",
            capture_output=True, timeout=30,
        )
    else:
        r = subprocess.run(
            [_DLLTOOL32, "-D", _LIBC_DLL_NAME, "-d", str(def_file), "-l", str(imp_lib)],
            capture_output=True, timeout=30,
        )
        if r.returncode != 0:
            return None

        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False) as f:
            f.write(_MAIN_STUB)
            stub_file = f.name
        try:
            cc = subprocess.run(
                [_GCC32] + _MINGW_CFLAGS_LINUX
                + [stub_file, str(src), str(imp_lib),
                   "-Wl,-e,_main", "-Wl,--subsystem,posix", "-o", str(exe)],
                capture_output=True, timeout=30,
            )
        finally:
            Path(stub_file).unlink(missing_ok=True)

    if cc.returncode != 0 or not exe.exists():
        return None
    return exe


_LIBC_DEF_CONTENT_CRT = "EXPORTS\nstrlen\nstrncmp\nmemcpy\nfree\nmalloc\n"


def _build_linux_crt_pe(tmp_path: Path, use_wsl: bool, *, arch: str = "x64") -> "Path | None":
    """Cross-compile tests/Linux/03_linux_with_crt/main.c as a PE with libc.so.6 imports.

    Returns the path to the compiled PE, or None on failure.
    Output goes to the stable tests/Linux_x{64,86}/ directory.
    """
    prebuild_dir = _LINUX_PREBUILD_X64 if arch == "x64" else _LINUX_PREBUILD_X86
    stable = prebuild_dir / f"03_linux_with_crt_{arch}.pe"
    if stable.exists():
        return stable
    prebuild_dir.mkdir(parents=True, exist_ok=True)

    src = TESTS_DIR / "Linux" / "03_linux_with_crt" / "main.c"
    if not src.exists():
        return None

    exe      = stable
    def_file = tmp_path / f"libc_crt_{arch}.def"
    imp_lib  = tmp_path / f"liblibc_crt_{arch}.a"
    def_file.write_text(_LIBC_DEF_CONTENT_CRT, encoding="ascii")

    if arch == "x64":
        _GCC    = "x86_64-w64-mingw32-gcc"
        _DLLTOOL = "x86_64-w64-mingw32-dlltool"
    else:
        _GCC    = "i686-w64-mingw32-gcc"
        _DLLTOOL = "i686-w64-mingw32-dlltool"
    _MAIN_STUB = "void __main(void) {}"
    # i686-w64-mingw32 COFF decorates C symbols with a leading underscore
    _coff_main = "_main" if arch == "x86" else "main"

    if use_wsl:
        def_wsl = _win_path_to_wsl(def_file)
        imp_wsl = _win_path_to_wsl(imp_lib)
        src_wsl = _win_path_to_wsl(src)
        exe_wsl = _win_path_to_wsl(exe)

        r = _wsl_bash_run(
            f"{_DLLTOOL} -D {_LIBC_DLL_NAME} -d {def_wsl} -l {imp_wsl}",
            capture_output=True, timeout=30,
        )
        if r.returncode != 0:
            return None

        cc = _wsl_bash_run(
            f"printf '%s' '{_MAIN_STUB}' > /tmp/_peor_crt_stub_{arch}.c"
            f" && {_GCC} " + " ".join(_MINGW_CFLAGS_LINUX)
            + f" /tmp/_peor_crt_stub_{arch}.c {src_wsl} {imp_wsl}"
            f" -Wl,-e,{_coff_main} -Wl,--subsystem,posix -o {exe_wsl}",
            capture_output=True, timeout=30,
        )
    else:
        r = subprocess.run(
            [_DLLTOOL, "-D", _LIBC_DLL_NAME, "-d", str(def_file), "-l", str(imp_lib)],
            capture_output=True, timeout=30,
        )
        if r.returncode != 0:
            return None

        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False) as f:
            f.write(_MAIN_STUB)
            stub_file = f.name
        try:
            cc = subprocess.run(
                [_GCC] + _MINGW_CFLAGS_LINUX
                + [stub_file, str(src), str(imp_lib),
                   f"-Wl,-e,{_coff_main}", "-Wl,--subsystem,posix", "-o", str(exe)],
                capture_output=True, timeout=30,
            )
        finally:
            Path(stub_file).unlink(missing_ok=True)

    if cc.returncode != 0 or not exe.exists():
        return None
    return exe


@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_03_linux_with_crt(arch, tmp_path):
    """Linux C++ shellcode with CRT imports: uses strlen/malloc/free from libc.so.6.

    Compiles main.c linking against a libc.so.6 import lib; the Linux import
    resolver dlopen()s libc.so.6 at runtime.  Returns 73 on success.
    Tested for both x64 and x86.
    """
    prebuilt = (_LINUX_PREBUILD_X64 if arch == "x64" else _LINUX_PREBUILD_X86) / f"03_linux_with_crt_{arch}.pe"

    if arch == "x64":
        mingw_cmd, use_wsl = _find_mingw_gcc()
        if not prebuilt.exists() and mingw_cmd is None:
            pytest.skip("x86_64-w64-mingw32-gcc not found (native PATH or WSL)")
        if use_wsl is None:
            use_wsl = platform.system() == "Windows"
        loader = _ensure_linux_loader(use_wsl)
        if loader is None:
            pytest.skip("Linux test_loader not found and could not be built via WSL")
        exe = _build_linux_crt_pe(tmp_path, use_wsl, arch=arch)
    else:
        mingw_cmd, use_wsl = _find_mingw_gcc_32()
        if not prebuilt.exists() and mingw_cmd is None:
            pytest.skip("i686-w64-mingw32-gcc not found (native PATH or WSL)")
        if use_wsl is None:
            use_wsl = platform.system() == "Windows"
        loader = _ensure_linux_loader_32(use_wsl)
        if loader is None:
            pytest.fail("32-bit Linux test_loader not found and could not be built via WSL — run: wsl sudo apt-get install gcc-multilib")
        exe = _build_linux_crt_pe(tmp_path, use_wsl, arch=arch)

    if exe is None:
        pytest.fail("Failed to build linux_crt PE (dlltool or mingw-gcc unavailable)")

    sc = tmp_path / f"linux_crt_{arch}.bin"
    _shellcodify_platform(exe, sc, _PLATFORM_LINUX)

    if use_wsl:
        sc_wsl = _win_path_to_wsl(sc)
        loader_wsl = _win_path_to_wsl(loader)
        result = subprocess.run(
            ["wsl", "--", loader_wsl, sc_wsl], capture_output=True, timeout=15
        )
    else:
        result = subprocess.run([str(loader), str(sc)], capture_output=True, timeout=15)

    assert result.returncode == 0, (
        f"[linux_crt {arch}] loader crashed with code {result.returncode}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )
    stdout = result.stdout.decode(errors="replace").strip()
    assert stdout == str(LINUX_CRT_RETURN_CODE), (
        f"[linux_crt {arch}] expected stdout '{LINUX_CRT_RETURN_CODE}', got {stdout!r}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


_LIBC_DEF_CONTENT_SIGNAL = "EXPORTS\nsignal\nraise\n"
_LINUX_SIGNAL_SRC = TESTS_DIR / "Linux" / "04_linux_signal" / "main.c"


def _build_linux_signal_pe(tmp_path: Path, use_wsl: bool, *, arch: str = "x64") -> "Path | None":
    """Cross-compile tests/Linux/04_linux_signal/main.c as a PE with libc.so.6 signal/raise imports."""
    prebuild_dir = _LINUX_PREBUILD_X64 if arch == "x64" else _LINUX_PREBUILD_X86
    stable = prebuild_dir / f"04_linux_signal_{arch}.pe"
    if stable.exists():
        return stable
    prebuild_dir.mkdir(parents=True, exist_ok=True)

    src = _LINUX_SIGNAL_SRC
    if not src.exists():
        return None

    exe      = stable
    def_file = tmp_path / f"libc_signal_{arch}.def"
    imp_lib  = tmp_path / f"liblibc_signal_{arch}.a"
    def_file.write_text(_LIBC_DEF_CONTENT_SIGNAL, encoding="ascii")

    if arch == "x64":
        _GCC    = "x86_64-w64-mingw32-gcc"
        _DLLTOOL = "x86_64-w64-mingw32-dlltool"
    else:
        _GCC    = "i686-w64-mingw32-gcc"
        _DLLTOOL = "i686-w64-mingw32-dlltool"
    _MAIN_STUB = "void __main(void) {}"
    _coff_main = "_main" if arch == "x86" else "main"

    if use_wsl:
        def_wsl = _win_path_to_wsl(def_file)
        imp_wsl = _win_path_to_wsl(imp_lib)
        src_wsl = _win_path_to_wsl(src)
        exe_wsl = _win_path_to_wsl(exe)

        r = _wsl_bash_run(
            f"{_DLLTOOL} -D {_LIBC_DLL_NAME} -d {def_wsl} -l {imp_wsl}",
            capture_output=True, timeout=30,
        )
        if r.returncode != 0:
            return None

        cc = _wsl_bash_run(
            f"printf '%s' '{_MAIN_STUB}' > /tmp/_peor_sig_stub_{arch}.c"
            f" && {_GCC} " + " ".join(_MINGW_CFLAGS_LINUX)
            + f" /tmp/_peor_sig_stub_{arch}.c {src_wsl} {imp_wsl}"
            f" -Wl,-e,{_coff_main} -Wl,--subsystem,posix -o {exe_wsl}",
            capture_output=True, timeout=30,
        )
    else:
        r = subprocess.run(
            [_DLLTOOL, "-D", _LIBC_DLL_NAME, "-d", str(def_file), "-l", str(imp_lib)],
            capture_output=True, timeout=30,
        )
        if r.returncode != 0:
            return None

        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False) as f:
            f.write(_MAIN_STUB)
            stub_file = f.name
        try:
            cc = subprocess.run(
                [_GCC] + _MINGW_CFLAGS_LINUX
                + [stub_file, str(src), str(imp_lib),
                   f"-Wl,-e,{_coff_main}", "-Wl,--subsystem,posix", "-o", str(exe)],
                capture_output=True, timeout=30,
            )
        finally:
            Path(stub_file).unlink(missing_ok=True)

    if cc.returncode != 0 or not exe.exists():
        return None
    return exe


@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_04_linux_signal(arch, tmp_path):
    """Linux import resolver: PE imports signal()/raise() from libc.so.6; shellcode installs
    SIGUSR1 handler and raises it; returns 77 (SIGNAL_RETURN_CODE) when handler is called.
    Tested for both x64 and x86.
    """
    prebuilt = (_LINUX_PREBUILD_X64 if arch == "x64" else _LINUX_PREBUILD_X86) / f"04_linux_signal_{arch}.pe"

    if arch == "x64":
        mingw_cmd, use_wsl = _find_mingw_gcc()
        if not prebuilt.exists() and mingw_cmd is None:
            pytest.skip("x86_64-w64-mingw32-gcc not found (native PATH or WSL)")
        if use_wsl is None:
            use_wsl = platform.system() == "Windows"
        loader = _ensure_linux_loader(use_wsl)
        if loader is None:
            pytest.skip("Linux test_loader not found and could not be built via WSL")
    else:
        mingw_cmd, use_wsl = _find_mingw_gcc_32()
        if not prebuilt.exists() and mingw_cmd is None:
            pytest.skip("i686-w64-mingw32-gcc not found (native PATH or WSL)")
        if use_wsl is None:
            use_wsl = platform.system() == "Windows"
        loader = _ensure_linux_loader_32(use_wsl)
        if loader is None:
            pytest.fail("32-bit Linux test_loader not found and could not be built via WSL — run: wsl sudo apt-get install gcc-multilib")

    exe = _build_linux_signal_pe(tmp_path, use_wsl, arch=arch)
    if exe is None:
        pytest.fail("Failed to build linux_signal PE (dlltool or mingw-gcc unavailable)")

    sc = tmp_path / f"linux_signal_{arch}.bin"
    _shellcodify_platform(exe, sc, _PLATFORM_LINUX)

    if use_wsl:
        sc_wsl     = _win_path_to_wsl(sc)
        loader_wsl = _win_path_to_wsl(loader)
        result = subprocess.run(["wsl", "--", loader_wsl, sc_wsl], capture_output=True, timeout=15)
    else:
        result = subprocess.run([str(loader), str(sc)], capture_output=True, timeout=15)

    assert result.returncode == 0, (
        f"[linux_signal {arch}] loader crashed with code {result.returncode}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )
    stdout = result.stdout.decode(errors="replace").strip()
    assert stdout == str(LINUX_SIGNAL_RETURN_CODE), (
        f"[linux_signal {arch}] expected stdout '{LINUX_SIGNAL_RETURN_CODE}', got {stdout!r}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


_LINUX_GLOBAL_CTOR_SRC = TESTS_DIR / "Linux" / "05_linux_global_ctor" / "main.cpp"


@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_05_linux_global_ctor(arch, tmp_path):
    """Linux global C++ constructor test: peor's ctors runner fires two Adder constructors
    before main(); counter reaches 99; main returns 99.  Tested for x64 and x86.
    """
    prebuild_dir = _LINUX_PREBUILD_X64 if arch == "x64" else _LINUX_PREBUILD_X86
    prebuilt = prebuild_dir / f"05_linux_global_ctor_{arch}.pe"

    if arch == "x64":
        gpp_cmd, use_wsl = _find_mingw_gpp_posix()
        gpp_skip = "x86_64-w64-mingw32-g++-posix not found (install g++-mingw-w64-x86-64)"
        loader = _ensure_linux_loader(use_wsl)
    else:
        gpp_cmd, use_wsl = _find_mingw_gpp_posix_32()
        gpp_skip = "i686-w64-mingw32-g++-posix not found (install g++-mingw-w64-i686)"
        loader = _ensure_linux_loader_32(use_wsl)

    if not prebuilt.exists() and gpp_cmd is None:
        pytest.skip(gpp_skip)
    if use_wsl is None:
        use_wsl = platform.system() == "Windows"
    if loader is None:
        pytest.fail("Linux test_loader not found and could not be built — install gcc-multilib")

    if not prebuilt.exists():
        prebuild_dir.mkdir(parents=True, exist_ok=True)
        cc = _compile_cpp_pe(_LINUX_GLOBAL_CTOR_SRC, prebuilt, use_wsl, "main", "posix", arch=arch)
        assert cc.returncode == 0, (
            f"[linux_global_ctor {arch}] compile failed:\n{cc.stderr.decode(errors='replace')}"
        )
    exe = prebuilt

    sc = tmp_path / f"linux_global_ctor_{arch}.bin"
    _shellcodify_platform(exe, sc, _PLATFORM_LINUX)

    if use_wsl:
        sc_wsl     = _win_path_to_wsl(sc)
        loader_wsl = _win_path_to_wsl(loader)
        result = subprocess.run(["wsl", "--", loader_wsl, sc_wsl], capture_output=True, timeout=15)
    else:
        result = subprocess.run([str(loader), str(sc)], capture_output=True, timeout=15)

    assert result.returncode == 0, (
        f"[linux_global_ctor {arch}] loader crashed with code {result.returncode}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )
    stdout = result.stdout.decode(errors="replace").strip()
    assert stdout == str(LINUX_GLOBAL_CTOR_RETURN_CODE), (
        f"[linux_global_ctor {arch}] expected stdout '{LINUX_GLOBAL_CTOR_RETURN_CODE}', got {stdout!r}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


_EFI_MEMORY_SERVICES_SRC = TESTS_DIR / "EFI" / "05_efi_memory_services" / "main.c"


@pytest.mark.parametrize("arch", ["x64", "x86", "arm64"])
def test_05_efi_memory_services(arch, tmp_path):
    """EFI shellcode calls AllocatePool from EFI_BOOT_SERVICES, writes magic byte 66,
    reads it back; returns EFI_SUCCESS on match so QEMU shuts down cleanly.
    Tested for both x64 and x86.
    """
    _build_and_run_efi(tmp_path, _EFI_MEMORY_SERVICES_SRC, arch=arch)


@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_17_mingw_cpp_exceptions(arch, tmp_path):
    """Windows MinGW DWARF C++ exception shellcode: throws PeorMinGWException{42}, returns 42.

    Uses peor's ctors runner to initialise DWARF EH frames before entry.
    Tests that peor's Windows chain now supports .init_array-based EH registration.
    """
    if arch == "x64":
        gpp_cmd, use_wsl = _find_mingw_gpp_posix()
        skip_msg = "x86_64-w64-mingw32-g++-posix not found"
        loader = TESTS_DIR / "Win_x64" / "test_loader.exe"
    else:
        gpp_cmd, use_wsl = _find_mingw_gpp_posix_32()
        skip_msg = "i686-w64-mingw32-g++-posix not found"
        loader = TESTS_DIR / "Win_x86" / "test_loader.exe"

    if gpp_cmd is None:
        pytest.skip(skip_msg)
    if not loader.exists():
        pytest.skip(f"test_loader not found: {loader}")

    src = TESTS_DIR / "Windows" / "17_mingw_cpp_exceptions" / "main.cpp"
    exe = tmp_path / f"mingw_cpp_{arch}.exe"
    cc = _compile_cpp_pe(src, exe, use_wsl, "WinMain", "windows", arch=arch)
    assert cc.returncode == 0, f"MinGW C++ compile failed:\n{cc.stderr.decode(errors='replace')}"

    sc = tmp_path / f"mingw_cpp_{arch}.bin"
    _shellcodify(exe, sc)

    result = subprocess.run([str(loader), str(sc)], capture_output=True, timeout=15)
    assert result.returncode == MINGW_CPP_EH_RETURN_CODE, (
        f"[mingw_cpp {arch}] expected exit {MINGW_CPP_EH_RETURN_CODE}, got {result.returncode}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch,cmd_path,loader_subdir", [
    ("x64", r"C:\Windows\System32\cmd.exe", "Win_x64"),
    ("x86", r"C:\Windows\SysWOW64\cmd.exe", "Win_x86"),
], ids=["x64", "x86"])
def test_cmdexe(arch, cmd_path, loader_subdir, tmp_path):
    """Windows cmd.exe shellcodified and run; verifies echo command output.

    Shellcodifies the system cmd.exe (System32 for x64, SysWOW64 for x86),
    runs via test_loader with stdin piped to 'echo PEOR_CMD_TEST', checks output.
    """
    if platform.system() != "Windows":
        pytest.skip("cmd.exe test is Windows-only")
    cmd_pe = Path(cmd_path)
    if not cmd_pe.exists():
        pytest.skip(f"cmd.exe not found at {cmd_path}")
    loader = TESTS_DIR / loader_subdir / "test_loader.exe"
    if not loader.exists():
        pytest.skip(f"test_loader not found: {loader}")

    sc = tmp_path / f"cmd_{arch}.bin"
    _shellcodify(cmd_pe, sc)

    cmd_input = b"echo PEOR_CMD_TEST\r\nexit\r\n"
    result = subprocess.run(
        [str(loader), str(sc)],
        input=cmd_input, capture_output=True, timeout=15,
    )
    stdout = result.stdout.decode(errors="replace")
    assert "PEOR_CMD_TEST" in stdout, (
        f"[cmdexe {arch}] 'PEOR_CMD_TEST' not found in output\n"
        f"stdout: {stdout[:500]!r}\nstderr: {result.stderr.decode(errors='replace')[:200]}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_18_bss_gap(arch, tmp_path):
    """Static zero-initialized array must be zero in shellcode output; returns 88 if all zero."""
    win_dir     = ARCH_DIRS[arch]
    pe_path     = win_dir / "18_bss_gap.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"18_bss_gap_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True, timeout=10,
    )
    assert result.returncode == 88, (
        f"[{arch}] expected exit code 88 (BSS was zero), got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_19_ordinal_imports(arch, tmp_path):
    """EXE imports ByNameFunc by name and OrdinalOnlyFunc by ordinal 7; sum must be 42."""
    win_dir     = ARCH_DIRS[arch]
    pe_path     = win_dir / "19_ordinal_imports.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"19_ordinal_imports_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True, timeout=10,
        cwd=str(win_dir),  # ordinal_helper.dll must be findable from test_loader cwd
    )
    assert result.returncode == 42, (
        f"[{arch}] expected exit code 42 (ordinal import resolved), got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_20_forwarded_exports(arch, tmp_path):
    """EXE imports GetCurrentProcessId_via_forward from forwarded_helper.dll (a forwarded export
    to KERNEL32.GetCurrentProcessId); verifies peor's resolver handles forwarded exports."""
    win_dir     = ARCH_DIRS[arch]
    pe_path     = win_dir / "20_forwarded_exports.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"20_forwarded_exports_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True, timeout=10,
        cwd=str(win_dir),  # forwarded_helper.dll must be findable in the app dir
    )
    assert result.returncode == 77, (
        f"[{arch}] expected exit code 77 (RtlMoveMemory resolved), got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_21_api_sets(arch, tmp_path):
    """EXE imports HeapAlloc from api-ms-win-core-heap-l1-1-0.dll (virtual API set DLL)."""
    win_dir     = ARCH_DIRS[arch]
    pe_path     = win_dir / "21_api_sets.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"21_api_sets_{arch}.bin"
    _shellcodify(pe_path, shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True, timeout=10,
    )
    assert result.returncode == 42, (
        f"[{arch}] expected exit code 42 (API set DLL resolved), got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )
