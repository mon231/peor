import os
import re
import sys
import time
import struct
import shutil
import ctypes
import platform
import subprocess
from pathlib import Path

import pytest
from pefile import PE

from pefile import OPTIONAL_HEADER_MAGIC_PE_PLUS

from peor.__main__ import (
    dump_memory_layout,
    _build_shellcode_chain,
    _find_export_rva,
    _SHELLCODES,
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
)

TESTS_DIR = Path(__file__).parent.parent

ARCH_DIRS = {
    "x86": TESTS_DIR / "Win_x86",
    "x64": TESTS_DIR / "Win_x64",
}

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

    # Click the OK button directly — more reliable than posting WM_COMMAND to the dialog.
    # SendMessageA is synchronous so the button-click is fully processed before we return.
    hwnd_ok = user32.FindWindowExA(hwnd, None, b"Button", None)
    if hwnd_ok:
        user32.SendMessageA(hwnd_ok, 0x00F5, 0, 0)  # BM_CLICK
    else:
        user32.SendMessageA(hwnd, _WM_COMMAND, _IDOK, 0)
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

    msgbox = _poll_and_dismiss_msgbox(_MSGBOX_TITLE)

    if not msgbox["found"]:
        proc.kill()
        pytest.fail(f"[{arch}] MessageBox '{_MSGBOX_TITLE}' did not appear within timeout")

    proc.wait(timeout=5)

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


def _win_path_to_wsl(p: Path) -> str:
    """Convert an absolute Windows path to its WSL /mnt/<drive>/... form."""
    s = str(p).replace("\\", "/")
    if len(s) >= 2 and s[1] == ":":
        return f"/mnt/{s[0].lower()}{s[2:]}"
    return s


def _find_mingw_gcc():
    """Return (cmd_prefix_list, use_wsl) or (None, None) if unavailable.

    Tries the native PATH first; falls back to WSL on Windows.
    """
    gcc = "x86_64-w64-mingw32-gcc"
    if shutil.which(gcc):
        return [gcc], False
    if platform.system() == "Windows" and shutil.which("wsl"):
        r = subprocess.run(["wsl", "--", "which", gcc],
                           capture_output=True, timeout=10)
        if r.returncode == 0:
            return ["wsl", "--", gcc], True
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
    loader = TESTS_DIR / "test_loader_linux" / "test_loader_linux"
    if loader.exists():
        return loader
    src = TESTS_DIR / "test_loader_linux" / "main.c"
    if not use_wsl or not shutil.which("wsl"):
        return None
    r = subprocess.run(
        ["wsl", "--", "gcc"] + _LINUX_LOADER_CFLAGS
        + ["-o", _win_path_to_wsl(loader), _win_path_to_wsl(src)],
        capture_output=True, timeout=30,
    )
    return loader if r.returncode == 0 and loader.exists() else None


def _find_clangcl() -> "str | None":
    """Return path to clang-cl or None if not found.

    Tries PATH first, then common LLVM install locations on Windows.
    """
    if shutil.which("clang-cl"):
        return shutil.which("clang-cl")
    candidates = [
        r"C:\Program Files\LLVM\bin\clang-cl.exe",
        r"C:\Program Files (x86)\LLVM\bin\clang-cl.exe",
        # VS-bundled LLVM (present on GitHub windows-latest runners)
        r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\Llvm\x64\bin\clang-cl.exe",
        r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin\clang-cl.exe",
    ]
    return next((p for p in candidates if Path(p).exists()), None)


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
    if use_wsl:
        src_wsl = _win_path_to_wsl(src)
        exe_wsl = _win_path_to_wsl(exe)
        cc = subprocess.run(
            ["wsl", "--", "bash", "-c",
             f"echo '{stub_c}' | {mingw_cmd[-1]} "
             + " ".join(_MINGW_CFLAGS)
             + f" -x c - {src_wsl} -Wl,-e,main -o {exe_wsl}"],
            capture_output=True, timeout=30,
        )
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
        loader = TESTS_DIR / "test_loader_linux" / "test_loader_linux"
        if not loader.exists():
            pytest.skip(
                "Linux test_loader not found — "
                "build with: gcc -O2 -ffixed-rbx -ffixed-r12 -ffixed-r13 "
                "-ffixed-r14 -ffixed-r15 -o tests/test_loader_linux/test_loader_linux "
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
        capture_output=True, timeout=30,
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
