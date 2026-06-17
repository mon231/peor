import re
import time
import ctypes
import subprocess
from pathlib import Path

import pytest
from pefile import PE

from peor.__main__ import dump_memory_layout

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
    dump_memory_layout(PE(str(pe_path)), shellcode_path)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True,
    )

    assert result.returncode == expected, (
        f"[{arch}] {test_name}: expected exit code {expected}, got {result.returncode}\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_03_winapi_messagebox(arch, tmp_path):
    win_dir = ARCH_DIRS[arch]
    pe_path = win_dir / "03_winapi_messagebox.exe"
    loader_path = win_dir / "test_loader.exe"
    _skip_if_missing(loader_path, pe_path)

    shellcode_path = tmp_path / f"03_winapi_messagebox_{arch}.bin"
    dump_memory_layout(PE(str(pe_path)), shellcode_path, resolve_imports=True)

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
    dump_memory_layout(PE(str(pe_path)), shellcode_path, resolve_imports=True)

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
    dump_memory_layout(PE(str(pe_path)), shellcode_path, resolve_imports=True)

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
    dump_memory_layout(PE(str(pe_path)), shellcode_path)

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
    dump_memory_layout(PE(str(pe_path)), shellcode_path, resolve_imports=True)

    result = subprocess.run(
        [str(loader_path), str(shellcode_path)],
        capture_output=True,
        timeout=10,
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
    dump_memory_layout(PE(str(pe_path)), shellcode_path, resolve_imports=True)

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
