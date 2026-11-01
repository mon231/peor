"""Real WDK-built kernel chain pipeline for the peor local-test VM suite.

Build steps (host side - no VM needed to compile):

1. WDK-compile a payload driver from ``kernelsrc/*.c`` into a real
   NATIVE-subsystem .sys in an executable in-memory copy (see
   ``WdkToolchain.compile_sys`` in ``_wdk.py``).
2. Convert the .sys into the peor kernel64 chain blob via the CLI
   (``python -m peor -i ... --platform kernel64``).
3. Embed the chain blob into a WDK-built loader driver: at SCM-load time
   ``loader_core.c`` allocates executable non-paged pool, copies the blob,
   calls it (real ring-0 execution of the peor output), and reports the
   chain's NTSTATUS to ``C:\\Windows\\Temp\\peor_chain_result.txt``.

Payload markers written by the payloads in ring-0:

* calc  (``kernelsrc/calc.c``)  -> ``peor_calc_result.txt``  with sum 5
* spawn (``kernelsrc/spawn.c``) -> ``peor_spawn_status.txt``, plus the
  REAL child process (cmd.exe) it starts writes ``peor_spawn_cmds.txt``.
"""
from __future__ import annotations

import pathlib
import subprocess

LOCAL = pathlib.Path(__file__).resolve().parent
REPO_ROOT = LOCAL.parent.parent
KNSRC = LOCAL / "kernelsrc"

# Documented ntoskrnl APIs imported directly (WDK ntoskrnl.lib):
# the loader allocates/copy-calls the chain and writes its own marker
# file; the payloads import the Zw triplet for their marker files.
SYMBOLS_LOADER = ("ExAllocatePoolWithTag", "ExFreePoolWithTag",
                  "ZwCreateFile", "ZwWriteFile", "ZwClose")
SYMBOLS_CALC = ("ExAllocatePoolWithTag", "ExFreePoolWithTag",
                "ZwCreateFile", "ZwWriteFile", "ZwClose",
                "RtlNtStatusToDosError", "RtlInitUnicodeString",
                "MmGetSystemRoutineAddress")
SYMBOLS_SPAWN = SYMBOLS_CALC

# NonPagedPool (win8+ executable memory region) - the type enum value
# must be an executable pool, so use legacy page-executable region:
POOL_EXECUTABLE = 0

DRIVER_OBJECT_UNLOAD_SLOT = 0x70   # x64 DRIVER_OBJECT->DriverUnload offset

PEOR_CHAIN_TAG = 0x524F4540        # ASCII 'PEOR' little-endian

PEOR_CHAIN_RESULT_PATH = r"C:\Windows\Temp\peor_chain_result.txt"
PEOR_CALC_RESULT_PATH = r"C:\Windows\Temp\peor_calc_result.txt"
PEOR_SPAWN_STATUS_PATH = r"C:\Windows\Temp\peor_spawn_status.txt"
PEOR_SPAWN_CMDS_PATH = r"C:\Windows\Temp\peor_spawn_cmds.txt"
PEOR_CHILD_EXE_PATH = r"C:\Windows\Temp\peor_child.exe"


class ChainBuildError(RuntimeError):
    """Failure of the peor CLI, WDK toolchain, or the source sources."""


def ensure_shellcodes() -> None:
    """peor/_shellcodes.py is a generated build artifact; mint lazily."""
    shellcodes = REPO_ROOT / "peor" / "_shellcodes.py"
    if not shellcodes.exists():
        subprocess.run(["python", "setup.py", "--name"],
                       capture_output=True, text=True,
                       cwd=str(REPO_ROOT), timeout=300, check=False)
    if not shellcodes.exists():
        raise ChainBuildError("python setup.py --name did not produce peor/_shellcodes.py")


def build_chain(sys_path: pathlib.Path, work_dir: pathlib.Path,
                platform: str = "kernel64") -> bytes:
    """peor CLI on a WDK-built payload .sys -> kernel chain bytes.

    Verifies the exact worst chain prologue the kernel64 resolver expects
    (5 55 56 57 = push rbx, rbp, rsi, rdi) so shellcode corruption can be
    detected before ever being pushed to the VM.
    """
    ensure_shellcodes()
    blob_path = work_dir / (sys_path.stem + "_chain.bin")
    proc = subprocess.run(
        ["python", "-m", "peor", "-i", str(sys_path),
         "--platform", platform, "-o", str(blob_path)],
        capture_output=True, text=True, timeout=300,
        cwd=str(REPO_ROOT),
    )
    if not blob_path.exists():
        raise ChainBuildError(
            f"peor CLI did not write chain: {blob_path}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    blob = blob_path.read_bytes()
    if blob[:4] != b"\x53\x55\x56\x57":
        raise ChainBuildError(
            f"peor chain output unexpected prologue: {blob[:8].hex()}"
        )
    return blob


def write_chain_blob_inc(blob: bytes, out_dir: pathlib.Path) -> pathlib.Path:
    """`chain_blob.inc` included by kernelsrc/loader_core.c.

    Static const array keeps the blob in .rdata (non-paged); loader_core
    copies it into executable non-paged pool at DriverEntry time.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = "/* Generated: embedded peor kernel64 chain bytes. */\n" \
            "static const unsigned char peorChainBlob[] = {\n"
    chunks = [", ".join(f"0x{b:02X}" for b in blob[i:i + 16]) + ","
              for i in range(0, len(blob), 16)]
    lines += "\n".join(chunks) + "\n};\n"
    inc = out_dir / "chain_blob.inc"
    inc.write_text(lines, encoding="ascii")
    return inc


def compile_loader(wdk, blob: bytes, out_dir: pathlib.Path,
                   chain_name: str = "loader") -> pathlib.Path:
    """WDK-compile the SCM loader embedding `blob` -> <name>.sys."""
    inc = write_chain_blob_inc(blob, out_dir)
    assert inc.name == "chain_blob.inc"
    return wdk.compile_sys(
        [KNSRC / "loader_core.c"],
        out_dir / f"peor_{chain_name}.sys",
        include_dirs=[str(out_dir), str(KNSRC)],
    )


# --------------------------------------------------------------------------
# markers
# --------------------------------------------------------------------------
# Payloads and loader report status via a simple marker file on the VM.
# Files are deleted by the VM harness before each run.
