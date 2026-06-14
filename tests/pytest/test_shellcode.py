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

# (test_name, expected_exit_code)
TEST_CASES = [
    ("01_simple_calc", 4950),     # importless: sum(0..99) = 4950
    ("02_relocs_functions", 90),  # with .reloc section: accumulate returns 100, g_value ends at 90
]


@pytest.mark.parametrize("arch", ["x86", "x64"])
@pytest.mark.parametrize("test_name,expected", TEST_CASES, ids=[t[0] for t in TEST_CASES])
def test_shellcode_returns_expected(arch, test_name, expected, tmp_path):
    win_dir = ARCH_DIRS[arch]
    pe_path = win_dir / f"{test_name}.exe"
    loader_path = win_dir / "test_loader.exe"

    if not loader_path.exists():
        pytest.skip(f"test_loader.exe not found at {loader_path} — build tests/tests.sln first")
    if not pe_path.exists():
        pytest.skip(f"{pe_path.name} not found at {pe_path}")

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
