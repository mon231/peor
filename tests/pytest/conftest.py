import shutil
import platform
import subprocess
from pathlib import Path

_TESTS_DIR = Path(__file__).parent.parent


def _win_to_wsl(p: Path) -> str:
    s = str(p).replace("\\", "/")
    if len(s) >= 2 and s[1] == ":":
        return f"/mnt/{s[0].lower()}{s[2:]}"
    return s


def _wsl_run(cmd: str, timeout: int = 360) -> int:
    git_bash_candidates = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
    ]
    git_bash = next((c for c in git_bash_candidates if Path(c).exists()), shutil.which("bash"))
    try:
        if git_bash:
            r = subprocess.run(
                [git_bash, "-c", f"wsl bash -c {repr(cmd)}"],
                capture_output=True, timeout=timeout,
            )
        else:
            r = subprocess.run(["wsl", "bash", "-c", cmd], capture_output=True, timeout=timeout)
        return r.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1


def pytest_sessionstart(session):
    if platform.system() != "Windows":
        return

    loader32 = _TESTS_DIR / "test_loader_linux" / "test_loader_linux_32.pe"
    if loader32.exists():
        return

    src = _TESTS_DIR / "test_loader_linux" / "main.c"
    if not src.exists():
        return

    probe = _wsl_run("echo 'int main(){}' | gcc -m32 -x c -o /dev/null - 2>/dev/null", timeout=20)
    if probe != 0:
        _wsl_run(
            "DEBIAN_FRONTEND=noninteractive sudo -n apt-get install -y gcc-multilib",
            timeout=120,
        )

    _wsl_run(
        "gcc -m32 -O2 -ffixed-ebx -ffixed-esi -ffixed-edi"
        f" -o {_win_to_wsl(loader32)} {_win_to_wsl(src)}",
        timeout=120,
    )
