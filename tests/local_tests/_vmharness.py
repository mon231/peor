"""SSH/SCP plumbing for the peor-kernel VM tests.

The VM is the Windows test machine the real ring-0 chains run on:

* ``push`` / ``pull``  --- copy files host<->VM over scp.
* ``run``              --- ssh command execution (OpenSSH client).
* ``service_create/start/stop/remove`` --- sc.exe wrappers used to load
    and unload the peor loader driver under test.
* ``read_text``        --- read a marker file back as text
    (``type``), or None when the file does not exist.

Configuration comes from environment variables (see conftest.py):
  PEOR_VM_HOST  (default 192.168.52.129)  PEOR_VM_PORT (22)
  PEOR_VM_USER  (empty = rely on ssh config/identity)   PEOR_VM_SSH_KEY
Requires sc.exe-compatible shell on the VM (the Windows OpenSSH default
shell works: commands run through cmd.exe).
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess


class VmError(RuntimeError):
    """Any VM plumbing failure (ssh/scp/sc)."""


class VmHarness:
    def __init__(self, host, port=22, user="", ssh_key=None,
                 connect_timeout=8):
        self.host = host
        self.port = int(port)
        self.user = user
        self.ssh_key = ssh_key
        self.connect_timeout = connect_timeout
        if shutil.which("ssh") is None:
            raise VmError("OpenSSH client (ssh.exe) not on PATH")

    # ------------------------------------------------------------------
    @classmethod
    def from_env(cls) -> "VmHarness":
        host = os.environ.get("PEOR_VM_HOST", "192.168.52.129")
        port = os.environ.get("PEOR_VM_PORT", "22")
        user = os.environ.get("PEOR_VM_USER", "")
        key = os.environ.get("PEOR_VM_SSH_KEY") or None
        return cls(host, port=port, user=user, ssh_key=key)

    @property
    def _target(self):
        return f"{self.user}@{self.host}" if self.user else self.host

    def _common_args(self):
        args = ["-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", f"Port={self.port}",
                "-o", f"ConnectTimeout={self.connect_timeout}"]
        if self.ssh_key:
            args += ["-i", self.ssh_key]
        return args

    # ------------------------------------------------------------------
    def reachable(self) -> bool:
        """Cheap connectivity probe (no credential requirement checked)."""
        rc, _ = self.run("ver", timeout=self.connect_timeout + 6, check=False)
        return rc == 0

    def run(self, cmd, timeout=60, check=True):
        proc = subprocess.run(
            ["ssh", *self._common_args(), self._target, cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if check and proc.returncode != 0:
            raise VmError(
                f"ssh {self._target} failed rc={proc.returncode}: {cmd!r}\n{out}")
        return proc.returncode, out

    def push(self, src: pathlib.Path, dst: str, timeout=120):
        proc = subprocess.run(
            ["scp", "-o", "BatchMode=yes", "-o", f"Port={self.port}",
             *(["-i", self.ssh_key] if self.ssh_key else []),
             str(src), f"{self._target}:{dst}"],
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0:
            raise VmError(f"scp push {src} -> {dst} failed\n"
                          f"{proc.stdout}\n{proc.stderr}")

    def pull(self, src: str, dst: pathlib.Path, timeout=120):
        dst = pathlib.Path(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            ["scp", "-o", "BatchMode=yes", "-o", f"Port={self.port}",
             *(["-i", self.ssh_key] if self.ssh_key else []),
             f"{self._target}:{src}", str(dst)],
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0:
            raise VmError(f"scp pull {src} -> {dst} failed\n"
                          f"{proc.stdout}\n{proc.stderr}")
        return dst

    def read_text(self, path: str, timeout=30) -> str | None:
        rc, out = self.run(f'type "{path}"', timeout=timeout, check=False)
        if rc != 0:
            return None
        return out

    def cleanup_marker(self, path: str):
        self.run(f'if exist "{path}" del /f /q "{path}"', check=False)

    # ------------------------------------------------------------------
    # driver-service helpers (sc.exe; runs as the ssh user, typically SYSTEM)
    def service_create(self, name: str, bin_path: str):
        self.run(f'sc create {name} type= kernel start= demand '
                 f'binPath= "{bin_path}"', timeout=60)

    def service_start(self, name: str):
        self.run(f"sc start {name}", timeout=120)

    def service_stop(self, name: str):
        self.run(f"sc stop {name}", check=False, timeout=60)

    def service_remove(self, name: str):
        self.run(f"sc delete {name}", check=False, timeout=60)
