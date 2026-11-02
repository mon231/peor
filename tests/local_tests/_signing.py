"""Test-signing support for the local VM driver tests.

Windows refuses to load an unsigned kernel driver (SC StartService
FAILED 577) even with `bcdedit /set testsigning on`: the image must at
least carry an Authenticode signature that chains to a local trusted
root. This helper:

1. Creates a one-off self-signed CodeSigning certificate on the host
   (cached in a per-user directory so test runs reuse it).
2. Signs each WDK-built loader .sys with signtool (embedded signature).
3. Writes the certificate to the VM's `Root` and `TrustedPeople`
   stores over ssh (`certutil -addstore -f ...`, the ssh session is
   high-integrity when the user is an administrator).

Cache dir override: PEOR_TESTCERT_DIR. Delete the PFX to regenerate.
"""
from __future__ import annotations

import os
import pathlib
import subprocess

PFX_PASSWORD = "peor-local-test-not-a-secret"
CERT_SUBJECT = "peor-local-test-signing"
CERT_NAME = "peor-local-test"

_TEMPLATES = (
    # signtool under the WDK bin dir (kit_root, kit_version).
    ("C:\\Program Files (x86)\\Windows Kits\\10\\bin\\{ver}\\x64\\signtool.exe", {}),
    ("C:\\Program Files (x86)\\Windows Kits\\10\\bin\\{ver}\\x86\\signtool.exe", {}),
)


def cache_dir() -> pathlib.Path:
    d = pathlib.Path(os.environ.get("PEOR_TESTCERT_DIR") or
                    (pathlib.Path(os.environ.get("TEMP", ".")) / "opencode" / "cert"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _pfx() -> pathlib.Path:
    return cache_dir() / f"{CERT_NAME}.pfx"


def _cer() -> pathlib.Path:
    return cache_dir() / f"{CERT_NAME}.cer"


def signtool(wdk) -> pathlib.Path:
    """Locate signtool.exe under the WDK this test run is using."""
    cands = [
        wdk.kit_root / "bin" / wdk.kit_version / "x64" / "signtool.exe",
        wdk.kit_root / "bin" / wdk.kit_version / "x86" / "signtool.exe",
    ]
    for c in cands:
        if c.exists():
            return c
    raise RuntimeError(f"signtool.exe not found in {[str(c) for c in cands]}")


def _run(cmd, timeout=120):
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise RuntimeError(f"{' '.join(str(c) for c in cmd)} rc={proc.returncode}\n{out}")
    return out


def ensure_cert() -> tuple[pathlib.Path, pathlib.Path]:
    """Host-side self-signed code-signing cert (PFX + CER), cached."""
    pfx, cer = _pfx(), _cer()
    if pfx.exists() and cer.exists():
        return pfx, cer
    pw = subprocess.list2cmdline([PFX_PASSWORD])
    ps = f"""
$cert = New-SelfSignedCertificate -Type CodeSigningCert `
    -Subject "CN={CERT_SUBJECT}" -CertStoreLocation Cert:\\CurrentUser\\My `
    -KeyUsage DigitalSignature -KeyExportPolicy Exportable `
    -TextExtension @('2.5.29.37={{text}}1.3.6.1.5.5.7.3.3')
Export-PfxCertificate -Cert $cert -FilePath "{pfx}" -Password `
    (ConvertTo-SecureString -String \"{pw}\" -AsPlainText -Force) | Out-Null
Export-Certificate -Cert $cert -FilePath "{cer}" -Type CERT | Out-Null
Remove-Item ("Cert:\\CurrentUser\\My\\" + $cert.Thumbprint) -Force | Out-Null
Write-Output $cert.Thumbprint
"""
    del_path = cache_dir() / "mkcert.ps1"
    del_path.write_text(ps, encoding="utf-8-sig")
    thumb = _run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                  "-File", str(del_path)])
    if not (pfx.exists() and cer.exists()):
        raise RuntimeError(f"cert generation failed; output:\n{thumb}")
    return pfx, cer


def sign(wdk, sys_path: pathlib.Path) -> pathlib.Path:
    """Embed an Authenticode signature into the .sys (in place)."""
    pfx, _ = ensure_cert()
    _run([str(signtool(wdk)), "sign", "/f", str(pfx), "/p", PFX_PASSWORD,
          "/fd", "sha256", "/v", str(sys_path)], timeout=180)
    return sys_path


def install_on_vm(vm, timeout=60) -> None:
    """Trust the test cert on the VM (Root + TrustedPeople)."""
    _, cer = ensure_cert()
    remote = rf"C:\Windows\Temp\{cer.name}"
    vm.push(cer, remote)
    try:
        for store in ("Root", "TrustedPeople"):
            vm.run(f'certutil -addstore -f {store} "{remote}"', timeout=timeout)
    finally:
        vm.cleanup_marker(remote)
