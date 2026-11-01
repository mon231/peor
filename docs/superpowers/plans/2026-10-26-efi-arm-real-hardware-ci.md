# EFI-ARM Real-Hardware CI Job Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the existing EFI ARM32/ARM64 pytest cases on a real `windows-11-arm` GitHub-hosted runner, in addition to (not instead of) the existing QEMU-emulated run on `ubuntu-latest`.

**Architecture:** One new job in `.github/workflows/test.yml`, on `runs-on: windows-11-arm`, that installs the same toolchain the existing `test-efi-qemu` job uses (clang targeting `aarch64-w64-mingw32`/`armv7-w64-mingw32`, `qemu-system-aarch64`/`qemu-system-arm`, ARM OVMF firmware) and runs the same `-k "efi and (arm64 or arm32)"` pytest selection. `tests/pytest/test_shellcode.py` already has a WSL fallback path (`_find_clang_arm64_wsl`, `_find_qemu_ovmf`'s native-Windows-path check) baked in for exactly this scenario — prefer it over inventing a new native-Windows toolchain path, since it reuses code this repo already trusts.

**Tech Stack:** GitHub Actions, WSL2 (preferred) or native Windows binaries (fallback), pytest.

**Spec:** `C:\Users\avart\Desktop\Projects\peor\docs\superpowers\specs\2026-10-26-windows-arm-support-design.md` (Goal 1 only — this plan does not touch Goals 2-5, the non-EFI Windows ARM chain, which has its own plan)

## Global Constraints

- No test may be skipped locally or in CI (CONTRIBUTING.md / CLAUDE.md / PLAN.md).
- This job is additive: the existing `test-efi-qemu` job on `ubuntu-latest` is untouched.
- The new job joins `test-summary`'s required `needs:` list — a failure here fails the whole pipeline, same as every other job (explicit project decision, no exception for `windows-11-arm` being in public preview).
- Background processes capped at 50 minutes runtime.
- No un-asked-for `git push` — each push to validate the CI job against the real runner needs confirmation first (pushing is visible to others / affects shared CI state).

## Review Focus

- **Runner unavailability**: if `windows-11-arm` is actually unobtainable (queue, quota, or label typo) the job must fail loudly, not silently skip — verified by `test-summary` treating it as required.
- **Toolchain not found**: if WSL2/clang/qemu aren't present and the fallback also fails, the pytest assertions in `test_shellcode.py` (`assert clang is not None`, `assert qemu is not None`) already turn that into a hard failure rather than a skip — confirm this still holds on this runner, don't add a new `pytest.skip`.
- **Timeout**: ARM QEMU boots are already slow on emulated x64 hosts (360s timeout in the existing job); real hardware should be faster, but pick a timeout that won't flake, not a lowball one copied blindly.
- **Duplicate work**: the `-k` filter must select only the ARM EFI cases, not re-run the x64/x86 EFI cases a second time on a runner that doesn't need to prove those.
- **Firmware/package drift**: pin or at least log the exact qemu/OVMF package versions installed, so a future Ubuntu/WSL image bump that silently changes firmware paths is traceable (the existing `_find_qemu_ovmf` already probes several candidate paths — don't narrow that, but do verify which one actually matches on this runner image).

---

## Task 1: `test-efi-windows-arm` CI job

**Files:**
- Modify: `.github/workflows/test.yml`

**Interfaces:**
- Consumes: `tests/pytest/test_shellcode.py`'s existing `_find_clang_arm64_wsl`, `_find_clang_arm32_wsl`, `_find_qemu_ovmf` — unmodified, no code changes in this task.
- Produces: a job named `test-efi-windows-arm`, consumed by Task 2 (added to `test-summary`'s `needs:`).

- [ ] **Step 1: Add a diagnostic-only job stub to confirm the runner label resolves and basic tooling works**

```yaml
  test-efi-windows-arm:
    runs-on: windows-11-arm
    steps:
      - uses: actions/checkout@v4
      - name: Sanity check runner
        shell: pwsh
        run: |
          python --version
          wsl --status
```
Push this alone first (on a throwaway branch) and confirm the job starts and both commands run (even if `wsl --status` errors — that answers the WSL-availability question for Step 2).

- [ ] **Step 2: Decide and implement the toolchain install path, based on Step 1's result**

If WSL2 is present (preferred path — reuses the existing `_find_clang_arm64_wsl`/`_wsl_bash_run` code path with zero `test_shellcode.py` changes):
```yaml
      - name: Set up WSL2 Ubuntu
        uses: Vampire/setup-wsl@v3
        with:
          distribution: Ubuntu-24.04
      - name: Install clang/lld/qemu-arm in WSL
        shell: wsl-bash {0}
        run: |
          sudo apt-get update -y
          sudo apt-get install -y clang lld qemu-system-arm qemu-efi-aarch64 qemu-efi-arm
```
If WSL2 is unavailable on this runner image, fall back to native installs (chocolatey for qemu, an LLVM/clang release that includes the `aarch64-w64-mingw32`/`armv7-w64-mingw32` targets — `_find_clang_arm64`/`_find_clang_arm32` already probe `PATH` natively first, so no code change is needed either way) and place `qemu-system-aarch64.exe`/`qemu-system-arm.exe` + firmware where `_find_qemu_ovmf`'s native-Windows candidates (`C:\Program Files\qemu\...`) expect them, or add `QEMU`/share dir to `PATH` so `shutil.which` finds it.

- [ ] **Step 3: Add the Python setup, build, and test steps**

```yaml
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ env.PYTHON_VERSION }}
      - name: Install Python dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e .
          pip install pytest pytest-timeout
      - name: Build prebuilt EFI test-source PEs (build_tests.py)
        run: python tests/build_tests.py --target efi
      - name: Run EFI shellcode tests (ARM64 + ARM32, real windows-11-arm hardware)
        run: pytest tests/pytest -v --timeout=360 -k "efi and (arm64 or arm32)"
```
Adjust `--timeout` after Step 4's real run if it's consistently too tight or needlessly loose.

- [ ] **Step 4: Push and verify the job goes green on the real runner**

Push to a throwaway branch, watch the Actions run (`gh run watch` or the Actions UI) until `test-efi-windows-arm` passes. Fix whichever of Step 2's two paths actually applies based on real failures (missing package name, wrong firmware path, etc.) — iterate here, not by adding a skip.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/test.yml
git commit -m "ci: run EFI ARM32/64 tests on real windows-11-arm hardware"
```

## Task 2: Wire into the required gate

**Files:**
- Modify: `.github/workflows/test.yml:369` (the `test-summary` job's `needs:` list)

**Interfaces:**
- Consumes: Task 1's job name `test-efi-windows-arm`.
- Produces: nothing further consumes this — terminal task for this plan.

- [ ] **Step 1: Add `test-efi-windows-arm` to `test-summary`'s `needs:` list**

Edit the existing list (currently `build-windows`, `build-windows-debug`, `test-windows`, `test-windows-debug`, `build-linux-mingw`, `test-linux-mingw`, `test-efi-qemu`) to also include `test-efi-windows-arm`.

- [ ] **Step 2: Push and verify `test-summary` now depends on and reports the new job**

Confirm in the Actions UI that `test-summary` lists `test-efi-windows-arm: success` (or correctly fails the whole run if you force a failure in it, then revert the forced failure).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/test.yml
git commit -m "ci: require the real-hardware EFI ARM job in the test-summary gate"
```
