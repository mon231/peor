# PLAN

Standing rules — apply to every item:
- **NEVER DO GIT COMMIT**
- Always remove all unused files / comments / ...
- Every feature needs a test. Every test must have a deterministic success criterion.
- Follow CONTRIBUTING conventions: `%define` named constants, hex literals, one responsibility per asm file, infer asm usage from PE headers, update README.md after each feature.
- Re-run the full test suite (`pip install -e . && pytest tests/pytest -v`) after any code change.
- Prefer tests that pass in CI without a GUI or a VM (skip with `pytest.skip` when binaries are absent, guard GUI tests with `os.getenv("CI")`).
- When mission from the PLAN file is done, remove it from the PLAN file.
- NEVER use magic-numbers (in all python/asm/cpp code).
  for example, instead `dirs[14].VirtualAddress` use `dirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress`
- Whenever possible, add both x86 and x64 tests!!
- do NOT have different folders for c/cpp code tests per arch (instead Linux_x86, Linux_x64 simply have a Linux folder. the same for EFI_x32 and EFI_x64, just make an EFI folder. where needed, use "ifdef"s to determine arch and types)
- when adding tests and looking for their return code, choose a special return code (not 0/1/-1, but something unique like 42/88/..., to make sure we do not get the wanted return-code by mistake)

## NOTEs
1. ALL of the tests MUST pass locally (if needed, use wsl/qemu/qemu-wsl. the test-runner must support it!). no skip, no fail
1. you are NOT allowed to SKIP tests on the local machine. NOTE the ci/cd must run ALL the tests too!
1. compile linux binaries into "<binary name>.pe" names, so these will be gitignored

---

## Work Queue (execute in order)

### CI/CD — MSYS2 fix pushed, needs re-verification

First real-CI run (https://github.com/mon231/peor/actions/runs/28576369139) confirmed the
big wins: `test-efi-qemu` (all 4 archs, including the arm64 fix) and both Linux jobs all
**passed**. Only `test-windows`/`test-windows-debug` failed, both at the same step:
`cp: '/mingw64/bin/gcc.exe' and '/mingw64/bin/x86_64-w64-mingw32-gcc.exe' are the same
file` — MSYS2's `mingw-w64-x86_64-gcc` package already ships the triple-prefixed name as
the same file as `gcc.exe`, so the unconditional `cp` failed. Fixed by guarding each `cp`
with an existence check (only alias what's actually missing — the `-posix`-suffixed g++
names, which MSYS2 doesn't provide). Needs another push to confirm this specific fix
works; still can't verify the EH-model concern (SEH/DWARF/SJLJ) without a real run.

---

## Future TODOs — Deferred (explicitly blocked)

### Windows kernel mode (x86 + x64)

**Goal:** shellcode that resolves imports and calls `DriverEntry` from ring-0.
**Status:** blocked — standing rule "do not insmod into my linux/windows for now", waiting for VM
env for dev/tests.

**Implementation plan**
1. **Import resolver** — `asm/imports_resolver64_km.asm`: `gs:[0x18]` → `KPCR` → walk to
   `ntoskrnl.exe` base → find `MmGetSystemRoutineAddress` in its export table → use it for all
   subsequent imports. x86 variant: `asm/imports_resolver32_km.asm` via `fs:[0x1c]`.
2. **Entrypoint resolver** — `asm/entrypoint_resolver_km{32,64}.asm`: call
   `DriverEntry(DriverObject=NULL, RegistryPath=NULL)`.
3. **Platform wiring** — add `'kernel'` entry in `_SHELLCODES`, selected when `Subsystem == 1`
   (`IMAGE_SUBSYSTEM_NATIVE`). Remove the current `ValueError` for subsystem 1.

**Test**
- **Mocked (CI-safe)**: a user-mode test harness allocates a fake `KPCR`/`KPRCB` at a chosen
  address and overrides `GS`/`FS` base (on x64 via `_writegsbase_u64`), then runs the resolver.
  Asserts that `MmGetSystemRoutineAddress`'s export slot is resolved.
- **Real (self-hosted VM)**: WDM driver PE `tests/Km/01_km_dbgprint/main.c` calls `DbgPrint`;
  assert `STATUS_SUCCESS`. x86 + x64 variants.

**CI/CD**
- Mocked test: `windows-latest` runner, pure user-mode, no VM needed.
- Real test: self-hosted runner with Hyper-V, test-signed driver, `NtLoadDriver` + WinDbg
  automation.

---

### FULL ARM32 / ARM64 support

**Goal:** Windows/Linux (non-EFI) shellcodes for ARM32 Thumb-2 (`0x01C4`) and AArch64 (`0xAA64`).

**What's already done:** ARM64 EFI chain (relocs, ctors, EFI entrypoint). ARM32 EFI chain.

**What's needed for Windows ARM64:**
- `asm/imports_resolver_arm64.asm` — walk PEB_LDR via `x18` (TEB on Windows ARM64), find
  kernel32/ntdll, resolve imports by name and ordinal.
- `asm/entrypoint_resolver_arm64.asm` — pass `(argc, argv, envp)` per ARM64 ABI calling convention
  (x0, x1, x2).
- `asm/tls_callbacks_arm64.asm` — call TLS callbacks before entrypoint.
- ...
- Test runner: `windows11-arm` GitHub Actions runner available; use it for build + test.

**What's needed for Windows ARM32:**
- `asm/imports_resolver_arm32.asm` — walk PEB_LDR via `r8` (TEB on Windows ARM32 = `TEB.NtTib.Self`
  at `fs:[0]`), find kernel32/ntdll, resolve imports.
- `asm/entrypoint_resolver_arm32.asm` — pass `(argc, argv, envp)` per ARM32 ABI (r0, r1, r2).
- Tests: same `windows11-arm` runner (can run ARM32 code via WoW64 on ARM64 Windows).

**CI/CD:** `windows11-arm` self-hosted or GitHub-hosted runner for both build and execution tests.

<!-- claude --resume a9e0393c-7bac-408a-8024-515edea0ad04 -->
