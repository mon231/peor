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

## Future TODOs - Deferred (explicitly blocked)

### Windows kernel mode (x86 + x64)

**Goal:** shellcode that resolves imports and calls `DriverEntry` from ring-0.
**Status:** blocked — standing rule "do not insmod into my linux/windows for now", waiting for VM env for dev/tests.

**Implementation plan**
1. **Import resolver** — `asm/imports_resolver64_km.asm`: `gs:[0x18]` → `KPCR` → walk to `ntoskrnl.exe` base → find `MmGetSystemRoutineAddress` in its export table → use it for all subsequent imports. x86 variant: `asm/imports_resolver32_km.asm` via `fs:[0x1c]`.
2. **Entrypoint resolver** — `asm/entrypoint_resolver_km{32,64}.asm`: call `DriverEntry(DriverObject=NULL, RegistryPath=NULL)`.
3. **Platform wiring** — add `'kernel'` entry in `_SHELLCODES`, selected when `Subsystem == 1` (IMAGE_SUBSYSTEM_NATIVE). Remove the current `ValueError` for subsystem 1.

**Test**
- **Mocked (CI-safe)**: a user-mode test harness allocates a fake `KPCR`/`KPRCB` at a chosen address and overrides `GS`/`FS` base (on x64 via `_writegsbase_u64`), then runs the resolver. Asserts that `MmGetSystemRoutineAddress`'s export slot is resolved.
- **Real (self-hosted VM)**: WDM driver PE `tests/Km_x64/01_km_dbgprint/main.c` calls `DbgPrint`; assert `STATUS_SUCCESS`.

**CI/CD**
- Mocked test: `windows-latest` runner, pure user-mode, no VM needed.
- Real test: self-hosted runner with Hyper-V, test-signed driver, `NtLoadDriver` + WinDbg automation.

### FULL ARM32 / ARM64 shellcode support
**Goal:** all existing resolvers ported to ARM Thumb/A32 and AArch64. any shellcode-stub of windows/linux/kernels/uefi/...
**Implement**
- One asm file per resolver per arch (`*_arm.asm`, `*_arm64.asm`). Keystone: `KS_ARCH_ARM` / `KS_ARCH_ARM64`.
- ARM PE `Machine` values: `0x01C4` (Thumb-2), `0xAA64` (AArch64). Detect in `_validate_pe` and select the right `_SHELLCODES` entry.
- ARM32 EH uses EHABI; AArch64 uses DWARF — both require new EH fixer variants.
- TestLoader NOP sled must use 4-byte-aligned offsets.

**CI/CD**
NOTE there's a windows11-arm runner! use it for the arm stuff (build/test wherever needed)
- `ubuntu-latest` + QEMU user-mode (`qemu-arm-static`, `qemu-aarch64-static`) + MinGW/LLVM cross-compiler.
