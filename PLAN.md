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

## Done

- **C++ exceptions (Linux + EFI)** — `tests/cpp_eh_support/` supplies freestanding `peor_crtbegin.c` / `peor_crtend.c` / `freestanding.c`; `_compile_cpp_pe` uses them instead of system crtbegin/crtend. Linux targets link import libs for `libc.so.6` / `libpthread.so.0` via dlltool.
- **Windows MinGW DWARF exceptions** — `tests/Windows/17_mingw_cpp_exceptions/main.cpp` + `test_17_mingw_cpp_exceptions` (x64+x86). ctors runner added to the Windows PE chain so `.init_array` EH frame registration runs before entry.
- **Linux CRT imports test** — `tests/Linux/03_linux_with_crt/main.c` uses `strlen`/`malloc`/`free`/`memcpy` from `libc.so.6`; `test_03_linux_with_crt` (x64+x86) verifies the Linux import resolver handles multiple libc symbols.
- **cmd.exe shellcodification** — `test_cmdexe` (x64+x86) shellcodifies `C:\Windows\System32\cmd.exe` / `SysWOW64\cmd.exe` and verifies `echo PEOR_CMD_TEST` output.
- **EFI vcxproj files** — `tests/EFI/01_efi_hello`, `02_efi_print`, `03_efi_simple_calc` now have `.vcxproj` files and are wired into `tests.sln`; the `test-efi-qemu` CI job downloads MSVC-built binaries from `build-windows`.
- **ctors runner in Windows chain** — Added `ctors`/`ctors_rva_magic`/`ctors_size_magic` to both `OPTIONAL_HEADER_MAGIC_PE` and `OPTIONAL_HEADER_MAGIC_PE_PLUS` entries in `_SHELLCODES`; safe for MSVC PEs (skipped when no `.init_array`/`.ctors` section).

## Active TODOs (ordered)

### 1. Fix test_02_linux_cpp_exceptions[x64] — SEH emulator for Linux
**Root cause:** x64 MinGW GCC 13-posix uses Windows SEH exclusively (no DWARF). `unwind-seh.o` in `libgcc_eh.a` references 5 kernel32 IAT symbols + `vterminate.o` references stdio symbols. These don't exist on Linux.

**Fix:** Create `tests/cpp_eh_support/seh_linux64.c` compiled with `-DPEOR_LINUX_SEH` and linked into x64 Linux builds only. It must provide:
- `__imp___acrt_iob_func`, `fwrite`, `fputs`, `fputc`, `__mingw_vsprintf` (vterminate no-ops)
- `__imp_RtlCaptureContext` — inline asm to capture all GPRs + RIP into a PEOR_CONTEXT
- `__imp_RtlLookupFunctionEntry` — parse `__ImageBase` PE headers → binary search `.pdata`
- `__imp_RtlVirtualUnwind` — decode UNWIND_INFO codes, invoke personality, return handler
- `__imp_RaiseException` — two-phase SEH dispatch loop (phase1=0x20474343, phase2=0x21474343)
- `__imp_RtlUnwindEx` — restore RSP to target_frame, set RAX=retval, jump to landing_pad

Wire into `_compile_cpp_pe` in `test_shellcode.py` for `is_linux and arch == "x64"`.

### 2. More Linux tests (x86 + x64)
Add `tests/Linux/04_linux_signal/main.c` — install SIGUSR1 handler, raise it, return 77.
Add `tests/Linux/05_linux_global_ctor/main.cpp` — global ctor increments counter, main checks == 99.
Add vcxproj files for each where possible, we want it to compile via the solution compilation!

### 3. More EFI tests (x86 + x64)
Add `tests/EFI/04_efi_cpp_exceptions/main.cpp` — throw/catch, EFI entry, return 55.
Add `tests/EFI/05_efi_memory_services/main.c` — allocate via EFI AllocatePool stub, return 66.
Add vcxproj files for each, we want it to compile via the solution compilation!

### 4. CI/CD caching
Add `cache` steps for: apt packages (MinGW, QEMU, OVMF), pip installs, compiled test objects.

### 5. ARM/ARM64 UEFI CI/CD support
Add `qemu-system-aarch64` + AAVMF to EFI CI job; cross-compile EFI tests with `aarch64-w64-mingw32-gcc`,
same for arm32 wherever possible, for all uefi tests and shellcodes.

### 6. Debug-Mode support
make all existing test c/cpp projects to compile in both debug and release modes, then ensure all shellcodes works for both debug/release! the release one should optimize max on speed.
Just compile the tests solution for both debug and release, make sure it works, if not - bugfix whatever needed.

### 7. Remove falsy stubs
To support efi/linux stuff, you've implemented empty stubs, functions whose symbols where required for compilation,
But these has empty/incorrect implementation, which makes our repo falsy and creates more place for mistakes!
Wherever possible: remove these stubs / implement them correctly. use compilation/linkage techniques to completly avoid implementing falsy stubs, which might cause severe bugs in the future (for example, having a pthread-impl that always "return 0" might make the optimizer avoid any pthread-required stuff, which makes it skip initialization of global/static variables). the same for fread/... and other libc falsy implementations, which make the repo worse.

---
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

### ARM32 / ARM64 shellcode support
**Goal:** all existing resolvers ported to ARM Thumb/A32 and AArch64. any shellcode-stub of windows/linux/kernels/uefi/...
**Implement**
- One asm file per resolver per arch (`*_arm.asm`, `*_arm64.asm`). Keystone: `KS_ARCH_ARM` / `KS_ARCH_ARM64`.
- ARM PE `Machine` values: `0x01C4` (Thumb-2), `0xAA64` (AArch64). Detect in `_validate_pe` and select the right `_SHELLCODES` entry.
- ARM32 EH uses EHABI; AArch64 uses DWARF — both require new EH fixer variants.
- TestLoader NOP sled must use 4-byte-aligned offsets.

**CI/CD**
NOTE there's a windows11-arm runner! use it for the arm stuff (build/test wherever needed)
- `ubuntu-latest` + QEMU user-mode (`qemu-arm-static`, `qemu-aarch64-static`) + MinGW/LLVM cross-compiler.

