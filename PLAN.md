# PLAN

Standing rules — apply to every item:
- **NEVER DO GIT COMMIT**
- Every feature needs a test. Every test must have a deterministic success criterion.
- Follow CONTRIBUTING conventions: `%define` named constants, hex literals, one responsibility per asm file, infer asm usage from PE headers, update README.md after each feature.
- Re-run the full test suite (`pip install -e . && pytest tests/pytest -v`) after any code change.
- Prefer tests that pass in CI without a GUI or a VM (skip with `pytest.skip` when binaries are absent, guard GUI tests with `os.getenv("CI")`).
- NEVER use magic-numbers (in all python/asm/cpp code).
  for example, instead `dirs[14].VirtualAddress` use `dirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress`

Items are ordered by priority: highest first. Within a priority tier, cheapest effort first.

---

## P1 — Quick wins (Python or C only, no new asm, no new platform)

### 1. CLR / managed PE rejection

**Goal:** `peor` currently produces broken output silently for .NET PEs. Detect and refuse.

**Implement**
- In `_validate_pe()` (`peor/__main__.py`): if `len(dirs) > 14 and dirs[14].VirtualAddress != 0`, raise `ValueError("CLR/managed PE (DataDir[14] non-zero) is not supported")`.

**Test**
- In `tests/pytest/test_shellcode.py`: construct a minimal fake CLR PE in Python (patch DataDir[14] of an existing test PE using `struct.pack`), call `dump_memory_layout`, assert `ValueError` is raised.
- No new binary needed — done entirely in Python.

**CI/CD**
- Pure Python; runs on any runner with no prerequisites beyond `pip install -e .`.

---

### 2. Deterministic output

**Goal:** guarantee `peor(PE) == peor(PE)` always, and catch any future accidental randomness.

**Implement**
- No code change required (output is already deterministic). This item is test-only.

**Test**
- on each test, call `dump_memory_layout` twice and assert the content of the output-file is the same.

**CI/CD**
- Pure Python; runs on any runner.

---

### 3. Write to stdout (`-o -`)

**Goal:** allow `peor -i foo.exe -r -o - | xxd` and similar shell pipelines.

**Implement**
- In `parse_arguments()`: keep `output_file` as `Path` but allow the string `"-"`.
- In `dump_memory_layout` (or `main()`): if `output_file == Path("-")`, write to `sys.stdout.buffer` instead of `output_file.write_bytes(...)`.

**Test**
- Add `test_stdout_output`: invoke `peor` as a subprocess with `-o -`, capture stdout bytes, assert they match the bytes written to a real file by a second call.

**CI/CD**
- Pure Python; runs on any runner.

---

### 4. `--info` dry-run

**Goal:** show which resolvers will fire and their sizes, without writing output — useful for debugging and auditing.

**Implement**
- Add `--info` flag to `parse_arguments()`.
- In the case `--info` present, do not allow the `-o` flag for output file
- Extract the component sizes from `_build_shellcode_chain` (return a dict alongside the bytes, or compute sizes separately).
- Print a table to stdout:
  ```
  imports    312 B
  relocs      96 B
  cxx_eh      80 B
  seh        128 B
  tls          —
  align_pad    8 B
  PE image  45312 B
  ──────────────────
  total     45936 B
  ```

**Test**
- Add `test_info_mode`: invoke `peor --info -i 11_cpp_exceptions.exe` as a subprocess, assert `"cxx_eh"` and `"seh"` appear in stdout and no output file is written.

**CI/CD**
- Pure Python; runs on any runner.

---

### 5. TestLoader offset (NOP sled)

**Goal:** prove shellcodes are truly position-independent by running them at a random offset inside the allocation.

**Implement**
- Edit `tests/test_loader/main.c`:
  1. `srand((unsigned)GetTickCount())` at startup.
  2. `DWORD offset = (rand() % 1024) + 1;`  (x86/x64: any value; ARM: round up to next multiple of 4)
  3. `VirtualAlloc(NULL, shellcode_len + offset, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)`
  4. `memset(base, 0x90, offset);`
  5. `memcpy(base + offset, shellcode, shellcode_len);`
  6. Call `base + offset`.

**Test**
- All 26 existing tests become the regression suite for this change automatically — rebuild `tests.sln` and rerun.

**CI/CD**
- Rebuild `tests\tests.sln` (both Release|x64 and Release|Win32) in the CI job before running pytest.

---

### 7. CI — build test binaries inside the CI job

**Goal:** build and test in different stages.

**Implement**
- Add a `windows-latest` job `build` to `.github/workflows/test.yml` that:
  1. Installs MSVC tools via `microsoft/setup-msbuild@v2`.
  1. Installs python + pip-upgrade
  1. Caches the installed utils
  1. Runs `msbuild tests\tests.sln /p:Configuration=Release /p:Platform=x64 /m`.
  1. Runs `msbuild tests\tests.sln /p:Configuration=Release /p:Platform=Win32 /m`.
  1. Caches the built binaries (depend the /tests folder, except the pytest.py one)
  1. Runs `pip install -e .`.
  1. Runs `python -m pytest tests\pytest -v`.

Then add a "test-windows-shellcodes" stage, that uses the built artifacts (which won't be uploaded as ci-artifact)

**Test**
- The job is the test. All 26 tests (minus the GUI one) must pass.

**CI/CD**
- The item IS the CI/CD change.

---

### 9. Update README.md

**Goal:** keep README current after each feature lands.

**Implement**
- After each item above/below: add a row to the test table, update the feature matrix, add a CLI usage example for new flags.

**Test / CI/CD** — documentation; no automated check needed.

---

## P2 — New test cases (need new VS project per test)

Each item below requires: a new `tests/NN_name/` folder with `main.cpp` + `.vcxproj`, a new row in `tests/tests.sln`, a rebuild, and a new `test_NN_*` function in `tests/pytest/test_shellcode.py`.

---

### 10. Multiple TLS callbacks

**Goal:** verify the TLS array-iteration loop calls all callbacks in order.

**Implement**
- `tests/13_tls_multi_callbacks/main.cpp`: declare five TLS callbacks in `.CRT$XLB` and `.CRT$XLC`. Each atomically adds its index value to `g_counter`. they also maintain a `is_negative` that each test mark as true/false if its odd/even, then multiply and add their index into `g_counter`, to ensure correct order. `main()` returns `g_counter`.
- Expected exit code = sum of even index values minus sum of all odd index values.

**Test**
- `test_13_tls_multi_callbacks[x86/x64]`: assert `returncode == expected_sum`.

**CI/CD**
- Part of the windows CI job

---

### 11. Global C++ constructors (file-scope statics)

**Goal:** exercise `.CRT$XCU` / `.CRT$XI` — distinct from the lazy-init path tested by `test_10`.

**Implement**
- `tests/14_global_ctors/main.cpp`: file-scope `static MyCounter g_counter;` whose constructor increments a global. `main()` asserts the constructor ran and the created object returns the counter value.
- Expected exit code = 42.

**Test**
- `test_14_global_ctors[x86/x64]`: assert `returncode == 42`.

**CI/CD**
- Part of the windows CI job.

---

### 12. Nested / rethrown C++ exceptions

**Goal:** stress multi-frame unwind in `cxx_eh_fixer64.asm` with `throw;` and destructor-during-unwind.

**Implement**
- `tests/15_nested_exceptions/main.cpp`:
  - Inner function throws `int(1)`, caught by a mid-level handler that re-throws.
  - Outer handler catches and returns 55.
- Expected exit code = 55.

**Test**
- `test_15_nested_exceptions[x86/x64]`: assert `returncode == 55`.

**CI/CD**
- Part of the windows CI job.

---

### 13. Bound imports

**Goal:** confirm that a PE with a bound-import table (DataDir[11]) still resolves correctly.

**Implement**
- Test-only (no new asm). In `tests/pytest/test_shellcode.py`, add a Python fixture that copies `02_relocs_functions.exe`, injects a fake non-empty `DataDir[11]` entry (set VirtualAddress to a non-zero sentinel), and shellcodifies it.
- The regular import resolver overwrites the IAT regardless, so bound values are silently discarded.

**Test**
- `test_bound_imports[x86/x64]`: assert `returncode == 90` (same as `test_02`).

**CI/CD**
- Pure Python; runs on any runner.

---

### 14. Delay-load imports

**Goal:** expose and fix the gap where DataDir[13] (`IMAGE_DELAYLOAD_DESCRIPTOR`) is ignored.

**Implement**
1. **Test PE** — `tests/16_delay_load/main.cpp`: delay-loads `kernel32.dll!GetTickCount` (non-GUI, CI-safe) via `#pragma comment(lib, "delayimp.lib")` + `/DELAYLOAD:kernel32.dll`. Calls it, returns the low byte of the result XOR'd to a fixed value (assert non-zero).
2. **Resolver** — `asm/imports_resolver{32,64}_delayload.asm`: walk `ImgDelayDescr` (DataDir[13]), `LoadLibrary` + `GetProcAddress` each entry, patch the delay-load IAT slots before entry. Single responsibility: delay-load only.
3. **Python wiring** — add `_has_delay_imports(pe)` (checks `DataDir[13].VirtualAddress != 0`) in `__main__.py`. Include the delay-load resolver in the chain when true and `resolve_imports` is set.

**Test**
- `test_16_delay_load[x86/x64]`: assert `returncode != 0` (tick count is non-zero) and `returncode` is consistent across two runs (deterministic check not applicable here — just assert non-zero and clean exit).

**CI/CD**
- Part of the windows CI job (rebuild tests.sln).

---

### 15. Very large PE

**Goal:** catch 32-bit displacement overflow for images approaching 2 GB.

**Implement**
- assert and throw if expected binaries doesn't match conditions

---

### Remove the resolve-imports flag
Flags like "resolve-imports" must not be in peor.
PEOR has to infer if the resolve-imports is required.
PEOR also has to let the user choose NOT to include the resolve-imports, but this has to be an explicit choice.

---

### 16. MinGW / Clang-cl cross-compiler PE

**Goal:** catch section-layout differences from non-MSVC toolchains.

**Implement**
- **MinGW**: on `ubuntu-latest`, cross-compile `tests/01_simple_calc/main.c` with `x86_64-w64-mingw32-gcc -nostdlib -e main`. MinGW DWARF EH means `cxx_eh_fixer` must NOT fire (no `.pdata`).
- **Clang-cl**: on `windows-latest`, compile with `clang-cl /MT /EHsc`. SEH layout should match MSVC.
- No new VS project needed for MinGW (build in CI script). Clang-cl can reuse existing projects with a toolset override.

**Test**
- `test_mingw_simple_calc[x64]`: assert `returncode == 4950`.
- `test_clangcl_simple_calc[x64]`: assert `returncode == 4950`.

**CI/CD**
- MinGW: `ubuntu-latest` runner, `sudo apt-get install -y gcc-mingw-w64`.
- Clang-cl: `windows-latest` runner, install LLVM via `winget` or Chocolatey.

---

## P3 — New features (Python ± new asm, same Windows user-mode platform)

### 17. Custom entry point (`--entry`)

**Goal:** call a named export instead of the OEP — extract a single function as a self-contained shellcode.

**Implement**
1. Add `--entry` / `-e` to `parse_arguments()`. Value is an ordinal or a string (export name, if there are both ordinal and a function-name with same name, choose the ordinal).
2. In `dump_memory_layout`, if `--entry` is given, look up the export VA in `pe.DIRECTORY_ENTRY_EXPORT` and pass it to `_build_shellcode_chain` as `override_ep_rva`.
3. `entrypoint_resolver{32,64}.asm` reads the EP RVA from a fixed offset immediately after the resolver code (patched by peor at conversion time, like `PE_OFFSET_PLACEHOLDER`). Use a new `%define EP_RVA_MAGIC 0xCECECECE` placeholder for this.

**Test**
- `test_custom_entry[x64]`: shellcodify `05_dll_entry.dll` with `--entry DllMain`; assert `returncode == 42`.

**CI/CD**
- Part of the windows CI job.

---

## P4 — New platforms

### 18. Linux / WSL user-mode

**Goal:** a PE whose code calls `libc.so.6 write()`, converted by peor, executed on Linux.

**Implement**
1. **Test PE** — `tests/Linux_x64/01_linux_write/main.c`: `write(1, "PEOR\n", 5); return 0;`. Compile as 64-bit PE: `x86_64-w64-mingw32-gcc -nostdlib -e _start`, declaring `write` as import from `libc.so.6`.
2. **Import resolver** — `asm/imports_resolver64_linux.asm`: call `dlopen(libname, RTLD_NOW)` + `dlsym(handle, funcname)` for each import entry. Use `rip`-relative strings for library names. Expose as `IMPORTS_64_LINUX`.
3. **Reloc / entrypoint resolvers** — existing x64 versions work if the PE has no Windows-specific relocs. Add a `'linux'` entry in `_SHELLCODES` that omits SEH/VEH.
4. **Platform detection** — select `'linux'` when `Subsystem == IMAGE_SUBSYSTEM_POSIX_CUI (3)` or `--platform linux` is passed.
5. **Linux loader** — `tests/loader/test_loader_linux.c`: `mmap` + `mprotect(PROT_EXEC)` + function-pointer call. Build with a Makefile on Linux.

**Test**
- `test_01_linux_write[x64]`: skip if not on Linux or loader absent. Run loader, capture stdout, assert `"PEOR\n"`.

**CI/CD**
- New `ubuntu-latest` job: install MinGW (`gcc-mingw-w64`), build Linux loader, `pip install -e .`, run `pytest -k test_01_linux_write`.

---

### 19. Windows kernel mode (x86 + x64)

**Goal:** shellcode that resolves imports and calls `DriverEntry` from ring-0.

**Implement**
1. **Import resolver** — `asm/imports_resolver64_km.asm`: `gs:[0x18]` → `KPCR` → walk to `ntoskrnl.exe` base → find `MmGetSystemRoutineAddress` in its export table → use it for all subsequent imports. x86 variant: `asm/imports_resolver32_km.asm` via `fs:[0x1c]`.
2. **Entrypoint resolver** — `asm/entrypoint_resolver_km{32,64}.asm`: call `DriverEntry(DriverObject=NULL, RegistryPath=NULL)`.
3. **Platform wiring** — add `'kernel'` entry in `_SHELLCODES`, selected when `Subsystem == 1` (IMAGE_SUBSYSTEM_NATIVE) or `--platform kernel`. Remove the current `ValueError` for subsystem 1.

**Test**
- **Mocked (CI-safe)**: a user-mode test harness allocates a fake `KPCR`/`KPRCB` at a chosen address and overrides `GS`/`FS` base (on x64 via `_writegsbase_u64`), then runs the resolver. Asserts that `MmGetSystemRoutineAddress`'s export slot is resolved.
- **Real (self-hosted VM)**: WDM driver PE `tests/Km_x64/01_km_dbgprint/main.c` calls `DbgPrint`; assert `STATUS_SUCCESS`.

**CI/CD**
- Mocked test: `windows-latest` runner, pure user-mode, no VM needed.
- Real test: self-hosted runner with Hyper-V, test-signed driver, `NtLoadDriver` + WinDbg automation.

---

### 20. EFI application (test + import resolvers)

**Goal:** convert an EFI application PE to shellcode runnable under OVMF/QEMU.

**Implement**
1. **Entrypoint resolver** — `asm/entrypoint_resolver_efi64.asm`: `mov rcx, 0; mov rdx, 0; call [ep]`. Created separately from the Windows resolver to keep single-responsibility.
2. **Import resolver** — `asm/imports_resolver_efi64.asm`: obtain `EFI_SYSTEM_TABLE*` stashed by the shellcode prefix → `BootServices->LocateProtocol` → resolve each imported DLL name as a protocol GUID (static GUID table in asm data section).
3. **CLI flag** — `--efi-null-args`: pass NULL for `ImageHandle` and `SystemTable`. Selected automatically when `Subsystem == 0x0A`.
4. **Platform wiring** — `'efi'` entry in `_SHELLCODES`. Remove the current `ValueError` for EFI subsystems.

**Test**
- `tests/EFI_x64/01_efi_hello/main.c`: return `EFI_SUCCESS` immediately. Compile with EDK2 or `x86_64-w64-mingw32-gcc` with EFI headers.
- Run shellcode under QEMU + OVMF (`-nographic -serial stdio`), assert `qemu` exits 0.

**CI/CD**
```yaml
- run: sudo apt-get install -y qemu-system-x86 ovmf
- run: python -m pytest -k test_01_efi_hello
```

---

## P5 — Future / Far future

### 21. ARM32 / ARM64 shellcode support

**Goal:** all existing resolvers ported to ARM Thumb/A32 and AArch64.

**Implement**
- One asm file per resolver per arch (`*_arm.asm`, `*_arm64.asm`). Keystone: `KS_ARCH_ARM` / `KS_ARCH_ARM64`.
- ARM PE `Machine` values: `0x01C4` (Thumb-2), `0xAA64` (AArch64). Detect in `_validate_pe` and select the right `_SHELLCODES` entry.
- ARM32 EH uses EHABI; AArch64 uses DWARF — both require new EH fixer variants.
- TestLoader NOP sled must use 4-byte-aligned offsets.

**CI/CD**
- `ubuntu-latest` + QEMU user-mode (`qemu-arm-static`, `qemu-aarch64-static`) + MinGW/LLVM cross-compiler.

---

### 22. Native C++ exceptions in UEFI (FAR FUTURE)

**Goal:** UEFI C++ code with `try/catch` that works via a statically-linked libunwind.

**Implement**
1. Statically link LLVM `libunwind` into the EFI image so `.pdata`/`.xdata` tables are self-contained in the PE.
2. At peor conversion time, read those tables and emit a shellcode prefix that calls `__register_frame` before the PE entry.
3. Requires the EFI entrypoint resolver from item 20.

**CI/CD**
- Reuses the QEMU + OVMF harness from item 20. Test PE must throw, catch, and return a known exit code.
