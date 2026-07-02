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

### P0 — CI/CD fixup
NOTE ci/cd failures [here](https://github.com/mon231/peor/actions/runs/28352771023). all tests must pass both local and ci/cd

### P1 — BSS / virtual sections: zero-initialize the gap

**Why:** PE sections where `VirtualSize > SizeOfRawData` represent zero-initialized (BSS-like) data.
When peor copies raw PE bytes into the shellcode buffer, the gap between `SizeOfRawData` and
`VirtualSize` is never zeroed, so global zero-initialized arrays contain heap garbage at runtime.

**Implementation**
- Python (`__main__.py`): after copying each section's raw bytes into the output buffer, memset the
  remaining `VirtualSize - SizeOfRawData` bytes to `0x00`.
- No asm changes needed.

**Test** — `tests/Windows/18_bss_gap/`
- `main.c`: declare `static int g_arr[4096];` (zero-initialized by C spec); compute checksum of all
  elements; return `88` if all zero, `0` otherwise (so 88 = pass).
- Add `test_18_bss_gap[x86]` and `test_18_bss_gap[x64]` to `test_shellcode.py`.

---

### P2 — Import by ordinal

**Why:** `IMAGE_THUNK_DATA` entries with bit 31 set (x86) or bit 63 set (x64) encode an import by
ordinal (low 16 bits = ordinal number) rather than by name. Common examples: `WS2_32` exports
several functions by ordinal. The current resolvers treat the thunk value as a name-pointer RVA,
causing silent wrong-function resolution or a crash.

**Implementation**
- `asm/imports_resolver32.asm` + `asm/imports_resolver64.asm`: before looking up the import by name
  pointer, test the high bit of the thunk value. If set, call
  `GetProcAddress(hModule, MAKEINTRESOURCE(ordinal))` where ordinal = low 16 bits of the thunk.
  `MAKEINTRESOURCE(n)` = `(LPCSTR)(ULONG_PTR)(WORD)n` — pass the raw ordinal as the second arg to
  `GetProcAddress` with the high bytes zeroed.
- Same logic for the delay-load resolvers (`imports_resolver32_delayload.asm`,
  `imports_resolver64_delayload.asm`).

**Test** — `tests/Windows/19_ordinal_imports/`
- Project: an EXE + companion DLL. The DLL exports two functions: one by name (`ByNameFunc`), one
  by ordinal only (`ordinal 7`, no name in the export table). The EXE imports both; `ByNameFunc`
  returns 30, the ordinal-7 function returns 12. EXE returns their sum = `42`.
- `19_ordinal_imports.vcxproj` + companion `ordinal_helper.vcxproj` (DLL).
- Add `test_19_ordinal_imports[x86]` and `test_19_ordinal_imports[x64]`.
- NOTE the pytest cwd (both local and ci/cd)

---

### P3 — Forwarded exports

**Why:** A DLL export whose function RVA falls *inside* the export directory's VA range is a
forwarded export — the RVA points to an ASCII string `"DLL.FuncName"` rather than code. Example:
`NTDLL.RtlMoveMemory` → `"KERNEL32.MoveMemory"`. The current import resolver follows the RVA as
code and jumps to garbage.

**Detection rule:** if resolved export RVA ≥ `ExportDir.VirtualAddress` AND
< `ExportDir.VirtualAddress + ExportDir.Size`, it is a forward string.

**Implementation**
- `asm/imports_resolver32.asm` + `asm/imports_resolver64.asm`: after reading the export function
  RVA, add a bounds-check against the export directory range. On match, parse the ASCII forward
  string: split at `.`, call `LoadLibraryA` on the DLL part, then `GetProcAddress` for the function
  part. If the function part starts with `#`, it encodes an ordinal — handle as P2 ordinal lookup.
- Same logic for delay-load resolvers.

**Test** — `tests/Windows/20_forwarded_exports/`
- Project: EXE that imports `RtlMoveMemory` from `ntdll.dll` (which forwards to
  `kernel32.MoveMemory` on all modern Windows). Uses it to copy a 4-byte buffer; returns `77` if
  the copy is correct.
- Add `test_20_forwarded_exports[x86]` and `test_20_forwarded_exports[x64]`.

---

### P4 — API sets: test and document

**Why:** Modern Windows PEs import from virtual DLL names like `api-ms-win-core-heap-l1-1-0.dll`
that have no file on disk. `LoadLibraryA("api-ms-win-...")` succeeds on modern Windows because the
OS ApiSet schema redirects the call to the real implementation DLL. The shellcode's import resolver
calls `LoadLibraryA`, so this *likely* already works. We need to verify.

**Implementation**
- Python / asm: no changes expected.
- If the test fails: detect `api-ms-win-` prefix in import DLL names and emit a warning (not a
  hard error — they often still resolve at runtime via `LoadLibraryExW` with
  `LOAD_LIBRARY_AS_DATAFILE`).

**Test** — `tests/Windows/21_api_sets/`
- `main.c`: import `HeapAlloc` / `HeapFree` from `api-ms-win-core-heap-l1-1-0.dll` (force this
  via a `.def` / pragma); allocate a buffer, write `42` into it, free it, return `42`.
- Add `test_21_api_sets[x86]` and `test_21_api_sets[x64]`.
- If the test passes: document in README as "supported". If it fails: fix the resolver or add
  rejection with clear message.

---

### P5 — `--info` expansion + PE validation layer

**Why:** `--info` currently dumps raw PE header fields. Users have no way to know in advance which
stubs will be chained, what size the shellcode will be, or whether peor supports their PE's features.
All unsupported-feature detection is also scattered across the code.

**Implementation**
- Python: add `_detect_pe_features(pe) -> PeFeatures` dataclass (or named dict) that returns:
  - `arch` (x86/x64/arm32/arm64), `subsystem`, `has_relocs`, `has_imports`, `has_delay_imports`,
    `has_tls`, `has_seh`, `has_cxx_eh`, `has_ctors`, `ordinal_imports: list[str]`,
    `forwarded_exports: bool`, `packed: bool`, `api_set_imports: list[str]`, `bss_sections: list`
  - `required_stubs: list[str]` — ordered list of stub names that would be chained
  - `issues: list[str]` — human-readable warnings/errors
- `--info` output: print each stub name + its assembled byte size + total shellcode size estimate;
  print the feature flags; print any issues.
- Validation before conversion: call `_detect_pe_features`, raise `PeorUnsupportedError` for any
  hard issues (packed PE, unsupported machine type). Log warnings for soft issues.

**Test** — extend existing `test_info_mode[x64]`: assert the new fields appear in `--info` output.
Add a test that a packed PE prints an error and exits non-zero.

---

### P6 — Refactor: split `__main__.py` into focused modules

**Why:** `__main__.py` does CLI parsing, PE feature detection, stub chain assembly, offset patching,
and output — all in one file. Adding new features (e.g., ARM32 EFI) requires editing the same blob.

**New structure** (no behaviour change, all existing tests must still pass):

```
peor/
  __main__.py          ← CLI only: argparse, calls peor.convert() or peor.info()
  _pe_features.py      ← _detect_pe_features(pe) → PeFeatures dataclass; all PE-header reads
  _chain_builder.py    ← build_shellcode(features, pe_bytes) → bytes; stub selection + patching
  _shellcodes.py       ← unchanged (auto-generated by setup.py)
```

**Rules:**
- `_pe_features.py` must not import `_shellcodes` — it only reads PE headers.
- `_chain_builder.py` must not parse PE headers directly — it only reads from `PeFeatures`.
- `__main__.py` must not contain PE-parsing or byte-patching logic.
- Named constants for every PE field offset/flag (no magic numbers).

---

### P7 — ARM32 UEFI shellcodes

**Why:** ARM32 (Thumb-2, `IMAGE_FILE_MACHINE_ARMNT = 0x01C4`) is a supported UEFI target on
Raspberry Pi 3/4 (32-bit firmware), some embedded boards, and QEMU `virt` machine. peor currently
rejects ARM32 PEs. The ARM64 EFI chain already proves the pattern; ARM32 follows the same
architecture.

**New asm files:**

1. `asm/relocations_resolver_arm32.asm`
   - Iterate `.reloc` blocks (same binary format as x86/x64).
   - Handle three relocation types:
     - `IMAGE_REL_BASED_HIGHLOW (3)`: 32-bit absolute address — same as x86, add delta to the DWORD.
     - `IMAGE_REL_BASED_ARM_MOV32 (13)`: a `MOVW r, #imm16` / `MOVT r, #imm16` Thumb-2 pair at the
       target RVA. Extract the 32-bit value encoded across both instructions, add delta, write back.
     - `IMAGE_REL_BASED_THUMB_MOV32 (14)`: same encoding as type 13 (same instruction pair, just
       flagged differently in some toolchains) — handle identically to type 13.
   - All other types: skip (type 0 = ABSOLUTE = no-op).
   - Keystone arch: `KS_ARCH_ARM`, mode: `KS_MODE_THUMB`.

2. `asm/entrypoint_resolver_efi_arm32.asm`
   - UEFI calls this stub as `efi_main(r0=EFI_HANDLE, r1=EFI_SYSTEM_TABLE*)`.
   - Save `r0`/`r1` in callee-saved registers (e.g., `r4`/`r5`) before calling ctors.
   - Jump to PE OEP restoring `r0`/`r1` (same values passed in by firmware).
   - ARM32 4-byte-aligned Thumb-2 code; no `BX LR` confusion.
   - `ctors_runner_arm32.asm` already exists — chain it before this stub.

**Python changes (`__main__.py` or `_pe_features.py` after P7):**
- Add constant `IMAGE_FILE_MACHINE_ARMNT = 0x01C4`.
- Add `'efi_arm32'` chain in `_SHELLCODES`:
  `[relocs_arm32, ctors_arm32, efi_entrypoint_arm32]`
  — selected when `Machine == 0x01C4` and `Subsystem == IMAGE_SUBSYSTEM_EFI_APPLICATION`.
- All other ARM32 subsystems: raise `PeorUnsupportedError` (not yet supported).

**EFI loader (`tests/EFI/efi_loader/main.c`):**
- Add `#ifdef __arm__` branch for ARM32. Memory layout and EFI API calls are identical to x86
  (32-bit pointer size). The `AllocatePages` path used by ARM64 is likely needed here too (UEFI
  ARM32 requires page-aligned executable memory).

**Test infrastructure (`test_shellcode.py`):**
- Add `_CLANG_CFLAGS_EFI_ARM32 = ["--target=armv7-w64-mingw32", "-fuse-ld=lld", "-nostdlib",
  "-nodefaultlibs", "-nostartfiles", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables"]`.
- Add `_find_clang_arm32()` / `_find_clang_arm32_wsl()` — same pattern as ARM64 equivalents.
- Add `_compile_efi_pe_arm32(src, out, extra_includes, entry_fn)`.
- Add `_find_qemu_ovmf("arm32")` — QEMU machine `virt` (`qemu-system-arm`), firmware from
  `qemu-efi-arm` package (Ubuntu path TBD during implementation; investigate
  `/usr/share/qemu-efi-arm/QEMU_EFI.fd` or `/usr/share/AAVMF/AAVMF32_CODE.fd`).
- Extend `@pytest.mark.parametrize("arch", ["x64", "x86", "arm64", "arm32"])` for:
  `test_01_efi_hello`, `test_02_efi_print`, `test_03_efi_simple_calc`,
  `test_04_efi_cpp_exceptions`, `test_05_efi_memory_services`.

**C++ exceptions for ARM32 EFI:**
- Compile with `-fno-unwind-tables -fno-asynchronous-unwind-tables` (same as x64/x86 EFI).
- This forces SJLJ (setjmp/longjmp) exceptions — no `.ARM.exidx` / `.ARM.extab` generated.
- SJLJ exceptions are self-contained in the compiled code; no additional shellcode stub is needed.
- No `cxx_eh_fixer_arm32.asm` required.

**EFI system table access:**
- ARM32 uses 32-bit pointers — same offsets as x86 EFI.
- Existing test C files already use `#ifdef _WIN64` to select 64-bit vs 32-bit offsets.
- `_WIN64` is NOT defined for ARM32 → 32-bit paths are used automatically. No source changes needed
  in the test EFI C files.

**CI/CD:**
- `test-efi-qemu` apt-get: add `qemu-efi-arm` (or equivalent ARM32 firmware package).
- The `-k "efi"` filter already selects all EFI tests including the new `arm32` parametrize.

### POST-QUEUE
when done, rebuild then re-run all tests locally, and edit the ci/cd for all newly-added changes, then update the README.md
remove from plan everything that was already implemented

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

### FULL ARM32 / ARM64 Windows shellcode support

**Goal:** Windows (non-EFI) shellcode for ARM32 Thumb-2 (`0x01C4`) and AArch64 (`0xAA64`).

**What's already done:** ARM64 EFI chain (relocs, ctors, EFI entrypoint). ARM32 EFI chain (P8
above).

**What's needed for Windows ARM64:**
- `asm/imports_resolver_arm64.asm` — walk PEB_LDR via `x18` (TEB on Windows ARM64), find
  kernel32/ntdll, resolve imports by name and ordinal.
- `asm/entrypoint_resolver_arm64.asm` — pass `(argc, argv, envp)` per ARM64 ABI calling convention
  (x0, x1, x2).
- `asm/tls_callbacks_arm64.asm` — call TLS callbacks before entrypoint.
- Test runner: `windows11-arm` GitHub Actions runner available; use it for build + test.

**What's needed for Windows ARM32:**
- `asm/imports_resolver_arm32.asm` — walk PEB_LDR via `r8` (TEB on Windows ARM32 = `TEB.NtTib.Self`
  at `fs:[0]`), find kernel32/ntdll, resolve imports.
- `asm/entrypoint_resolver_arm32.asm` — pass `(argc, argv, envp)` per ARM32 ABI (r0, r1, r2).
- Tests: same `windows11-arm` runner (can run ARM32 code via WoW64 on ARM64 Windows).

**CI/CD:** `windows11-arm` self-hosted or GitHub-hosted runner for both build and execution tests.

### Packed PE detection (fail loudly, or test and ensure it works)

**Why:** A packed PE (UPX, ASPack, Themida, …) will "work" through peor but produce shellcode that
unpacks itself using `VirtualAlloc`/`VirtualProtect` — imports that come from the packer stub, not
the original program. The result silently crashes or does nothing useful.

**Implementation** — Python validation, no asm changes:
1. **Known packer section names**: if any section name is in
   `{".upx0", ".upx1", "UPX0", "UPX1", ".aspack", ".adata", "ASPack", ".packed", "pebundle"}`,
   raise `PeorUnsupportedError("packed PE detected: packer section '{name}' found")`.
3. These checks run inside the new validation layer (P6).

**Test** — `tests/pytest/test_packed_pe.py` (or add to `test_shellcode.py`):
- Build a UPX-packed variant of an existing test PE in a fixture; assert `peor()` raises
  `PeorUnsupportedError` with "packed" in the message.
- Also test a normal PE is NOT rejected.
