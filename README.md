# PEOR — PE-to-Shellcode Converter

PEOR converts a compiled Windows PE file (EXE or DLL, x86 or x64) into a
position-independent shellcode that can be loaded into any flat memory buffer
and executed without a loader, module list, or image base guarantee.

The output is a self-contained binary: a small assembly stub prepended to a
memory-mapped copy of the original PE.  No OS loader involvement is needed; the
stub performs whatever setup the PE requires (relocations, imports, delay-load
imports, exception tables, TLS callbacks) before jumping to the entry point.

> **Disclaimer** — PEOR is made for educational purposes and embedded-software
> development (bare-metal, UEFI pre-OS, custom hypervisors, security research
> labs, CTF challenges).  It must not be used for any unauthorized or illegal
> activity.  Use legally, and only with full authorization on systems you own or
> have explicit permission to test.

---

## Installation

```
pip install peor
```

Or from source:

```
git clone https://github.com/mon231/peor
cd peor
pip install -e .
```

Python 3.10+ is required.  The Keystone assembler (`keystone-engine`) is a
build-time dependency used by `setup.py` to assemble the stub components; it
does not need to be present at runtime.

---

## Usage

```
python -m peor -i input.exe -o output.bin
python -m peor -i input.dll -o output.bin            # DLLs work too
python -m peor -i input.exe -o -                     # write shellcode to stdout
python -m peor -i input.exe --info                   # show resolver sizes (dry-run)
python -m peor -i input.exe --entry MyExport -o out.bin  # call a named export instead of OEP
python -m peor -i input.exe --no-imports -o out.bin  # skip all import resolvers
```

| Flag | Meaning |
|---|---|
| `-i / --input-file` | Path to the source PE (EXE or DLL, x86 or x64) |
| `-o / --output-file` | Path to write the shellcode binary, or `-` for stdout |
| `-m / --ignore-imports` | Zero the import directory in the output (for importless PEs loaded by a custom environment) |
| `--no-imports` | Skip all import resolvers even if the PE has imports |
| `-e / --entry NAME` | Call export `NAME` (by name or ordinal) instead of the PE's OEP |
| `--info` | Print resolver component sizes without writing output |

Import resolution is **automatic**: if the PE has an import directory (`DataDir[1]`)
or a delay-load directory (`DataDir[13]`), the matching resolver is prepended
automatically.  Use `--no-imports` to opt out.

The shellcode is then executed by any loader that allocates executable memory,
copies the binary in, and calls it (e.g. `VirtualAlloc` + `memcpy` + `call`).
A minimal reference loader is included in `tests/test_loader/` (Windows) and
`tests/test_loader_linux/` (Linux, for importless MinGW PEs).

---

## How It Works

### Output format

```
┌──────────────────────────────────────────────────────┐
│  shellcode prefix (assembled stubs, position-independent)  │
│  ┌──────────────────────────────────────────────────┐ │
│  │  [import resolver]    (auto, if DataDir[1] set)  │ │
│  │  relocation resolver                             │ │
│  │  [delay-load resolver](auto, if DataDir[13] set) │ │
│  │  [C++ EH IAT fixer]   (x64, if needed)           │ │
│  │  [SEH registrar]      (x86 always, x64 if .pdata)│ │
│  │  [TLS callback invoker](if TLS directory present) │ │
│  │  entry point dispatcher                          │ │
│  └──────────────────────────────────────────────────┘ │
│  memory-mapped PE image (headers + sections, zero-padded) │
└──────────────────────────────────────────────────────┘
```

Each stub runs and falls through to the next.  RBX carries the PE base
address forward through the chain.  After the chain completes, execution jumps
to the PE's own entry point (or to the export named by `--entry`).

**Note on ordering**: the delay-load resolver runs *after* the relocs resolver
so that base-relocation patches applied to the delay-load IAT are subsequently
overwritten with the real function addresses resolved via `LoadLibraryA` +
`GetProcAddress`.

---

## Shellcode Methods Explained

### Base Relocations

Windows PE files are compiled with a preferred `ImageBase`.  When the OS loads a
PE at a different address it applies *base relocations*: the `.reloc` section
lists every absolute pointer in the image that must be adjusted by
`delta = actual_base - preferred_base`.

PEOR's relocation stubs (`relocations_resolver32/64.asm`) are position-independent
and use the CALL/POP trick to discover their own runtime address:

```asm
call _base       ; push next-instruction address
_base:
pop rbx          ; RBX = runtime address of _base label
```

The distance from `_base` to the PE image header is a compile-time constant
(`PE_OFFSET_PLACEHOLDER`) that `setup.py` patches at install time.  At runtime:
1. Compute `delta = actual_base - PE.OptionalHeader.ImageBase`.
2. If `delta == 0`, skip (already at preferred address).
3. Walk `IMAGE_BASE_RELOCATION` blocks; for each `IMAGE_REL_BASED_HIGHLOW`
   (x86) or `IMAGE_REL_BASED_DIR64` (x64) entry, add `delta` to the stored
   pointer.

PEs compiled with `/FIXED` have no `.reloc` section; the stub detects this and
falls through immediately.

---

### Usermode Import Resolution

When the PE has a non-zero import directory (`DataDir[1]`), the import stub
(`imports_resolver32/64.asm`) resolves every entry in `IMAGE_IMPORT_DESCRIPTOR`
before the reloc stub runs.

**Step 1 — find kernel32** via the PEB loader list, without any imports of its
own:

| Architecture | PEB register | PEB offset | Ldr offset | Module list |
|---|---|---|---|---|
| x86 | `FS:[0x30]` | `+0x0C` → Ldr | `+0x14` → InMemoryOrderModuleList | `[0]=exe`, `[1]=ntdll`, `[2]=kernel32` |
| x64 | `GS:[0x60]` | `+0x18` → Ldr | `+0x20` → InMemoryOrderModuleList | same order |

`DllBase` sits at `+0x10` from an `InMemoryOrderLinks` node.

**Step 2 — locate `GetProcAddress`** by walking kernel32's export table:
scan `AddressOfNames` for the string, resolve via `AddressOfNameOrdinals` +
`AddressOfFunctions`.

**Step 3 — use `GetProcAddress` to get `LoadLibraryA`**, then walk
`IMAGE_IMPORT_DESCRIPTOR`; for each DLL: call `LoadLibraryA`, then call
`GetProcAddress` for each thunk.

---

### Delay-Load Import Resolution

When the PE has a non-zero delay-load directory (`DataDir[13]`), the delay-load
stub (`imports_resolver32/64_delayload.asm`) resolves every entry in
`IMAGE_DELAY_IMPORT_DESCRIPTOR` after the relocs stub runs.

The delay-load resolver uses the same PEB walk as the regular import resolver
to obtain `GetProcAddress` and `LoadLibraryA` independently.  For each
`ImgDelayDescr` entry (modern `grAttrs=1` RVA format):
1. Call `LoadLibraryA(rvaDLLName + PE_base)` → module handle.
2. Walk the delay-load INT (`rvaINT`); for each thunk call
   `GetProcAddress(module, name_or_ordinal)`.
3. Patch the delay-load IAT slot (`rvaIAT`) with the resolved VA.

This runs *after* the relocs resolver so that any `DIR64` relocation applied to
the delay-load IAT is subsequently overwritten with the real function address.

---

### x64 Exception Tables (SEH Registrar)

x64 Windows uses *table-based* structured exception handling.  There is no
stack-linked SEH frame chain; instead, the kernel's unwinder calls
`RtlLookupFunctionEntry` to find a `RUNTIME_FUNCTION` record (from `.pdata`) for
the faulting RIP.  That record points to unwind info and the frame handler.

When a PE runs as shellcode from `VirtualAlloc` memory it is not registered
with the OS module list.  `RtlLookupFunctionEntry` falls back to dynamic
function tables registered via `RtlAddFunctionTable`.

`seh_registrar64.asm` does exactly this:
1. Walk PEB `InMemoryOrderModuleList[1]` to get ntdll's base without any imports.
2. Scan ntdll's export table for `RtlAddFunctionTable`.
3. Call `RtlAddFunctionTable(DataDir[3].VA + base, count, base)` where
   `DataDir[3]` is the exception directory.

This is only inserted when `DataDir[3].VirtualAddress != 0`.

---

### x86 Exceptions — Bypassing SafeSEH (VEH Approach)

x86 Windows uses a *stack-based* SEH chain: each function prologue pushes an
`EXCEPTION_REGISTRATION_RECORD` onto the stack and links it into `FS:[0]`.
When an exception is dispatched, the kernel walks this chain calling each
handler.

**The problem — SafeSEH / `RtlIsValidHandler`:** On Windows Vista+ with DEP,
`RtlDispatchException` calls `RtlIsValidHandler` before each call.  This checks
that the handler address belongs to a module known to `RtlPcToFileHeader`.  On
Windows 11 WoW64, `RtlPcToFileHeader` uses `NtQueryVirtualMemory
(MemoryImageInformation)` at the kernel level; `VirtualAlloc` memory always
returns `ImageBase=0`, so no usermode LDR-list injection can fix this.

**The fix — Vectored Exception Handlers:** `RtlAddVectoredExceptionHandler`
registers a VEH that runs *before* `RtlDispatchException` walks the chain — and
VEH handlers are never validated by `RtlIsValidHandler`.

`seh_registrar32.asm`:
1. Walk PEB `InMemoryOrderModuleList[1]` to get ntdll's base.
2. Scan ntdll's export table for `RtlAddVectoredExceptionHandler` directly
   (kernel32's `AddVectoredExceptionHandler` is a forwarded export; resolving it
   via a raw export-table walk returns the forwarder string, not a callable VA).
3. Register a VEH with `First=TRUE`.

The VEH handler:
- Ignores any exception code other than `0xE06D7363` (the MSVC C++ exception
  magic).
- Walks the SEH chain from `FS:[0]`, calling each frame's handler directly
  (bypassing `RtlIsValidHandler`).
- When `__CxxFrameHandler3` finds a matching catch block it internally calls
  `RtlUnwind` and longjmps to the catch body — it never returns to the VEH.
  `RtlUnwind` does **not** invoke `RtlIsValidHandler` during the unwind phase,
  so unwind handlers in `VirtualAlloc` memory work correctly.
- If the chain is exhausted without a match, returns
  `EXCEPTION_CONTINUE_SEARCH` so Windows can handle it as unhandled.

Note: this approach deliberately avoids LDR-list injection, which would cause
`GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)` to return the
shellcode base — causing the CRT's `_beginthreadex` wrapper to call
`FreeLibraryAndExitThread(shellcode_base, result)` and crash.

---

### x64 Typed C++ Exceptions (IAT Hook)

Modern MSVC (exception magic `0x19930522`) changed how `_CxxThrowException`
passes the throw object to the frame handler:

1. Calls `RtlPcToFileHeader(throw_site, &ImageBase)` to get the module base.
2. Stores `ThrowInfo - ImageBase` (a 32-bit RVA) in `ExceptionInformation[2]`.
3. Stores `ImageBase` in `ExceptionInformation[3]`.

`__CxxFrameHandler3` reconstructs the pointer as `ImageBase + RVA`.

For shellcode not in the loader list, `RtlPcToFileHeader` returns `NULL`.
Storing a 64-bit `ThrowInfo` as a 32-bit offset from `NULL` truncates the
high 32 bits — the reconstructed pointer is garbage and the catch block never
fires.

`cxx_eh_fixer64.asm` patches the PE's own IAT entry for `RtlPcToFileHeader`
to point to a small hook stub assembled inline:
- If the queried address is within the PE image (`base ≤ addr < base + SizeOfImage`),
  the hook writes `base` into the out-parameter and returns `base`.
- Otherwise it tail-calls the real `RtlPcToFileHeader`.

Two values — `SizeOfImage` and the IAT RVA — are baked in by
`peor/__main__.py` at conversion time, replacing placeholder constants in the
assembled bytes.

x86 does not need this hook.  On 32-bit Windows all addresses fit in 32 bits;
`ThrowInfo - NULL` is just `ThrowInfo`, and `NULL + ThrowInfo` reconstructs the
correct pointer.

---

### TLS Callbacks

A PE can declare Thread-Local Storage callbacks in `IMAGE_DIRECTORY_ENTRY_TLS`
(data directory index 9).  The OS normally invokes these before `main`.  When
running as shellcode, the OS is not involved, so PEOR must invoke them manually.

`tls_callbacks32/64.asm`:
1. Read `DataDir[9].VirtualAddress` (TLS directory RVA).
2. Read `IMAGE_TLS_DIRECTORY.AddressOfCallBacks` (a VA pointing to a
   null-terminated array of callback VAs).
3. Call each non-null entry as `callback(hModule=base, DLL_PROCESS_ATTACH, NULL)`.

This stub is only inserted when the TLS directory is present and
`AddressOfCallBacks` is non-zero.

---

### Entry Point Dispatcher

`entrypoint_resolver32/64.asm` reads `AddressOfEntryPoint` from the optional
header (or the RVA supplied by `--entry`).  If `IMAGE_FILE_DLL` is set in
`Characteristics`, it calls `DllMain(base, DLL_PROCESS_ATTACH, NULL)` using the
correct calling convention (x86 stdcall / x64 Microsoft ABI).  For EXEs it
jumps directly to the entry point.

---

## Test Suite

All tests live in `tests/` and are driven by `pytest`.  Each test:
1. Calls `dump_memory_layout` to produce a shellcode binary.
2. Executes it via `tests/Win_x86/test_loader.exe` or
   `tests/Win_x64/test_loader.exe`.
3. Asserts on the process exit code.

Build the test PEs first (see **Building**), then run:

```
pytest tests/pytest -v
```

| # | Test | Arch | What it verifies | Expected exit |
|---|---|---|---|---|
| 01 | `01_simple_calc` | x86, x64 | Importless EXE; loop 0–99, no relocations needed | 4950 |
| 02 | `02_relocs_functions` | x86, x64 | Importless EXE with static globals and `.reloc` section; tests relocation resolver | 90 |
| 03 | `03_winapi_messagebox` | x86, x64 | EXE calling `MessageBoxA`; tests import resolver and interactive dialog | 0 (skipped in CI) |
| 04 | `04_crt_printf_rand` | x86, x64 | CRT EXE (`printf` + `rand`); tests full CRT startup with imports | 0 (stdout = `Random: <n>`) |
| 05 | `05_dll_entry` | x86, x64 | DLL whose `DllMain` calls `ExitProcess(42)`; tests DLL entry dispatch | 42 |
| 06 | `06_stripped_relocs` | x86, x64 | EXE compiled `/FIXED` (no `.reloc` section); resolver must skip relocation | 99 |
| 07 | `07_cpp_exceptions` | x86, x64 | `__try`/`__except` with `RaiseException(77,...)`; tests SEH registrar | 77 |
| 08 | `08_cpp_thread` | x86, x64 | `std::thread` lambda sets `result=42`; tests CRT thread machinery | 42 |
| 09 | `09_resources` | x86, x64 | EXE reads string resource 100 from its own `.rsrc` section via `__ImageBase`; tests resource preservation | 42 |
| 10 | `10_tls_callbacks` | x86, x64 | TLS callback sets `g_result=88`; tests TLS callback invoker runs before `main` | 88 |
| 11 | `11_cpp_exceptions` | x86, x64 | Typed C++ `throw`/`catch`; tests that the correct catch branch fires | 123 |
| 12 | `12_seh_exceptions` | x86, x64 | Same as 11 but compiled `/EHa` (SEH-integrated C++ exceptions) | 123 |
| 13 | `13_tls_multi_callbacks` | x86, x64 | Five TLS callbacks in sequence with ordering check | computed sum |
| 14 | `14_global_ctors` | x86, x64 | File-scope C++ constructor runs before `main` | 42 |
| 15 | `15_nested_exceptions` | x64 | Nested/rethrown C++ exceptions test multi-frame unwind | 55 |
| 16 | `16_delay_load` | x86, x64 | Delay-loaded `winmm.dll!timeGetTime`; tests delay-load IAT pre-patching | 1..250 |
| — | `certificate_signed_pe` | x86, x64 | PE with a dummy `WIN_CERTIFICATE` appended; verifies security directory is handled | 90 |
| — | `clr_pe_rejection` | — | CLR/managed PE raises `ValueError` | ValueError |
| — | `disp32_overflow` | — | Relocs resolver disp32 overflow check raises `ValueError` | ValueError |
| — | `custom_entry` | x64 | `--entry DllMain` calls a named export instead of OEP | 42 |
| — | `mingw_simple_calc` | x64 | MinGW cross-compiled importless EXE; CI-only (skipped if compiler absent) | 4950 |

Test 03 requires an interactive desktop and is automatically skipped when the
`CI` environment variable is set.

---

## Building

Requirements: Visual Studio 2022 with the C++ workload.

```bat
rem Release builds (used by pytest)
msbuild tests\tests.sln /p:Configuration=Release /p:Platform=Win32
msbuild tests\tests.sln /p:Configuration=Release /p:Platform=x64
```

Binaries land in `tests/Win_x86/` and `tests/Win_x64/`.  Post-build steps
automatically run `python -m peor` on each output to produce the corresponding
`.shellcode` files alongside the PE.

For the MinGW cross-platform test (Linux/Ubuntu):

```bash
sudo apt-get install -y gcc-mingw-w64-x86-64 gcc
gcc -O2 -o tests/test_loader_linux/test_loader_linux tests/test_loader_linux/main.c
pytest tests/pytest -v -k test_mingw_simple_calc
```

---

## Supported PE Types

| Type | x86 | x64 |
|---|---|---|
| Windows GUI/console EXE | ✅ | ✅ |
| Windows DLL | ✅ | ✅ |
| EFI application | ❌ (planned) | ❌ (planned) |
| Windows kernel driver | ❌ (planned) | ❌ (planned) |

EFI and kernel-mode support are on the roadmap.  Attempting to convert them
raises `ValueError` with a descriptive message.
