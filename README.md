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
python -m peor -i linux.exe --platform linux -o shell.bin  # force Linux import chain
python -m peor -i app.efi -o shell.bin               # EFI application (auto-detected)
```

| Flag | Meaning |
|---|---|
| `-i / --input-file` | Path to the source PE (EXE or DLL, x86 or x64) |
| `-o / --output-file` | Path to write the shellcode binary, or `-` for stdout |
| `-m / --ignore-imports` | Zero the import directory in the output (for importless PEs loaded by a custom environment) |
| `--no-imports` | Skip all import resolvers even if the PE has imports |
| `-e / --entry NAME` | Call export `NAME` (by name or ordinal) instead of the PE's OEP |
| `--info` | Print resolver component sizes without writing output |
| `--platform PLATFORM` | Override platform detection: `windows` (default), `linux`, or `efi` |

Platform and import chain selection is **automatic**:
- Windows PEs (subsystems 2–3) use the PEB-walk import resolver.
- POSIX\_CUI PEs (subsystem 7) use the Linux `dlopen`/`dlsym` resolver.
- EFI application PEs (subsystems 10–13) use the EFI entry dispatcher (no import resolver).

Use `--platform` to override detection; use `--no-imports` to skip import resolvers entirely.

The shellcode is executed by any loader that allocates executable memory, copies the binary
in, and calls it (e.g. `VirtualAlloc` + `memcpy` + `call`).
Reference loaders are in `tests/test_loader/` (Windows) and `tests/test_loader_linux/`
(Linux; calls the shellcode with zero arguments — it is fully self-contained).

---

## How It Works

### Output format

```
┌──────────────────────────────────────────────────────┐
│  shellcode prefix (PIC asm stubs)                    │
│ ┌──────────────────────────────────────────────────┐ │
│ │ [import resolver]    (auto, if DataDir[1] set)   │ │
│ │ relocation resolver                              │ │
│ │ [delay-load resolver](auto, if DataDir[13] set)  │ │
│ │ [C++ EH IAT fixer]   (x64, if needed)            │ │
│ │ [SEH registrar]      (x86 always, x64 if .pdata) │ │
│ │ [TLS callback invoker] (ThreadLocalStorage init) │ │
│ │ [.init_array runner]   (EFI/Linux, if present)   │ │
│ │ entry point dispatcher                           │ │
│ └──────────────────────────────────────────────────┘ │
│  memory-mapped PE image (headers + sections, padded) │
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

### Linux User-Mode Import Resolution

When the PE subsystem is POSIX\_CUI (7) or `--platform linux` is specified and
the PE has an import directory, the Linux import resolver
(`imports_resolver32/64_linux.asm`) is used instead of the PEB-walk resolver.

The shellcode is **fully self-contained** — the caller passes no arguments.
The reference Linux loader invokes it with zero arguments:

```c
int result = ((int (*)(void))mem)();
```

At runtime the resolver:
1. Opens `/proc/self/maps` via a raw syscall (no libc).
2. Scans the output for the `libc.so` mapping to find libc's base address.
3. Parses the ELF header (x64: ELF64; x86: ELF32): walks program headers for
   `PT_DYNAMIC`, then scans `DT_HASH`/`DT_SYMTAB`/`DT_STRTAB` to find
   `dlsym` and `dlopen` by symbol-table scan.
4. Walks `IMAGE_IMPORT_DESCRIPTOR` entries from `DataDir[1]`; for each DLL
   calls `dlopen(dll_name, RTLD_LAZY)`, then for each thunk calls
   `dlsym(handle, name)` and patches the IAT slot.

String literals (`/proc/self/maps`, `dlsym`, `dlopen`, `libc.so`) are embedded
via the call-over-data trick (no absolute addresses).  All calls use the
System V ABI (x64: RDI/RSI/RDX; x86: stack cdecl).

---

### EFI Entry Dispatcher

When the PE subsystem is an EFI application (10–13), an EFI entry dispatcher is
used instead of the standard Windows entry dispatcher.  No import resolver is
inserted (EFI applications are expected to be importless).

Four dispatcher variants exist, one per architecture — **all fully
self-contained**: the shellcode is called as `EFI_STATUS(void)`, with no
arguments from the loader (not even `ImageHandle`/`SystemTable`, which the
firmware itself passed to the *loader*, not the shellcode).  Every dispatcher
locates `EFI_SYSTEM_TABLE` itself and calls `efi_main(NULL, SystemTable)`:

**x86 / x64** (`entrypoint_resolver_efi32/64.asm`):
1. Attempts a fast path: reads the `EFI_SYSTEM_TABLE` pointer from the loader's
   stack frame at a fixed RSP offset (calibrated to the reference EFI loader
   compiled with GCC at `-O0`).
2. Falls back to a memory scan from `SCAN_END` down to `0x10000`, checking each
   16-byte aligned address for `EFI_SYSTEM_TABLE_SIGNATURE` (`0x5453595320494249`),
   `Revision >= 2.0`, `HeaderSize >= 0x78`, and valid `BootServices`/`ConOut` pointers.
   Scan range: `0x10000–0x20000000` for x64, `0x10000–0x10000000` for x86.
3. Calls `efi_main(NULL, SystemTable)` with the appropriate ABI.

**ARM64** (`entrypoint_resolver_efi_arm64.asm`):
1. Fast path: reads `EFI_SYSTEM_TABLE` from `efi_loader_main`'s own stack frame at a
   fixed SP offset (calibrated the same way as x86/x64's fast path, but confirmed by
   disassembling the actual compiled loader rather than by inspecting source — clang
   `-O0` for `aarch64-w64-mingw32` saves the `system_table` argument at `[sp+0x70]`
   right after `sub sp, sp, #0x90`; the resolver's own prologue shifts that by 0x10),
   then validates it with the same signature/BootServices/ConOut checks as the scan.
2. Falls back to the memory scan below only if the fast-path candidate fails
   validation.

**Why ARM64 needs the fast path (and x64/x86 treat it as optional):** ARM64's 256 MiB
QEMU-virt scan range also contains EDK2's own live structures (unlike x64/x86's mostly
empty scan range), so a pure scan can find a false-positive match that still passes
every check — the resolved `ConOut->OutputString` then points into unrelated EDK2 code,
and calling it crashes with a QEMU `Synchronous Exception` deep inside the firmware.
Reading the real pointer directly off the stack sidesteps this; the scan stays only as
a last-resort fallback (as it does for x64/x86 too, mainly so the resolver still works
if `tests/EFI/efi_loader/main.c`'s ARM64 branch or its compile flags ever change enough
to move that stack slot).

**ARM32** (`entrypoint_resolver_efi_arm32.asm`): always does the memory scan (no stack
fast path — not needed, arm32 has no false-positive problem in practice). Same
signature/`BootServices`/`ConOut` validation, using the 32-bit `EFI_TABLE_HEADER`
layout. `ARM32_EFI_PREFIX` runs first, but only to push `r4-r11`/`lr` for AAPCS
callee-save — it no longer captures any firmware-supplied register.

Scan range for both ARM64 and ARM32 is `0x40000000–0x50000000` — the RAM window QEMU's
`virt` machine maps at `-m 256M`, matching how the ARM64/ARM32 EFI tests boot.

**ARM64 ADRP alignment requirement**: ARM64 code uses `ADRP` (page-granular
PC-relative addressing) to access `.rodata` symbols.  `ADRP` is correct only
when the PE image base is 4 KB page-aligned.  The ARM64 EFI chain is therefore
padded to exactly 4096 bytes; when the loader allocates `exec_buf` via
`AllocatePages` (which guarantees page-alignment), the PE starts at
`exec_buf + 4096` — also page-aligned.  Reference EFI loaders for ARM64 must
use `AllocatePages` (not `AllocatePool`) for this reason.

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

### `.init_array` Constructor Runner (EFI and Linux)

GCC-compiled C++ binaries register C++ global constructors — and the GCC
exception-handling runtime's frame tables — via function pointers stored in the
`.init_array` (or `.ctors`) section.  On EFI and Linux shellcode chains, the OS
loader is bypassed entirely, so PEOR must call these constructors manually before
the entry point.

`ctors_runner32/64.asm`:
1. Compute `start = PE_base + .init_array RVA` and `end = start + size`.
2. Walk the array; for each non-null function pointer, call it.
3. Preserve `RBX`/`EBX` (PE base) and RSP alignment across all calls.

The RVA and size are baked in at conversion time by `peor/__main__.py`, replacing
placeholder constants `CTORS_SECTION_RVA` / `CTORS_SECTION_SIZE` in the assembled
bytes.  This stub is only inserted when the PE contains a `.init_array` or `.ctors`
section with non-zero virtual size.

**Native C++ exceptions** — EFI and Linux shellcodes support C++ `try/catch` via the
GCC exception-handling runtime; `peor` runs `.init_array` constructors (including EH
frame registration) before the entry point.

For **Linux x64** and **EFI x64** targets, MinGW GCC (posix-threading) uses Windows
SEH mechanics (no DWARF).  `seh_linux64.c` (`tests/cpp_eh_support/`) is compiled
into x64 Linux/EFI builds to provide a freestanding Windows SEH emulator: it
implements `RtlCaptureContext`, `RtlLookupFunctionEntry`, `RtlVirtualUnwind`,
`RaiseException`, and `RtlUnwindEx` as well as all `libc.so.6`/`libpthread.so.0`
symbols that libsupc++/libgcc\_eh need, with raw Linux syscalls (Linux mode) or a
128 KB static buffer (EFI mode).  For **Linux x86** and **EFI x86**, cdecl matches
the Linux IA-32 and SJLJ/DWARF ABIs so no shim is required.

---

### Entry Point Dispatcher

`entrypoint_resolver32/64.asm` reads `AddressOfEntryPoint` from the optional
header (or the RVA supplied by `--entry`).  If `IMAGE_FILE_DLL` is set in
`Characteristics`, it calls `DllMain(base, DLL_PROCESS_ATTACH, NULL)` using the
correct calling convention (x86 stdcall / x64 Microsoft ABI).  For EXEs it
jumps directly to the entry point.

---

## Module Structure

```
peor/
  __main__.py       ← CLI only: argparse, --info / -o dispatch
  _pe_features.py   ← PE header reads: PeFeatures dataclass, _detect_pe_features(),
                       _validate_pe_features(), all IMAGE_DIRECTORY_ENTRY_* constants
  _chain_builder.py ← Stub selection and byte patching: _SHELLCODES table, _build_shellcode_chain(),
                       dump_memory_layout(), _select_chain()
  _shellcodes.py    ← Auto-generated shellcode byte arrays (assembled by setup.py)
```

`_pe_features.py` has no dependency on `_shellcodes` or `_chain_builder`.
`_chain_builder.py` reads all PE feature decisions from `PeFeatures`; it only uses the raw PE
object for memory-layout reads (`pe.get_data()`, `pe.sections`).

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
| — | `mingw_simple_calc` | x64 | MinGW cross-compiled importless EXE; uses WSL on Windows, native compiler on Linux CI; Linux loader prints full int to stdout | stdout=4950 |
| — | `clangcl_simple_calc` | x64 | clang-cl `/MT` compiled EXE with static CRT; Windows-only (skipped if `clang-cl` absent) | 4950 |
| — | `01_linux_write` | x64 | Linux-platform PE (subsystem 7) importing `write` from `libc.so.6`; shellcode finds `dlsym`/`dlopen` itself via `/proc/self/maps`; asserts "PEOR\n" in stdout | stdout=PEOR |
| — | `01_linux_write_x86` | x86 | Same as above but compiled as PE32 with i686-w64-mingw32-gcc; uses x86 Linux chain and 32-bit loader | stdout=PEOR |
| — | `02_linux_cpp_exceptions` | x64, x86 | Linux C++ shellcode: `throw`/`catch` a custom type, return code 42 for typed catch, 88 for catch-all; x64 uses Windows-SEH emulator (`seh_linux64.c`) | 42 |
| — | `03_linux_with_crt` | x64, x86 | Linux PE using `strlen`/`malloc`/`free`/`memcpy` from `libc.so.6`; tests multi-symbol dlopen/dlsym resolver | 73 |
| — | `04_linux_signal` | x64, x86 | Linux PE installing SIGUSR1 handler via `signal()`, raising it via `raise()`, returns 77; tests signal-handling imports | 77 |
| — | `05_linux_global_ctor` | x64, x86 | Linux C++ PE with a global constructor that increments a counter; `main` asserts `counter == 99`; tests `.init_array` runner | 99 |
| — | `01_efi_hello` | x64, x86, arm64, arm32 | Minimal EFI application PE; peor converts it; EFI loader with embedded shellcode boots under QEMU+OVMF/AAVMF; shellcode calls ResetSystem(Shutdown) | QEMU exit 0 |
| — | `02_efi_print` | x64, x86, arm64, arm32 | EFI shellcode uses ConOut->OutputString to print "PEOR\_EFI\_HELLO"; checks QEMU stdout | PEOR\_EFI\_HELLO in stdout |
| — | `03_efi_simple_calc` | x64, x86, arm64, arm32 | EFI shellcode computes sum(0..99)=4950, prints "PEOR\_4950" via ConOut; checks QEMU stdout | PEOR\_4950 in stdout |
| — | `04_efi_cpp_exceptions` | x64, x86, arm32 | EFI C++ shellcode: `throw`/`catch` a custom type; x64 uses freestanding Windows-SEH emulator (static heap); x86/arm32 use DWARF/SJLJ; asserts "PEOR\_CPP\_EH\_OK" in QEMU stdout | PEOR\_CPP\_EH\_OK in stdout |
| — | `05_efi_memory_services` | x64, x86, arm64, arm32 | EFI shellcode calls AllocatePool/FreePool to exercise BootServices memory management; asserts "PEOR\_MEM\_OK" in QEMU stdout | PEOR\_MEM\_OK in stdout |
| — | `test_efi_x86_shellcode_conversion` | x86 | PE32 EFI application compiled with i686-w64-mingw32-gcc; verifies peor produces non-empty shellcode using x86 EFI chain | non-empty bin |

Test 03 requires an interactive desktop and is automatically skipped when the
`CI` environment variable is set.

Linux tests (`01_linux_write` through `05_linux_global_ctor`, both x64 and x86 variants)
and EFI QEMU tests (`01_efi_hello` through `05_efi_memory_services`) require a Linux
runner.  Building the Linux PE test binaries requires `gcc-mingw-w64-x86-64`,
`gcc-mingw-w64-i686`, `binutils-mingw-w64-*`, `g++-mingw-w64-x86-64`,
`g++-mingw-w64-i686`, `gcc`, and `gcc-multilib`.  EFI QEMU tests additionally
require `qemu-system-x86` and `ovmf`.  On Windows, tests use WSL for compilation
and the native Windows loader for execution.

---

## Building

`tests/pytest/test_shellcode.py` contains **no build logic**: every test reads a
prebuilt fixture and fails loudly (never skips) if it's missing. `tests/build_tests.py`
builds every fixture the current host's toolchains support — Linux test loaders and
PEs, and EFI test-source PEs (all 4 archs); the MSVC test suite is a separate MSBuild
step (`tests/tests.sln`). Use `--target {linux,efi,windows}` to build only one group
(`windows` = the mingw/clang-cl fixtures under `tests/Win_*_MinGW/`), or no `--target`
for everything the host supports. CI calls it the same way per job (see
`.github/workflows/test.yml`).

The EFI loader (which embeds each test's peor-generated shellcode) is the one fixture
that can't be a plain prebuilt file for every arch:
- **x64/x86**: `build_tests.py` compiles it once per arch with a fixed-size placeholder
  blob (`tests/EFI/efi_loader/main.c`); at test time `_embed_shellcode_in_loader()` just
  byte-patches a copy — no compiler runs there either.
- **ARM64/ARM32**: still compiled per-test (`_compile_arm_efi_loader`, the one remaining
  compiler call in the whole test file). The blob+patch scheme above reproducibly hangs
  this QEMU/EDK2 ARM firmware at boot for reasons not yet root-caused — unrelated to the
  scan/false-positive issue described above; see `PEOR_ARM_LEGACY_SHELLCODE` in
  `tests/EFI/efi_loader/main.c` and `PLAN.md` — so ARM keeps the known-working per-test
  compile (`-DPEOR_ARM_LEGACY_SHELLCODE`, `#include "shellcode_data.h"`) instead.

Manual/IDE builds still work the same way:

Requirements: Visual Studio 2022 with the C++ workload.

```bat
rem Release builds (used by pytest)
msbuild tests\tests.sln /p:Configuration=Release /p:Platform=Win32
msbuild tests\tests.sln /p:Configuration=Release /p:Platform=x64
```

Binaries land in `tests/Win_x86/` and `tests/Win_x64/`.  Post-build steps
automatically run `python -m peor` on each output to produce the corresponding
`.shellcode` files alongside the PE.

For the MinGW cross-platform and Linux import tests (Linux/Ubuntu):

```bash
sudo apt-get install -y \
    gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 \
    gcc-mingw-w64-i686   binutils-mingw-w64-i686 \
    g++-mingw-w64-x86-64 g++-mingw-w64-i686 \
    gcc gcc-multilib

python tests/build_tests.py --target linux
pytest tests/pytest -v -k "linux"
```

Linux test PEs land in `tests/Linux_x64/` and `tests/Linux_x86/`; `build_tests.py`
skips anything already built there, so re-runs are fast. The Linux NMakefile vcxproj
files (`tests/Linux/0[1-5]_*.vcxproj`) can be opened in Visual Studio and built
individually; they are listed in `tests.sln` for IDE visibility but excluded from the
default MSBuild target (no `Build.0` entry) to keep the Windows build independent of
MinGW availability.

For the EFI QEMU tests (Linux/Ubuntu):

```bash
sudo apt-get install -y \
    gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 \
    gcc-mingw-w64-i686   binutils-mingw-w64-i686 \
    g++-mingw-w64-x86-64 g++-mingw-w64-i686 \
    clang lld \
    qemu-system-x86 ovmf ovmf-ia32 \
    qemu-system-arm qemu-efi-aarch64 qemu-efi-arm

python tests/build_tests.py --target efi
pytest tests/pytest -v -k "efi"
```

EFI tests build a UEFI application PE, convert it with peor, embed the shellcode
in an EFI loader PE, and boot it under QEMU+OVMF.  The shellcode scans memory for
`EFI_SYSTEM_TABLE_SIGNATURE` at runtime — no runtime parameters are passed from
the loader.  The loader calls `ResetSystem(EfiResetShutdown)` on success — QEMU
exits 0.  QEMU's `vvfat` driver presents the `EFI/BOOT` directory as a virtual
FAT disk (no `mtools` needed).

On Windows with WSL, MinGW tests automatically use `wsl -- gcc ...` for compilation
and the native `test_loader.exe` for execution.

---

## Supported PE Types

| Type | x86 | x64 |
|---|---|---|
| Windows GUI/console EXE | ✅ | ✅ |
| Windows DLL | ✅ | ✅ |
| Linux user-mode EXE (POSIX\_CUI, subsystem 7) | ✅ | ✅ |
| EFI application (subsystems 10–13) | ✅ | ✅ |
| Windows kernel driver | ❌ | ❌ |

Attempting to convert unsupported combinations raises `ValueError` or `PeorUnsupportedError` with a descriptive message.

---

## PE Feature Detection (`--info`)

`peor --info -i input.exe` prints a feature summary and a stub-size breakdown without writing output:

```
PE features:
  arch              x64
  subsystem         2
  has_relocs        yes
  has_imports       yes
  has_delay_imports no
  has_tls           no
  has_seh           yes
  has_cxx_eh        yes
  has_ctors         no
  packed            no
  bss_sections      none
  ordinal_imports   none
  api_set_imports   none
  forwarded_exports no
  required_stubs    imports -> relocs -> cxx_eh_fixer -> seh -> entrypoint
  issues            none

  imports      1234 B
  relocs        567 B
  cxx_eh        89 B
  seh           45 B
  entrypoint    33 B
  PE image   65536 B
  ──────────────────────
  total      67504 B  (input.exe)
```

**Packed PE rejection**: peor detects common packer section names (`.upx0`, `.upx1`, `UPX0`, `UPX1`, `.aspack`, `ASPack`, `.packed`, `pebundle`) and raises `PeorUnsupportedError` before conversion.  Both `--info` and `-o` paths reject packed PEs.
