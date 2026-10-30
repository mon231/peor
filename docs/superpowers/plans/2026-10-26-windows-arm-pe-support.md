# Windows ARM32/ARM64 PE Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give PEOR a full, non-EFI Windows PE shellcode chain for ARM64 and ARM32, at feature parity with the existing x64/x86 chain, with tests and CI.

**Architecture:** Each new asm resolver is assembled by `setup.py`'s `_assemble_shellcodes()` (keystone already supports `KS_ARCH_ARM64` and `KS_ARCH_ARM`/`KS_MODE_THUMB` — see `assemble_arm64`/`assemble_arm32` helpers already present) into a new `bytes` constant in `peor/_shellcodes.py`, then wired into two new `_SHELLCODES` dict entries (`_PLATFORM_ARM64`, `_PLATFORM_ARM32`) in `peor/_chain_builder.py`. Base relocations and ctors already have ARM64/ARM32 asm (`RELOCS_ARM64/32`, `CTORS_RUNNER_ARM64/32`, built for the EFI chain but format-identical for Windows PEs) — reuse them unchanged. Tests follow the existing one-folder-per-case / MSVC `.vcxproj` convention, with ARM64 and ARM32 added as new build platforms to each existing test project (mirrors how the EFI chain added "arm64"/"arm32" to `@pytest.mark.parametrize("arch", ...)` lists rather than creating new folders).

**Tech Stack:** Python 3.10+, keystone-engine, pefile, MSVC (`cl.exe`/MSBuild) for the 01-16/18-21 test ports, llvm-mingw/clang for test 17's ARM port, pytest, GitHub Actions (`windows-11-arm` runner).

**Spec:** `C:\Users\avart\Desktop\Projects\peor\docs\superpowers\specs\2026-10-26-windows-arm-support-design.md` (Goals 2-5 — Goal 1, the EFI-ARM real-hardware CI job, has its own plan: `docs/superpowers/plans/2026-10-26-efi-arm-real-hardware-ci.md`, independent of this one)

## Global Constraints

- No test may be skipped locally or in CI, ever (CONTRIBUTING.md / CLAUDE.md / PLAN.md).
- Named constants only — no magic numbers in new asm/python (e.g. `IMAGE_FILE_MACHINE_ARM64`-style names, not raw `0xAA64`).
- One responsibility per asm file; asm usage inferred from PE headers, never hardcoded per-call.
- No new per-architecture test folders — extend existing numbered folders' build platforms and existing pytest `parametrize` lists, matching the Linux/EFI convention already in this repo.
- Distinctive non-trivial test return codes (never 0/1/-1) for any new return-code-based test.
- `README.md` updated per feature added (CONTRIBUTING.md rule); `PLAN.md`'s "FULL ARM32/ARM64 support" deferred section removed once this plan's goals are done (per `PLAN.md`'s own standing rule: "When mission from the PLAN file is done, remove it from the PLAN file").
- Both ARM64 and ARM32 variants, wherever possible (explicit project decision — see spec).
- Build/test/deploy CI stages stay separate; installs happen before build/test in any new CI job (CONTRIBUTING.md CI rule).

## Review Focus

- **Real ARM64 Windows PE silently misclassified today**: `_chain_builder._select_chain`'s fallback branch (`entry = _SHELLCODES.get(features.pe_type)`) has no machine check outside the Linux/EFI branches — an ARM64 Windows PE (`pe_type == OPTIONAL_HEADER_MAGIC_PE_PLUS`, same as x64) currently falls through to the **x64** chain with no error. Task 1 must close this before any ARM64 test can mean anything; the task's own test must assert that an ARM64 input PE resolves to `_PLATFORM_ARM64`, not x64.
- **ARM32 vs. x86 PE type collision**: same issue for ARM32 (`pe_type == OPTIONAL_HEADER_MAGIC_PE`, same as x86) — must resolve to `_PLATFORM_ARM32`, not x86.
- **`--entry <export>` on ARM**: README documents `--entry` working for any input; the new ARM64/ARM32 entrypoint resolvers must support it the same way `ENTRYPOINT_32/64` do (patch `EP_RVA_MAGIC`, not just `AddressOfEntryPoint`).
- **`--no-imports`/`-m` on ARM**: these flags must behave identically once imports exist for ARM (zeroing the import directory, skipping the resolver) — don't let the new `_SHELLCODES` entries silently break `_zero_import_dir`'s `dir_array_offset` lookup (ARM64 optional header layout is PE32+, same offset as x64 — `112`; ARM32 is PE32, same offset as x86 — `96`; verify against the real compiled test PEs, don't assume).
- **MSVC ARM32 desktop toolset unavailability**: flagged as a real risk in the spec. Task 1's first step is exactly the check that determines whether the rest of the ARM32 half of this plan is buildable as planned at all — surface this to the human partner immediately if MSVC ARM32 desktop isn't installable, don't silently substitute a toolchain mid-plan.

---

## Task 1: Platform dispatch + non-EFI entrypoint resolver (ARM64 + ARM32)

> **2026-10-27 update:** `asm/entrypoint_resolver_arm64.asm` / `ENTRYPOINT_ARM64`
> already exist as of the parallel Linux-ARM plan
> (`docs/superpowers/plans/2026-10-27-linux-arm-pe-support.md`, on branch
> `arm_support-linux-arm`) — that plan's import resolver needed a real
> (non-mock) entrypoint stub to actually test against, discovered the gap,
> and wrote the generic version since x64 already shares one file between
> Linux and Windows. **Reuse it, don't recreate it** — read it first and
> confirm it satisfies this task's DLL/EXE dispatch requirements (it reads
> `x19` = PE base set by `relocations_resolver_arm64.asm`, detects
> `IMAGE_FILE_DLL`, calls `DllMain` or branches to the OEP via an EP_RVA_MAGIC
> literal pool — same logic as `entrypoint_resolver64.asm`). Only
> `asm/entrypoint_resolver_arm32.asm` / `ENTRYPOINT_ARM32` still need writing.

**Files:**
- Create: `asm/entrypoint_resolver_arm64.asm` (**may already exist** — see note above, check before writing)
- Create: `asm/entrypoint_resolver_arm32.asm`
- Modify: `setup.py` (add `assemble_arm64`/`assemble_arm32` calls + `ENTRYPOINT_ARM64`/`ENTRYPOINT_ARM32` constants, include both in the existing `EP_RVA_MAGIC` uniqueness-check loop)
- Modify: `peor/_pe_features.py` (add `_PLATFORM_ARM64 = 'arm64'`, `_PLATFORM_ARM32 = 'arm32'`)
- Modify: `peor/_chain_builder.py` (import the two new constants; add `_SHELLCODES[_PLATFORM_ARM64]` / `_SHELLCODES[_PLATFORM_ARM32]` entries; fix `_select_chain`'s fallback branch to check `features.machine` before `features.pe_type`)
- Create: `tests/01_simple_calc/main.c` — **no change**, only new build platforms in the existing `.vcxproj`
- Modify: `tests/01_simple_calc/01_simple_calc.vcxproj` (add `ARM64` and `ARM` platform configurations)
- Modify: `tests/tests.sln` (add the same two platforms to its configuration list)
- Modify: `tests/pytest/test_shellcode.py` (`ARCH_DIRS` gets `"arm64": TESTS_DIR / "Win_ARM64"`, `"arm32": TESTS_DIR / "Win_ARM32"`; `test_01_simple_calc`'s `@pytest.mark.parametrize("arch", [...])` gains `"arm64", "arm32"`)
- Modify: `tests/build_tests.py` (whatever step currently produces `Win_x86`/`Win_x64` via MSBuild needs the ARM64/ARM platform added to its invocation, or a parallel invocation)

**Interfaces:**
- Consumes: `RELOCS_ARM64`, `RELOCS_ARM32`, `CTORS_RUNNER_ARM64`, `CTORS_RUNNER_ARM32` (existing, unmodified, from `peor/_shellcodes.py`); `_MACHINE_ARM64`, `_MACHINE_ARMNT`, `_MACHINE_ARMTHUMB` (existing, already imported in `_chain_builder.py`); the existing generic `ep_rva_magic`/`EP_RVA_MAGIC` patch logic in `_build_shellcode_chain` (unmodified — already architecture-agnostic).
- Produces: `ENTRYPOINT_ARM64`, `ENTRYPOINT_ARM32` (`bytes` constants in `peor/_shellcodes.py`); `_PLATFORM_ARM64`, `_PLATFORM_ARM32` (string constants in `peor/_pe_features.py`, consumed by every later task that adds a resolver to these two `_SHELLCODES` entries); `tests/Win_ARM64/01_simple_calc.exe`, `tests/Win_ARM32/01_simple_calc.exe` (consumed by Task 1's own test and as the template every later task's bulk-port follows).

- [ ] **Step 1: Verify the MSVC ARM32 desktop toolset is actually installable/present**

On a Windows dev machine (or the `windows-11-arm` runner once Task 10 stands it up), confirm `cl.exe /?` works under an `ARM`-targeted Developer Command Prompt (`vcvarsall.bat x86_arm` or the VS Build Tools ARM component). If it is not available at all in current VS Build Tools, stop and report this to the human partner before writing any ARM32 asm — it changes this task's (and every later ARM32 sub-task's) toolchain, a decision they made explicitly in the spec.

- [ ] **Step 2: Write the failing platform-dispatch test**

```python
def test_select_chain_arm64_not_confused_with_x64():
    # A real ARM64 PE has pe_type == PE32+ (same as x64) but machine == IMAGE_FILE_MACHINE_ARM64.
    features = _detect_pe_features(PE(str(ARCH_DIRS["arm64"] / "01_simple_calc.exe")))
    entry = _select_chain(features)
    assert entry is _SHELLCODES[_PLATFORM_ARM64]

def test_select_chain_arm32_not_confused_with_x86():
    features = _detect_pe_features(PE(str(ARCH_DIRS["arm32"] / "01_simple_calc.exe")))
    entry = _select_chain(features)
    assert entry is _SHELLCODES[_PLATFORM_ARM32]
```
(These need `01_simple_calc.exe` built for both ARM platforms first — do Steps 3-6 before running this.)

- [ ] **Step 3: Add `ARM64`/`ARM` platform configurations to `01_simple_calc.vcxproj` and `tests.sln`, build, confirm MSBuild produces the two new `.exe` files**

Run: `msbuild tests/tests.sln /p:Configuration=Release /p:Platform=ARM64 /t:01_simple_calc` and the `ARM` platform equivalent. Expected: `tests/Win_ARM64/01_simple_calc.exe` and `tests/Win_ARM32/01_simple_calc.exe` exist.

- [ ] **Step 4: Write `asm/entrypoint_resolver_arm64.asm` and `asm/entrypoint_resolver_arm32.asm`**

Same responsibility as `entrypoint_resolver64.asm`/`32.asm`: locate the PE base at runtime (reuse the same self-locating convention `relocations_resolver_arm64.asm`/`arm32.asm` already establish for this codebase — don't invent a second convention), read `AddressOfEntryPoint` via the `EP_RVA_MAGIC` (`0xCECECECE`) placeholder exactly once, jump to `base + EP_RVA_MAGIC` with no arguments (Windows `mainCRTStartup`-style entry takes none — unlike the EFI entrypoint stubs, which pass `ImageHandle`/`SystemTable`).

- [ ] **Step 5: Wire `setup.py`, `_pe_features.py`, `_chain_builder.py`**

In `setup.py`: add the two `assemble_arm64`/`assemble_arm32` calls (alongside the existing ARM64/ARM32 calls, before any x86 `assemble()` call — same ordering constraint the file already documents), add both to the `EP_RVA_MAGIC` uniqueness loop, write `ENTRYPOINT_ARM64`/`ENTRYPOINT_ARM32` into `_shellcodes.py`'s generated output.
In `_pe_features.py`: add `_PLATFORM_ARM64 = 'arm64'`, `_PLATFORM_ARM32 = 'arm32'` next to the existing platform-key constants.
In `_chain_builder.py`: import the two new constants and `ENTRYPOINT_ARM64`, `ENTRYPOINT_ARM32`; add:
```python
_SHELLCODES[_PLATFORM_ARM64] = {
    'relocs': RELOCS_ARM64, 'imports': b'', 'delay_imports': b'',
    'entrypoint': ENTRYPOINT_ARM64, 'seh': b'', 'seh_always': False,
    'tls': b'', 'ctors': CTORS_RUNNER_ARM64,
    'ctors_rva_magic': _CTORS_RVA_MAGIC, 'ctors_size_magic': _CTORS_SIZE_MAGIC,
    'tail': b'', 'dir_array_offset': 112, 'disp64_off': 8, 'ep_rva_magic': _EP_RVA_MAGIC,
}
_SHELLCODES[_PLATFORM_ARM32] = {
    'relocs': RELOCS_ARM32, 'imports': b'', 'delay_imports': b'',
    'entrypoint': ENTRYPOINT_ARM32, 'seh': b'', 'seh_always': False,
    'tls': b'', 'ctors': CTORS_RUNNER_ARM32,
    'ctors_rva_magic': _CTORS_RVA_MAGIC, 'ctors_size_magic': _CTORS_SIZE_MAGIC,
    'tail': b'', 'dir_array_offset': 96, 'disp32_off': 8, 'ep_rva_magic': _EP_RVA_MAGIC,
}
```
(verify `dir_array_offset`/`disp64_off`/`disp32_off` against the actual compiled PEs per the Review Focus note — these values assume ARM64 optional-header layout matches x64's and ARM32 matches x86's; confirm with `pefile` against the real `.exe` before trusting them.) Note: no `'imports'` entry means `_compute_required_stubs`/`_build_shellcode_chain` already skip it (both check `entry.get('imports')` truthiness) — safe placeholder until Task 2.
Then fix `_select_chain`'s fallback:
```python
    if features.machine == _MACHINE_ARM64:
        return _SHELLCODES[_PLATFORM_ARM64]
    if features.machine in (_MACHINE_ARMNT, _MACHINE_ARMTHUMB):
        return _SHELLCODES[_PLATFORM_ARM32]
    entry = _SHELLCODES.get(features.pe_type)
```
placed immediately before that final fallback line, mirroring the structure the EFI branch above it already uses.

- [ ] **Step 6: `pip install -e .` to re-run `_assemble_shellcodes()`, then run the Step 2 tests**

Run: `pytest tests/pytest/test_shellcode.py -k "select_chain_arm" -v`
Expected: PASS.

- [ ] **Step 7: Add `"arm64"`, `"arm32"` to `ARCH_DIRS` and to `test_01_simple_calc`'s parametrize list, run it end-to-end**

Run: `pytest tests/pytest/test_shellcode.py -k "test_01_simple_calc" -v --timeout=60`
Expected: PASS for all four arches (x86, x64, arm64, arm32) — this is the first real shellcode→execute round-trip on ARM, run via the real test loader (`test_loader.exe`, which also needs `ARM64`/`ARM` platforms added to `tests/test_loader/test_loader.vcxproj` as part of this step).

- [ ] **Step 8: Commit**

```bash
git add asm/entrypoint_resolver_arm64.asm asm/entrypoint_resolver_arm32.asm setup.py \
        peor/_pe_features.py peor/_chain_builder.py \
        tests/01_simple_calc/01_simple_calc.vcxproj tests/test_loader/test_loader.vcxproj \
        tests/tests.sln tests/pytest/test_shellcode.py tests/build_tests.py
git commit -m "feat: non-EFI Windows ARM64/ARM32 entrypoint resolver + platform dispatch"
```

## Task 2: Usermode import resolver (ARM64 + ARM32)

**Files:**
- Create: `asm/imports_resolver_arm64.asm`
- Create: `asm/imports_resolver_arm32.asm`
- Modify: `setup.py` (assemble both, add `IMPORTS_ARM64_UM`/`IMPORTS_ARM32_UM` constants)
- Modify: `peor/_chain_builder.py` (`_SHELLCODES[_PLATFORM_ARM64]['imports']`, `[_PLATFORM_ARM32]['imports']`, plus each entry's `'tail'` — the byte sequence stripped so the resolver falls through, same role as `_IMPORTS_TAIL_32`/`_IMPORTS_TAIL_64`)
- Modify: `tests/03_winapi_messagebox/03_winapi_messagebox.vcxproj` (add `ARM64`/`ARM` platforms)
- Modify: `tests/pytest/test_shellcode.py` (`test_03_winapi_messagebox`'s parametrize list gains `"arm64", "arm32"`)

**Interfaces:**
- Consumes: Task 1's `_PLATFORM_ARM64`/`_PLATFORM_ARM32` dict entries, `ENTRYPOINT_ARM64`/`ARM32` chain (unmodified).
- Produces: `IMPORTS_ARM64_UM`, `IMPORTS_ARM32_UM` (consumed by Task 3's delay-load resolver, which mirrors this one's PEB-walk/`GetProcAddress`-equivalent logic for `LoadLibraryA`+`GetProcAddress` lookups).

- [ ] **Step 1: Research the ARM64/ARM32 Windows TEB access convention**

ARM64 Windows: `x18` is the platform register holding the TEB pointer (verify the exact TEB→PEB→Ldr→module-list offsets against a real disassembly or Microsoft's public `ntdll`/`winnt.h` offsets — don't assume x86/x64 offsets translate 1:1). ARM32 Windows: confirm whether TEB is reachable the same way x86 reaches it via `fs:[0x18]`, or via a different mechanism (e.g. `CP15`/coprocessor register, or a documented ABI register) — this is explicitly left to the builder in the spec; resolve it here, before writing the asm.

- [ ] **Step 2: Write `asm/imports_resolver_arm64.asm` and `asm/imports_resolver_arm32.asm`**

Same responsibility as `imports_resolver64.asm`/`32.asm`: walk the PEB's loader module list to find `kernel32.dll` without using any imports of its own, resolve `GetProcAddress`+`LoadLibraryA` by export-table walk, then resolve every `IMAGE_IMPORT_DESCRIPTOR` entry in the target PE. End with the same kind of fall-through tail (a `RET`/`JMP`-equivalent) the x86/x64 versions use, so `_strip_tail` can cut it.

- [ ] **Step 3: Wire `setup.py` + `_chain_builder.py`**

Add the two assemble calls, write `IMPORTS_ARM64_UM`/`IMPORTS_ARM32_UM`, set `_SHELLCODES[_PLATFORM_ARM64]['imports'] = IMPORTS_ARM64_UM` (and ARM32 equivalent), set each entry's `'tail'` to match whatever fall-through sequence Step 2 produced.

- [ ] **Step 4: Add `ARM64`/`ARM` platforms to `03_winapi_messagebox.vcxproj`, build, add to pytest parametrize, run**

Run: `pytest tests/pytest/test_shellcode.py -k "test_03_winapi_messagebox" -v --timeout=60`
Expected: PASS for all four arches — this is the import resolver's first real proof (the test polls for and dismisses a real `MessageBoxA` window, confirming `user32.dll` was actually loaded and called through the resolved import).

- [ ] **Step 5: Commit**

```bash
git add asm/imports_resolver_arm64.asm asm/imports_resolver_arm32.asm setup.py \
        peor/_chain_builder.py tests/03_winapi_messagebox/03_winapi_messagebox.vcxproj \
        tests/pytest/test_shellcode.py
git commit -m "feat: non-EFI Windows ARM64/ARM32 usermode import resolver"
```

## Task 3: Delay-load import resolver (ARM64 + ARM32)

**Files:**
- Create: `asm/imports_resolver_arm64_delayload.asm`
- Create: `asm/imports_resolver_arm32_delayload.asm`
- Modify: `setup.py`, `peor/_chain_builder.py` (`'delay_imports'` key on both ARM entries)
- Modify: `tests/16_delay_load/16_delay_load.vcxproj`, `tests/pytest/test_shellcode.py` (`test_16_delay_load` parametrize)

**Interfaces:**
- Consumes: Task 2's PEB-walk-to-`kernel32`/`LoadLibraryA`/`GetProcAddress` approach (same lookup logic, different descriptor structure: `IMAGE_DELAYLOAD_DESCRIPTOR` instead of `IMAGE_IMPORT_DESCRIPTOR`).
- Produces: `DELAY_IMPORTS_ARM64_UM`, `DELAY_IMPORTS_ARM32_UM`.

- [ ] **Step 1: Write `asm/imports_resolver_arm64_delayload.asm` and `_arm32_delayload.asm`**

Same responsibility as `imports_resolver32_delayload.asm`/`64_delayload.asm`: walk `IMAGE_DELAYLOAD_DESCRIPTOR` entries, resolve via the same `LoadLibraryA`+`GetProcAddress` the main import resolver already found. Expected to need no ARM-specific logic beyond the calling-convention glue Task 2 already worked out.

- [ ] **Step 2: Wire, build, test**

Mirror Task 2 Steps 3-4 exactly, for `16_delay_load` instead of `03_winapi_messagebox`.
Run: `pytest tests/pytest/test_shellcode.py -k "test_16_delay_load" -v --timeout=60`
Expected: PASS for all four arches.

- [ ] **Step 3: Commit**

```bash
git add asm/imports_resolver_arm64_delayload.asm asm/imports_resolver_arm32_delayload.asm \
        setup.py peor/_chain_builder.py tests/16_delay_load/16_delay_load.vcxproj \
        tests/pytest/test_shellcode.py
git commit -m "feat: non-EFI Windows ARM64/ARM32 delay-load import resolver"
```

## Task 4: TLS callback invoker (ARM64 + ARM32)

**Files:**
- Create: `asm/tls_callbacks_arm64.asm`, `asm/tls_callbacks_arm32.asm`
- Modify: `setup.py`, `peor/_chain_builder.py` (`'tls'` key on both ARM entries)
- Modify: `tests/10_tls_callbacks/10_tls_callbacks.vcxproj`, `tests/13_tls_multi_callbacks/13_tls_multi_callbacks.vcxproj`
- Modify: `tests/pytest/test_shellcode.py` (both tests' parametrize lists)

**Interfaces:**
- Consumes: Task 1's chain (no import dependency — TLS callback invocation doesn't need the import resolver to have run first, same as the x86/x64 chain order).
- Produces: `TLS_CALLBACKS_ARM64`, `TLS_CALLBACKS_ARM32`.

- [ ] **Step 1: Write `asm/tls_callbacks_arm64.asm` and `_arm32.asm`**

Same responsibility as `tls_callbacks32.asm`/`64.asm`: read the `IMAGE_TLS_DIRECTORY`'s `AddressOfCallBacks`, walk the null-terminated callback pointer array, call each with `(DllHandle=base, Reason=DLL_PROCESS_ATTACH, Reserved=NULL)`.

- [ ] **Step 2: Wire, build, test**

Mirror Task 2's wiring pattern. Both `10_tls_callbacks` and `13_tls_multi_callbacks` get `ARM64`/`ARM` platforms.
Run: `pytest tests/pytest/test_shellcode.py -k "tls_callbacks" -v --timeout=60`
Expected: PASS for all four arches, both test numbers.

- [ ] **Step 3: Commit**

```bash
git add asm/tls_callbacks_arm64.asm asm/tls_callbacks_arm32.asm setup.py \
        peor/_chain_builder.py tests/10_tls_callbacks tests/13_tls_multi_callbacks \
        tests/pytest/test_shellcode.py
git commit -m "feat: non-EFI Windows ARM64/ARM32 TLS callback invoker"
```

## Task 5: SEH-equivalent exception support (ARM64 + ARM32)

**Files:**
- Create: `asm/seh_registrar_arm64.asm`, `asm/seh_registrar_arm32.asm` **or** no new asm file at all, if research in Step 1 shows the OS already handles table-based unwind from the image's own `.pdata`/`.xdata` without any runtime registration step — rename/skip accordingly, this is explicitly left open in the spec.
- Modify: `setup.py` (if a new asm file exists), `peor/_chain_builder.py` (`'seh'`/`'seh_always'` keys on both ARM entries)
- Modify: `tests/12_seh_exceptions/12_seh_exceptions.vcxproj`, `tests/pytest/test_shellcode.py`

**Interfaces:**
- Consumes: nothing from earlier ARM tasks.
- Produces: `SEH_REGISTRAR_ARM64`/`ARM32` (or confirmation that no runtime stub is needed — either way, this task's finding is what Task 6 checks first for whether C++ EH needs anything analogous).

- [ ] **Step 1: Research whether ARM64/ARM32 Windows need any runtime SEH registration at all**

x86 registers a linked-list `EXCEPTION_REGISTRATION_RECORD` (no image-relative table exists); x64 walks `.pdata`'s `RUNTIME_FUNCTION` table and must register it because the loader normally does that at module-load time and shellcode has no module. ARM64/ARM32 also use `.pdata`/`.xdata` (different encoding than x64's, but the same "loader would normally register this" problem) — determine whether an equivalent runtime registration call (there is a documented API family for this, used by x64's loader-equivalent registration too) is actually required for structured exceptions to work when the image wasn't loaded by the OS loader. Write this finding down in the task's commit message or a one-line code comment, since it is a materially different answer per architecture.

- [ ] **Step 2: Write the test first**

Add `ARM64`/`ARM` platforms to `12_seh_exceptions.vcxproj`; add `"arm64", "arm32"` to `test_12_seh_exceptions`'s parametrize list. Run it before implementing anything new — Expected: FAIL (crash or wrong exit code) with just Tasks 1-4's chain, confirming SEH genuinely needs this task's work.

- [ ] **Step 3: Implement whatever Step 1 found is actually needed**

If registration is needed: write `asm/seh_registrar_arm64.asm`/`arm32.asm` per Step 1's finding, wire into `setup.py`/`_chain_builder.py` the same way every prior task did. If not needed: set `'seh': b''` explicitly (already the default) and document in a code comment why, so a future reader doesn't assume it was simply forgotten.

- [ ] **Step 4: Run test 12, verify PASS**

Run: `pytest tests/pytest/test_shellcode.py -k "test_12_seh_exceptions" -v --timeout=60`
Expected: PASS for all four arches.

- [ ] **Step 5: Commit**

```bash
git add asm/seh_registrar_arm64.asm asm/seh_registrar_arm32.asm setup.py \
        peor/_chain_builder.py tests/12_seh_exceptions tests/pytest/test_shellcode.py
git commit -m "feat: non-EFI Windows ARM64/ARM32 SEH support"
```

## Task 6: C++ exception handling (ARM64 + ARM32)

**Files:**
- Create: `asm/cxx_eh_fixer_arm64.asm` **only if Step 1's research shows it's needed** (x86 has none either — only x64 does, because only x64's C++ runtime references the IAT entry this fixer patches; ARM64/ARM32 may follow either the x86 or the x64 pattern, confirm against real compiled output rather than assuming symmetry with either)
- Modify: `setup.py`, `peor/_chain_builder.py` (`'cxx_eh_fixer'` key, only on whichever ARM entries actually need it)
- Modify: `tests/07_cpp_exceptions/07_cpp_exceptions.vcxproj`, `tests/11_cpp_exceptions/11_cpp_exceptions.vcxproj`, `tests/15_nested_exceptions/15_nested_exceptions.vcxproj`
- Modify: `tests/pytest/test_shellcode.py` (all three tests' parametrize lists)

**Interfaces:**
- Consumes: Task 5's SEH finding (C++ EH on Windows is built on top of the same `.pdata`/`.xdata` unwind machinery SEH uses).
- Produces: `CXX_EH_FIXER_ARM64` if needed.

- [ ] **Step 1: Research whether ARM64/ARM32 MSVC C++ EH needs the IAT fixup `cxx_eh_fixer64.asm` performs for x64**

Compile `tests/07_cpp_exceptions/main.cpp` for ARM64 and ARM32, inspect whether it references `RtlPcToFileHeader` via the IAT the way the x64 build does (`_find_iat_rva(pe, b'RtlPcToFileHeader')` in `_pe_features.py` is how this is detected — run it against the compiled ARM PEs directly to check).

- [ ] **Step 2: Write the tests first (add ARM64/ARM platforms + parametrize), confirm they fail without this task's code**

Run: `pytest tests/pytest/test_shellcode.py -k "cpp_exceptions or nested_exceptions" -v --timeout=60`
Expected: FAIL on arm64/arm32 (wrong exit code or crash) before Step 3.

- [ ] **Step 3: Implement per Step 1's finding**

If needed, write `asm/cxx_eh_fixer_arm64.asm` following `cxx_eh_fixer64.asm`'s approach (patch the C++ runtime's IAT-resolved helper to point at `RtlPcToFileHeader`'s runtime address instead of the unresolved IAT stub) and wire it the same way Task 5 wired `seh_registrar`. If not needed on either ARM arch, document why in a code comment, same as Task 5 Step 3's fallback.

- [ ] **Step 4: Run all three cpp-exception tests, verify PASS**

Run: `pytest tests/pytest/test_shellcode.py -k "cpp_exceptions or nested_exceptions" -v --timeout=60`
Expected: PASS for all four arches, all three test numbers.

- [ ] **Step 5: Commit**

```bash
git add asm/cxx_eh_fixer_arm64.asm setup.py peor/_chain_builder.py \
        tests/07_cpp_exceptions tests/11_cpp_exceptions tests/15_nested_exceptions \
        tests/pytest/test_shellcode.py
git commit -m "feat: non-EFI Windows ARM64/ARM32 C++ exception handling"
```

## Task 7: Ctors runner confirmation (ARM64 + ARM32)

**Files:**
- Modify: `tests/14_global_ctors/14_global_ctors.vcxproj`, `tests/pytest/test_shellcode.py`

**Interfaces:**
- Consumes: `CTORS_RUNNER_ARM64`/`ARM32` (already assembled, already wired into both `_SHELLCODES` entries in Task 1 — no new asm or python wiring expected in this task).
- Produces: nothing new — this task is pure verification that the EFI-built ctors runner genuinely works unchanged for non-EFI Windows PEs too.

- [ ] **Step 1: Add `ARM64`/`ARM` platforms to `14_global_ctors.vcxproj`, add to pytest parametrize, run**

Run: `pytest tests/pytest/test_shellcode.py -k "test_14_global_ctors" -v --timeout=60`
Expected: PASS for all four arches with zero code changes, confirming the reuse assumption from the spec. If it fails, the ctors runner's RVA/size magic patching (shared with the EFI chain) has an undiscovered Windows-PE-specific assumption — investigate before moving on, don't paper over it.

- [ ] **Step 2: Commit**

```bash
git add tests/14_global_ctors/14_global_ctors.vcxproj tests/pytest/test_shellcode.py
git commit -m "test: confirm ctors runner works unchanged for non-EFI Windows ARM64/ARM32"
```

## Task 8: Bulk-port the remaining straightforward tests

**Files:**
- Modify: `tests/02_relocs_functions/`, `04_crt_printf_rand/`, `05_dll_entry/`, `06_stripped_relocs/`, `08_cpp_thread/`, `09_resources/`, `18_bss_gap/`, `19_ordinal_imports/` (+ `ordinal_helper.vcxproj`), `20_forwarded_exports/` (+ `forwarded_helper.vcxproj`), `21_api_sets/` — each `.vcxproj` gets `ARM64`/`ARM` platforms
- Modify: `tests/pytest/test_shellcode.py` — each of these tests' `parametrize("arch", ...)` gains `"arm64", "arm32"`

**Interfaces:**
- Consumes: every resolver from Tasks 1-7 (these tests combine existing features — relocs+entrypoint+imports+ctors+bss handling — rather than exercising anything new).
- Produces: nothing new — terminal verification task before CI wiring.

- [ ] **Step 1: Add platforms, build, run each in turn**

For each test number, add the platforms, build (`msbuild ... /p:Platform=ARM64` and `/p:Platform=ARM`), add to pytest, run that one test alone first (`-k "test_NN_..."`) before moving to the next — isolates which specific test exposes a gap in Tasks 1-7's resolvers, rather than discovering ten failures at once.

Expected per test: PASS for all four arches, OR a specific, attributable failure that sends you back to whichever Task 1-7 resolver is actually responsible (e.g. `19_ordinal_imports` failing points at the import resolver's ordinal-lookup path, not at anything new in this task).

- [ ] **Step 2: Run the full non-EFI suite together, confirm nothing regressed**

Run: `pytest tests/pytest/ -v --timeout=60 -k "not linux and not efi"`
Expected: PASS, x86/x64/arm64/arm32 all green.

- [ ] **Step 3: Commit**

```bash
git add tests/02_relocs_functions tests/04_crt_printf_rand tests/05_dll_entry \
        tests/06_stripped_relocs tests/08_cpp_thread tests/09_resources tests/18_bss_gap \
        tests/19_ordinal_imports tests/20_forwarded_exports tests/21_api_sets \
        tests/pytest/test_shellcode.py
git commit -m "test: port remaining Windows x64/x86 test cases to ARM64/ARM32"
```

## Task 9: Test 17 (mingw C++ exceptions) on ARM64 + ARM32

**Files:**
- Modify: `tests/Windows/17_mingw_cpp_exceptions/` (or wherever its source lives — confirm exact path first; it's built outside the `.vcxproj`/MSBuild flow per `test.yml`)
- Modify: `tests/pytest/test_shellcode.py` (its test function's parametrize list)

**Interfaces:**
- Consumes: the same llvm-mingw/clang toolchain `_find_clang_arm64_wsl`/`_find_clang_arm32_wsl` already use for the EFI-ARM tests (reuse, don't reinvent).
- Produces: nothing consumed elsewhere — this is the one test case in the whole suite that deliberately exercises a different C++ ABI/EH model (GNU, not MSVC) than every other task in this plan.

- [ ] **Step 1: Confirm llvm-mingw can target a Windows (not EFI) subsystem for ARM64/ARM32**

The existing EFI-ARM compile helpers (`_compile_efi_pe_arm64`/`arm32`) pass `-Wl,--subsystem=efi_application`; this test needs the normal console/GUI Windows subsystem instead. Verify the same clang+lld invocation works with `-Wl,--subsystem=console` (or whatever `17_mingw_cpp_exceptions` actually targets on x64/x86 today — check its current MSYS2 build step in `test.yml` for the exact flags to mirror).

- [ ] **Step 2: Build and add to pytest, run**

Add `"arm64", "arm32"` to its parametrize list (and `ARCH_DIRS` already covers the output directories from Task 1).
Run: `pytest tests/pytest/test_shellcode.py -k "mingw" -v --timeout=60`
Expected: PASS for all four arches, same `MINGW_CPP_EH_RETURN_CODE = 42` the x64/x86 variant already checks.

- [ ] **Step 3: Commit**

```bash
git add tests/Windows/17_mingw_cpp_exceptions tests/pytest/test_shellcode.py
git commit -m "test: port mingw C++ exceptions test (17) to ARM64/ARM32 via llvm-mingw"
```

## Task 10: CI wiring on `windows-11-arm`

**Files:**
- Modify: `.github/workflows/test.yml` (new `build-windows-arm`, `test-windows-arm` jobs, mirroring `build-windows`/`test-windows`'s structure but `runs-on: windows-11-arm`, MSVC ARM64/ARM platform builds, plus an llvm-mingw install step for Task 9's test 17; add both new jobs to `test-summary`'s `needs:`)
- Modify: `tests/pytest/test_shellcode.py` (rename `_EFI_PREBUILT_ARM64`/`_EFI_PREBUILT_ARM32` constants and their `Win_ARM64`/`Win_ARM32` paths to `Win_ARM64_EFI`/`Win_ARM32_EFI`)
- Modify: `tests/build_tests.py` (same rename, wherever it references the EFI ARM prebuilt dirs)
- Rename directory: `tests/Win_ARM64/` → `tests/Win_ARM64_EFI/`, `tests/Win_ARM32/` → `tests/Win_ARM32_EFI/` (the EFI `.efi` files already in there use distinct filenames from the non-EFI `.exe` files Tasks 1-9 add to the plain `Win_ARM64`/`Win_ARM32` dirs — e.g. `01_efi_hello.efi` vs. `01_simple_calc.exe` — so there's no filename collision either way; this rename is a naming-convention cleanup, not a correctness fix, and can run before or after Tasks 1-9 without breaking either)

**Interfaces:**
- Consumes: every task's test ports (this job just needs to build and run what already works locally).
- Produces: nothing further in this plan.

- [ ] **Step 1: Rename the EFI-ARM prebuilt directories and update their references**

`git mv tests/Win_ARM64 tests/Win_ARM64_EFI` and the ARM32 equivalent; update `_EFI_PREBUILT_ARM64`/`_EFI_PREBUILT_ARM32` in `test_shellcode.py` and the matching paths in `build_tests.py`. Run the existing EFI test suite locally/in CI to confirm nothing broke: `pytest tests/pytest -v -k "efi and (arm64 or arm32)"`.

- [ ] **Step 2: Add `build-windows-arm` job**

Mirror `build-windows`'s structure: checkout, Python setup, `pip install -e .`, MSBuild with `/p:Platform=ARM64` and `/p:Platform=ARM` for Release, plus whatever Task 9 needs for llvm-mingw's test 17. Cache and upload the resulting `tests/Win_ARM64`/`tests/Win_ARM32` binaries as artifacts, same pattern as `build-windows`.

- [ ] **Step 3: Add `test-windows-arm` job**

Mirror `test-windows`'s structure, `runs-on: windows-11-arm`, downloads the Task 2 artifacts, installs llvm-mingw (for test 17 only), runs:
```yaml
      - run: pytest tests/pytest/ -v --timeout=60 -k "not linux and not efi and (arm64 or arm32)"
```

- [ ] **Step 4: Add both new jobs to `test-summary`'s `needs:` list**

- [ ] **Step 5: Push and verify green on the real runner, fixing whatever install-step specifics the first real run exposes**

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/test.yml tests/pytest/test_shellcode.py tests/build_tests.py \
        tests/Win_ARM64_EFI tests/Win_ARM32_EFI
git commit -m "ci: build and test non-EFI Windows ARM64/ARM32 on windows-11-arm"
```

## Task 11: Documentation

**Files:**
- Modify: `README.md` (document ARM64/ARM32 as supported Windows architectures, same table/prose style as the existing x64/x86/EFI sections)
- Modify: `PLAN.md` (remove the "FULL ARM32 / ARM64 support" deferred section entirely, per its own standing rule)

**Interfaces:** none — pure documentation, no code consumed or produced.

- [ ] **Step 1: Update `README.md`**

Add ARM64/ARM32 to the platform-detection table and the "How It Works" architecture notes wherever x64/x86 are currently listed, following the existing prose style exactly.

- [ ] **Step 2: Remove the completed section from `PLAN.md`**

Delete the "### FULL ARM32 / ARM64 support" block under "Future TODOs — Deferred (explicitly blocked)" — it's no longer deferred or blocked.

- [ ] **Step 3: Commit**

```bash
git add README.md PLAN.md
git commit -m "docs: document Windows ARM64/ARM32 support, remove completed PLAN.md item"
```
