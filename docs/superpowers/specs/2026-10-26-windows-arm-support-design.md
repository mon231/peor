# Windows ARM32/ARM64 PE Support — Design

## Intent & why

PEOR converts a PE file into position-independent shellcode by chaining
asm stubs (imports, relocs, delay-load, C++ EH fixup, SEH registration, TLS
callbacks, ctors, entrypoint dispatch) ahead of a memory-mapped copy of the
PE image. Today that chain exists for:

- Windows x86 / x64 (full chain)
- Linux x86 / x64 (imports via `dlopen`/`dlsym`, relocs, ctors, no EH/TLS/SEH)
- EFI x86 / x64 / ARM32 / ARM64 (relocs, ctors, EFI entrypoint dispatcher —
  no import resolver, because EFI apps don't use the Windows loader)

`PLAN.md` has carried a deferred TODO for real (non-EFI) Windows ARM32/ARM64
support since before this session: a Windows PE compiled for ARM is a
normal subsystem-2/3 PE like x64/x86, but PEOR has no PEB-walk import
resolver, entrypoint dispatcher, TLS callback stub, delay-load resolver, or
SEH-equivalent for ARM. This was explicitly blocked waiting for a usable
ARM dev/test environment — GitHub now offers a free-tier, hosted
`windows-11-arm` runner, which removes that blocker.

This design also covers a smaller, independent prerequisite: running the
*existing* EFI-ARM32/64 tests (which already pass under QEMU emulation on
`ubuntu-latest`) on real ARM64 hardware via that same runner, for
higher-confidence signal before building on top of it.

## Goals

1. Add a CI job that runs the existing EFI ARM32/ARM64 test suite on the
   real `windows-11-arm` GitHub-hosted runner (in addition to the existing
   QEMU-emulated job on `ubuntu-latest` — not a replacement).
2. Implement a full, non-EFI Windows PE shellcode chain for both ARM64 and
   ARM32, at feature parity with the existing x64/x86 chain:
   - PEB-walk import resolver (usermode)
   - delay-load import resolver
   - base relocation resolver (**already exists**: `RELOCS_ARM64` /
     `RELOCS_ARM32` in `_shellcodes.py` — reuse as-is, format is identical
     between EFI and Windows PE base relocations)
   - ctors/`.init_array` runner (**already exists**: `CTORS_RUNNER_ARM64` /
     `CTORS_RUNNER_ARM32` — reuse as-is)
   - entrypoint dispatcher (new — the EFI ARM entrypoint stubs call
     `efi_main(ImageHandle, SystemTable)`; Windows entry has a different
     calling convention and must support `--entry <export>` the same way
     `ENTRYPOINT_32/64` do)
   - TLS callback invoker (new)
   - SEH-equivalent exception registration (new — ARM64/ARM32 use a
     table-based unwind model (`.pdata`/`.xdata`), not x86's linked
     `EXCEPTION_REGISTRATION_RECORD` chain or x64's `RUNTIME_FUNCTION`
     table walk verbatim; exact handling is a builder decision, see below)
   - C++ EH IAT fixer, only if ARM64/ARM32 actually need the x64-style fixup
     (builder to confirm against real compiled output; may not apply)
3. Port the existing numbered test matrix (currently 01–21) to ARM64 and
   ARM32: full parity means every test case that has a Windows x64/x86
   variant today gets ARM64 + ARM32 variants, following the one-folder-
   per-test / `#ifdef`-by-arch convention already used for EFI and Linux.
4. Wire the new resolvers into `_shellcodes.py` / `_chain_builder.py` /
   `_pe_features.py` platform detection, so `peor -i foo.exe` auto-detects
   `IMAGE_FILE_MACHINE_ARM64` (`0xAA64`) / `IMAGE_FILE_MACHINE_ARMNT`
   (`0x01C4`) the same way it already auto-detects x64/x86/EFI today.
5. Build and run the new ARM test binaries on the `windows-11-arm` runner
   in CI, following the existing build→cache→test job split pattern in
   `.github/workflows/test.yml`.

## Non-goals

- Windows kernel-mode ARM support (kernel mode entirely is already a
  separate, still-blocked PLAN.md item for x64/x86; ARM kernel mode is out
  of scope here too).
- Changing how the existing x64/x86/Linux/EFI chains work.
- Replacing the QEMU-emulated EFI-ARM CI job — the new real-hardware job is
  additive.

## Anti-goals (would make this a failure even if "technically working")

- Any test silently skipped locally or in CI because an ARM toolchain
  piece was missing (CONTRIBUTING.md rule: no skips, ever).
- Magic numbers in new asm/python (must use named constants, same as the
  rest of the codebase: `IMAGE_FILE_MACHINE_ARM64`, not `0xAA64` inline).
- New per-architecture test folders (`tests/ARM64/`, `tests/ARM32/`) —
  must follow the existing single-folder-plus-`#ifdef` convention.

## Constraints

- Every CONTRIBUTING.md convention applies: named constants, hex literals,
  one responsibility per asm file, asm usage inferred from PE headers,
  README.md updated per feature, distinctive non-trivial test return codes
  (not 0/1/-1), both-arch tests wherever possible, no C stub/placeholder
  functions, build/test/deploy CI stages kept separate.
- All tests must pass locally and in CI — no skips (CLAUDE.md + PLAN.md,
  repeated emphatically in both).
- Background processes (including any local QEMU/VM run while developing)
  capped at 50 minutes runtime.
- `tests/Win_ARM32/` and `tests/Win_ARM64/` are **currently** the prebuilt
  EFI ARM32/64 `.efi` binaries. The naming convention elsewhere is
  `Win_x64` (plain Windows PE) vs. `Win_x64_EFI` (EFI). To stay consistent,
  this work renames the existing dirs to `Win_ARM32_EFI` / `Win_ARM64_EFI`
  and uses the now-free `Win_ARM32` / `Win_ARM64` names for the new,
  non-EFI Windows ARM test binaries. (Mirrors `tests/pytest/test_shellcode.py`
  constants `_EFI_PREBUILT_ARM64` / `_EFI_PREBUILT_ARM32`, which get
  renamed to match.)

## Decisions already made (yours — recorded here, not open)

- **Arch scope**: both ARM64 and ARM32 (not ARM64-only).
- **Test depth**: full parity with the x64/x86 suite — not just the
  happy-path relocs+imports+entrypoint subset. TLS, C++ EH, SEH-equivalent,
  delay-load, and ctors tests all get ARM32/64 variants.
- **Build toolchain for the new Windows ARM test `.exe`/`.dll` binaries**:
  MSVC (`cl.exe`) via Visual Studio Build Tools, matching how the existing
  x64/x86 `.vcxproj` suite builds (MSBuild), rather than clang-cl/MinGW
  (which is what the EFI-ARM tests use today, since EFI needs a GNU-style
  target triple clang supports and MSVC doesn't do EFI).
  - **Known risk, flagged for the builder**: MSVC's ARM32 **desktop**
    (Win32, non-UWP) compiler target has been removed from newer Visual
    Studio Build Tools versions — only ARM64 and ARM64EC are consistently
    available in current installers. The builder must verify, early,
    whether `windows-11-arm`'s preinstalled or installable VS Build Tools
    offer an ARM32 desktop target at all. If it does not, ARM32 test
    binaries fall back to clang-cl with the Windows SDK (not the
    `armv7-w64-mingw32` GNU target used for EFI) — this is a deviation
    from the decision above and must be called out explicitly (to the
    human partner, not silently) if it happens, since it changes a
    decision they made.
- **CI runner**: `windows-11-arm` (GitHub-hosted, free tier, public
  preview GA) for both the EFI-ARM real-hardware job and the new
  non-EFI Windows ARM build+test jobs. **Verified**: `mon231/peor` is a
  public repo, so free-tier `windows-11-arm` minutes apply — no infra
  fallback needed.
- **Test 17 (`17_mingw_cpp_exceptions`) on ARM**: the existing MSVC-only
  toolchain decision above does not cover it — test 17 is deliberately
  built via MinGW (MSYS2 on x64/x86 today), not MSBuild/MSVC, to exercise
  GNU-ABI C++ EH. Real mingw-w64 has no ARM Windows target; the only
  toolchain that produces a MinGW-ABI PE for Windows-on-ARM is
  **llvm-mingw** (clang+lld, `aarch64-w64-mingw32` / `armv7-w64-mingw32`
  triples) — the same toolchain already installed for the EFI-ARM tests.
  Decision: install llvm-mingw/clang **alongside** MSVC Build Tools on the
  `windows-11-arm` runner, used only for test 17's ARM64/ARM32 variants,
  mirroring how `test.yml` already runs MSYS2 MinGW as a separate step
  from MSBuild for x64/x86. Every other ported test (01–16, 18–21) still
  builds via MSVC/MSBuild.
- **CI gate**: the new `windows-11-arm` jobs (EFI-ARM real-hardware,
  non-EFI ARM build+test) are added to `test-summary`'s required `needs:`
  list, same as every other job — full "no skip, ever" enforcement, no
  exception for the new runner type being in public preview.

## What's left to the builder

- Exact ARM64/ARM32 PEB-walk offsets and register conventions for the
  import resolver (ARM64 Windows: `x18` is the platform-reserved TEB
  register; ARM32 Windows: TEB is at `TPIDRURW`/via a different mechanism
  than x86's `fs:[0x18]` — must be verified against real Windows ARM
  behavior, not assumed from x86/x64 by analogy).
- Whether ARM64/ARM32 need an equivalent of `cxx_eh_fixer64.asm` (x64-only
  today) — determine from how MSVC actually emits the C++ EH IAT reference
  on ARM, if at all.
- The SEH-equivalent design for ARM64/ARM32 (table-based `.pdata`/`.xdata`
  unwind, no linked-list registration like x86, no direct
  `RUNTIME_FUNCTION` walk-and-register like x64's current approach) —
  research what, if anything, actually needs runtime registration vs. what
  the OS already handles from the image's own exception directory.
- Whether delay-load resolution differs in any ARM-specific way from the
  existing x64/x86 `imports_resolver{32,64}_delayload.asm` logic (expected:
  no, same `IMAGE_DELAYLOAD_DESCRIPTOR` structure, different calling-
  convention glue only).
- Exact CI steps to install/verify an MSVC ARM64/ARM32 desktop toolset on
  `windows-11-arm` (choco/vs_buildtools.exe component IDs), and to install
  or vendor `qemu-system-aarch64`/`qemu-system-arm` + ARM OVMF firmware for
  the real-hardware EFI job (likely simpler there since the goal is just
  "run natively, not emulated on an x64 host" for the already-existing
  tests — check if ARM64 Windows hosts can run `qemu-system-aarch64` with
  hardware acceleration (WHPX/Hyper-V) rather than TCG, which is the actual
  point of this job).
- New test numbering continues from the existing max (21 →  22+) for any
  genuinely new test case; ports of existing 01–21 to ARM reuse the same
  number (new arch variant of an existing folder), per the existing
  Linux/EFI pattern.
- Return codes for new tests: pick distinctive values not already used by
  sibling tests in the same numbered folder (check `test_shellcode.py`
  before picking).
