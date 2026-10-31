# Linux ARM64/ARM32 PE Shellcode Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend peor's existing Linux usermode PE-shellcode chain (currently x86/x64 only — resolves PE imports via `dlopen`/`dlsym` instead of the Windows loader, since the shellcode runs raw on Linux) to ARM64 and ARM32.

**Architecture:** One new import-resolver asm file per arch (`imports_resolver_arm64_linux.asm`, `imports_resolver_arm32_linux.asm`), reusing the exact algorithm `asm/imports_resolver64_linux.asm` already implements (parse `/proc/self/maps` for `libc.so`, walk its ELF `PT_DYNAMIC`/symtab for `dlopen`/`dlsym`, then walk the PE `IMAGE_IMPORT_DESCRIPTOR` table calling them) — only the raw syscall numbers, ELF32-vs-ELF64 struct offsets (ARM32 only), and the AArch64/ARM32 calling convention change. Relocations and ctors already have working ARM64/ARM32 stubs (`relocations_resolver_arm{64,32}.asm`, `ctors_runner_arm{64,32}.asm`) reused as-is — this plan touches only the import resolver and platform wiring. No new CI job needed to validate ARM64 (free-tier `ubuntu-24.04-arm` hosted runner, native, no emulation); ARM32 validates via `qemu-arm-static` (user-mode emulation of a single binary, not a VM boot — much simpler than the EFI-ARM full-system QEMU path this session is separately debugging).

**Tech Stack:** Keystone-engine (`KS_ARCH_ARM64` / `KS_ARCH_ARM` + `KS_MODE_THUMB`, same as the existing EFI ARM stubs), pytest, GitHub Actions (`ubuntu-24.04-arm`, `ubuntu-latest` + `qemu-user-static`).

**Spec:** No separate design doc — this plan is scoped directly from the existing Linux x86/x64 implementation (`asm/imports_resolver64_linux.asm`, `asm/imports_resolver32_linux.asm`) and the existing ARM64/ARM32 EFI/relocs/ctors stubs, per explicit instruction to proceed without a separate brainstorming round (2026-10-27).

## Global Constraints

- No test may be skipped locally or in CI (CONTRIBUTING.md / CLAUDE.md / PLAN.md) — if a syscall/ABI detail can't be confirmed, keep researching, never skip.
- Named constants only, hex literals, one responsibility per asm file (CONTRIBUTING.md).
- Both-arch tests wherever possible — here that means ARM64 **and** ARM32 variants of every ported test, same as the x64/x86 pair today.
- Single test folder per case across archs (`tests/Linux/01_linux_write/`, not a new `tests/Linux_ARM64/` source tree) — same convention already used for `tests/Linux_x64`/`tests/Linux_x86` prebuilt-binary output dirs vs. the single `tests/Linux/` source tree. New prebuilt dirs: `tests/Linux_arm64/`, `tests/Linux_arm32/`.
- Distinctive non-trivial return codes for any new test (not 0/1/-1).
- Small, understandable commits. Commit+push directly to this plan's branch is authorized once CI is believed to work (same scoped exception already granted for the EFI-ARM CI plan, extended here by explicit user instruction to "fan out subagents" on ARM support work, 2026-10-27).
- Background processes capped at 50 minutes.
- Branch: a new branch off `arm_support` (not `arm_support-ci-spike`, which is a separate throwaway branch for the unrelated EFI-ARM CI debugging happening in parallel) — propose `arm_support-linux-arm`.

## Review Focus

- **Wrong syscall numbers**: ARM64 and ARM32 Linux have *different* syscall tables from each other and from x86_64 (e.g. x86_64 `openat`=0x101, ARM64 `openat`=0x38, ARM32 `openat`=0x142). A copy-paste of the x86_64 resolver's `%define SYS_*` values onto ARM is the single most likely silent-wrong-answer bug — every syscall number must be looked up for the specific arch, not inherited.
- **ELF32 vs ELF64 struct offsets (ARM32 only)**: `Elf32_Ehdr`/`Elf32_Phdr`/`Elf32_Dyn`/`Elf32_Sym` offsets and sizes differ from the 64-bit ones the x64 resolver hardcodes (e.g. `e_phoff` is `0x1C` not `0x20`, `Elf32_Sym` is 16 bytes not 24). Reusing the 64-bit `%define`s unmodified on ARM32 corrupts every subsequent read.
- **PE-base self-location mechanism mismatch**: `asm/imports_resolver64_linux.asm` finds its own position via the `call`/`pop` trick, then scans *forward* in memory for the next MZ/PE signature — it does NOT rely on a chain-convention register. `asm/relocations_resolver_arm64.asm`, by contrast, computes PE base via a keystone-patched literal pool (`adr` + `PE_OFFSET` patched by `setup.py`) into `x19`/the ARM32 equivalent. The import resolver runs *before* relocs in the chain (see `peor/_chain_builder.py`'s `_build_shellcode_chain` concatenation order — verify, don't assume), so it cannot assume `x19` is already set. Confirm empirically which mechanism is correct for the ARM Linux resolver (most likely: same forward-scan-from-self technique as the x64/x86 Linux resolver, since that's arch-agnostic and needs no `setup.py` patching changes) before writing the stub, and say which one was used and why in the implementation report.
- **`_select_chain`'s existing latent bug extends to Linux too**: today `_select_chain(features, _PLATFORM_LINUX)` picks `_PLATFORM_LINUX_32`/`_PLATFORM_LINUX` purely from `features.pe_type` (PE32 vs PE32+), with no machine-type check — exactly the same bug already flagged for the non-EFI Windows chain in `docs/superpowers/specs/2026-10-26-windows-arm-support-design.md`. A real ARM64 Linux PE (PE32+, same `pe_type` as x64) or ARM32 Linux PE (PE32, same `pe_type` as x86) would silently get the x64/x86 Linux chain instead of the new ARM one. Must add `features.machine` checks exactly as Task 1 does for the non-EFI Windows chain.
- **`qemu-arm-static` vs. true hardware for ARM32**: there is no free-tier *32-bit* ARM Linux GitHub-hosted runner, hosted or otherwise — only `ubuntu-24.04-arm` (AArch64). ARM32 Linux tests must run via `qemu-arm-static` user-mode emulation of the single test binary (works on either `ubuntu-latest` or `ubuntu-24.04-arm` as host) — confirm this is installed/available (`apt-get install qemu-user-static` or similar) rather than assuming it's preinstalled, and confirm it's genuinely emulating ARM32 instructions correctly (not just failing to exec and reporting a misleading error) by testing against a trivial known-good ARM32 ELF first.

---

## Task 1: ARM64 Linux import resolver + platform wiring + test 01 port

**Files:**
- Create: `asm/imports_resolver_arm64_linux.asm`
- Modify: `setup.py` (assemble the new file into `IMPORTS_ARM64_LINUX`, exported into `peor/_shellcodes.py` — follow the exact pattern already used for `IMPORTS_64_LINUX`; remember the file's documented ordering constraint: all ARM64/ARM32 `assemble_arm64()`/`assemble_arm32()` calls must happen **before** any x86 `assemble()` call, since setting `KS_OPT_SYNTAX_NASM` for x86 permanently poisons keystone's ARM state)
- Modify: `peor/_pe_features.py` (add `_PLATFORM_LINUX_ARM64 = 'linux_arm64'`)
- Modify: `peor/_chain_builder.py` (add a `_SHELLCODES[_PLATFORM_LINUX_ARM64]` entry — reuse `RELOCS_ARM64`/`CTORS_RUNNER_ARM64` already imported for the EFI ARM64 entry, same `ctors_rva_magic`/`ctors_size_magic`/`ep_rva_magic` as every other entry; fix `_select_chain`'s Linux branch to check `features.machine == _MACHINE_ARM64` before falling back to the `pe_type`-only check, mirroring how the EFI branch already does this)
- Test: `tests/pytest/test_shellcode.py` (extend `test_01_linux_write`'s `@pytest.mark.parametrize("arch", [...])` to include `"arm64"`)
- Create: `tests/Linux_arm64/` (new prebuilt-binary output dir, parallel to `tests/Linux_x64/`)

**Interfaces:**
- Consumes: `RELOCS_ARM64`, `CTORS_RUNNER_ARM64` (already in `peor/_shellcodes.py`, unchanged).
- Produces: `IMPORTS_ARM64_LINUX` (bytes constant in `peor/_shellcodes.py`), `_PLATFORM_LINUX_ARM64` (string constant in `peor/_pe_features.py`) — both consumed by Task 3's CI wiring and by any later test-porting work, not otherwise by Task 2 (ARM32 is a fully independent file/constant pair).

- [ ] **Step 1: Research the exact ARM64 Linux syscall numbers and self-location mechanism**

Confirm (do not assume): `openat`=`0x38`, `read`=`0x3F`, `close`=`0x39` (AArch64 Linux syscall table — verify against an authoritative source, e.g. `asm-generic/unistd.h`, before using). Confirm whether the import resolver should self-locate the PE base via the same forward-MZ/PE-scan technique `imports_resolver64_linux.asm` uses (likely correct — it runs before relocs in the chain, see Review Focus above) or must set up `x19` via a patched literal pool like `relocations_resolver_arm64.asm` does. Record the decision and why in a comment at the top of the new file, same style as the existing file's header comment block.

- [ ] **Step 2: Write `asm/imports_resolver_arm64_linux.asm`**

Port `asm/imports_resolver64_linux.asm`'s algorithm line-for-line in structure (open `/proc/self/maps` → read → close → scan for `libc.so` → parse base → walk `PT_DYNAMIC` → find `dlopen`/`dlsym` via symtab/strtab → walk `IMAGE_IMPORT_DESCRIPTOR` calling them) but in AArch64 assembly: syscalls via `svc #0` with the syscall number in `x8` and args in `x0`-`x5` (not `rax`/`rdi`/`rsi`/`rdx`/`r10`/`syscall`), string embedding via `adr`/literal-pool (keystone ARM64 mode, not the x86 `call`/`pop` trick — `relocations_resolver_arm64.asm` shows the pattern), callee-saved registers per AAPCS64 (`x19`-`x28`) for anything that must survive a `dlsym` call. ELF64 struct offsets are identical to the x64 file's (`ELF64_EHDR_PHOFF` etc.) since Linux ARM64 is also a 64-bit ELF target — reuse those `%define` values unchanged.

- [ ] **Step 3: Add `setup.py` assembly + export**

Add an `assemble_arm64()` call for the new file (placed with the other ARM64 assembly calls, before any x86 `assemble()` call per the file's documented ordering constraint) producing `IMPORTS_ARM64_LINUX`, and add it to the `SHELLCODES_PY.write_text(...)` constants list.

- [ ] **Step 4: Wire `_pe_features.py` / `_chain_builder.py`**

Add `_PLATFORM_LINUX_ARM64 = 'linux_arm64'` to `peor/_pe_features.py`. Add a `_SHELLCODES[_PLATFORM_LINUX_ARM64]` entry to `peor/_chain_builder.py` mirroring the existing `_PLATFORM_LINUX` entry's shape (`relocs: RELOCS_ARM64`, `imports: IMPORTS_ARM64_LINUX`, `ctors: CTORS_RUNNER_ARM64`, `seh`/`tls`/`delay_imports`: `b''`, same `ctors_rva_magic`/`ctors_size_magic`/`ep_rva_magic` constants every entry uses). Fix `_select_chain`'s `if platform == _PLATFORM_LINUX:` branch to check `features.machine == _MACHINE_ARM64` (returning the new entry) before its existing `pe_type`-only fallback.

- [ ] **Step 5: Run the existing test suite to confirm no regression**

Run: `pytest tests/pytest -v`
Expected: all currently-passing tests still pass (ARM64 Linux test not yet added to parametrize list, or added but still failing until Step 6/7 — note which).

- [ ] **Step 6: Cross-compile an ARM64 PE variant of test 01 and port the pytest case**

`tests/Linux/01_linux_write/main.c` already exists (shared source, used via `#ifdef`/arch-neutral C — confirm it needs no arch-specific changes, it's calling `write()` which is arch-agnostic). Cross-compile it for ARM64 the same way the x64/x86 variants are built (check `_build_linux_write_pe`'s compiler invocation in `test_shellcode.py` for the exact mingw/clang target triple pattern used, and the subsystem=posix flag that makes peor auto-select the Linux chain) producing `tests/Linux_arm64/01_linux_write_arm64.pe`. Add `"arm64"` to `test_01_linux_write`'s parametrize list, with the ARM64-specific loader path (new `test_loader_linux_arm64.pe`, cross-compiled the same way the existing x64/x86 loaders are, or confirmed reusable if the loader itself is already arch-neutral — check `_ensure_linux_loader`).

- [ ] **Step 7: Run and verify test_01_linux_write[arm64] passes**

Run: `pytest tests/pytest/test_shellcode.py::test_01_linux_write -v -k arm64`
Expected: PASS, stdout contains `PEOR\n` (same assertion the x64/x86 variants use).

- [ ] **Step 8: Commit**

```bash
git add asm/imports_resolver_arm64_linux.asm setup.py peor/_pe_features.py peor/_chain_builder.py tests/pytest/test_shellcode.py tests/Linux_arm64/
git commit -m "feat: add ARM64 Linux import resolver, wire into chain builder, port test 01"
```

## Task 2: ARM32 Linux import resolver + platform wiring + test 01 port

**Files:**
- Create: `asm/imports_resolver_arm32_linux.asm`
- Modify: `setup.py`, `peor/_pe_features.py` (`_PLATFORM_LINUX_ARM32 = 'linux_arm32'`), `peor/_chain_builder.py`, `tests/pytest/test_shellcode.py`
- Create: `tests/Linux_arm32/`

**Interfaces:**
- Consumes: `RELOCS_ARM32`, `CTORS_RUNNER_ARM32` (already in `peor/_shellcodes.py`, unchanged).
- Produces: `IMPORTS_ARM32_LINUX`, `_PLATFORM_LINUX_ARM32` — independent of Task 1's ARM64 constants (different file, different dict key), but both tasks touch the **same** three shared files (`setup.py`, `peor/_pe_features.py`, `peor/_chain_builder.py`) — dispatch sequentially after Task 1 lands, never in parallel with it, to avoid merge conflicts on those files.

- [ ] **Step 1: Research the exact ARM32 (EABI) Linux syscall numbers, ELF32 struct offsets, and self-location mechanism**

Confirm: `openat`=`0x142` (322), `read`=`0x3` , `close`=`0x6` (ARM EABI syscall table — verify against an authoritative source before using; these are **different** from both the x64 and the ARM64 numbers). Confirm ELF32 struct layout: `Elf32_Ehdr.e_phoff`=`0x1C`, `e_phentsize`=`0x2A`, `e_phnum`=`0x2C`; `Elf32_Phdr`: `p_type`@`0x00`, `p_vaddr`@`0x08`, size `0x20`; `Elf32_Dyn`: size `0x08` (`d_tag` then `d_val`, both 4 bytes); `Elf32_Sym`: `st_name`@`0x00`, `st_value`@`0x04`, size `0x10` — verify each against an authoritative ELF32 reference before using, do not assume these are correct as typed here. Confirm the self-location mechanism decision the same way Task 1 did (likely: same answer, forward-scan, for consistency — but ARM32/Thumb `adr` range limits may force a different literal-pool approach than AArch64's; note this if so).

- [ ] **Step 2: Write `asm/imports_resolver_arm32_linux.asm`**

Port the same algorithm in ARM32 (Thumb, per `relocations_resolver_arm32.asm`'s existing mode choice — check it and match) assembly: syscalls via `svc #0` with the syscall number in `r7` and args in `r0`-`r6`, AAPCS32 callee-saved registers (`r4`-`r11`) for anything surviving a `dlsym` call, ELF32 struct offsets from Step 1 (not the ELF64 ones Task 1 used).

- [ ] **Step 3: Add `setup.py` assembly + export**

Add an `assemble_arm32()` call producing `IMPORTS_ARM32_LINUX`, added to the `SHELLCODES_PY.write_text(...)` constants list, placed with the other ARM32 assembly calls (before any x86 `assemble()` call).

- [ ] **Step 4: Wire `_pe_features.py` / `_chain_builder.py`**

Add `_PLATFORM_LINUX_ARM32 = 'linux_arm32'`. Add a `_SHELLCODES[_PLATFORM_LINUX_ARM32]` entry mirroring `_PLATFORM_LINUX_32`'s shape but with `RELOCS_ARM32`/`IMPORTS_ARM32_LINUX`/`CTORS_RUNNER_ARM32`. Extend `_select_chain`'s Linux branch (already touched in Task 1) to also check `features.machine in (_MACHINE_ARMNT, _MACHINE_ARMTHUMB)`.

- [ ] **Step 5: Run the existing test suite to confirm no regression**

Run: `pytest tests/pytest -v`
Expected: all previously-passing tests (including Task 1's new `test_01_linux_write[arm64]`) still pass.

- [ ] **Step 6: Cross-compile an ARM32 PE variant of test 01 and port the pytest case**

Same process as Task 1 Step 6, targeting ARM32, producing `tests/Linux_arm32/01_linux_write_arm32.pe` and (if needed) `test_loader_linux_arm32.pe`. Add `"arm32"` to `test_01_linux_write`'s parametrize list.

- [ ] **Step 7: Run and verify test_01_linux_write[arm32] passes**

Run: `pytest tests/pytest/test_shellcode.py::test_01_linux_write -v -k arm32`
Expected: PASS, stdout contains `PEOR\n`.

**Note on how "passes" is verified for ARM32 locally**: this machine is x86_64 Windows — running an ARM32 ELF binary locally requires `qemu-arm-static` (or equivalent user-mode emulation) same as CI will. If genuinely unavailable in this dev environment, this step's local verification is blocked on Task 3's CI environment setup landing first; say so explicitly in the report rather than silently skipping the test (CLAUDE.md: no skips, ever — "blocked pending CI tooling, not skipped" is the honest status, not a pass).

- [ ] **Step 8: Commit**

```bash
git add asm/imports_resolver_arm32_linux.asm setup.py peor/_pe_features.py peor/_chain_builder.py tests/pytest/test_shellcode.py tests/Linux_arm32/
git commit -m "feat: add ARM32 Linux import resolver, wire into chain builder, port test 01"
```

## Task 3: CI wiring + port remaining tests (02-05)

**Files:**
- Modify: `.github/workflows/test.yml` (new jobs: ARM64 Linux build+test on `ubuntu-24.04-arm`; ARM32 Linux build+test on `ubuntu-latest` + `qemu-user-static`)
- Modify: `tests/pytest/test_shellcode.py` (extend tests 02-05's parametrize lists to `arm64`/`arm32`, following Task 1/2 Step 6's established cross-compile pattern for each)

**Interfaces:**
- Consumes: Task 1's `_PLATFORM_LINUX_ARM64`/Task 2's `_PLATFORM_LINUX_ARM32` chain wiring (both must be merged first — this task is sequential after both, not parallel with either).
- Produces: nothing further consumes this — terminal task for this plan.

- [ ] **Step 1: Add the ARM64 Linux build+test job on `ubuntu-24.04-arm`**

Native, no emulation — install the same cross-compiler toolchain the existing `build-linux-mingw`/`test-linux-mingw` jobs use (check those jobs' exact install steps first and mirror), run `pytest tests/pytest -v -k "linux and arm64"`.

- [ ] **Step 2: Add the ARM32 Linux build+test job on `ubuntu-latest` with `qemu-user-static`**

Install `qemu-user-static` (`apt-get install -y qemu-user-static` or the distro-correct package name — verify it's actually available on the `ubuntu-latest` image, don't assume) before running `pytest tests/pytest -v -k "linux and arm32"`; sanity-check with a trivial known-good ARM32 ELF run through `qemu-arm-static` first, per the Review Focus item above, so a real crash isn't masked by a broken emulation setup.

- [ ] **Step 3: Port tests 02-05 to ARM64 and ARM32**

Following the Step 6 pattern established in Tasks 1 and 2: `02_linux_cpp_exceptions`, `03_linux_with_crt`, `04_linux_signal`, `05_linux_global_ctor`. Each gets its own cross-compiled ARM64+ARM32 binary pair and parametrize-list extension. Watch for test 02/07/11/15-style C++ EH tests needing the same `cxx_eh_fixer`-equivalent research already flagged for the Windows ARM plan — determine per-test whether it applies to the Linux ABI path too (expected: Linux C++ EH goes through libstdc++'s own unwinder, likely needs no `peor`-side fixup at all, unlike the Windows-specific `cxx_eh_fixer64.asm` — verify, don't assume).

- [ ] **Step 4: Run the full test suite, confirm zero skips, zero failures**

Run: `pytest tests/pytest -v`
Expected: all tests pass, including every new ARM64/ARM32 Linux variant.

- [ ] **Step 5: Add to `test-summary`'s required `needs:` list**

Same as every other job — no exception.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/test.yml tests/pytest/test_shellcode.py
git commit -m "ci: add Linux ARM64/ARM32 build+test jobs, port tests 02-05"
```
