# PLAN

Standing rules — apply to every item:
- **NEVER DO GIT COMMIT** (exception, 2026-10-26: user explicitly authorized commit+push
  directly to `arm_support` for the ARM support work below, scoped to that work, small
  understandable commits, push only once CI is believed to work — see that TODO)
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

## TODOs

### FULL ARM32 / ARM64 support - IN PROGRESS (subagent-driven-development)

**Goal:** real, non-EFI Windows shellcodes for ARM32 Thumb-2 (`0x01C4`) and AArch64 (`0xAA64`),
full feature parity with the existing x64/x86 chain (imports, delay-load, relocs, TLS, SEH,
C++ EH, ctors). Plus: run the already-working EFI ARM32/64 tests on real `windows-11-arm`
hardware (today they only run emulated via QEMU on `ubuntu-latest`).

**Status:** being executed via the superpowers subagent-driven-development process.
Commits/pushes authorized for this work specifically, including to topic branches
(explicit user instruction, 2026-10-27: "always keep going with more subagents...
feel free to push to non-main branches, but note the whole feature should be
contained in one branch when done (arm_support)"). Do not hand-edit the asm/python
files this covers without checking the plans below first — there are active ledgers
tracking per-task progress and review state.

**Active branches/worktrees (2026-10-30) — all must fold back into `arm_support` when done:**
- `arm_support` — the long-lived feature branch; final merge target for everything below.
- `arm_support-ci-spike` — **DONE 2026-10-30, folded back into `arm_support`** (fast-forward).
  Final state: `test-efi-windows-arm` job green on real `windows-11-arm` hardware — native
  ARM64 QEMU from MSYS2 clangarm64 (the choco one is x64-only and its emulated TCG brings
  up as an instant 0xC00000FF crash; proven not a firmware/device/flag issue by bisection),
  full `share/qemu` resource tree copied at BOTH the choco convention (`<exe-dir>\share\qemu`)
  AND the MSYS2 `get_relocated_path()` convention (`<exe-dir>\..\share\qemu`) — QEMU's own
  rom search lands at `C:\Program Files\share\qemu` (run 41037146428 proved the choco path
  alone isn't searched). 11/11 EFI arm64+arm32 tests passed on real hardware, and the full
  9-job workflow (incl. restored spike-disabled jobs + the new job required in `test-summary`)
  is green end to end (runs 41043107299, 41046091823). See that plan's ledger for details.
- `arm_support-linux-arm` (`.worktrees/arm_support-linux-arm`) — Linux ARM64 import
  resolver (Task 1 of the Linux-ARM plan below). Resolver/entrypoint/wiring done,
  one remaining bug being chased (`write()` call crashes post-resolution — see that
  plan's ledger).
- `arm_support-linux-arm32` (`.worktrees/arm_support-linux-arm32`, branched off
  `arm_support-linux-arm`) — Task 2 of the same plan, ARM32 Linux import resolver.
- `arm_support-windows-pe` (`.worktrees/arm_support-windows-pe`, also branched off
  `arm_support-linux-arm` to inherit its shared `entrypoint_resolver_arm64.asm`) —
  Task 1 of the big Windows ARM PE-support plan below (non-EFI Windows ARM64/32
  entrypoint + platform dispatch). **Done for ARM64** (128 passed, real MSBuild
  build + pefile verification). **ARM32 deferred** (user decision, 2026-10-30):
  this machine's only installed Windows SDK (10.0.26100.0) is the exact version
  where Microsoft removed 32-bit ARM desktop import libs — a genuine missing-files
  problem, not a policy gate (confirmed via `Microsoft.Cpp.WindowsSDK.targets`'s
  real `Exists()` checks). ARM32 asm/wiring is written and keystone/capstone
  verified but parked, not build-tested. Revisit with an older SDK (<=10.0.22621)
  or the `windows-11-arm` CI runner once stood up.

**Design doc (read this first for the full rationale/decisions):**
`docs/superpowers/specs/2026-10-26-windows-arm-support-design.md`

**Plans (execute in this order):**
1. `docs/superpowers/plans/2026-10-26-efi-arm-real-hardware-ci.md` — small: add a CI job that
   runs the existing EFI ARM32/64 tests on real `windows-11-arm` hardware, additive to the
   existing QEMU job, required in `test-summary`'s gate.
2. `docs/superpowers/plans/2026-10-26-windows-arm-pe-support.md` — large: new
   `imports_resolver_arm{64,32}.asm`, `entrypoint_resolver_arm{64,32}.asm`,
   `tls_callbacks_arm{64,32}.asm`, delay-load + SEH + C++ EH equivalents, ported test suite
   (01-21), CI on `windows-11-arm`. Reuses the existing `RELOCS_ARM64/32` and
   `CTORS_RUNNER_ARM64/32` (already assembled for the EFI chain — format-identical for Windows
   PEs, no changes needed there).

Ledgers (per-task progress, what's done, review verdicts, rulings):
`.superpowers/sdd/2026-10-26-efi-arm-real-hardware-ci/progress.md`,
`.superpowers/sdd/2026-10-26-windows-arm-pe-support/progress.md` (Task 1 in progress
on `arm_support-windows-pe`, see branch list above).

**Parallel, separate effort (2026-10-27):** Linux ARM64/ARM32 support (extends
the existing Linux x86/x64 usermode chain — dlopen/dlsym-based import
resolution — to ARM). Not part of the Windows ARM design doc above; scoped
and dispatched directly per user instruction, no separate brainstorming
round. Plan: `docs/superpowers/plans/2026-10-27-linux-arm-pe-support.md`.
Branch: `arm_support-linux-arm` (off `arm_support`, separate from the EFI-ARM
CI spike branch). Ledger: `.superpowers/sdd/2026-10-27-linux-arm-pe-support/progress.md`.

**Corrections to this TODO's own earlier draft**, found while writing the design doc/plans —
do not trust the old specifics below if you ever revert to them:
- The non-EFI Windows entrypoint does **not** take `(argc, argv, envp)` — that's the
  Linux/EFI calling convention. A normal Windows PE's entry (`mainCRTStartup`-style) takes no
  arguments; the new `entrypoint_resolver_arm{64,32}.asm` jump to the entry with none, same as
  the existing non-ARM `entrypoint_resolver{32,64}.asm`.
- The exact ARM64 (`x18`-based TEB access) and especially ARM32 (TEB access mechanism is NOT
  confirmed to be `r8`/`fs:[0]` by analogy with x86 — this needs real verification, not
  assumption) PEB-walk details are explicitly left as research steps in the import-resolver
  plan task, not settled facts — verify against real disassembly/documentation before coding.

### controlable CLI flags - NEXT
we want this tool to be extremly embedded-supportive.
each feature must be opt-out able.
peor finds what stubs are needed, but the user can pass cli flags to remove stubs.
if there's efi and the user doesn't need the efi_handle/system_table to be real, he can remove the lookup stub.

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
