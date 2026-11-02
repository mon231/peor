# PLAN — Windows kernel-mode (ring-0) PE → shellcode support

Only the next-up feature lives here. Full task breakdown + design:
`docs/superpowers/plans/2026-11-02-kernel-test-vs-solution.md`
and `docs/superpowers/specs/2026-11-02-kernel-test-vs-solution-design.md`.

## Status

- km64 + km32 import resolvers, entrypoint resolvers, platform wiring: DONE
  (`asm/imports_resolver*_km.asm`, kernel shellcodes in `_SHELLCODES`).
- Kernel test surface moved to a real MSBuild/WDK VS solution
  `tests/local_tests/solution/` (loader + calc + spawn driver projects),
  pytest facade `tests/local_tests/_solution.py`
  (`find_msbuild`, `Solution.build`, `verify_kernel_chain_prologue`).
- Release|Debug x64 green. Post-build peor run emits chain bins per config.
- VM: `Windows 11 x64.vmx`, ssh administrator@192.168.52.129, testsigning ON.

## Known open issues

1. **Win32 (km32) solution builds** — WDK 10.0.28000 hard-blocks kernel x86:
   need `WindowsTargetPlatformVersion=10.0.22000.0` for Win32 configs +
   committed `ntoskrnl_x86.def` (15 payload import names, DLL ntoskrnl.exe)
   → `lib.exe /machine:x86 /def:` per build, linked Win32-only; `/GS` off
   for x86 (no BufferOverflowK.lib). Test asserts def covers real x64
   imports too.
2. **Spawn chain bug** — `RtlCreateUserThread` returns `0xC000000D` at the
   USERTHREAD step (section/process/ALLOCVM/PEB/entryRVA all succeeded).
   Suspect `tests/local_tests/kernelsrc/spawn.c` ~lines 386-394, call
   `RTLCREATEUSERTHREAD_f(...)`: 10-arg order or arg-reply use.
   Kernel debugging channel (WinDbg MCP `mcp_windbg`) planned for root
   cause; note: an MCP-restart changes the kd session id, and a *manual*
   kd attach crashed the host 2026-11-02 — use the MCP tool only.
3. **VM loader-load instability** — same loader .sys yields
   rc=2 / 1784 / 998 across boots (see SDD ledger); control drivers load
   every boot. Not on the critical path; verify once on a fresh boot with
   the kd channel OFF.

## Remaining queue

1. Win32 solution build + green 4-config matrix (commit after).
2. Loader-contract negative test + calc test on the new file-read flow;
   delete old pipeline pieces (`_kernel_chain_build.write_chain_blob_inc`,
   `compile_loader`), keep `PEOR_*_PATH` + `ensure_shellcodes`.
3. Refactor `test_kernel_create_process.py` onto the solution chain flow;
   mark the spawn test xfail until item 4 lands.
4. Root-cause + fix the `RtlCreateUserThread` 0xC000000D spawn bug.
5. Full emulated + local regression, README update, push, PR #6 update.
