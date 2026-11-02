# Kernel tests: Visual Studio solution + file-fed loader (design)

Date: 2026-11-02
Status: draft for approval

## Intent and why

Requirement (user): the kernel test drivers MUST be built by a Visual Studio
solution — one driver project for the SCM loader, one driver project per test
payload. The test project is itself a kernel driver (a PE); peor receives that
PE and builds a shellcode the loader knows how to load. The loader reads the
shellcode from the file `C:\shellcode` at runtime (user's pick), so the loader
binary is fixed and payload projects stay independent.

## Goals

- `tests/local_tests/solution/` holds `peor_kernel_tests.sln` with three
  real kernel-mode driver projects (WDK, x64, WDM):
  - `loader` — fixed SCM loader. DriverEntry: opens `\??\C:\shellcode`,
    reads the peor chain blob into `NonPagedPoolExecute`, calls it, writes
    `PEOR_CHAIN_RESULT=0x<status>`, registers DriverUnload (frees pool).
    DbgPrint breadcrumbs (`PEORLOADER: ...`) stay.
  - `calc` — payload driver project, source `kernelsrc/calc.c`.
  - `spawn` — payload driver project, source `kernelsrc/spawn.c`.
- Payload projects output plain kernel-driver PE files (subsystem NATIVE);
  their vcxproj **post-build step** runs the peor CLI (user amendment):
  `python -m peor -i <payload.sys> --platform kernel64 / kernel32 -o
  <name>_chain.bin`. The solution must build both x64 and x86 and both
  Release and Debug; every one of the four payload builds produces its
  platform-matched chain artifact. On the VM (x64 kernel) the tests execute
  the x64 chains (Release and Debug); x86 chains are built and confirmed by
  the post-build conversion but cannot be executed by the x64 loader on the
  x64 VM.
- local_tests pytest flow per test: msbuild the solution -> peor CLI on the
  test's payload .sys -> sign loader with existing self-signed cert flow ->
  ssh push loader .sys and the chain blob to VM `C:\shellcode` -> `sc create`/
  `sc start` -> read markers back (`peor_chain_result.txt`, per-payload
  markers unchanged).
- Existing passing behavior preserved: calc test, marker formats, signing/DSE
  setup, `clean_vm_markers`, DbgPrint breadcrumbs.
- After the restructure, fix the still-open spawn failure
  (`RtlCreateUserThread` returns 0xC000000D in the ring-0 payload) and get
  `test_kernel_create_process.py` passing on the VS solution build.

## Non-goals / anti-goals

- No changes to the emulated suite (`tests/pytest/test_kernel_shellcode.py`).
- No new payload features; payload sources only move project membership.
- No kd/KDNET setup changes; WinDbg MCP remains the debug channel.
- No new test kinds (e.g. usermode tests) inside the solution.

## Approaches

- (a) Hand-rolled `cl`/`link` per test (`_wdk.py compile_sys`) — rejected:
  violates the VS-solution requirement.
- (b) One loader per test, shellcode embedded via generated `chain_blob.inc`
  (previous approach) — rejected: user picked runtime file load; embeds also
  duplicate the loader per payload.
- (c) CHOSEN: single loader driver project that reads the shellcode from
  `C:\shellcode`; per-test payload driver projects; peor CLI converts the
  payload PE at test time; the chain blob is pushed as a plain file.
  Tradeoff: adds one file-reading step to the loader (ZwReadFile over
  `\??\C:\shellcode`) and an artifact push; removes all per-test loader
  rebuilds. If a future payload needs more than one file argument, a naming
  convention (`C:\shellcode.<test>`) extends the path without touching the
  loader contract; the current contract is exactly `C:\shellcode`.

## Parts decided (user or confirmed by today's state)

- Shellcode delivery: runtime file load from `C:\shellcode` (user decision).
- VM/build target: same VM harness, same ssh/sc service flow, same signing.
- Marker files and formats unchanged; `PEOR_CHAIN_RESULT` written by loader.
- peor CLI invoked from the payload projects' vcxproj post-build step, for
  both architectures and both Release/Debug configs (user amendment).
- Tests execute x64 Release and x64 Debug chains on the VM; x86 builds exist
  as post-build conversion artifacts (x64 VM cannot run a 32-bit native
  driver or 32-bit shellcode from the 64-bit loader).
- The payload PEs fed to peor are the VS-built driver outputs; peor's
  kernel64 chain already accepts them (proven by the passing calc run).

## Left to the builder (builder's calls, called out as such)

- Exact WDK/MSBuild wiring of the `.vcxproj` files
  (`ConfigurationType=Driver` + WDK `WDK.x64.WindowsKernelModeDriver`
  props/targets from kit 10.0.28000.0; fall back to whichever import set the
  installed kit actually supports — verified present).
- `_wdk.py` keeps path-finding helpers (VS/MSBuild, WDK, signtool); the
  hand-rolled `compile_sys` gets replaced by the msbuild driver. `build_chain`
  moves to "run peor CLI on a payload .sys, return blob bytes/path".
- Loader file-read details (ZwQueryInformationFile for size, handle in
  KernelMode, close before call), error NTSTATUSes logged to the marker.
- Solution defines: keep the current payload defines by compiling the same
  `.c` files with the same include dirs.
- Loader rebuild contract: no per-test rebuild; projects share a common
  include dir for `payload_common.h` and `chain_blob.inc` is deleted.
