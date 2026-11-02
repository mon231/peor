# tests/local_tests

Real-kernel pytest tests: they execute **real peor Windows-kernel outputs**
(WDK-built drivers, converted by `python -m peor` into kernel64 chain
blobs) on the team's Windows VM over SSH. Unlike `tests/pytest`, nothing
here is emulated: the chains run in ring-0 of the VM.

## Mandatory test

`test_kernel_create_process.py::test_real_process_run_on_vm` — the spawn
payload creates a REAL user-mode process (cmd.exe) from ring-0; the
argument shown to the test is the child process itself writing
`C:\Windows\Temp\peor_spawn_cmds.txt` through `dir C:\ > it`.

## How it works

1. **Host build (no VM needed)** — see `_wdk.py`, `_kernel_chain_build.py`:
   * WDK (`cl.exe`/`link.exe` over `km\ntoskrnl.lib`) compiles a payload
     driver (`kernelsrc/calc.c`, `kernelsrc/spawn.c`) into a real
     NATIVE-subsystem `.sys`.
   * `python -m peor -i payload.sys --platform kernel64` converts it into
     the kernel chain blob.
   * `kernelsrc/loader_core.c` embeds the blob (generated
     `chain_blob.inc`) and is built with the WDK into an SCM-loadable
     `peor_<name>.sys`.
   * `test_build_sanity.py` runs this whole pipeline without the VM so
     toolchain breakage is found even when the VM is offline.
2. **VM execution** — `_vmharness.py` pushes the loader, `sc create`s a
   kernel service and starts it; Windows loads the driver in ring-0, its
   DriverEntry copies the chain blob into executable non-paged pool and
   calls it. The chain resolves imports (SIDT-based kernel resolver) and
   runs the payload for real.
3. **Proof** — each payload writes NTSTATUS marker files on the VM
   (`C:\Windows\Temp\peor_*`); `test_kernel_calc.py` asserts the calc sum
   (3+2 via a real `RtlNtStatusToDosError` call) and the create-process
   test asserts the child's own `dir` output file.

## Prerequisites

* Windows host with WDK: `winget install --id Microsoft.WindowsWDK.10.0.28000`
  **and the matching SDK**: `winget install --id Microsoft.WindowsSDK.10.0.28000`
  (the WDK's km headers need the same-version SDK's `shared\ntdef.h`).
* Visual Studio C++ toolset (cl.exe) — VS 2022 or newer.
* Windows VM reachable over SSH. Credentials via env vars:

  ```
  PEOR_VM_HOST=192.168.52.129   # default when unset
  PEOR_VM_PORT=22               # default 22
  PEOR_VM_USER=                 # rely on ssh config/agent
  PEOR_VM_SSH_KEY=              # optional -i key path
  ```

  VM must allow kernel driver loading: either `bcdedit /set testsigning on`
  + reboot (test-signed builds) or an appropriately signed loader. Loading
  failures surface as `peor_chain_result` file absence / event-log noise.

* Tests skip automatically (pytest.skip) when the VM is unreachable or
  the WDK toolchain is missing — run `pytest tests/local_tests` anywhere.

## File map

| File | Role |
| --- | --- |
| `_wdk.py` | find VS + WDK, cl/link wrapper (driver + user exe builds) |
| `_kernel_chain_build.py` | `python -m peor` chain build, chain blob `.inc`, loader compile |
| `_vmharness.py` | ssh/scp/sc plumbing |
| `kernelsrc/payload_common.h` | marker-writing helpers (kernel mode, no CRT) |
| `kernelsrc/loader_core.c` | SCM loader: alloc exec pool, copy chain, call, report |
| `kernelsrc/calc.c` | `3+2` through real `RtlNtStatusToDosError` |
| `kernelsrc/spawn.c` | section/process/thread manual creation; runs cmd.exe |
| `test_build_sanity.py` | whole host-side pipeline, no VM |
| `test_kernel_calc.py` | real ring-0 calc test on the VM |
| `test_kernel_create_process.py` | mandatory real-process-on-VM test |
