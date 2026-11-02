# Kernel tests → Visual Studio solution build Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hand-rolled WDK `cl`/`link` pipeline in `tests/local_tests/` with a Visual Studio solution of three driver projects whose loader executes the peor shellcode read from `C:\shellcode`, with peor run as the payload projects' vcxproj post-build step for both archs and both configs.

**Architecture:** `tests/local_tests/solution/peor_kernel_tests.sln` builds `loader`, `calc`, `spawn` as WDM kernel drivers for {Debug,Release}x{Win32,x64}. Payload post-build emits `<OutDir>peor_<name>_chain_<arch>.bin` via `python -m peor`. Loader is fixed; DriverEntry reads `\??\C:\shellcode` into `NonPagedPoolExecute` and calls it. pytest drives msbuild, signing, ssh ssh push of `.sys` + chain blob, `sc create/start`, marker asserts; spawn's open ring-0 bug (`RtlCreateUserThread`→0xC000000D) is debugged on the new build with WinDbg MCP.

**Tech Stack:** MSBuild (VS 18 Community at `C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe`), WDK 10.0.28000.0 kernel-mode driver props (`C:\Program Files (x86)\Windows Kits\10\build\10.0.28000.0\{x64,Win32}\WindowsKernelModeDriver\WDK.<plat>.WindowsKernelModeDriver.*`), peor CLI (`linux | efi | kernel64 | kernel32`), pytest local_tests + WinDbg MCP (`open_kd_session`, `net:port=50000,key=1.1.1.1`).

**Spec:** `docs/superpowers/specs/2026-11-02-kernel-test-vs-solution-design.md`

## Global Constraints

- Loader binary MUST stay fixed forever: shellcode contract is file `\??\C:\shellcode`, read at run time. No `chain_blob.inc`, no embed, no per-test loader rebuild.
- Payload vcxproj post-build: `python -m peor -i "$(TargetPath)" --platform kernel64|kernel32 -o "<artifact path>"`, `WorkingDirectory` = repo root `$(SolutionDir)..\..\..\` so the `peor` package resolves; repo root has `peor/` package; `kb.ensure_shellcodes()` still seeds `peor/_shellcodes.py` before msbuild.
- Full config matrix builds: {Debug,Release}x{Win32,x64}. VM tests execute x64 Release + x64 Debug only (x64 kernel cannot run an x86 driver).
- Marker names/formats unchanged: `PEOR_CHAIN_RESULT=0x<8 hex><CRLF>` (kernel `text[64]`, `hexCharset`), plus per-payload markers; `clean_vm_markers` cleans the same four paths.
- Loader MUST free its pool before returning any failure status (DriverUnload will not run after a failed DriverEntry); breadcrumbs `PEORLOADER: ...` stay.
- OutDir pinned deterministic: `$(SolutionDir)out\$(Configuration)\$(PlatformName)\`; TargetNames `peor_loader|peor_calc|peor_spawn` → `peor_loader.sys`, chains `peor_calc_chain_x64.bin` / `peor_spawn_chain_x86.bin` / `..._chain_Win32.bin`? — NO: arch suffix derives from `$(PlatformName)` = `x64`|`Win32`: chain artifact is `<OutDir>$(TargetName)_chain_$(PlatformName).bin`.
- Chain prologue verification bytes (from `_kernel_chain_build.build_chain` today): kernel64 blob starts `4883ec20`, kernel32 starts `83ec10`; verification moves to `_solution.verify_kernel_chain_prologue`, no magic inline hex inside tests.
- `_kernel_chain_build.write_chain_blob_inc` + `compile_loader` deleted after the switch; `kb.PEOR_*_PATH` constants and `ensure_shellcodes`/`build_chain`-invoking peor CLI keep working for any legacy no-VM path.
- Repo rules still apply: each feature ships with a test; README.md updates with the feature; no test-skipping in local runs (`PEOR_VM_USER=administrator` must be set by the runner).

## Review Focus

- Loader started with missing or tiny `C:\shellcode` → must return a probeable NTSTATUS in `PEOR_CHAIN_RESULT` (and free its pool), NOT call garbage memory. Test: `test_kernel_loader_contract.py::test_loader_needs_chain_file` (Task 2).
- Wrong-arch chain pushed (x86 chain, x64 loader) → garbage execution, VM crash risk. Pin via artifact naming by `$(PlatformName)` + prologue check consumed by any pusher. Test: artifact test asserts per-config prologues (Task 1).
- Stale chain artifact from another config reused (same `<name>_chain` name across configs) → per-config `$(OutDir)` prevents it; artifact test asserts Release/x64 and Debug/x64 chain bins are distinct paths and contain matching-size `peor` shells (Task 1).
- Flaky/absent projectile pieces on other dev boxes (msbuild/WDK missing) → `_solution` raises `WdkError`-style clear error, conftest skips with the same Welcome skip msg (Task 1).
- DriverUnload pool free on success still exercised: `sc stop` after successful calc run removes driver without leak (zombie s: not directly observable; review note, existing `sc stop` flow unchanged).

---

### Task 1: Solution skeleton + msbuild facade + artifact test

**Files:**
- Create: `tests/local_tests/_solution.py`
- Create: `tests/local_tests/solution/peor_kernel_tests.sln`
- Create: `tests/local_tests/solution/loader.vcxproj`, `calc.vcxproj`, `spawn.vcxproj`
- Create: `tests/local_tests/test_kernel_solution.py`

**Interfaces:**
- Consumes: existing `kb.ensure_shellcodes()` (chain seed), WDK paths (`C:\Program Files (x86)\Windows Kits\10`).
- Produces (Task 2/3 depend on these EXACT names):
  - `_solution.find_msbuild() -> pathlib.Path` (vswhere or default path)
  - `_solution.Solution.build(config: str, platform: str) -> SolutionBuild` (config ∈ {Debug, Release}, platform ∈ {x64, Win32}); runs msbuild on the .sln with `/p:BuildProjectReferences`; raises `_solution.SolutionError` on msbuild exit≠0
  - `class SolutionBuild` — `.config`/`.platform`; `.sys(name: str) -> Path` → `<OutDir>peor_<name>.sys`; `.chain_bin(name: str) -> Path` → `<OutDir>peor_<name>_chain_$(PlatformName).bin` (name without "peor_" prefix)
  - `_solution.verify_kernel_chain_prologue(blob: bytes, platform: str) -> None` (raises `SolutionError`)
- conftest gains a `solution` fixture returning `_solution.Solution`; the `chain_build` fixture (kb module) STAYS for `kb.PEOR_*_PATH` marker constants and `ensure_shellcodes`. VM tests use `wdk, vm, chain_build, solution`.

- [ ] **Step 1: Write the failing artifact test** `test_kernel_solution.py`

```python
@pytest.mark.parametrize("platform", ["x64", "Win32"])
@pytest.mark.parametrize("config", ["Release", "Debug"])
def test_solution_build_produces_drivers_and_chains(config, platform, solution):
    kb.ensure_shellcodes()
    built = solution.build(config, platform)
    for name in ("loader", "calc", "spawn"):
        sys_path = built.sys(name)
        assert sys_path.exists(), str(sys_path)
    blob = built.chain_bin("calc").read_bytes()
    _solution.verify_kernel_chain_prologue(blob, platform)
    blob = built.chain_bin("spawn").read_bytes()
    _solution.verify_kernel_chain_prologue(blob, platform)
    if platform == "x64" and config == "Release":
        assert built.chain_bin("calc") != built.chain_bin("calc", config="Debug") # distinct dirs are implicit
```

Run: `python -m pytest tests/local_tests/test_kernel_solution.py -x -q`
Expected: FAIL — `solution` fixture `ModuleNotFoundError`/no sln yet.

- [ ] **Step 2: Write `_solution.py`**

`find_msbuild()` → default path then vswhere; `Solution.build()` invokes msbuild subprocess with `/p:Configuration=$(config) /p:Platform=$(platform)`; on failure raises with captured output. No CRT assumptions; no cl/link.

- [ ] **Step 3: Write the 3 vcxproj + sln**

Per project:
- Import `$(VCInstallDir)...Microsoft.Cpp.props` then the WDK kernel prop/targets for the arch; `ConfigurationType=Driver`, `DriverType=WDM`, `TargetName=peor_<name>`; `OutDir=$(SolutionDir)out\$(Configuration)\$(PlatformName)\`.
- Sources: payload projects add `..\kernelsrc\<calc.c|spawn.c>` + `payload_common.h`; loader adds `..\kernelsrc\loader_core.c`; `AdditionalIncludeDirectories=$(ProjectDir)..\kernelsrc`.
- Payload post-build (`PeorKernelChain` target, `AfterTargets="PostBuildEvent"`):

```xml
<Exec Command='python -m peor -i "$(TargetPath)" --platform kernel64 -o "$(OutDir)$(TargetName)_chain_x64.bin"'
      WorkingDirectory='$(SolutionDir)..\..\..' />
```

with the second variant under `Condition="'$(Platform)'=='Win32'"` emitting `kernel32` + `_chain_Win32.bin` suffix. Loader project has NO peor step. Builder's exact WDK prop/target import set verified against kit contents (both `...props` and `...targets` for x64/Win32 exist under the kit path above); if the kit's target file names differ, pin the actual names found and note them here.

- [ ] **Step 4: Run test — pass**

Run: `python -m pytest tests/local_tests/test_kernel_solution.py -x -q` (`msbuild` per config takes minutes; runner must tolerate it).
Expected: PASS (both archs build; post-build chain artifacts exist with correct arch prologues).

- [ ] **Step 5: Commit**

```bash
git add tests/local_tests/_solution.py tests/local_tests/solution tests/local_tests/test_kernel_solution.py
git commit -m "build: WDK kernel test drivers as Visual Studio solution"
```

---

### Task 2: Loader reads `C:\shellcode` + calc VM test on the new flow

**Files:**
- Modify: `tests/local_tests/kernelsrc/loader_core.c` (rewrite embed portion)
- Modify: `tests/local_tests/test_kernel_calc.py`
- Modify: `tests/local_tests/conftest.py` (fixture rename)
- Create: `tests/local_tests/test_kernel_loader_contract.py`

**Interfaces:**
- Consumes: Task 1 `solution.build/config|platform`, `_solution.SolutionBuild`, `_signing.sign(wdk, sys_path)` as today, `vm.push/pull`, `vm.service_create/...`, `kb.PEOR_*_PATH`.
- Produces: loader contract — DriverEntry: `\??\C:\shellcode`, `ZwQueryInformationFile` size, ≥ `PEOR_MIN_CHAIN_SIZE` (name a constant `0x20` in source; no magic number), alloc `NonPagedPoolExecute`, `ZwReadFile`, breadcrumbs `PEORLOADER: shellcode file= size= pool=`; on failure: free pool, still write `PEOR_CHAIN_RESULT=0x<status>` BEFORE returning nonzero.

- [ ] **Step 1: Write the failing negative test** `test_kernel_loader_contract.py`

```python
def test_loader_needs_chain_file(wdk, chain_build, solution, vm):
    built = solution.build("Release", "x64")
    vm.push(built.sys("loader"), rf"C:\Windows\Temp\peor_load_calc.sys")
    vm.run("del /q C:\\shellcode", check=False)
    vm.run("sc create peorLoaderNeed type= kernel start= demand "
           "binPath= C:\\Windows\\Temp\\peor_load_calc.sys", check=False)
    rc, out = vm.run("sc start peorLoaderNeed", check=False)
    assert "FAILED" in out or rc != 0            # no silent success on a missing shellcode
    text = vm.read_text(chain_build.PEOR_CHAIN_RESULT_PATH)
    assert text is not None and "PEOR_CHAIN_RESULT=0x" in text
    assert "PEOR_CHAIN_RESULT=0x00000000" not in text
    vm.run("sc delete peorLoaderNeed", check=False)
```

Run: `pytest tests/local_tests/test_kernel_loader_contract.py -x -q`
Expected: FAIL (current embedded loader loads fine without the file → chain result says 0x... wait — no file is written? With embed, DriverEntry runs calc fine and returns 0: StartService SUCCEEDS → `FAILED` absent → assertion hit).

- [ ] **Step 2: Rewrite loader_core.c for the file contract**

Replace `#include "chain_blob.inc"` + `sizeof(peorChainBlob)`/`RtlCopyMemory(peorChainBlob)` with the `ZwCreateFile`/`ZwReadFile` flow above; keep everything else (markers, breadcrumbs, unload, status return semantics). No CRT: statuses composed by hand, as in the current file.

- [ ] **Step 3: Refactor test_kernel_calc.py + conftest**

conftest: add `solution` fixture (`chain_build` keeps returning kb for marker constants). test_kernel_calc: `_build` replaced by

```python
built = solution.build("Release", "x64")
_signing.sign(wdk, built.sys("loader"))
vm.push(built.sys("loader"), remote_sys)
vm.push(built.chain_bin("calc"), r"C:\shellcode")
```

then the existing create/start/cleanup/asser flow UNCHANGED (marker asserts identical).

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/local_tests/test_kernel_loader_contract.py tests/local_tests/test_kernel_calc.py -x -q` with `PEOR_VM_USER` set.
Expected: PASS both (calc still green through the new file-fed loader; loader contract promotes `PEOR_CHAIN_RESULT=0x...` failure on missing file).

- [ ] **Step 5: Delete dead embed pipeline**

Remove `write_chain_blob_inc`, `compile_loader` from `_kernel_chain_build.py`; grep no remaining callers. Keep `ensure_shellcodes` + `build_chain`-replacing `peor` CLI runner (build_chain keeps existing test use).

Run: `python -m pytest tests/local_tests/test_kernel_solution.py -q` — still green.

- [ ] **Step 6: Commit**

```bash
git add tests/local_tests/kernelsrc/loader_core.c tests/local_tests/test_kernel_calc.py tests/local_tests/conftest.py tests/local_tests/test_kernel_loader_contract.py tests/local_tests/_kernel_chain_build.py
git commit -m "feat: kernel loader reads peor shellcode file (C:\\shellcode)"
```

---

### Task 3: Spawn test on the new flow (bug carried over)

**Files:**
- Modify: `tests/local_tests/test_kernel_create_process.py`

**Interfaces:**
- Consumes: Task 2 flow (sign loader, push loader + chain_bin("spawn"), sc create/start, markers).
- Produces: unchanged public contract of the spawn test; parametrize over `("Release","x64")` and `("Debug","x64")` so both executed configs are covered.

- [ ] **Step 1: Refactor the test; parametrize configs**

Replace `_build` with wall `solution.build(config,"x64")` + pushes as in Task 2 (`chain_bin("spawn")`). Keep every existing assert, incl. `MISSING_ROUTINE` and `process-was-real`.

- [ ] **Step 2: Run it (both configs)**

Run: `python -m pytest tests/local_tests/test_kernel_create_process.py -q -rs` with `PEOR_VM_USER` set.
Expected: FAIL today, an error `USERTHREAD=0xC000000D` visible in the spawn markers. Record the exact chain traceback; no commit of a passing claim.

- [ ] **Step 3: Commit the refactor (test still red on the open bug)**

```bash
git add tests/local_tests/test_kernel_create_process.py
git commit -m "test: spawn VM test on VS solution flow (bug open)"
```

---

### Task 4: Ring-0 `USERTHREAD=0xC000000D` root cause + fix

**Files:**
- Modify: `tests/local_tests/kernelsrc/spawn.c` (RTLCREATEUSERTHREAD_f invocation; possibly type/arg order only)
- Modifies nothing else unless root cause is in the chain resolver (then a regression test in `tests/pytest/test_kernel_shellcode.py` grows as part of the fix).

**Interfaces:**
- Consumes: mcp_windbg session kd `kd-4586e7cb` (`net:port=50000,key=1.1.1.1`, symbols `srv*c:\symbols*https://msdl.microsoft.com/download/symbols`), Task 3-built spawn drivers, `vm` fixture.
- Produces: root-cause note + fixed spawn.c passing BOTH config runs; `PEOR_SPAWN=process-was-real` on the VM.

- [ ] **Step 1: Collect live evidence (no fix yet)**

kd: after `bc*`, set

```
bp nt!RtlpCreateUserThreadEx ".if (@rdx==0) {r rcx,rdx,r8,r9,r10; dq @rsp L8; k7;} .else {g}"
```

(the spawn call passes SecurityDescriptor = NULL; k7 frames locate the exec-pool caller). Resume `g`, then reproduce via ssh `sc start` on a fresh test pass.

- [ ] **Step 2: Interpret entry state.**

If `r8d`≠0 at ENTRY (CreateFlags would be our garbage) — sweep the caller from its exec-pool return address: `u <caller-0x40> L20`, disassemble the call site; if `r8d`==0 at entry, single-step `ZwCreateThreadEx` (`tc` limited, or bp the return path) to catch where 0xC000000D originates. Write down the mechanism.

- [ ] **Step 3: Fix spawn.c only after the mechanism is known** (per the four-phase rule: root cause BEFORE fix; likely culprits based on today's disassembly: our call site's r8/register materialization between `KeUnstackDetachProcess` and the call; or arg-order mismatch in the 10-arg invoke)

- [ ] **Step 4: Re-run Task 3 test (both configs) → PASS; full release pass**

Run: `python -m pytest tests/local_tests/test_kernel_create_process.py -q -rs` with `PEOR_VM_USER`.
Expected: PASS both, `PEOR_SPAWN=process-was-real` in the marker.

- [ ] **Step 5: Emulated mirror test if the fix touched chain-level behavior** (only needed for machinery bugs; arg-order bug fixes live in the C source — add no emulated case)

- [ ] **Step 6: Commit**

```bash
git add tests/local_tests/kernelsrc/spawn.c
git commit -m "fix: kernel spawn payload USERTHREAD call (ring-0)"
```

---

### Task 5: Regression sweep + docs + push

**Files:**
- Modify: `README.md` (new section: solution layout, `C:\shellcode` contract, config matrix, new test names)
- Modify: `PLAN.md` (+ design doc status)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Full suites**

Run: `$env:PEOR_VM_USER="administrator"; python -m pytest tests/local_tests tests/pytest -q` (win mode emulation noise pre-existed).
Expected: all pass (emulated kernel suite untouched: was 12 passed).

- [ ] **Step 2: README + PLAN update** — solution tree diagram, faster loader contract, config matrix semantics, how to run (the exact msbuild/pytest commands from Tasks 1/2).

- [ ] **Step 3: Commit + push + PR**

```bash
git add README.md PLAN.md docs/superpowers/specs/2026-11-02-kernel-test-vs-solution-design.md
git commit -m "docs: local kernel tests build via VS solution + C:\\shellcode loader"
git push origin kernelic_features
gh pr edit 6 --body-file <updated body>
```
