# CLAUDE_TODO

Tasks ordered by priority.
Implement, add tests for any needed case.
Attempt to add tests that would run correctly on CI/CD too.

---

## REFACTOR

- [ ] **create CCP exceptions test**
  create a new test-case where a visual-studio project cpp compiles with SEH-exceptions instead of cpp-exceptions, then use peor and ensure it supports SEH-based cpp types

- [ ] **Collapse PE-type dispatch into lookup table**
  `dump_memory_layout` repeats `if pe.PE_TYPE == ...` four times...
  PEOR should select pre-shellcodes by himself, according to the PE type (efi, usermode, kernelmode, ...) and apply them.
  Remove the irrelevant cli flags for now. Also, remove the irrelevant shellcodes (which aren't generated via `_assemble_shellcodes`).
  When an unsupported PE is used (e.g. efi that needs something more than relocs), throw - and unsupport it.

- [ ] **Python -> ASM interaction**
  Some magic-numbers in the asm files are expected to be binary-replaced by the python before producing them.
  Make these magics a defined-bytes variable in the ASM file, then the binary-replace will be named and look much better

- [ ] **ASM file responsibility**
  The goal of peor is to use the least possible shellcodes (asm files) amount needed.
  For example, the relocs-resolver shellcode must be minimal and should not contain any other logic (exceptions/imports/..., these will have their own asm shellcode files).
  Split asm files where needed, give them meaningfull names. The python code should understand what shellcodes to use, according to the PE type and headers

- [ ] **Split `dump_memory_layout` into smaller functions**
  Function does many stuff. Extract each into its own readable, maintainable, simple function.

---

## NEAR FUTURE

- [ ] **TLS callback support**
  Both reloc resolvers jump straight to `AddressOfEntryPoint`. PEs with `IMAGE_DIRECTORY_ENTRY_TLS` (data dir index 9) must invoke `IMAGE_TLS_DIRECTORY.AddressOfCallBacks` first. Walk and call each non-null callback before jumping OEP. Add a test PE that uses TLS (e.g. a C++ static with a constructor).
  create a dedicated test for it.

- [ ] **support certificate-signed PE file**
  create a test for it

- [ ] **support windows-PE embedded resources**
  create a test for it

- [ ] **PE embedded resources — test coverage**
  `.rsrc` section is already included via the section loop.
  Verify resource RVAs survive relocation correctly; add a test PE that reads its own string resource at runtime.

---

## FAR FUTURE

- [ ] **Linux/WSL libc test**
  Compile a PE that calls libc `write()` to stdout, run on WSL via the shellcode loader. Needs a Linux-hosted test_loader and a clear spec for what "PE targeting Linux" means (MinGW? custom subsystem?). Defer until spec is written.

- [ ] **Windows kernel shellcode support**
  Create shellcodes to support windows kernel in all x86/x64

- [ ] **EFI import resolvers**
  No PEB, no kernel32. Must walk EFI system table → `EFI_BOOT_SERVICES` → `LocateProtocol` to resolve imports.
  High complexity; leave placeholders until there is a concrete EFI test target.

## VERY FAR FUTURE

- [ ] **ARM32 / ARM64 shellcode support**
  support all usermode/kernelmode/efi and all shellcodes, on ARM/AArch64 thumb/normal modes too
