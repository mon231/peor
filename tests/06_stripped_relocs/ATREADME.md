CURRENT: implement support to: Stripped relocs handling, DLL entry support and c++ exceptions (for now, support SEH only). create new tests per case, and a visualstudio project that generates the EXACT correct binary. also, create a test for cpp project that uses std::thread, and implement needed features

TODO: the ci/cd winapi messagebox fails (errors running MessageBox/GUI/... on github containers?)
TODO: extreme code refactor is required

TODOs:
  - EFI import resolvers (currently empty placeholders)
  - Windows-Kernel import resolvers (currently empty placeholders)
  - ARM32/64 shellcodes supports
  - compile PE to linux, that uses libc functions (i.e. write to stdout), test it on wsl

FUTURE:
  - support windows-PE embedded resources
  - TLS callback support — the import resolver currently jumps straight to AddressOfEntryPoint; some PEs (especially those
  with security cookies or C++ statics) run TLS callbacks first. test it
