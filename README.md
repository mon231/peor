# PEOR - PortableExecutable Shellcodifier
This project is made to create embedded-shellcodes out of PE files. <br />

*NOTE* that `PEOR` isn't made to easily shellcodify Windows usermode-executables, <br />
As it won't resolve imports for you. For such features, use [pe2shellcode](https://github.com/hasherezade/pe_to_shellcode).

## What can PEOR do?
`PEOR` is the worst PE shellcodifier! ¡El peor del mundo! <br />
It won't resolve your imports, nor optimize your PE-sections. <br />
`PEOR` is intended to shellcodify PE-files for embedded usage, <br />
Thus not using allocations / setting page-protections for sections. <br />
You can use `PEOR` to shellcodify kernel modules, but `PEOR` won't resolve imports for you. <br />
You can use it to shellcodify uefi applications, but `PEOR` won't locate the EFI_SYSTEM_TABLE nor provide a image_handle to the entrypoint. <br />
You can use `PEOR` to write a simple piece of code, that compiles into a PE-file, and make a shellcode out of it. <br />
The resulted shellcode can be executed on any machine (as long as it has a x86/x64 cpu).

Advantages over normal pe-shellcodifiers:
- you can write your embedded-code once and execute it anywhere (windows usermode/kernel, linux, uefi, embedded-flash devices, ...)

Disadvanteges over normal pe-shellcodifiers:
- we only support embedded-code, thus custom features like `implicit imports` and `exceptions` are not supported by the shellcodifier, and should be implemented by the user, within the shellcode scope
- we can't trust the existence of allocation functions (like `VirtualAlloc` or `ExAllocatePoolWithTag`), thus the whole PE-file is resolved (including the bss sections!), highly increasing the shellcode size
- we can't assume that `PAGE-PROTECTION` concept even exists, thus `PEOR` assumes that the whole shellcode is mapped to `RWX` memory

## How to use PEOR?
Simply provide a PE-file whose code fits to your target platform (i.e. do not access `CR3` register from usermode context) and has no exceptions / implicit-imports. <br />
You may use exceptionless cpp-code using [`etl`](https://github.com/ETLCPP/etl), or rust-code with custom allocator. <br />
Simply install `PEOR` using `pip`:
```bash
pip install --upgrade peor
```

Then use it with an input PE-file:
```bash
peor -i my_pe.exe -o my_shellcode.bin
```
