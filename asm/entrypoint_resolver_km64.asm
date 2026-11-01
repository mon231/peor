; x64 kernel-mode entrypoint resolver.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_64 / KS_OPT_SYNTAX_NASM).
;
; On entry: RBX = PE base (set by relocations_resolver64, which runs earlier in
; the chain). Driver images have no DllMain: DriverEntry(DriverObject,         RegistryPath) is the only entry.
; Calls DriverEntry(NULL, NULL), then restores the callee-save registers that
; the kernel chain's prologue pushed before the import resolver (see
; imports_resolver64_km.asm) and RETURNS DriverEntry's NTSTATUS to the loader.
;
; Stack contract: the 8 prologue pushes (RBX/RBP/RSI/RDI/R12-R15) are still on
; the stack below everything this stub does; the final pops unwind them in
; reverse order so `ret` lands back in the kernel loader.

%define EP_RVA_MAGIC        0xcececece  ; patched by peor: DriverEntry RVA
%define E_LFANEW_OFFSET     0x3C        ; DOS header e_lfanew offset
%define SHADOW_SPACE        0x28        ; 32-byte shadow + 8-byte alignment

    mov  esi, dword [rbx + E_LFANEW_OFFSET]
    add  rsi, rbx                        ; RSI = NT headers
    mov  eax, EP_RVA_MAGIC               ; DriverEntry RVA (patched at build time)
    add  rax, rbx                        ; RAX = DriverEntry VA

    xor  ecx, ecx                        ; arg1: DriverObject = NULL
    xor  edx, edx                        ; arg2: RegistryPath = NULL
    sub  rsp, SHADOW_SPACE
    call rax                             ; DriverEntry(NULL, NULL) -> NTSTATUS
    add  rsp, SHADOW_SPACE

    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbp
    pop  rbx
    ret                                  ; NTSTATUS to the kernel-mode loader
