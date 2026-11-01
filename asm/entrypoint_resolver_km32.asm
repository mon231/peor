; x86 (32-bit) kernel-mode entrypoint resolver.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_32 / KS_OPT_SYNTAX_NASM).
;
; On entry: EBX = PE base (set by relocations_resolver32, which runs earlier in
; the chain). Driver images have no DllMain: DriverEntry(DriverObject,
; RegistryPath) is the only entry. Calls DriverEntry(NULL, NULL), then restores
; the callee-save registers that the kernel chain's prologue pushed before the
; import resolver (see imports_resolver32_km.asm) and RETURNS DriverEntry's
; NTSTATUS to the loader.
;
; Stack contract: the 4 prologue pushes (EBX/EBP/ESI/EDI) are still on the
; stack below everything this stub does; the final pops unwind them in reverse
; order so `ret` lands back in the kernel loader. DriverEntry is __stdcall on
; x86, so it cleans its own two arguments off the stack.

%define EP_RVA_MAGIC        0xcececece  ; patched by peor: DriverEntry RVA
%define E_LFANEW_OFFSET     0x3C        ; DOS header e_lfanew offset
%define NTAPI_ARGUMENTS     0x08        ; stdcall: 2 stack arguments

    mov  esi, dword [ebx + E_LFANEW_OFFSET]
    add  esi, ebx                        ; ESI = NT headers
    mov  eax, EP_RVA_MAGIC               ; DriverEntry RVA (patched at build time)
    add  eax, ebx                        ; EAX = DriverEntry VA

    push 0                               ; arg2: RegistryPath = NULL
    push 0                               ; arg1: DriverObject = NULL
    call eax                             ; DriverEntry(NULL, NULL) -> NTSTATUS
    add  esp, NTAPI_ARGUMENTS            ; no-op for stdcall, kept defensive

    pop  edi
    pop  esi
    pop  ebp
    pop  ebx
    ret                                  ; NTSTATUS to the kernel-mode loader
