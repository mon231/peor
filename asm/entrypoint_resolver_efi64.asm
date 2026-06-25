; x64 EFI entry-point resolver - calls PE entry with NULL ImageHandle/SystemTable.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_64 / KS_OPT_SYNTAX_NASM).
;
; On entry: RBX = PE base (set by relocations_resolver64).
;           RSP = 8 (mod 16) - loader's return address is on the stack.
; Calls efi_main(NULL, NULL) using the MSABI (EFI calling convention on x86-64).
; Returns the EFI_STATUS (RAX) to the caller.

; Named constants
%define EP_RVA_MAGIC    0xcececece    ; patched by peor: actual AddressOfEntryPoint RVA
%define EFI_IMAGE_FILE_DLL  0x2000   ; IMAGE_FILE_DLL flag in FileHeader.Characteristics

    mov esi, [rbx + 0x3C]
    add rsi, rbx                     ; RSI = NT headers
    mov eax, EP_RVA_MAGIC            ; AddressOfEntryPoint RVA (patched by peor)
    add rax, rbx                     ; RAX = entry point VA

    ; EFI entry signature (MSABI): EFI_STATUS efi_main(EFI_HANDLE, EFI_SYSTEM_TABLE*)
    ; Pass NULL for both arguments (no EFI system table needed for our test)
    sub rsp, 0x28                    ; 32-byte MSABI shadow space + 8-byte align; RSP = 0 (mod 16)
    xor ecx, ecx                     ; arg1: ImageHandle = NULL
    xor edx, edx                     ; arg2: SystemTable = NULL
    call rax                         ; efi_main(NULL, NULL)
    add rsp, 0x28
    ret
