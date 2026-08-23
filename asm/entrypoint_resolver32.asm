; x86 entry-point resolver - dispatches to DllMain or OEP.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_32 / KS_OPT_SYNTAX_NASM).
;
; On entry: EBX = PE base (set by relocations_resolver32).
; Detects IMAGE_FILE_DLL and calls DllMain(base, DLL_PROCESS_ATTACH, NULL),
; otherwise jumps to AddressOfEntryPoint.

; Named constants
%define DLL_PROCESS_ATTACH 0x01
%define IMAGE_FILE_DLL     0x2000
%define EP_RVA_MAGIC       0xcececece    ; patched by peor: actual AddressOfEntryPoint RVA (or --entry override)

    mov esi, [ebx + 0x3C]
    add esi, ebx                         ; ESI = NT headers
    mov eax, EP_RVA_MAGIC                ; AddressOfEntryPoint RVA (patched by peor at conversion time)
    add eax, ebx                         ; EAX = OEP VA

    test word [esi + 0x16], IMAGE_FILE_DLL
    jz _exe_entry

    ; DLL: stdcall DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)
    push 0x00                            ; lpvReserved = NULL
    push DLL_PROCESS_ATTACH
    push ebx                             ; hinstDLL = PE base
    call eax                             ; DllMain(base, 1, NULL)
    hlt                                  ; DllMain should call ExitProcess; if not, halt

_exe_entry:
    jmp eax
