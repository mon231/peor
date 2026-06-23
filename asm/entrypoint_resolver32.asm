; x86 entry-point resolver - dispatches to DllMain or OEP.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_32 / KS_OPT_SYNTAX_NASM).
;
; On entry: EBX = PE base (set by relocations_resolver32).
; Detects IMAGE_FILE_DLL and calls DllMain(base, DLL_PROCESS_ATTACH, NULL),
; otherwise jumps to AddressOfEntryPoint.

    mov esi, [ebx + 0x3C]
    add esi, ebx                         ; ESI = NT headers
    mov eax, [esi + 0x28]                ; AddressOfEntryPoint RVA
    add eax, ebx                         ; EAX = OEP VA

    test word [esi + 0x16], 0x2000       ; IMAGE_FILE_DLL?
    jz _exe_entry

    ; DLL: stdcall DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)
    push 0                               ; lpvReserved = NULL
    push 1                               ; DLL_PROCESS_ATTACH
    push ebx                             ; hinstDLL = PE base
    call eax                             ; DllMain(base, 1, NULL)
    hlt                                  ; DllMain should call ExitProcess; if not, halt

_exe_entry:
    jmp eax
