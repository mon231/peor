; x64 entry-point resolver - dispatches to DllMain or OEP.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_64 / KS_OPT_SYNTAX_NASM).
;
; On entry: RBX = PE base (set by relocations_resolver64).
;           RSP = 8 (mod 16) - loader's return address is on the stack.
; Detects IMAGE_FILE_DLL and calls DllMain(base, DLL_PROCESS_ATTACH, NULL),
; otherwise jumps to AddressOfEntryPoint.

    mov esi, [rbx + 0x3C]
    add rsi, rbx                         ; RSI = NT headers
    mov eax, [rsi + 0x28]                ; AddressOfEntryPoint RVA
    add rax, rbx                         ; RAX = OEP VA
    push rax                             ; save OEP; RSP = 0 (mod 16)

    test word [rsi + 0x16], 0x2000       ; IMAGE_FILE_DLL?
    jz _exe_entry

    ; DLL: call DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)
    ; pop OEP first so shadow space + align works out.
    pop rax                              ; OEP = DllMain; RSP = 8 (mod 16)
    mov rcx, rbx                         ; arg1: hinstDLL = PE base
    mov edx, 1                           ; arg2: DLL_PROCESS_ATTACH
    xor r8d, r8d                         ; arg3: lpvReserved = NULL
    sub rsp, 0x28                        ; 32-byte shadow + 8-byte align; RSP = 0 (mod 16)
    call rax                             ; DllMain(base, DLL_PROCESS_ATTACH, NULL)
    add rsp, 0x28
    hlt                                  ; DllMain should call ExitProcess; if not, halt

_exe_entry:
    pop rax                              ; OEP; RSP = 8 (mod 16)
    jmp rax
