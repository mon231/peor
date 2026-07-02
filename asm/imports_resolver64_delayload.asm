; x64 (64-bit) delay-load import resolver - position-independent shellcode
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_64 / KS_OPT_SYNTAX_NASM).
;
; Algorithm:
;   1. PEB walk (GS:[0x60]) -> kernel32 base -> GetProcAddress (R12) -> LoadLibraryA (R13)
;   2. Scan forward from current IP for "MZ"+"PE" -> PE base in R14
;   3. Walk IMAGE_DELAY_IMPORT_DESCRIPTORs in DataDir[13]; for each: LLA then GPA each INT entry
;   4. JMP RAX (terminal bytes stripped by peor so execution falls through to relocs resolver)
;
; ImgDelayDescr layout (grAttrs=1, RVA format, modern MSVC):
;   +0x00 DWORD grAttrs         (1 = RVA format)
;   +0x04 DWORD rvaDLLName      (RVA of DLL name string)
;   +0x08 DWORD rvaHmod         (RVA of module handle slot)
;   +0x0C DWORD rvaIAT          (RVA of delay-load IAT)
;   +0x10 DWORD rvaINT          (RVA of delay-load INT/import name table)
;   +0x14 DWORD rvaBoundIAT
;   +0x18 DWORD rvaUnloadIAT
;   +0x1C DWORD dwTimeStamp
;   Total: 0x20 bytes
;
; DataDir[13] for PE32+: NT_headers + 0xF0
;   DataDir[0] at NT+0x88; DataDir[13] at NT+0x88+13*8 = NT+0xF0
;
; Register map (non-volatile, callee-saved across CALL):
;   RBX = kernel32 base (phase 1/2), then current DLL module handle (phase 3)
;   RBP = kernel32 export directory VA (phase 2)
;   R12 = GetProcAddress VA
;   R13 = LoadLibraryA VA
;   R14 = PE image base
;   R15 = current delay-load IAT slot pointer
;   RSI = INT walk pointer
;   RDI = current ImgDelayDescr pointer
;
; Keystone notes:
;   - [gs:0x60] not supported: use "db 0x65" prefix before "mov rax, [0x60]"

; Named constants
%define DELAY_DATADIR_OFF      0xf0       ; offset of DataDir[13].RVA from NT headers (PE32+)
%define DELAY_NAME_RVA_OFF     0x04       ; ImgDelayDescr.rvaDLLName
%define DELAY_IAT_RVA_OFF      0x0c       ; ImgDelayDescr.rvaIAT
%define DELAY_INT_RVA_OFF      0x10       ; ImgDelayDescr.rvaINT
%define DELAY_DESCR_SIZE       0x20       ; sizeof(ImgDelayDescr) = 32 bytes

    push rsi
    push rdi
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0x28                       ; 32-byte shadow + 8 align (8 pushes=64 -> RSP 0 mod 16)

    ; PEB walk -> kernel32 base in RBX
    db 0x65
    mov rax, [0x60]                     ; RAX = PEB
    mov rax, [rax + 0x18]              ; PEB.Ldr
    mov rsi, [rax + 0x20]              ; InMemoryOrderModuleList.Flink
    mov rsi, [rsi]                      ; skip: exe
    mov rsi, [rsi]                      ; skip: ntdll -> kernel32
    mov rbx, [rsi + 0x20]              ; kernel32 DllBase (InMemoryOrder+0x20 = struct+0x30)

    ; Locate kernel32 export directory
    mov eax, [rbx + 0x3c]              ; e_lfanew (32-bit, zero-extends)
    add rax, rbx                        ; NT headers VA
    mov eax, [rax + 0x88]              ; DataDir[0].VA (export dir RVA, PE64: NT+0x88)
    add rax, rbx                        ; Export dir VA
    mov rbp, rax                        ; RBP = export dir
    mov ecx, [rax + 0x18]              ; NumberOfNames
    mov edx, [rax + 0x20]
    add rdx, rbx                        ; AddressOfNames VA

    ; Embed "GetProcAddress\0" via CALL/POP
    call _gpa_str
    db 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0
_gpa_str:
    pop rdi                             ; RDI = &"GetProcAddress"

_gpa_loop:
    dec ecx
    js _done
    mov esi, [rdx + rcx * 4]
    add rsi, rbx                        ; candidate name VA
    push rsi
    push rcx
    push rdx
    push rdi
    mov ecx, 0x0f                       ; compare 15 bytes including NUL
    cld
    repe cmpsb
    pop rdi
    pop rdx
    pop rcx
    pop rsi
    jnz _gpa_loop

    ; Name matched: resolve ordinal -> VA
    mov esi, [rbp + 0x24]
    add rsi, rbx                        ; AddressOfNameOrdinals VA
    movzx ecx, word [rsi + rcx * 2]    ; ordinal
    mov esi, [rbp + 0x1c]
    add rsi, rbx                        ; AddressOfFunctions VA
    mov eax, [rsi + rcx * 4]
    add rax, rbx                        ; GetProcAddress VA
    mov r12, rax                        ; R12 = GetProcAddress

    ; GetProcAddress(kernel32, "LoadLibraryA") -> R13
    call _lla_str
    db 'L','o','a','d','L','i','b','r','a','r','y','A',0
_lla_str:
    pop rdx                             ; RDX = "LoadLibraryA" (arg2)
    mov rcx, rbx                        ; RCX = kernel32 handle (arg1)
    call r12                            ; GetProcAddress -> RAX = LoadLibraryA VA
    mov r13, rax                        ; R13 = LoadLibraryA

    ; Scan forward from current IP for PE image (MZ + valid PE sig)
    call _here
_here:
    pop rsi                             ; RSI = runtime address of this pop
    add rsi, 0x100                      ; skip ahead past reloc/PE blob start

_scan_mz:
    inc rsi
    cmp word [rsi], 0x5a4d              ; "MZ" ?
    jnz _scan_mz
    mov eax, [rsi + 0x3c]              ; e_lfanew
    cmp eax, 0x400                      ; reject false positives with huge e_lfanew
    ja _scan_mz
    lea rdx, [rsi + rax]               ; NT headers VA
    cmp dword [rdx], 0x4550            ; "PE\0\0" ?
    jnz _scan_mz
    mov r14, rsi                        ; R14 = PE image base

    ; Walk DataDir[13] (delay-load descriptor table)
    mov eax, [rsi + 0x3c]
    add rax, rsi                        ; NT headers VA
    mov eax, [rax + DELAY_DATADIR_OFF] ; DataDir[13].RVA (32-bit, zero-extends)
    test eax, eax
    jz _done
    add rax, r14                        ; delay-load descriptor table VA
    mov rdi, rax                        ; RDI = current ImgDelayDescr*

_desc_loop:
    mov eax, [rdi + DELAY_NAME_RVA_OFF]
    test eax, eax
    jz _done                            ; null rvaDLLName = end of table
    add rax, r14                        ; DLL name VA (grAttrs=1, RVA-based)
    mov rcx, rax                        ; arg1: dll name string
    call r13                            ; LoadLibraryA(dll_name) -> RAX
    test rax, rax
    jz _next_desc
    mov rbx, rax                        ; RBX = module handle

    mov esi, [rdi + DELAY_INT_RVA_OFF]  ; rvaINT (32-bit)
    test rsi, rsi
    jz _next_desc
    add rsi, r14                        ; INT VA
    mov eax, [rdi + DELAY_IAT_RVA_OFF]
    add rax, r14                        ; delay-load IAT VA
    mov r15, rax                        ; R15 = IAT ptr

_thunk_loop:
    mov rax, [rsi]                      ; 64-bit thunk entry
    test rax, rax
    jz _next_desc                       ; null = end of thunk array

    test rax, rax                       ; check sign bit (bit 63 = ordinal flag in x64 thunks)
    js _by_ordinal

    ; Import by name: RAX = RVA of IMAGE_IMPORT_BY_NAME
    add rax, r14                        ; IMAGE_IMPORT_BY_NAME VA
    add rax, 0x02                       ; skip Hint WORD -> function name
    mov rdx, rax                        ; arg2: name string
    mov rcx, rbx                        ; arg1: module handle
    call r12                            ; GetProcAddress(module, name) -> RAX
    jmp _save_func

_by_ordinal:
    and rax, 0x0000ffff                 ; low 16 bits = ordinal number
    mov rdx, rax                        ; arg2: ordinal
    mov rcx, rbx                        ; arg1: module handle
    call r12                            ; GetProcAddress(module, ordinal) -> RAX

_save_func:
    mov [r15], rax                      ; write resolved VA to delay-load IAT slot (64-bit)
    add rsi, 0x08                       ; advance INT ptr (8-byte thunk)
    add r15, 0x08                       ; advance IAT ptr
    jmp _thunk_loop

_next_desc:
    add rdi, DELAY_DESCR_SIZE
    jmp _desc_loop

_done:
    add rsp, 0x28
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop rdi
    pop rsi
    jmp rax                             ; terminal bytes (ff e0) - stripped by peor
