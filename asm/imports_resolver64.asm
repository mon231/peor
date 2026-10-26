; x64 (64-bit) usermode import resolver - position-independent shellcode
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_64 / KS_OPT_SYNTAX_NASM).
;
; Algorithm:
;   1. PEB walk (GS:[0x60]) -> kernel32 base
;   2. Scan kernel32 export table for GetProcAddress (into R12), then get LoadLibraryA (into R13)
;   3. Scan forward from current IP for "MZ" + "PE" signature -> PE base in R14
;   4. Walk IMAGE_IMPORT_DESCRIPTOR; for each DLL: LLA then GPA each thunk into IAT (R15)
;   5. Restore non-volatile regs + JMP RAX (terminal bytes stripped by peor)
;
; Register map (non-volatile, callee-saved across CALL):
;   RBX = kernel32 base (phase 1/2), then current DLL module handle (phase 4)
;   RBP = kernel32 export directory VA (phase 2)
;   R12 = GetProcAddress VA
;   R13 = LoadLibraryA VA
;   R14 = PE image base
;   R15 = current IAT slot pointer
;   RSI = INT/FT walk pointer
;   RDI = current IMAGE_IMPORT_DESCRIPTOR pointer
;
; Keystone notes:
;   - [gs:0x60] not supported: use "db 0x65" prefix before "mov rax, [0x60]"
;   - "db 'string'" not supported: use comma-separated char literals
;   - "js near label" not supported: use bare "js label"

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
    ; "mov rax, [gs:0x60]" encoded as GS-prefix (0x65) + "mov rax, [0x60]"
    db 0x65
    mov rax, [0x60]                     ; RAX = PEB
    mov rax, [rax + 0x18]              ; PEB.Ldr
    mov rsi, [rax + 0x20]              ; InMemoryOrderModuleList.Flink
    mov rsi, [rsi]                      ; skip: exe
    mov rsi, [rsi]                      ; skip: ntdll -> next = kernel32
    mov rbx, [rsi + 0x20]              ; kernel32 DllBase (InMemoryOrder+0x20 = struct+0x30)

    ; Locate kernel32 export directory
    mov eax, [rbx + 0x3C]              ; e_lfanew (32-bit, zero-extends)
    add rax, rbx                        ; NT headers VA
    mov eax, [rax + 0x88]              ; DataDir[0].VA = Export dir RVA (PE64: NT+0x88)
    add rax, rbx                        ; Export dir VA
    mov rbp, rax                        ; RBP = export dir
    mov ecx, [rax + 0x18]              ; NumberOfNames
    mov edx, [rax + 0x20]              ; AddressOfNames RVA
    add rdx, rbx                        ; AddressOfNames VA

    ; Embed "GetProcAddress\0" via CALL/POP
    call _gpa_str
    db 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0
_gpa_str:
    pop rdi                             ; RDI = pointer to "GetProcAddress"

_gpa_loop:
    dec ecx
    js _done                            ; exhausted all names (keystone uses near form)
    mov esi, [rdx + rcx * 4]           ; name RVA (32-bit)
    add rsi, rbx                        ; name VA
    push rsi
    push rcx
    push rdx
    push rdi
    mov ecx, 0x0f                       ; len("GetProcAddress\0") = 15
    cld
    repe cmpsb
    pop rdi
    pop rdx
    pop rcx
    pop rsi
    jnz _gpa_loop

    ; Name matched: resolve ordinal -> function address
    mov esi, [rbp + 0x24]              ; AddressOfNameOrdinals RVA
    add rsi, rbx
    movzx ecx, word [rsi + rcx * 2]    ; ordinal = NameOrdinals[match_index]
    mov esi, [rbp + 0x1C]              ; AddressOfFunctions RVA
    add rsi, rbx
    mov eax, [rsi + rcx * 4]           ; function RVA
    add rax, rbx                        ; function VA = GetProcAddress
    mov r12, rax                        ; R12 = GetProcAddress

    ; GetProcAddress(kernel32, "LoadLibraryA") -> R13
    call _lla_str
    db 'L','o','a','d','L','i','b','r','a','r','y','A',0
_lla_str:
    pop rdx                             ; RDX = "LoadLibraryA" (arg2)
    mov rcx, rbx                        ; RCX = kernel32 handle (arg1)
    call r12                            ; GetProcAddress(kernel32, "LoadLibraryA")
    mov r13, rax                        ; R13 = LoadLibraryA VA

    ; Scan forward from current IP for PE image (MZ + valid PE sig)
    call _here
_here:
    pop rsi                             ; RSI = runtime address of this pop
    add rsi, 0x100                      ; skip ahead past reloc/PE blob start

_scan_mz:
    inc rsi
    cmp word [rsi], 0x5A4D              ; "MZ" ?
    jnz _scan_mz
    mov eax, [rsi + 0x3C]              ; e_lfanew
    cmp eax, 0x400                      ; reject false positives with huge e_lfanew
    ja _scan_mz
    lea rdx, [rsi + rax]               ; NT headers VA
    cmp dword [rdx], 0x4550            ; "PE\0\0" ?
    jnz _scan_mz

    mov r14, rsi                        ; R14 = PE image base

    ; Walk IMAGE_IMPORT_DESCRIPTOR table
    mov eax, [rsi + 0x3C]
    add rax, rsi                        ; NT headers VA
    mov eax, [rax + 0x90]              ; DataDir[1].VA = Import dir RVA (PE64: NT+0x90)
    test eax, eax
    jz _done
    add rax, r14                        ; Import dir VA
    mov rdi, rax                        ; RDI = current IMAGE_IMPORT_DESCRIPTOR

_desc_loop:
    mov eax, [rdi + 0x0C]              ; Name RVA
    test eax, eax
    jz _done                            ; null descriptor = end of table
    add rax, r14                        ; Name VA
    mov rcx, rax                        ; arg1: dll name string
    call r13                            ; LoadLibraryA(dll_name) -> RAX = module handle
    test rax, rax
    jz _next_desc
    mov rbx, rax                        ; RBX = module handle

    ; Choose INT (OriginalFirstThunk) or fall back to FT (FirstThunk)
    mov esi, [rdi]                      ; OriginalFirstThunk RVA (32-bit)
    test rsi, rsi
    jz _use_ft
    add rsi, r14                        ; RSI = INT VA
    mov eax, [rdi + 0x10]              ; FirstThunk RVA
    add rax, r14                        ; IAT VA
    mov r15, rax                        ; R15 = IAT ptr
    jmp _thunk_loop

_use_ft:
    mov esi, [rdi + 0x10]              ; FirstThunk RVA
    add rsi, r14
    mov r15, rsi                        ; R15 = IAT ptr (same as INT ptr)

_thunk_loop:
    mov rax, [rsi]                      ; 64-bit thunk entry
    test rax, rax
    jz _next_desc                       ; null = end of thunk array

    test rax, rax                       ; check sign bit (bit 63 = ordinal flag in x64 thunks)
    js _by_ordinal

    ; Import by name: RAX = RVA of IMAGE_IMPORT_BY_NAME
    add rax, r14                        ; VA of IMAGE_IMPORT_BY_NAME
    add rax, 0x02                       ; skip Hint WORD -> function name string
    mov rdx, rax                        ; arg2: name string
    mov rcx, rbx                        ; arg1: module handle
    call r12                            ; GetProcAddress(module, name) -> RAX
    jmp _save_func

_by_ordinal:
    and rax, 0x0000FFFF                 ; low 16 bits = ordinal number
    mov rdx, rax                        ; arg2: ordinal
    mov rcx, rbx                        ; arg1: module handle
    call r12                            ; GetProcAddress(module, ordinal) -> RAX

_save_func:
    mov [r15], rax                      ; write resolved address to IAT slot (64-bit)
    add rsi, 0x08                       ; advance INT ptr (8-byte thunk entry)
    add r15, 0x08                       ; advance IAT ptr
    jmp _thunk_loop

_next_desc:
    add rdi, 0x14                       ; next IMAGE_IMPORT_DESCRIPTOR (20 bytes)
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
