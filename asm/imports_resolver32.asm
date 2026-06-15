; x86 (32-bit) usermode import resolver - position-independent shellcode
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_32 / KS_OPT_SYNTAX_NASM).
;
; Algorithm:
;   1. PEB walk (FS:[0x30]) -> kernel32 base
;   2. Scan kernel32 export table for GetProcAddress, then get LoadLibraryA
;   3. Scan forward from current IP for "MZ" + "PE" signature
;   4. Walk IMAGE_IMPORT_DESCRIPTOR table; for each entry: LLA(dll), then GPA each thunk
;   5. POPA + RET (terminal byte stripped by peor so execution falls through to reloc resolver)
;
; Keystone notes:
;   - [fs:0x30] not supported: use "db 0x64" prefix before "mov eax, [0x30]"
;   - "db 'string'" not supported: use comma-separated char literals
;   - "js near label" not supported: use bare "js label" (keystone auto-selects encoding)

    pushad
    mov ebp, esp
    sub esp, 8                          ; [ebp-4] = GPA ptr, [ebp-8] = LLA ptr

    ; PEB walk -> kernel32 base in EBX
    ; "mov eax, [fs:0x30]" encoded as FS-prefix (0x64) + "mov eax, [0x30]"
    db 0x64
    mov eax, [0x30]                     ; EAX = PEB
    mov eax, [eax + 0x0C]              ; PEB.Ldr
    mov esi, [eax + 0x14]              ; InMemoryOrderModuleList.Flink
    mov esi, [esi]                      ; skip: exe
    mov esi, [esi]                      ; skip: ntdll -> next = kernel32
    mov ebx, [esi + 0x10]              ; kernel32 DllBase

    ; Locate kernel32 export directory
    mov eax, [ebx + 0x3C]              ; e_lfanew
    add eax, ebx                        ; NT headers VA
    mov eax, [eax + 0x78]              ; DataDir[0].VA = Export dir RVA (PE32: NT+0x78)
    add eax, ebx                        ; Export dir VA
    push eax                            ; save export dir on stack
    mov ecx, [eax + 0x18]              ; NumberOfNames
    mov edx, [eax + 0x20]              ; AddressOfNames RVA
    add edx, ebx                        ; AddressOfNames VA

    ; Embed "GetProcAddress\0" via CALL/POP
    call _gpa_str
    db 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0
_gpa_str:
    pop edi                             ; EDI = pointer to "GetProcAddress"

_gpa_loop:
    dec ecx
    js _done                            ; exhausted all names (keystone uses near form)
    mov esi, [edx + ecx * 4]           ; name RVA
    add esi, ebx                        ; name VA
    push esi
    push ecx
    push edi
    mov ecx, 0x0f                       ; len("GetProcAddress\0") = 15
    cld
    repe cmpsb
    pop edi
    pop ecx
    pop esi
    jnz _gpa_loop

    ; Name matched: resolve via ordinals table
    pop eax                             ; restore export dir ptr
    mov esi, [eax + 0x24]              ; AddressOfNameOrdinals RVA
    add esi, ebx
    movzx ecx, word [esi + ecx * 2]    ; ordinal = NameOrdinals[match_index]
    mov esi, [eax + 0x1C]              ; AddressOfFunctions RVA
    add esi, ebx
    mov eax, [esi + ecx * 4]           ; function RVA
    add eax, ebx                        ; function VA = GetProcAddress
    mov [ebp - 4], eax                  ; save GPA

    ; GetProcAddress(kernel32, "LoadLibraryA") -> EAX
    call _lla_str
    db 'L','o','a','d','L','i','b','r','a','r','y','A',0
_lla_str:
    pop ecx                             ; ECX = "LoadLibraryA"
    push ecx                            ; arg2: proc name
    push ebx                            ; arg1: kernel32 handle
    call [ebp - 4]                      ; GetProcAddress -> EAX = LoadLibraryA VA
    mov [ebp - 8], eax                  ; save LLA

    ; Scan forward from current IP for PE image (MZ + valid PE sig)
    call _here
_here:
    pop esi                             ; ESI = runtime address of this pop
    add esi, 0x100                      ; skip ahead past reloc/PE blob start

_scan_mz:
    inc esi
    cmp word [esi], 0x5A4D              ; "MZ" ?
    jnz _scan_mz
    mov eax, [esi + 0x3C]              ; e_lfanew
    lea edx, [esi + eax]               ; NT headers VA
    cmp dword [edx], 0x4550            ; "PE\0\0" ?
    jnz _scan_mz

    ; Walk IMAGE_IMPORT_DESCRIPTOR table
    mov eax, [esi + 0x3C]
    add eax, esi                        ; NT headers VA
    mov eax, [eax + 0x80]              ; DataDir[1].VA = Import dir RVA (PE32: NT+0x80)
    test eax, eax
    jz _done
    add eax, esi                        ; Import dir VA
    mov edi, eax                        ; EDI = current IMAGE_IMPORT_DESCRIPTOR

_desc_loop:
    mov eax, [edi + 0x0C]              ; Name RVA
    test eax, eax
    jz _done                            ; null descriptor = end of table
    add eax, esi                        ; Name VA
    push eax                            ; arg: dll name string
    call [ebp - 8]                      ; LoadLibraryA(dll_name) -> EAX = module handle
    test eax, eax
    jz _next_desc
    mov ebx, eax                        ; EBX = module handle

    ; Choose INT (OriginalFirstThunk) or fall back to FT (FirstThunk)
    mov edx, [edi]                      ; OriginalFirstThunk RVA
    test edx, edx
    jz _use_ft
    add edx, esi                        ; INT VA
    mov ecx, [edi + 0x10]              ; FirstThunk RVA
    add ecx, esi                        ; IAT VA
    jmp _thunk_loop

_use_ft:
    mov edx, [edi + 0x10]              ; FirstThunk RVA (use as both INT and IAT)
    add edx, esi
    mov ecx, edx

_thunk_loop:
    mov eax, [edx]                      ; 32-bit thunk entry
    test eax, eax
    jz _next_desc                       ; null = end of thunk array

    test eax, 0x80000000                ; ordinal import flag (bit 31)?
    jnz _by_ordinal

    ; Import by name
    push ecx                            ; save IAT ptr
    push edx                            ; save INT ptr
    add eax, esi                        ; VA of IMAGE_IMPORT_BY_NAME
    add eax, 2                          ; skip Hint WORD -> function name
    push eax                            ; arg2: name string
    push ebx                            ; arg1: module handle
    call [ebp - 4]                      ; GetProcAddress(module, name) -> EAX
    pop edx                             ; restore INT ptr
    pop ecx                             ; restore IAT ptr
    jmp _save_func

_by_ordinal:
    push ecx
    push edx
    and eax, 0x0000FFFF                 ; low 16 bits = ordinal number
    push eax                            ; arg2: ordinal
    push ebx                            ; arg1: module handle
    call [ebp - 4]                      ; GetProcAddress(module, ordinal) -> EAX
    pop edx
    pop ecx

_save_func:
    mov [ecx], eax                      ; write resolved address to IAT slot
    add edx, 4                          ; advance INT ptr
    add ecx, 4                          ; advance IAT ptr
    jmp _thunk_loop

_next_desc:
    add edi, 0x14                       ; next IMAGE_IMPORT_DESCRIPTOR (20 bytes)
    jmp _desc_loop

_done:
    mov esp, ebp
    popad
    ret                                 ; terminal byte - stripped by peor
