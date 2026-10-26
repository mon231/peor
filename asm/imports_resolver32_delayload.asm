; x86 (32-bit) delay-load import resolver - position-independent shellcode
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_32 / KS_OPT_SYNTAX_NASM).
;
; Algorithm:
;   1. PEB walk (FS:[0x30]) -> kernel32 base -> GetProcAddress -> LoadLibraryA
;   2. Scan forward from current IP for "MZ"+"PE" -> PE base in ESI
;   3. Walk IMAGE_DELAY_IMPORT_DESCRIPTORs in DataDir[13]; for each: LLA then GPA each INT entry
;   4. RET (terminal byte stripped by peor so execution falls through to relocs resolver)
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
; DataDir[13] for PE32: NT_headers + 0xE0
;   DataDir[0] at NT+0x78; DataDir[13] at NT+0x78+13*8 = NT+0xE0
;
; Keystone notes:
;   - [fs:0x30] not supported: use "db 0x64" before "mov eax, [0x30]"
;   - bare decimal literals treated as hex by Keystone NASM mode; use 0x prefix

; Named constants
%define DELAY_DATADIR_OFF      0xe0       ; offset of DataDir[13].RVA from NT headers (PE32)
%define DELAY_NAME_RVA_OFF     0x04       ; ImgDelayDescr.rvaDLLName
%define DELAY_IAT_RVA_OFF      0x0c       ; ImgDelayDescr.rvaIAT
%define DELAY_INT_RVA_OFF      0x10       ; ImgDelayDescr.rvaINT
%define DELAY_DESCR_SIZE       0x20       ; sizeof(ImgDelayDescr) = 32 bytes
%define IMAGE_ORDINAL_FLAG32   0x80000000 ; bit 31 = ordinal import flag (x86)

    pushad
    mov ebp, esp
    sub esp, 0x08                       ; [ebp-4] = GPA ptr, [ebp-8] = LLA ptr

    ; PEB walk -> kernel32 base in EBX
    db 0x64
    mov eax, [0x30]                     ; EAX = PEB  (FS:[0x30])
    mov eax, [eax + 0x0c]              ; PEB.Ldr
    mov esi, [eax + 0x14]              ; InMemoryOrderModuleList.Flink
    mov esi, [esi]                      ; skip: exe
    mov esi, [esi]                      ; skip: ntdll -> kernel32
    mov ebx, [esi + 0x10]              ; kernel32 DllBase

    ; Locate kernel32 export directory
    mov eax, [ebx + 0x3c]
    add eax, ebx                        ; NT headers VA
    mov eax, [eax + 0x78]              ; DataDir[0] RVA (export dir, PE32: NT+0x78)
    add eax, ebx                        ; Export dir VA
    push eax                            ; save export dir
    mov ecx, [eax + 0x18]              ; NumberOfNames
    mov edx, [eax + 0x20]
    add edx, ebx                        ; AddressOfNames VA

    ; Embed "GetProcAddress\0" via CALL/POP
    call _gpa_str
    db 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0
_gpa_str:
    pop edi                             ; EDI = &"GetProcAddress"

_gpa_loop:
    dec ecx
    js _done                            ; exhausted names without a match
    mov esi, [edx + ecx * 4]
    add esi, ebx                        ; candidate name VA
    push esi
    push ecx
    push edi
    mov ecx, 0x0f                       ; compare 15 bytes including NUL
    cld
    repe cmpsb
    pop edi
    pop ecx
    pop esi
    jnz _gpa_loop

    pop eax                             ; export dir (success path)
    mov esi, [eax + 0x24]
    add esi, ebx                        ; AddressOfNameOrdinals VA
    movzx ecx, word [esi + ecx * 2]    ; ordinal
    mov esi, [eax + 0x1c]
    add esi, ebx                        ; AddressOfFunctions VA
    mov eax, [esi + ecx * 4]
    add eax, ebx                        ; GetProcAddress VA
    mov [ebp - 4], eax                  ; save GPA

    ; GetProcAddress(kernel32, "LoadLibraryA") -> EAX
    call _lla_str
    db 'L','o','a','d','L','i','b','r','a','r','y','A',0
_lla_str:
    pop ecx                             ; ECX = "LoadLibraryA"
    push ecx
    push ebx
    call [ebp - 4]                      ; GetProcAddress -> EAX = LoadLibraryA VA
    mov [ebp - 8], eax                  ; save LLA

    ; Scan forward from current IP for PE image (MZ + valid PE sig)
    call _here
_here:
    pop esi                             ; ESI = runtime address of this pop
    add esi, 0x100                      ; skip ahead past reloc/PE blob start

_scan_mz:
    inc esi
    cmp word [esi], 0x5a4d              ; "MZ" ?
    jnz _scan_mz
    mov eax, [esi + 0x3c]              ; e_lfanew
    cmp eax, 0x400                      ; reject false positives with huge e_lfanew
    ja _scan_mz
    lea edx, [esi + eax]               ; NT headers VA
    cmp dword [edx], 0x4550            ; "PE\0\0" ?
    jnz _scan_mz
    ; ESI = PE base

    ; Walk DataDir[13] (delay-load descriptor table)
    mov eax, [esi + 0x3c]
    add eax, esi                        ; NT headers VA
    mov eax, [eax + DELAY_DATADIR_OFF] ; DataDir[13].RVA
    test eax, eax
    jz _done
    add eax, esi                        ; delay-load descriptor table VA
    mov edi, eax                        ; EDI = current ImgDelayDescr*

_desc_loop:
    mov eax, [edi + DELAY_NAME_RVA_OFF]
    test eax, eax
    jz _done                            ; null rvaDLLName = end of table
    add eax, esi                        ; DLL name VA (grAttrs=1, RVA-based)
    push eax
    call [ebp - 8]                      ; LoadLibraryA(dll_name) -> EAX
    test eax, eax
    jz _next_desc
    mov ebx, eax                        ; EBX = module handle

    mov edx, [edi + DELAY_INT_RVA_OFF]  ; rvaINT
    test edx, edx
    jz _next_desc
    add edx, esi                        ; INT VA
    mov ecx, [edi + DELAY_IAT_RVA_OFF]
    add ecx, esi                        ; delay-load IAT VA

_thunk_loop:
    mov eax, [edx]
    test eax, eax
    jz _next_desc                       ; null entry = end of thunk array

    test eax, IMAGE_ORDINAL_FLAG32
    jnz _by_ordinal

    ; Import by name
    push ecx
    push edx
    add eax, esi                        ; IMAGE_IMPORT_BY_NAME VA
    add eax, 0x02                       ; skip Hint WORD -> function name
    push eax
    push ebx
    call [ebp - 4]                      ; GetProcAddress(module, name) -> EAX
    pop edx
    pop ecx
    jmp _save_func

_by_ordinal:
    push ecx
    push edx
    and eax, 0x0000ffff                 ; low 16 bits = ordinal number
    push eax
    push ebx
    call [ebp - 4]                      ; GetProcAddress(module, ordinal) -> EAX
    pop edx
    pop ecx

_save_func:
    mov [ecx], eax                      ; write resolved VA to delay-load IAT slot (32-bit)
    add edx, 0x04                       ; advance INT ptr (4-byte thunk)
    add ecx, 0x04                       ; advance IAT ptr
    jmp _thunk_loop

_next_desc:
    add edi, DELAY_DESCR_SIZE
    jmp _desc_loop

_done:
    mov esp, ebp
    popad
    ret                                 ; terminal byte - stripped by peor
