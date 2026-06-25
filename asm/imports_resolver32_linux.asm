; x86 Linux usermode import resolver - self-contained dlsym/dlopen finder.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_32 / KS_OPT_SYNTAX_NASM).
;
; Uses int 0x80 syscalls (open=5, read=3, close=6) and ELF32 structures.
; Calling convention for dlopen/dlsym: IA-32 System V cdecl (args on stack).
; Falls through to relocs resolver; terminal RET (C3) stripped by peor.

%define SYS32_OPEN                  0x05
%define SYS32_READ                  0x03
%define SYS32_CLOSE                 0x06
%define O_RDONLY                    0x00
%define RTLD_DEFAULT                0x00
%define RTLD_LAZY                   0x01

%define ELF_MAGIC                   0x464C457F
%define PT_DYNAMIC                  0x02
%define DT_HASH                     0x04
%define DT_STRTAB                   0x05
%define DT_SYMTAB                   0x06
%define ELF32_EHDR_PHOFF            0x1C
%define ELF32_EHDR_PHENTSIZE        0x2A
%define ELF32_EHDR_PHNUM            0x2C
%define ELF32_PHDR_TYPE             0x00
%define ELF32_PHDR_VADDR            0x08
%define ELF32_PHDR_SIZE             0x20
%define ELF32_DYN_SIZE              0x08
%define ELF32_SYM_ST_VALUE          0x04
%define ELF32_SYM_SIZE              0x10
%define ELF_HASH_NCHAIN_OFF         0x04
%define MAX_SYM_SCAN                0x8000
%define MAPS_BUF_SIZE               0x2000

%define IMAGE_IMPORT_DESC_SIZE      0x14
%define IAT_SLOT_SIZE               0x04
%define IMPORT_BY_NAME_HINT_SIZE    0x02
%define E_LFANEW_OFFSET             0x3C
%define PE_SIGNATURE_DWORD          0x4550
%define MZ_SIGNATURE_WORD           0x5A4D
%define NT32_IMPORT_DIR_RVA_OFF     0x80
%define MAX_E_LFANEW                0x400
%define IMPORT_DESC_INT_RVA_OFF     0x00
%define IMPORT_DESC_NAME_RVA_OFF    0x0C
%define IMPORT_DESC_FT_RVA_OFF      0x10
%define ORDINAL_FLAG32              0x80000000

; String offsets from embedded table base
%define STR_PROC_SELF_MAPS          0
%define STR_DLOPEN                  16
%define STR_DLSYM                   23
%define STR_LIBC_SO                 29

    push ebp
    push ebx
    push esi
    push edi
    sub esp, 0x10               ; local slots: [esp+0]=dlopen, [esp+4]=dlsym, [esp+8]=libc_base, [esp+0xC]=spare

    ; Get string table base via call-over-data trick.
    ; keystone NASM does not support db "string"; use explicit hex bytes.
    call _after_strings
    ; "/proc/self/maps\0"  (STR_PROC_SELF_MAPS = 0, 16 bytes)
    db 0x2F,0x70,0x72,0x6F,0x63,0x2F,0x73,0x65,0x6C,0x66,0x2F,0x6D,0x61,0x70,0x73,0x00
    ; "dlopen\0"           (STR_DLOPEN = 16, 7 bytes)
    db 0x64,0x6C,0x6F,0x70,0x65,0x6E,0x00
    ; "dlsym\0"            (STR_DLSYM = 23, 6 bytes)
    db 0x64,0x6C,0x73,0x79,0x6D,0x00
    ; "libc.so\0"          (STR_LIBC_SO = 29, 8 bytes)
    db 0x6C,0x69,0x62,0x63,0x2E,0x73,0x6F,0x00
_after_strings:
    pop esi                     ; ESI = &strings[0]

    ; Allocate maps buffer on stack
    sub esp, MAPS_BUF_SIZE

    ; -- Open /proc/self/maps (sys_open: int 0x80, eax=5) ---------------------
    lea ebx, [esi + STR_PROC_SELF_MAPS]
    xor ecx, ecx                ; O_RDONLY
    xor edx, edx
    mov eax, SYS32_OPEN
    int 0x80
    test eax, eax
    js _find_done32

    mov ebx, eax                ; EBX = fd

    ; -- Read maps into buffer (sys_read: int 0x80, eax=3) --------------------
    mov ecx, esp                ; buffer
    mov edx, MAPS_BUF_SIZE
    mov eax, SYS32_READ
    int 0x80
    mov edi, eax                ; EDI = bytes_read (temp)

    ; -- Close fd (sys_close: int 0x80, eax=6) --------------------------------
    mov eax, SYS32_CLOSE
    int 0x80                    ; EBX still = fd

    test edi, edi
    js _find_done32

    ; Null-terminate buffer
    cmp edi, MAPS_BUF_SIZE
    jae _scan_maps32
    mov byte [esp + edi], 0

_scan_maps32:
    ; -- Scan buffer for "libc.so" ---------------------------------------------
    mov ebx, esp
    lea ecx, [esp + MAPS_BUF_SIZE - 7]
_scan_byte32:
    cmp ebx, ecx
    jae _find_done32
    cmp dword [ebx], 0x6362696C ; "libc"
    jne _next_byte32
    cmp byte [ebx + 4], 0x2E
    jne _next_byte32
    cmp byte [ebx + 5], 0x73
    jne _next_byte32
    cmp byte [ebx + 6], 0x6F
    jne _next_byte32
    jmp _found_libc32
_next_byte32:
    inc ebx
    jmp _scan_byte32

_found_libc32:
    mov ecx, ebx
_back_nl32:
    cmp ecx, esp
    je _parse_base32
    dec ecx
    cmp byte [ecx], 0x0A
    jne _back_nl32
    inc ecx
_parse_base32:
    xor ebx, ebx
_parse_hex32:
    movzx eax, byte [ecx]
    cmp al, 0x2D
    je _hex_done32
    cmp al, 0x61
    jae _hex_alpha32
    cmp al, 0x30
    jb _hex_done32
    cmp al, 0x39
    ja _hex_done32
    sub al, 0x30
    jmp _hex_add32
_hex_alpha32:
    cmp al, 0x66
    ja _hex_done32
    sub al, 0x57
_hex_add32:
    shl ebx, 4
    or ebx, eax
    inc ecx
    jmp _parse_hex32
_hex_done32:
    test ebx, ebx
    jz _find_done32

    ; Verify ELF magic
    cmp dword [ebx], ELF_MAGIC
    jne _find_done32

    ; -- Walk ELF32 phdrs for PT_DYNAMIC --------------------------------------
    ; EBX = libc base
    mov eax, [ebx + ELF32_EHDR_PHOFF]
    add eax, ebx                ; EAX = first phdr VA
    movzx ecx, word [ebx + ELF32_EHDR_PHNUM]  ; ECX = phnum
    mov [esp + MAPS_BUF_SIZE + 8], ebx  ; save libc base in local slot

_phdr_loop32:
    test ecx, ecx
    jz _find_done32
    cmp dword [eax + ELF32_PHDR_TYPE], PT_DYNAMIC
    je _got_dynamic32
    movzx edx, word [ebx + ELF32_EHDR_PHENTSIZE]
    add eax, edx
    dec ecx
    jmp _phdr_loop32

_got_dynamic32:
    mov edx, [eax + ELF32_PHDR_VADDR]
    add edx, ebx                ; EDX = .dynamic VA

    ; Walk DT entries; save DT_STRTAB/DT_SYMTAB/DT_HASH into stack locals
    ; stack layout above buffer:
    ;   [esp + MAPS_BUF_SIZE + 0]  = dlopen result
    ;   [esp + MAPS_BUF_SIZE + 4]  = dlsym result
    ;   [esp + MAPS_BUF_SIZE + 8]  = libc_base (set above)
    ;   [esp + MAPS_BUF_SIZE + 12] = DT_STRTAB
    ;   +16 = DT_SYMTAB, +20 = DT_HASH
    ; (we sub'ed 0x10 at entry, so we have room above the maps buffer)

    ; Actually use EBP, EDI for strtab/symtab/hash temporarily
    ; but we saved EDI earlier as bytes_read. Use stack slots instead.
    ; We have [esp + MAPS_BUF_SIZE + 0..0xF] = our 4 dword locals
    xor eax, eax
    ; Overload: use esi+offset for DT ptrs (ESI = string base, won't need it during ELF scan)
    ; Store: strtab at [esp+MAPS_BUF_SIZE+0], symtab at [esp+MAPS_BUF_SIZE+4], hash at [esp+MAPS_BUF_SIZE+0xC]
    mov dword [esp + MAPS_BUF_SIZE + 0], 0     ; strtab = 0
    mov dword [esp + MAPS_BUF_SIZE + 4], 0     ; symtab = 0
    mov dword [esp + MAPS_BUF_SIZE + 0xC], 0   ; hash = 0

_dyn_loop32:
    mov eax, [edx]              ; d_tag
    test eax, eax               ; DT_NULL
    jz _dyn_done32
    cmp eax, DT_STRTAB
    jne _chk_sym32
    mov eax, [edx + 4]
    mov [esp + MAPS_BUF_SIZE + 0], eax
    jmp _dyn_next32
_chk_sym32:
    cmp eax, DT_SYMTAB
    jne _chk_hash32
    mov eax, [edx + 4]
    mov [esp + MAPS_BUF_SIZE + 4], eax
    jmp _dyn_next32
_chk_hash32:
    cmp eax, DT_HASH
    jne _dyn_next32
    mov eax, [edx + 4]
    mov [esp + MAPS_BUF_SIZE + 0xC], eax
_dyn_next32:
    add edx, ELF32_DYN_SIZE
    jmp _dyn_loop32

_dyn_done32:
    mov ebp, [esp + MAPS_BUF_SIZE + 0]  ; EBP = DT_STRTAB
    mov edi, [esp + MAPS_BUF_SIZE + 4]  ; EDI = DT_SYMTAB
    test ebp, ebp
    jz _find_done32
    test edi, edi
    jz _find_done32
    mov ebx, [esp + MAPS_BUF_SIZE + 8]  ; EBX = libc base

    ; Determine symbol count
    mov ecx, MAX_SYM_SCAN
    mov eax, [esp + MAPS_BUF_SIZE + 0xC]  ; DT_HASH
    test eax, eax
    jz _sym_scan32
    mov ecx, [eax + ELF_HASH_NCHAIN_OFF]
    test ecx, ecx
    jz _find_done32

_sym_scan32:
    mov dword [esp + MAPS_BUF_SIZE + 0], 0   ; dlopen = 0
    mov dword [esp + MAPS_BUF_SIZE + 4], 0   ; dlsym = 0

_sym_loop32:
    test ecx, ecx
    jz _sym_done32
    mov eax, [edi]              ; st_name
    test eax, eax
    jz _sym_next32
    add eax, ebp                ; name VA

    ; Check "dlsym\0"
    cmp dword [esp + MAPS_BUF_SIZE + 4], 0
    jne _skip_dlsym32
    cmp dword [eax], 0x79736C64
    jne _skip_dlsym32
    cmp byte [eax + 4], 0x6D
    jne _skip_dlsym32
    cmp byte [eax + 5], 0x00
    jne _skip_dlsym32
    mov edx, [edi + ELF32_SYM_ST_VALUE]
    test edx, edx
    jz _skip_dlsym32
    cmp edx, ebx
    jae _skip_dlsym32
    add edx, ebx
    mov [esp + MAPS_BUF_SIZE + 4], edx
_skip_dlsym32:

    ; Check "dlopen\0"
    cmp dword [esp + MAPS_BUF_SIZE + 0], 0
    jne _skip_dlopen32
    cmp dword [eax], 0x706F6C64
    jne _skip_dlopen32
    cmp byte [eax + 4], 0x65
    jne _skip_dlopen32
    cmp byte [eax + 5], 0x6E
    jne _skip_dlopen32
    cmp byte [eax + 6], 0x00
    jne _skip_dlopen32
    mov edx, [edi + ELF32_SYM_ST_VALUE]
    test edx, edx
    jz _skip_dlopen32
    cmp edx, ebx
    jae _skip_dlopen32
    add edx, ebx
    mov [esp + MAPS_BUF_SIZE + 0], edx
_skip_dlopen32:

    ; Stop if both found
    cmp dword [esp + MAPS_BUF_SIZE + 0], 0
    je _sym_next32
    cmp dword [esp + MAPS_BUF_SIZE + 4], 0
    je _sym_next32
    jmp _sym_done32
_sym_next32:
    add edi, ELF32_SYM_SIZE
    dec ecx
    jmp _sym_loop32

_sym_done32:
    ; If dlsym not found, skip imports
    cmp dword [esp + MAPS_BUF_SIZE + 4], 0
    je _find_done32
    ; If dlopen not found, try dlsym(RTLD_DEFAULT, "dlopen")
    cmp dword [esp + MAPS_BUF_SIZE + 0], 0
    jne _find_done32
    mov eax, [esp + MAPS_BUF_SIZE + 4]  ; dlsym
    lea edx, [esi + STR_DLOPEN]
    push edx                    ; arg2: name
    push RTLD_DEFAULT           ; arg1: NULL handle
    call eax                    ; dlsym(RTLD_DEFAULT, "dlopen")
    add esp, 8
    mov [esp + MAPS_BUF_SIZE + 0], eax

_find_done32:
    ; Free maps buffer
    add esp, MAPS_BUF_SIZE

    ; Load dlopen/dlsym from locals
    mov ebx, [esp + 0]          ; ebx = dlopen (may be 0)
    mov esi, [esp + 4]          ; esi = dlsym

    test esi, esi
    jz _done32

    ; -- Scan for PE ----------------------------------------------------------
    call _here32
_here32:
    pop eax
    add eax, 0x80
    mov edi, eax

_scan_mz32:
    inc edi
    cmp word [edi], MZ_SIGNATURE_WORD
    jnz _scan_mz32
    mov eax, [edi + E_LFANEW_OFFSET]
    cmp eax, MAX_E_LFANEW
    ja _scan_mz32
    lea eax, [edi + eax]
    cmp dword [eax], PE_SIGNATURE_DWORD
    jnz _scan_mz32

    ; EDI = PE base
    mov eax, [edi + E_LFANEW_OFFSET]
    add eax, edi
    mov eax, [eax + NT32_IMPORT_DIR_RVA_OFF]
    test eax, eax
    jz _done32
    add eax, edi
    mov ebp, eax                ; EBP = first descriptor

_desc_loop32:
    mov eax, [ebp + IMPORT_DESC_NAME_RVA_OFF]
    test eax, eax
    jz _done32
    add eax, edi                ; DLL name VA

    ; dlopen(name, RTLD_LAZY) if available
    test ebx, ebx
    jz _no_dlopen32
    push RTLD_LAZY
    push eax
    call ebx                    ; dlopen(name, RTLD_LAZY)
    add esp, 8
    test eax, eax
    jz _next_desc32
    mov ecx, eax                ; ECX = handle
    jmp _got_handle32
_no_dlopen32:
    xor ecx, ecx                ; ECX = RTLD_DEFAULT
_got_handle32:

    ; INT or FirstThunk
    mov eax, [ebp + IMPORT_DESC_INT_RVA_OFF]
    test eax, eax
    jz _use_ft32
    add eax, edi
    push eax                    ; INT ptr
    mov eax, [ebp + IMPORT_DESC_FT_RVA_OFF]
    add eax, edi
    push eax                    ; IAT ptr
    jmp _thunk_loop32
_use_ft32:
    mov eax, [ebp + IMPORT_DESC_FT_RVA_OFF]
    add eax, edi
    push eax                    ; INT ptr (same as IAT)
    push eax                    ; IAT ptr

_thunk_loop32:
    ; [esp] = IAT ptr, [esp+4] = INT ptr
    mov eax, [esp + 4]          ; INT ptr
    mov eax, [eax]              ; thunk value
    test eax, eax
    jz _thunk_done32
    test eax, ORDINAL_FLAG32
    jnz _ordinal32
    add eax, edi
    add eax, IMPORT_BY_NAME_HINT_SIZE
    push eax                    ; arg2: name
    push ecx                    ; arg1: handle
    call esi                    ; dlsym(handle, name)
    add esp, 8
    jmp _save_fn32
_ordinal32:
    xor eax, eax
_save_fn32:
    mov edx, [esp]              ; IAT ptr
    mov [edx], eax
_next_thunk32:
    add dword [esp + 4], IAT_SLOT_SIZE
    add dword [esp], IAT_SLOT_SIZE
    jmp _thunk_loop32
_thunk_done32:
    pop edx
    pop edx                     ; discard INT/IAT ptrs

_next_desc32:
    add ebp, IMAGE_IMPORT_DESC_SIZE
    jmp _desc_loop32

_done32:
    add esp, 0x10               ; free local slots
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret                         ; terminal byte (C3) stripped by peor
