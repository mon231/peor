BITS 32

address_of_shellcode:
    call get_eip

get_eip:
    pop ebx                   ; EBX = current address

find_pe_address:
    mov edi, ebx
    add edi, address_of_pe - get_eip
    mov ebx, edi              ; EBX = PE base address

    ; Verify DOS header
    cmp word [ebx], 0x5A4D    ; "MZ" check
    jnz bad_quit

    ; Locate PE header
    mov esi, [ebx + 0x3C]     ; e_lfanew offset
    add esi, ebx              ; ESI = PE header VA
    cmp dword [esi], 0x4550   ; "PE\0\0" check
    jnz bad_quit

    ; Calculate delta (actual_base - preferred_base)
    mov eax, ebx
    sub eax, [esi + 0x34]     ; Subtract ImageBase
    mov edi, eax              ; EDI = delta
    test edi, edi
    jz pe_entry_jumper        ; Skip relocs if delta=0

    ; Get relocation table
    mov eax, [esi + 0xA0]     ; Reloc table RVA
    test eax, eax
    jz pe_entry_jumper        ; No relocs? Jump to entry
    add eax, ebx              ; Convert to VA
    mov esi, eax              ; ESI = reloc table VA

process_blocks:
    mov edx, [esi]            ; Page RVA
    mov ecx, [esi + 4]        ; Block size
    add esi, 8                ; Point to entries

    test ecx, ecx             ; End of relocs?
    jz pe_entry_jumper

    ; Calculate number of entries
    sub ecx, 8
    shr ecx, 1
    jz process_blocks         ; Empty block? Skip

process_entries:
    lodsw                     ; Get relocation entry
    test ax, ax
    jz process_blocks         ; End of block

    ; Extract type/offset
    movzx eax, ax
    mov ebp, eax
    and eax, 0x0FFF           ; Offset
    shr ebp, 12               ; Type

    cmp ebp, 3                ; IMAGE_REL_BASED_HIGHLOW?
    jne skip_entry

    ; Calculate target address
    lea ebp, [ebx + edx]      ; Page VA
    add ebp, eax              ; Target VA

    ; Apply delta to DWORD at target
    add [ebp], edi

skip_entry:
    dec ecx
    jnz process_entries
    jmp process_blocks

pe_entry_jumper:
    ; Re-acquire PE header
    mov esi, [ebx + 0x3C]     ; e_lfanew offset
    add esi, ebx              ; ESI = PE header VA

    ; Get entry point RVA
    mov eax, [esi + 0x28]     ; AddressOfEntryPoint
    add eax, ebx              ; Convert to VA
    jmp eax                   ; Transfer control

bad_quit:
    hlt                       ; Crash gracefully

address_of_pe:
    ; PE data appended here