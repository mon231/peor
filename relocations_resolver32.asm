BITS 32

address_of_shellcode:
    call get_eip

get_eip:
    pop ebx                     ; Get current EIP

find_pe_address:
    mov edi, ebx                ; Store EIP in EDI
    add edi, address_of_pe - get_eip

validate_pe_header:
    cmp word [edi], 0x5A4D      ; Look for MZ signature
    jne validate_pe_header      ; Keep looking (infinite) if not found PE
    mov ebx, edi                ; Store PE base

skip_dos_header:
    mov eax, [edi + 0x3C]       ; Get PE header offset
    add edi, eax                ; Point to PE header

process_relocs:
    mov esi, [edi + 0xA0]       ; Get relocation table RVA
    test esi, esi               ; Check if there is a relocation table
    jz pe_entry_jumper

    add esi, ebx                ; Get VA of reloc table

reloc_block:
    mov ecx, [esi]              ; Get block RVA
    test ecx, ecx               ; Check if this is the last block
    jz pe_entry_jumper          ; If RVA is 0, we're done with all blocks

    push esi                    ; Save pointer to current block
    mov edx, ecx                ; Save block RVA

    mov ecx, [esi + 4]          ; Get block size
    add esi, 8                  ; Skip to first entry
    sub ecx, 8                  ; Adjust count

next_reloc:
    movzx eax, word [esi]       ; Get relocation entry

    push ecx                    ; Save count
    mov ecx, eax                ; Save full entry
    shr ecx, 12                 ; Get relocation type
    cmp ecx, 3                  ; Check if IMAGE_REL_BASED_HIGHLOW
    pop ecx                     ; Restore count
    jne skip_reloc

    and eax, 0x0FFF             ; Mask to get offset
    add eax, edx                ; Add block RVA
    add eax, ebx                ; Add base address

    test eax, eax               ; Check if eax is not null
    jz skip_reloc               ; Skip if eax is null

    test eax, 0xFFFFF000        ; Check if eax is within a valid range
    jnz skip_reloc              ; Skip if eax is out of range

    mov edx, [eax]              ; Get value to fix
    add edx, ebx                ; Add delta
    mov [eax], edx              ; Write fixed-up value

skip_reloc:
    add esi, 2                ; Next entry
    sub ecx, 2                ; Decrease count
    jnz next_reloc            ; Process next if not done

    pop esi                   ; Restore block pointer
    add esi, [esi + 4]        ; Move to next block using current block's size
    jmp reloc_block           ; Process next block

pe_entry_jumper:
    mov eax, [edi + 0x28]     ; Get the address of the entry point (RVA)
    add eax, ebx              ; Convert to VA
    jmp eax                   ; Jump to the entry point of the PE

address_of_pe:
