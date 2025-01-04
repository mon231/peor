BITS 32

address_of_shellcode:
    call get_eip

get_eip:
    pop ebx                    ; Get current EIP

find_pe_address:
    mov edi, ebx               ; Store EIP in EDI
    add edi, address_of_pe - address_of_shellcode

validate_pe_header:
    cmp word [edi], 0x5A4D     ; Look for MZ signature
    jne validate_pe_header     ; Keep looking (infinite) if not found PE
    mov ebx, edi               ; Store PE base

skip_dos_header:
    mov eax, [edi + 0x3C]      ; Get PE header offset
    add edi, eax               ; Point to PE header

process_relocs:
    mov esi, [edi + 0xB0]      ; Get relocation table RVA

    test esi, esi              ; Check if there is a relocation table
    jz pe_entry_jumper

    add esi, ebx               ; Get VA of reloc table

reloc_block:
    mov ecx, [esi + 4]         ; Get block size
    add esi, 8                 ; Skip to first entry
    sub ecx, 8                 ; Adjust count

next_reloc:
    movzx eax, word [esi]      ; Get relocation entry
    cmp ax, 0                  ; Check if done
    je pe_entry_jumper         ; Jump to entry point if done

    and eax, 0x0FFF           ; Mask to get offset
    add eax, ebx              ; Add base address
    mov edx, [eax]            ; Get value to fix
    add edx, ebx              ; Add delta
    mov [eax], edx            ; Write fixed-up value

    add esi, 2                ; Next entry
    sub ecx, 2                ; Decrease count
    jnz next_reloc            ; Process next if not done

pe_entry_jumper:
    mov eax, [edi + 0x28]      ; Get the address of the entry point (RVA)
    add eax, ebx               ; Convert to VA
    jmp eax                    ; Jump to the entry point of the PE

address_of_pe:
