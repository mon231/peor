BITS 64

address_of_shellcode:
    call get_rip

get_rip:
    pop rbx                     ; Get current RIP

find_pe_address:
    mov rdi, rbx                ; Store RIP in RDI
    add rdi, address_of_pe - get_rip

validate_pe_header:
    cmp word [rdi], 0x5A4D      ; Look for MZ signature
    jne error                   ; Exit if PE not found
    mov rbx, rdi                ; Store PE base

skip_dos_header:
    mov eax, [rdi + 0x3C]       ; Get PE header offset (still 32-bit)
    add rdi, rax                ; Point to PE header

    ; Validate PE signature
    cmp dword [rdi], 0x00004550 ; "PE\0\0" signature
    jne error                   ; Exit if invalid PE

    ; Validate 64-bit PE
    cmp word [rdi + 0x4], 0x8664  ; Machine type should be AMD64
    jne error

process_relocs:
    mov rsi, [rdi + 0xB0]       ; Get relocation table RVA (note offset change for PE64)
    test rsi, rsi               ; Check if there is a relocation table
    jz pe_entry_jumper

    add rsi, rbx                ; Get VA of reloc table

reloc_block:
    mov ecx, [rsi]              ; Get block RVA (still 32-bit)
    test ecx, ecx               ; Check if this is the last block
    jz pe_entry_jumper          ; If RVA is 0, we're done with all blocks

    push rsi                    ; Save pointer to current block
    mov edx, ecx                ; Save block RVA

    mov ecx, [rsi + 4]          ; Get block size
    add rsi, 8                  ; Skip to first entry
    sub ecx, 8                  ; Adjust count
    shr ecx, 1                  ; Convert byte count to entry count (each entry is 2 bytes)

next_reloc:
    movzx eax, word [rsi]       ; Get relocation entry
    mov edx, [rsp]              ; Restore block RVA from stack
    mov edx, [rdx]              ; Get actual RVA value

    push rcx                    ; Save count
    mov ecx, eax                ; Save full entry
    shr ecx, 12                 ; Get relocation type
    cmp ecx, 10                 ; Check if IMAGE_REL_BASED_DIR64 (type 10)
    pop rcx                     ; Restore count
    jne skip_reloc

    and eax, 0x0FFF             ; Mask to get offset
    add eax, edx                ; Add block RVA
    mov rdx, rbx                ; Get base address in rdx
    add rdx, rax                ; Add offset to base to get relocation address

    mov rax, [rdx]              ; Get value to fix (64-bit)
    add rax, rbx                ; Add delta
    mov [rdx], rax              ; Write fixed-up value (64-bit)

skip_reloc:
    add rsi, 2                  ; Next entry
    dec ecx                     ; Decrease count
    jnz next_reloc              ; Process next if not done

    pop rsi                     ; Restore block pointer
    mov ecx, [rsi + 4]          ; Get block size
    add rsi, rcx                ; Move to next block
    jmp reloc_block            ; Process next block

pe_entry_jumper:
    mov eax, [rdi + 0x28]       ; Get the address of the entry point (RVA)
    add rax, rbx                ; Convert to VA using 64-bit addition
    jmp rax                     ; Jump to the entry point of the PE

error:
    int3                        ; Break for debugging

address_of_pe:
