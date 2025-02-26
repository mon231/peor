BITS 64

shellcode_start:
    call get_rip

get_rip:
    pop rbx                  ; RBX = current address

find_pe_base:
    lea rdi, [rbx + (address_of_pe - get_rip)]
    mov rbx, rdi             ; RBX = PE base address

    ; Verify DOS header ("MZ")
    cmp word [rbx], 0x5A4D
    jnz bad_quit

    ; Locate PE header
    mov esi, [rbx + 0x3C]    ; e_lfanew offset (32-bit)
    add rsi, rbx             ; RSI = PE header VA

    ; Verify PE signature
    cmp dword [rsi], 0x4550  ; "PE\0\0"
    jnz bad_quit

    ; Calculate delta (RBX - ImageBase)
    mov rax, [rsi + 0x30]    ; ImageBase (64-bit at offset 0x30)
    mov rdi, rbx
    sub rdi, rax             ; RDI = delta
    test rdi, rdi
    jz entry_point           ; Skip relocations if delta=0

    ; Get relocation directory
    mov eax, [rsi + 0xB8]    ; Reloc table RVA (offset 0xB8 in PE64)
    test eax, eax
    jz entry_point           ; No relocations? Jump to entry
    add rax, rbx             ; RAX = relocation table VA
    mov rsi, rax             ; RSI = relocation table

process_blocks:
    ; Read block header
    mov edx, [rsi]           ; Page RVA (32-bit)
    mov ecx, [rsi + 4]       ; Block size (32-bit)
    add rsi, 8               ; Move to entries

    test ecx, ecx            ; End of relocations?
    jz entry_point

    ; Calculate number of entries
    sub ecx, 8
    shr ecx, 1
    jz process_blocks        ; No entries? Next block

process_entries:
    lodsw                    ; AX = relocation entry
    test ax, ax
    jz process_blocks        ; End of block

    ; Extract type/offset
    movzx r8d, ax
    mov r9w, r8w             ; Save original value
    and r8d, 0x0FFF          ; Offset
    shr r9w, 12              ; Type

    ; Handle IMAGE_REL_BASED_DIR64 (type 10)
    cmp r9b, 0xA
    jne skip_entry

    ; Calculate target address: RBX + Page RVA + Offset
    lea r10, [rbx + rdx]     ; Page VA
    add r10, r8              ; Target VA

    ; Apply delta to QWORD at target
    add [r10], rdi

skip_entry:
    dec ecx
    jnz process_entries
    jmp process_blocks

entry_point:
    ; Re-acquire PE header
    mov esi, [rbx + 0x3C]    ; e_lfanew offset
    add rsi, rbx             ; RSI = PE header VA

    ; Get entry point and jump
    mov eax, [rsi + 0x28]    ; AddressOfEntryPoint (32-bit RVA)
    add rax, rbx             ; Convert to VA
    jmp rax

bad_quit:
    hlt                      ; Halt on error

address_of_pe:
    ; PE file appended here
