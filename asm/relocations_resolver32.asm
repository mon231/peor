; x86 (32-bit) relocation resolver - position-independent shellcode
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_32 / KS_OPT_SYNTAX_NASM).
;
; Locates the PE image appended immediately after this shellcode (_pe_start),
; applies IMAGE_REL_BASED_HIGHLOW (type 3) base relocations, then JMPs to
; the PE entry point.  Handles delta=0 (no relocs) and missing reloc table.
;
; NOTE: 0x7E7E7E7E is a placeholder patched by setup.py with (shellcode_size - 5).

    call _base
_base:
    pop ebx                              ; EBX = runtime address of _base
    lea edi, [ebx + 0x7E7E7E7E]         ; PATCHED: EDI = PE image base
    mov ebx, edi                         ; EBX = PE base

    cmp word [ebx], 0x5A4D               ; DOS "MZ" magic
    jnz _exit

    mov esi, [ebx + 0x3C]                ; e_lfanew
    add esi, ebx                         ; NT headers
    cmp dword [esi], 0x4550              ; "PE\0\0"
    jnz _exit

    mov eax, ebx
    sub eax, [esi + 0x34]                ; delta = actual_base - ImageBase (PE32: NT+0x34)
    mov edi, eax
    test edi, edi
    jz _jmp_ep                           ; delta=0, no relocation needed

    mov eax, [esi + 0xA0]                ; DataDir[5].VA (BaseReloc at NT+0xA0 for PE32)
    test eax, eax
    jz _jmp_ep
    add eax, ebx
    mov esi, eax                         ; ESI = first IMAGE_BASE_RELOCATION block

_block:
    mov edx, [esi]                       ; block.VirtualAddress
    mov ecx, [esi + 4]                   ; block.SizeOfBlock
    add esi, 8
    test ecx, ecx
    jz _jmp_ep                           ; null block = end sentinel
    sub ecx, 8
    shr ecx, 1                           ; number of 16-bit entries
    jz _block

_entry:
    lodsw                                ; AX = next entry, ESI += 2
    test ax, ax
    jz _block                            ; type 0 (ABS padding) -> done with block

    movzx eax, ax
    mov ebp, eax
    and eax, 0x0FFF                      ; lower 12 bits = page offset
    shr ebp, 0x0c                        ; upper 4 bits = reloc type
    cmp ebp, 3                           ; IMAGE_REL_BASED_HIGHLOW
    jnz _next_entry

    lea ebp, [ebx + edx]                 ; page VA = PE_base + block.VirtualAddress
    add ebp, eax                         ; target address
    add [ebp], edi                       ; patch DWORD at target += delta

_next_entry:
    dec ecx
    jnz _entry
    jmp _block

_jmp_ep:
    mov esi, [ebx + 0x3C]
    add esi, ebx
    mov eax, [esi + 0x28]                ; AddressOfEntryPoint (NT+0x28)
    add eax, ebx
    jmp eax

_exit:
    hlt

_pe_start:
