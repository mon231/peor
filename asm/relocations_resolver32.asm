; x86 relocation resolver - applies base relocations only.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_32 / KS_OPT_SYNTAX_NASM).
;
; On entry: (none required).
; On exit:  EBX = PE base, execution falls through to the next shellcode.
;
; Named constants
%define PE_OFFSET_PLACEHOLDER   0x7E7E7E7E  ; patched by setup.py: len(relocs) - 5
%define IMAGE_REL_BASED_HIGHLOW 0x03        ; base-relocation type for 32-bit absolute pointers

    call _base
_base:
    pop ebx                              ; EBX = runtime address of _base
    lea edi, [ebx + PE_OFFSET_PLACEHOLDER]  ; EDI = PE image base (offset patched at install)
    mov ebx, edi                         ; EBX = PE base
    push ebp                             ; preserve caller's EBP (used as scratch below)

    cmp word [ebx], 0x5A4D               ; DOS "MZ" magic
    jz _valid_mz
    hlt
_valid_mz:
    mov esi, [ebx + 0x3C]                ; e_lfanew
    add esi, ebx                         ; NT headers
    cmp dword [esi], 0x4550              ; "PE\0\0"
    jz _valid_pe
    hlt
_valid_pe:
    mov eax, ebx
    sub eax, [esi + 0x34]                ; delta = actual_base - ImageBase (PE32: NT+0x34)
    mov edi, eax
    test edi, edi
    jz _done                             ; delta=0, no relocation needed

    mov eax, [esi + 0xA0]                ; DataDir[5].VA (BaseReloc at NT+0xA0 for PE32)
    test eax, eax
    jz _done                             ; no .reloc section
    add eax, ebx
    mov esi, eax                         ; ESI = first IMAGE_BASE_RELOCATION block

_block:
    mov edx, [esi]                       ; block.VirtualAddress
    mov ecx, [esi + 4]                   ; block.SizeOfBlock
    add esi, 0x08
    test ecx, ecx
    jz _done                             ; null block = end sentinel
    sub ecx, 0x08
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
    cmp ebp, IMAGE_REL_BASED_HIGHLOW
    jnz _next_entry
    lea ebp, [ebx + edx]                 ; page VA = PE_base + block.VirtualAddress
    add ebp, eax                         ; target address
    add [ebp], edi                       ; patch DWORD at target += delta

_next_entry:
    dec ecx
    jnz _entry
    jmp _block

_done:
    pop ebp                              ; restore caller's EBP
    ; EBX = PE base; fall through to next shellcode.
