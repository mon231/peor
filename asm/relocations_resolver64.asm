; x64 relocation resolver - applies base relocations only.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_64 / KS_OPT_SYNTAX_NASM).
;
; On entry: (none required).
; On exit:  RBX = PE base, execution falls through to the next shellcode.
;
; 0x7E7E7E7E = PE_OFFSET_PLACEHOLDER, patched by setup.py with (shellcode_size - 5).
; The name must match _PE_OFFSET_PLACEHOLDER in setup.py.

    call _base
_base:
    pop rbx                              ; RBX = runtime address of _base
    lea rdi, [rbx + 0x7E7E7E7E]         ; PATCHED (PE_OFFSET_PLACEHOLDER): RDI = PE image base
    mov rbx, rdi                         ; RBX = PE base

    cmp word [rbx], 0x5A4D               ; "MZ"
    jz _valid_mz
    hlt
_valid_mz:
    mov esi, [rbx + 0x3C]                ; e_lfanew (32-bit, zero-extends to RSI)
    add rsi, rbx                         ; NT headers
    cmp dword [rsi], 0x4550              ; "PE\0\0"
    jz _valid_pe
    hlt
_valid_pe:
    mov rax, [rsi + 0x30]                ; ImageBase (PE64: OptHdr+0x18 = NT+0x30)
    mov rdi, rbx
    sub rdi, rax                         ; delta = actual_base - ImageBase
    test rdi, rdi
    jz _done                             ; delta=0, no relocation needed

    mov eax, [rsi + 0xB0]                ; DataDir[5].VA (BaseReloc at NT+0xB0 for PE64)
    test eax, eax
    jz _done                             ; no .reloc section
    add rax, rbx
    mov rsi, rax                         ; RSI = first IMAGE_BASE_RELOCATION block

_block:
    mov edx, [rsi]                       ; block.VirtualAddress (32-bit)
    mov ecx, [rsi + 4]                   ; block.SizeOfBlock
    add rsi, 8
    test ecx, ecx
    jz _done                             ; null block = end sentinel
    sub ecx, 8
    shr ecx, 1                           ; number of 16-bit entries
    jz _block

_entry:
    lodsw                                ; AX = next entry, RSI += 2
    test ax, ax
    jz _block                            ; type 0 (ABS padding) -> done with block
    movzx r8d, ax
    mov r9w, r8w
    and r8d, 0x0FFF                      ; page offset
    shr r9w, 0x0c                        ; reloc type
    cmp r9b, 0x0A                        ; IMAGE_REL_BASED_DIR64
    jnz _next_entry
    lea r10, [rbx + rdx]                 ; page VA
    add r10, r8                          ; target address
    add [r10], rdi                       ; patch QWORD at target += delta

_next_entry:
    dec ecx
    jnz _entry
    jmp _block

_done:
    ; RBX = PE base; fall through to next shellcode.
