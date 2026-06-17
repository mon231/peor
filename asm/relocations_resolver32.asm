; x86 (32-bit) relocation resolver with DLL-entry support
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_32 / KS_OPT_SYNTAX_NASM).
;
; Extension over the bare reloc resolver:
;   * Detects DLL images (IMAGE_FILE_DLL) and calls DllMain with the
;     standard DLL_PROCESS_ATTACH arguments instead of jumping to the entry
;     point directly.
;   * Correctly handles PEs with no .reloc section (DataDir[5].VA == 0).
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
    mov eax, [esi + 0x28]               ; AddressOfEntryPoint (NT+0x28)
    add eax, ebx                         ; EAX = OEP VA

    ; Check IMAGE_FILE_DLL (bit 13 of Characteristics at NT+0x16)
    test word [esi + 0x16], 0x2000
    jz _exe_entry

    ; DLL: call DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL) -- stdcall callee cleans args
    push 0                               ; arg3: lpvReserved = NULL
    push 1                               ; arg2: DLL_PROCESS_ATTACH
    push ebx                             ; arg1: hinstDLL = PE base
    call eax                             ; DllMain(base, 1, NULL)
    hlt                                  ; DllMain should call ExitProcess; if not, halt

_exe_entry:
    jmp eax

_exit:
    hlt

_pe_start:
