BITS 32

address_of_shellcode:
    call get_eip

get_eip:
    pop ebx

find_pe_address:
    mov edi, ebx
    add edi, address_of_pe - get_eip

    mov ecx, edi
    mov ebx, ecx

    ; Check DOS header magic (MZ)
    mov ax, 5A4Dh      ; Fix: Changed eax to ax to match size of comparison
    cmp word [ebx], ax ; Fix: Added word size specifier

check_first_header:
    mov esi, [ebx+3Ch]
    add esi, ebx

    ; Fix: Removed unnecessary store to stack
    cmp dword [esi], 4550h    ; "PE\0\0" signature
    jnz bad_quit

check_second_header:
    mov     eax, ebx
    cdq

    sub     eax, [esi+34h]    ; ImageBase
    mov     ecx, eax
    mov     [esp+24], eax     ; Delta
    sbb     edx, 0
    or      ecx, edx

    mov     [esp+28], edx     ; High part of delta
    jz      pe_entry_jumper

    ; Check if we have relocation directory
    mov     eax, [esi+0A0h]   ; Fix: Load relocation directory RVA first
    test    eax, eax          ; Fix: Check if relocation directory exists
    jz      pe_entry_jumper

    add     eax, ebx          ; Convert RVA to VA
    mov     esi, eax
    mov     eax, [esi+4]      ; Size of block
    lea     ecx, [esi+4]
    mov     [esp+16], ecx

    test    eax, eax
    jz      pe_entry_jumper

iteration:
    mov     edx, [esi]        ; RVA of block
    lea     edi, [eax-8]
    shr     edi, 1
    mov     [esp+20], edx
    xor     edx, edx          ; Fix: Use xor for clarity
    jz      iterate

inner_iteration:
    movzx   eax, word [esi+edx*2+8]
    mov     cx, ax
    shr     cx, 0Ch
    cmp     cx, 3
    jz      relocate

    cmp     cx, 0Ah
    jnz     inner_iter

relocate:
    mov     ecx, [esp+24]
    and     eax, 0FFFh
    add     eax, [esp+20]
    add     eax, ebx
    add     [eax], ecx
    mov     ecx, [esp+28]
    adc     [eax+4], ecx

inner_iter:
    inc     edx
    cmp     edx, edi
    jb      inner_iteration
    mov     ecx, [esp+16]

iterate:
    add     esi, [ecx]        ; Move to next block
    mov     eax, [esi+4]      ; Size of next block
    lea     ecx, [esi+4]
    mov     [esp+16], ecx

    test    eax, eax
    jnz     iteration

pe_entry_jumper:
    mov     eax, [esi+28h]    ; Get AddressOfEntryPoint
    add     eax, ebx          ; Convert RVA to VA
    jmp     eax               ; Jump to entry point

bad_quit:
    hlt

address_of_pe:
