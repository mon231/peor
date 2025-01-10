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

    mov eax, 5A4Dh
    cmp [ebx], ax

    jnz bad_quit

check_first_header:
    mov esi, [ebx+3Ch]
    add esi, ebx

    mov [esp + 32], esi
    cmp dword [esi], 4550h

    jnz bad_quit

check_second_header:
    mov     eax, ebx
    cdq

    sub     eax, [esi+34h]
    mov     ecx, eax
    mov     [esp+24], eax
    sbb     edx, 0
    or      ecx, edx

    mov     [esp+28], edx
    jz pe_entry_jumper

    cmp     dword [esi+0A4h], 0
    jz pe_entry_jumper

    mov     esi, [esi+0A0h]
    add     esi, ebx
    mov     eax, [esi+4]
    lea     ecx, [esi+4]
    mov     [esp+16], ecx

    test    eax, eax
    jz pe_entry_jumper
    nop

iteration:
    mov     edx, [esi]
    lea     edi, [eax-8]
    shr     edi, 1
    mov     [esp+20], edx
    mov     edx, 0
    jz iterate

inner_iteration:
    movzx   eax, word [esi+edx*2+8]
    mov cx, ax
    shr cx, 0Ch
    cmp cx, 3
    jz relocate

    cmp cx, 0Ah
    jnz inner_iter

relocate:
    mov ecx, [esp+24]
    and eax, 0FFFh
    add eax, [esp+20]
    add eax, ebx
    add [eax], ecx
    mov ecx, [esp+28]
    adc [eax+4], ecx

inner_iter:
    inc edx
    cmp edx, edi
    jb inner_iteration
    mov ecx, [esp+16]

iterate:
    add     esi, [ecx]
    mov     eax, [esi+4]
    lea     ecx, [esi+4]
    mov     [esp+16], ecx

    test    eax, eax
    jnz iteration

bad_quit:
    hlt

pe_entry_jumper:
    ; TODO: use correct stuff
    mov esi, [esp + 20h]
    mov eax, [esi + 28h]     ; Get the address of the entry point (RVA)
    add eax, ebx              ; Convert to VA
    jmp eax                   ; Jump to the entry point of the PE

address_of_pe:
