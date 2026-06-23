; ldr_register64.asm - Registers the PE as a fake module in PEB.Ldr so that
; LdrFindEntryForAddress (called by RtlPcToFileHeader, GetModuleHandleExW, etc.)
; can return our PE's base address. Required for modern MSVC C++ exceptions
; (magic 0x19930522): _CxxThrowException passes params[3]=ImageBase obtained via
; RtlPcToFileHeader; if our PE is not in the module list, ImageBase=NULL and
; __CxxFrameHandler3/4 cannot resolve ThrowInfo, so catch blocks never fire.
;
; On entry: RBX = PE base (already relocated), RSP = 8 (mod 16).
; On exit:  RBX = PE base, RSP -= 0x100 (fake LDR entry lives on stack for PE
;           lifetime), falls through. RSP mod 16 unchanged (0x100 = 16*16).
;
; Fake LDR_DATA_TABLE_ENTRY64 layout at [RSP .. RSP+0xFF]:
;   +0x00  InLoadOrderLinks.Flink  (8 bytes) <- linked into Ldr list
;   +0x08  InLoadOrderLinks.Blink  (8 bytes) <- linked into Ldr list
;   ... zeroed ...
;   +0x30  DllBase                 (8 bytes) <- set to RBX (PE base)
;   +0x40  SizeOfImage             (4 bytes) <- Python patches 0x49484746 -> actual value
;   ... rest zeroed ...
;
; SizeOfImage placeholder (little-endian bytes): 46 47 48 49 (= 0x49484746).
; setup.py leaves this magic; __main__.py binary-replaces it with the real SizeOfImage.

    ; Allocate 0x100 bytes on stack for the fake LDR_DATA_TABLE_ENTRY64.
    sub rsp, 0x100

    ; Zero the entire region (32 QWORDs = 256 bytes) using rdi as a walking pointer.
    lea rdi, [rsp]
    xor eax, eax
    mov ecx, 32
_zero_ldr64:
    mov [rdi], rax
    add rdi, 8
    dec ecx
    jnz _zero_ldr64

    ; Fill in the fields needed by LdrFindEntryForAddress.
    mov [rsp + 0x30], rbx                   ; DllBase = PE base

    ; SizeOfImage: magic placeholder replaced by Python at chain-build time.
    mov dword [rsp + 0x40], 0x49484746

    ; Get PEB (GS:[0x60]) then PEB.Ldr (PEB + 0x18).
    db 0x65
    mov rax, [0x60]                         ; RAX = PEB
    mov rax, [rax + 0x18]                   ; RAX = PEB.Ldr

    ; Insert fake entry at HEAD of InLoadOrderModuleList (Ldr + 0x10).
    ; list_head = &Ldr->InLoadOrderModuleList (a LIST_ENTRY: Flink at +0, Blink at +8)
    ; first     = list_head->Flink  (pointer to InLoadOrderLinks of current first module)
    lea r10, [rax + 0x10]                   ; R10 = list_head (ptr to LIST_ENTRY)
    mov r11, [r10]                           ; R11 = first = list_head->Flink

    mov [rsp + 0x00], r11                   ; new->Flink = first
    mov [rsp + 0x08], r10                   ; new->Blink = list_head
    mov [r11 + 0x08], rsp                   ; first->Blink = &new  (Blink is at LIST_ENTRY+8)
    mov [r10], rsp                           ; list_head->Flink = &new

    ; RSP stays 0x100 lower; fake entry remains valid for entire PE execution.
    ; Falls through to seh_registrar64 (if .pdata present) or tls_callbacks64.
