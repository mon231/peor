; ldr_register32.asm - Registers the PE as a fake module in PEB.Ldr (x86).
; Same purpose as ldr_register64.asm but for 32-bit PEs.
;
; Modern MSVC C++ exceptions on x86 (magic 0x19930522): _CxxThrowException calls
; GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, retAddr, &hMod) which
; internally calls LdrFindEntryForAddress to locate the module. For shellcode PEs
; not in the loader's list, hMod=NULL -> params[3]=0 -> ThrowInfo RVA resolved to
; address 0+RVA (small junk pointer) -> __CxxFrameHandler3/4 AV -> catch never fires.
;
; On entry: EBX = PE base (already relocated).
; On exit:  EBX = PE base, ESP -= 0x80 (fake LDR entry on stack), falls through.
;           ESP alignment: 0x80 = 8*16, mod-16 unchanged.
;
; Fake LDR_DATA_TABLE_ENTRY32 layout at [ESP .. ESP+0x7F]:
;   +0x00  InLoadOrderLinks.Flink  (4 bytes) <- linked into Ldr list
;   +0x04  InLoadOrderLinks.Blink  (4 bytes) <- linked into Ldr list
;   ... zeroed ...
;   +0x18  DllBase                 (4 bytes) <- set to EBX (PE base)
;   +0x20  SizeOfImage             (4 bytes) <- Python patches 0x49484746 -> actual value
;   ... rest zeroed ...
;
; SizeOfImage placeholder (little-endian bytes): 46 47 48 49 (= 0x49484746).
; setup.py leaves this magic; __main__.py binary-replaces it with the real SizeOfImage.

    ; Allocate 0x80 bytes on stack for the fake LDR_DATA_TABLE_ENTRY32.
    sub esp, 0x80

    ; Zero the entire region (32 DWORDs = 128 bytes) using edi as a walking pointer.
    lea edi, [esp]
    xor eax, eax
    mov ecx, 32
_zero_ldr32:
    mov [edi], eax
    add edi, 4
    dec ecx
    jnz _zero_ldr32

    ; Fill in the fields needed by LdrFindEntryForAddress.
    mov [esp + 0x18], ebx                   ; DllBase = PE base

    ; SizeOfImage: magic placeholder replaced by Python at chain-build time.
    mov dword [esp + 0x20], 0x49484746

    ; Get PEB32 (FS:[0x30]) then PEB.Ldr (PEB + 0x0C).
    db 0x64
    mov eax, [0x30]                         ; EAX = PEB32 (FS:[0x30])
    mov eax, [eax + 0x0C]                   ; EAX = PEB.Ldr

    ; Insert fake entry at HEAD of InLoadOrderModuleList (Ldr + 0x0C).
    ; list_head = &Ldr->InLoadOrderModuleList (a LIST_ENTRY: Flink at +0, Blink at +4)
    ; first     = list_head->Flink  (pointer to InLoadOrderLinks of current first module)
    lea ecx, [eax + 0x0C]                   ; ECX = list_head
    mov edx, [ecx]                           ; EDX = first = list_head->Flink

    mov [esp + 0x00], edx                   ; new->Flink = first
    mov [esp + 0x04], ecx                   ; new->Blink = list_head
    mov [edx + 0x04], esp                   ; first->Blink = &new  (Blink is at LIST_ENTRY+4)
    mov [ecx], esp                           ; list_head->Flink = &new

    ; ESP stays 0x80 lower; fake entry remains valid for entire PE execution.
    ; Falls through to tls_callbacks32 (or entrypoint_resolver32 if no TLS).
