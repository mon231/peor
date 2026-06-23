; cxx_eh_fixer32.asm - Patches the PE's IAT to hook GetModuleHandleExW so that
; _CxxThrowException gets the correct ImageBase for typed C++ exception matching.
;
; Problem: modern MSVC (exception magic 0x19930522) on x86 calls GetModuleHandleExW
; with GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS to locate the module containing the
; throw site. For shellcode PEs not in the loader list this returns NULL => the
; ThrowInfo address is stored as (ThrowInfo - 0) but later truncated by the 32-bit
; cast inside the frame handler, yielding a garbage pointer => handler crashes.
;
; On entry: EBX = PE base (from relocs resolver).
; On exit:  EBX unchanged; falls through to next shellcode.
;
; Two magic 32-bit constants replaced by peor/__main__.py at build time:
;   0xC1C2C3C4 (LE bytes C4 C3 C2 C1) = SizeOfImage
;   0xD1D2D3D4 (LE bytes D4 D3 D2 D1) = RVA of IAT entry for GetModuleHandleExW
;
; One magic replaced by setup.py at package-install time:
;   0xFEFEFEFE (LE bytes FE FE FE FE) = byte distance from _setup_ip32 to _data32

    ; == SETUP CODE (runs once, then jumps over the hook stub) ==
    call _setup_ip32            ; push &_setup_ip32, fall into setup
_setup_ip32:
    pop eax                     ; eax = &_setup_ip32

    ; Compute runtime address of _data32 (data area inside the hook stub).
    add eax, 0xFEFEFEFE         ; FORWARD_MAGIC: setup.py patches to (_data32 - _setup_ip32)

    ; Fill _data32[0] = pe_base, [4] = pe_end, [8] = orig_fn
    mov [eax], ebx              ; pe_base
    mov ecx, ebx
    add ecx, 0xC1C2C3C4         ; PE_SIZE_MAGIC32: peor patches to SizeOfImage
    mov [eax + 4], ecx          ; pe_end
    lea edx, [ebx + 0xD1D2D3D4] ; IAT_RVA_MAGIC32: peor patches; edx -> IAT slot
    mov ecx, [edx]              ; ecx = original GetModuleHandleExW pointer
    mov [eax + 8], ecx          ; orig_fn

    ; Patch IAT slot -> hook stub.
    ; _hook_stub32 is 5 bytes before _data32 (the CALL instruction prefix).
    lea ecx, [eax - 5]          ; ecx = &_hook_stub32
    mov [edx], ecx              ; IAT[GetModuleHandleExW] = &_hook_stub32

    jmp _after_stub32           ; skip over hook stub; continue chain

    ; == HOOK STUB (called later via IAT whenever GetModuleHandleExW is invoked) ==
    ; GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule) -> BOOL
    ; Stdcall: [esp+4]=dwFlags, [esp+8]=lpModuleName, [esp+12]=phModule
_hook_stub32:
    call _data_ref32            ; push &_data32, jump to _data_ref32
_data32:
    dd 0                        ; [0] pe_base  (filled by setup)
    dd 0                        ; [4] pe_end   (filled by setup)
    dd 0                        ; [8] orig_fn  (filled by setup)
_data_ref32:
    pop eax                     ; eax = &_data32; ESP restored

    ; Only intercept calls with GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS (bit 2)
    test dword [esp + 4], 4
    jz _hook_orig32

    ; Check if lpModuleName (used as address) is in [pe_base, pe_end)
    mov ecx, [esp + 8]          ; lpModuleName = address to look up
    cmp ecx, [eax]              ; vs pe_base
    jb _hook_orig32
    cmp ecx, [eax + 4]          ; vs pe_end
    jae _hook_orig32

    ; Address is inside our PE => write pe_base to *phModule, return TRUE
    mov ecx, [esp + 0xc]        ; phModule
    mov edx, [eax]              ; pe_base
    mov [ecx], edx              ; *phModule = pe_base
    mov eax, 1                  ; TRUE
    ret 0xc                     ; stdcall: 3 args * 4 bytes = 12

_hook_orig32:
    ; eax = &_data32 on all paths (never changed between pop eax and here)
    jmp dword [eax + 8]         ; tail-call original GetModuleHandleExW

_after_stub32:
    ; Execution falls through to tls_callbacks32 / entrypoint_resolver32.
