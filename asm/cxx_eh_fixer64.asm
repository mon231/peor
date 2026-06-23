; cxx_eh_fixer64.asm - Patches the PE's IAT to hook RtlPcToFileHeader so that
; _CxxThrowException gets the correct ImageBase for typed C++ exception matching.
;
; Problem: modern MSVC (exception magic 0x19930522) calls RtlPcToFileHeader to
; get the module's ImageBase, then stores (ThrowInfo - ImageBase) as a 32-bit RVA
; in ExceptionInformation[2] and ImageBase in ExceptionInformation[3].
; __CxxFrameHandler reconstructs the pointer as (ImageBase + RVA).
; For shellcode PEs not in the loader list, RtlPcToFileHeader returns NULL =>
; the RVA calculation truncates the 64-bit ThrowInfo address to 32 bits => garbage
; pointer => handler crashes => catch blocks never fire.
;
; On entry: RBX = PE base (from relocs resolver).
; On exit:  RBX unchanged; falls through to next shellcode.
;
; Two magic 32-bit constants replaced by peor/__main__.py at build time:
;   0x12345678 (LE bytes 78 56 34 12) = SizeOfImage
;   0x87654321 (LE bytes 21 43 65 87) = RVA of IAT entry for RtlPcToFileHeader
;
; One magic replaced by setup.py at package-install time:
;   0xFEFEFEFE (LE bytes FE FE FE FE) = byte distance from _setup_ip64 to _data64

    ; == SETUP CODE (runs once, then jumps over the hook stub) ==
    call _setup_ip64            ; push &_setup_ip64, fall into setup
_setup_ip64:
    pop rax                     ; rax = &_setup_ip64

    ; Compute runtime address of _data64 (data area inside the hook stub).
    ; The distance is a constant baked in by setup.py.
    add rax, 0x5A5A5A5A         ; FORWARD_MAGIC: setup.py patches to (_data64 - _setup_ip64)

    ; Fill _data64[0] = pe_base, [8] = pe_end, [16] = orig_fn
    mov [rax], rbx              ; pe_base
    mov rcx, rbx
    add rcx, 0x12345678         ; PE_SIZE_MAGIC: peor patches to SizeOfImage
    mov [rax + 8], rcx          ; pe_end
    lea rdx, [rbx + 0x87654321] ; IAT_RVA_MAGIC: peor patches; rdx -> IAT slot
    mov r10, [rdx]              ; r10 = original RtlPcToFileHeader pointer
    mov [rax + 0x10], r10       ; orig_fn

    ; Patch IAT slot -> hook stub.
    ; _hook_stub64 is 5 bytes before _data64 (the CALL instruction prefix).
    lea r11, [rax - 5]          ; r11 = &_hook_stub64
    mov [rdx], r11              ; IAT[RtlPcToFileHeader] = &_hook_stub64

    jmp _after_stub64           ; skip over hook stub; continue chain

    ; == HOOK STUB (called later via IAT whenever RtlPcToFileHeader is invoked) ==
    ; RtlPcToFileHeader(PVOID PcValue: RCX, PVOID* BaseOfImage: RDX) -> PVOID
_hook_stub64:
    call _data_ref64            ; push &_data64, jump to _data_ref64
_data64:
    db 0,0,0,0,0,0,0,0          ; [0]  pe_base  (filled by setup)
    db 0,0,0,0,0,0,0,0          ; [8]  pe_end   (filled by setup)
    db 0,0,0,0,0,0,0,0          ; [16] orig_fn  (filled by setup)
_data_ref64:
    pop r10                     ; r10 = &_data64; RSP restored

    mov rax, [r10]              ; rax = pe_base
    cmp rcx, rax                ; PcValue < pe_base?
    jb _hook_orig64
    mov r11, [r10 + 8]          ; r11 = pe_end
    cmp rcx, r11                ; PcValue >= pe_end?
    jae _hook_orig64

    ; PcValue is inside our PE => return pe_base as the module base
    mov [rdx], rax              ; *BaseOfImage = pe_base
    ret                         ; return pe_base in rax

_hook_orig64:
    ; PcValue is outside our PE => tail-call the real RtlPcToFileHeader
    mov rax, [r10 + 0x10]       ; orig_fn
    jmp rax

_after_stub64:
    ; Execution falls through to seh_registrar64 / tls_callbacks64 / entrypoint_resolver64.
