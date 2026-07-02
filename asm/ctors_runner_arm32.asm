; ARM32 (Thumb-2) .init_array runner.
; Assembled by keystone (KS_ARCH_ARM / KS_MODE_THUMB).
;
; On entry: r4 = PE base (from relocations_resolver_arm32).
; On exit:  r4 unchanged; falls through to next shellcode.
;
; Pool-loading technique: BL to _load_pools sets LR = pool1 address (plus Thumb bit).
; BIC removes the Thumb bit to get a clean pointer; then two LDR from [r0] and [r0,#4].
; No PC-relative alignment constraint: works regardless of blob start alignment.
;
; r5 = absolute start of .init_array
; r6 = absolute end of .init_array
; r0  = scratch / function pointer
; r12 = scratch (pool address via BIC of LR)

%define CTORS_SECTION_RVA  0xFAFBFCFD
%define CTORS_SECTION_SIZE 0xE1E2E3E4

    bl _load_ctors_pools        ; LR = address of _pool_rva (with Thumb bit set)
_pool_rva:
    .byte 0xFD, 0xFC, 0xFB, 0xFA   ; CTORS_SECTION_RVA magic (patched by chain_builder)
_pool_size:
    .byte 0xE4, 0xE3, 0xE2, 0xE1   ; CTORS_SECTION_SIZE magic (patched by chain_builder)
_load_ctors_pools:
    bic  r12, lr, #1           ; r12 = pool1 address (strip Thumb interworking bit)
    ldr  r5, [r12]             ; r5 = CTORS_SECTION_RVA
    ldr  r6, [r12, #4]         ; r6 = CTORS_SECTION_SIZE
    adds r5, r5, r4            ; r5 = absolute start of .init_array
    adds r6, r5, r6            ; r6 = absolute end of .init_array

_ctors_loop:
    cmp  r5, r6
    bhs  _ctors_done
    ldr  r0, [r5], #4          ; r0 = *r5, r5 += 4 (advance to next pointer)
    cbz  r0, _ctors_loop       ; skip null entries
    blx  r0                    ; call constructor (AAPCS: callee preserves r4-r11)
    b    _ctors_loop

_ctors_done:
    nop                         ; 2-byte pad to keep blob size a multiple of 4
