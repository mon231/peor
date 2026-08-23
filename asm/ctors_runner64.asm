; x64 .init_array runner.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_64 / KS_OPT_SYNTAX_NASM).
;
; On entry: RBX = PE base, RSP = 8 (mod 16).
; On exit:  RBX unchanged, RSP = 8 (mod 16); falls through to next shellcode.
;
; Iterates all function pointers in .init_array and calls each non-null one.
; R14, R15 are callee-saved (Windows x64 ABI) - preserved across constructor calls.
;
; RSP alignment trace (entry RSP = 8 mod 16):
;   sub rsp, 0x28 -> RSP = 0 (mod 16)
;   call rax      -> RSP = 8 (mod 16) at callee entry  (correct Windows/SysV ABI)
;   [callee ret]  -> RSP = 0 (mod 16)
;   add rsp, 0x28 -> RSP = 8 (mod 16)

%define CTORS_SECTION_RVA  0xFAFBFCFD
%define CTORS_SECTION_SIZE 0xE1E2E3E4

    lea r15, [rbx + CTORS_SECTION_RVA]
    lea r14, [r15 + CTORS_SECTION_SIZE]
    sub rsp, 0x28

_ctors_loop64:
    cmp r15, r14
    jae _ctors_done64
    mov rax, [r15]
    add r15, 0x08
    test rax, rax
    jz _ctors_loop64
    call rax
    jmp _ctors_loop64

_ctors_done64:
    add rsp, 0x28
