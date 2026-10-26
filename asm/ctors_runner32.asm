; x86 .init_array runner.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_32 / KS_OPT_SYNTAX_NASM).
;
; On entry: EBX = PE base.
; On exit:  EBX unchanged; falls through to next shellcode.
;
; Iterates all function pointers in .init_array and calls each non-null one.
; EDI, ESI are callee-saved (Windows x86 cdecl/stdcall ABI).

%define CTORS_SECTION_RVA  0xFAFBFCFD
%define CTORS_SECTION_SIZE 0xE1E2E3E4

    lea edi, [ebx + CTORS_SECTION_RVA]
    lea esi, [edi + CTORS_SECTION_SIZE]

_ctors_loop32:
    cmp edi, esi
    jae _ctors_done32
    mov eax, [edi]
    add edi, 0x04
    test eax, eax
    jz _ctors_loop32
    call eax
    jmp _ctors_loop32

_ctors_done32:
