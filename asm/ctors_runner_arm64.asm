// ARM64 .init_array runner.
// Assembled by keystone (KS_ARCH_ARM64 / KS_MODE_LITTLE_ENDIAN).
//
// On entry: x19 = PE base (from relocations_resolver_arm64).
// On exit:  x19 unchanged; falls through to next shellcode.
//
// x19-x22 are callee-saved in AArch64 ABI, so called constructors preserve them.
// No shadow space is needed (AArch64 UEFI calling convention).

%define CTORS_SECTION_RVA  0xFAFBFCFD
%define CTORS_SECTION_SIZE 0xE1E2E3E4

    ldr w0, _ctors_rva_pool
    b _after_rva_pool
_ctors_rva_pool:
    .byte 0xFD, 0xFC, 0xFB, 0xFA
_after_rva_pool:
    ldr w1, _ctors_size_pool
    b _after_size_pool
_ctors_size_pool:
    .byte 0xE4, 0xE3, 0xE2, 0xE1
_after_size_pool:
    add x21, x19, x0
    add x22, x21, x1

_ctors_loop:
    cmp x21, x22
    b.hs _ctors_done
    ldr x0, [x21], #8
    cbz x0, _ctors_loop
    blr x0
    b _ctors_loop

_ctors_done:
