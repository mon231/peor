// ARM64 .init_array runner.
// Assembled by keystone (KS_ARCH_ARM64 / KS_MODE_LITTLE_ENDIAN).
//
// On entry: x19 = PE base (from relocations_resolver_arm64),
//           x30 = the loader's return address (set by the loader's call,
//           threaded through the relocs resolver's trailing branches).
// On exit:  x30 restored to that return address; x19 unchanged; falls
//           through to next shellcode (the entrypoint stub).
//
// x19-x22 are callee-saved in AArch64 ABI, so called constructors preserve them.
// No shadow space is needed (AArch64 UEFI calling convention).
//
// x30 discipline: AArch64 has no return-address stack - the loader's call put
// the shellcode's return address in x30, and the entrypoint stub reaches the
// PE entry with `br` (no link). The C CTOR does preserve x19-x28 per AAPCS,
// but the blr below still overwrites x30 with the stub's return slot - so a
// leaf C entry (`main`, which never calls anything and therefore never saves
// x30) rets straight back into this stub's trailing branch instead of out to
// the loader: an infinite entrypoint/stub cycle (seen as a ~50/50 pc
// histogram between this stub's loop-back branch and the PE entry). Fix:
// stash x30 in x25 (callee-saved, preserved by all C ctors) before the first
// blr, and restore it in the exit fall-through. x64/x86 don't need this
// because their ctors runners keep the stack balanced (call/ret), so main's
// ret pops the loader's return address naturally.

%define CTORS_SECTION_RVA  0xFAFBFCFD
%define CTORS_SECTION_SIZE 0xE1E2E3E4

    mov x25, x30
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
    mov x30, x25

