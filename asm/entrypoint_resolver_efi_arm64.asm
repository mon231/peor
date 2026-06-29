// ARM64 EFI entrypoint resolver - calls efi_main with image_handle=NULL and the
// EFI_SYSTEM_TABLE pointer that was saved in x24 by the ARM64_EFI_PREFIX stub
// (mov x24, x1) prepended to the shellcode chain before relocations_resolver_arm64.
//
// On entry: x19 = PE base (from relocations_resolver_arm64), x24 = system_table.
// x24 is callee-saved and is not touched by the relocs resolver (which uses x20-x23)
// or the ctors runner (which uses x21-x22 and calls constructors that preserve x24).
//
// AArch64 UEFI calling convention: args in x0, x1; SP must be 16-byte aligned.
// Calls efi_main(NULL, system_table) and then returns to caller (efi_loader_main).

%define EP_RVA_MAGIC                            0xCECECECE

    ldr w0, _ep_rva_pool
    add x25, x19, x0
    b _after_ep_rva_pool
_ep_rva_pool:
    .byte 0xCE, 0xCE, 0xCE, 0xCE
_after_ep_rva_pool:

    str x30, [sp, #-16]!
    movz x0, 0
    mov x1, x24
    blr x25
    ldr x30, [sp], #16
    ret
