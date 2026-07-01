; ARM32 (Thumb-2) EFI entrypoint resolver.
; Assembled by keystone (KS_ARCH_ARM / KS_MODE_THUMB).
;
; On entry: r4 = PE base, r9 = image_handle, r10 = system_table.
;   (r9/r10 were saved by ARM32_EFI_PREFIX before relocations ran.)
;   (r4-r11/LR were pushed to stack by ARM32_EFI_PREFIX; SP is balanced.)
;
; Pool layout: uses r7 (low reg) to force T1 LDR (2 bytes), keeping pool at offset 4
; (4-byte aligned if blob start is 4-byte aligned, guaranteed by chain layout).
;   offset 0: ldr r7, _ep_rva_pool   T1 (2 bytes): AlignedPC=4, pool at 4, imm8=0
;   offset 2: b.n _after_ep_rva_pool T2 (2 bytes): branch to offset 8
;   offset 4: .word 0xCECECECE       EP_RVA_MAGIC (patched by chain_builder)
;   offset 8: _after_ep_rva_pool:
;
; Calls efi_main(r0=image_handle, r1=system_table) via blx.
; After efi_main returns, pops r4-r11 and LR-as-PC to return to EFI firmware.

%define EP_RVA_MAGIC 0xCECECECE

    ldr  r7, _ep_rva_pool       ; r7 = AddressOfEntryPoint RVA (T1, 2 bytes)
    b.n  _after_ep_rva_pool     ; skip pool (2 bytes)
_ep_rva_pool:
    .word 0xCECECECE            ; EP_RVA_MAGIC: patched at shellcode-build time
_after_ep_rva_pool:
    add  r7, r7, r4             ; r7 = OEP absolute address (bit 0 set = Thumb)
    mov  r0, r9                 ; r0 = image_handle
    mov  r1, r10                ; r1 = system_table
    blx  r7                     ; efi_main(image_handle, system_table) -> r0 = EFI_STATUS
    pop  {r4, r5, r6, r7, r8, r9, r10, r11, pc}
