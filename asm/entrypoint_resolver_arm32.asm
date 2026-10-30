; ARM32 (Thumb-2) entry-point resolver - dispatches to DllMain or OEP.
; Assembled by keystone (KS_ARCH_ARM / KS_MODE_THUMB).
; Shared by any non-EFI ARM32 chain (the generic Windows ARM32 chain today) -
; this is the direct ARM32 analog of entrypoint_resolver64.asm /
; entrypoint_resolver_arm64.asm. NOT entrypoint_resolver_efi_arm32.asm, which
; has a different, EFI-specific responsibility (locating EFI_SYSTEM_TABLE by
; memory scan instead of dispatching to DllMain/OEP).
;
; On entry: r4 = PE base (set by relocations_resolver_arm32.asm).
; Detects IMAGE_FILE_DLL and calls DllMain(base, DLL_PROCESS_ATTACH, NULL),
; otherwise branches to AddressOfEntryPoint. AAPCS32 needs no shadow space
; (that is an x64 Windows ABI quirk only) - this stub never touches SP, so
; whatever alignment the loader handed it is preserved.
;
; Pool-loading technique (same proven idiom as entrypoint_resolver_efi_arm32.asm):
; uses a low register (r0) so keystone/LLVM always picks the 2-byte T1 LDR
; (literal) encoding for the backward PC-relative load, rather than relying on
; the alternate 4-byte T2 form.

%define DLL_PROCESS_ATTACH        0x01
%define IMAGE_FILE_DLL            0x2000
%define EP_RVA_MAGIC              0xCECECECE   ; patched by peor: actual AddressOfEntryPoint RVA (or --entry override)
%define PE_E_LFANEW_OFFSET        0x3C
%define NT_CHARACTERISTICS_OFFSET 0x16

    ldr  r0, _ep_rva_pool        ; r0 = AddressOfEntryPoint RVA (T1, 2 bytes)
    b.n  _after_ep_rva_pool      ; skip pool (2 bytes)
_ep_rva_pool:
    .word 0xCECECECE             ; EP_RVA_MAGIC: patched by peor at conversion time
_after_ep_rva_pool:
    add  r0, r0, r4              ; r0 = OEP absolute VA (bit 0 set = Thumb, per compiler convention)
    mov  r6, r0                  ; stash OEP VA (r0 is about to be reused as scratch)

    ldr  r1, [r4, #PE_E_LFANEW_OFFSET]
    add  r1, r1, r4               ; r1 = NT headers
    ldrh r2, [r1, #NT_CHARACTERISTICS_OFFSET]
    tst  r2, #IMAGE_FILE_DLL
    beq  _exe_entry

    ; DLL: call DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)
    mov  r0, r4                   ; arg1: hinstDLL = PE base
    movs r1, #DLL_PROCESS_ATTACH   ; arg2: DLL_PROCESS_ATTACH
    movs r2, #0                    ; arg3: lpvReserved = NULL
    blx  r6                        ; DllMain(base, DLL_PROCESS_ATTACH, NULL)
    bkpt #0                        ; DllMain should call ExitProcess; if not, trap

_exe_entry:
    bx   r6
