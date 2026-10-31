; ARM32 (Thumb-2) entry-point resolver - dispatches to DllMain or OEP.
; Assembled by keystone (KS_ARCH_ARM / KS_MODE_THUMB).
; Shared by every non-EFI ARM32 chain (Linux usermode today; the generic
; Windows ARM32 chain can reuse this same file once it lands - this is the
; direct ARM32 analog of entrypoint_resolver_arm64.asm, which is itself the
; AArch64 analog of entrypoint_resolver64.asm, already shared between x64's
; Windows and Linux platform entries unmodified).
;
; On entry: r4 = PE base (set by relocations_resolver_arm32.asm - see that
; file's own header comment: "On exit: r4 = PE base; falls through to next
; shellcode").
; Detects IMAGE_FILE_DLL and calls DllMain(base, DLL_PROCESS_ATTACH, NULL),
; otherwise dispatches to AddressOfEntryPoint. AAPCS32 needs no shadow space
; (an x64 Windows ABI quirk) and no stack realignment here - this stub never
; touches SP.

%define DLL_PROCESS_ATTACH        0x01
%define IMAGE_FILE_DLL            0x2000
%define PE_E_LFANEW_OFFSET        0x3C
%define NT_CHARACTERISTICS_OFFSET 0x16

    ldr r0, [r4, #PE_E_LFANEW_OFFSET]
    add r9, r4, r0                  ; r9 = NT headers

    ; EP_RVA_MAGIC must be a raw 4-byte literal (not folded into a mov/movw/movt
    ; opcode's immediate bits) because peor finds-and-replaces it as bytes
    ; after assembly - same literal-pool technique entrypoint_resolver_efi_arm32.asm
    ; already uses for its own patched EP_RVA_MAGIC (forward T1 2-byte ldr-literal,
    ; low register, pool immediately after the skip branch).
    ldr r0, _ep_rva_pool         ; r0 = AddressOfEntryPoint RVA (T1, 2 bytes)
    b.n _after_ep_rva_pool       ; skip pool (2 bytes)
_ep_rva_pool:
    .word 0xCECECECE             ; patched by peor at conversion time -> real AddressOfEntryPoint RVA
_after_ep_rva_pool:
    add r10, r0, r4               ; r10 = OEP absolute address (bit 0 set = Thumb)

    ldrh r11, [r9, #NT_CHARACTERISTICS_OFFSET]
    tst r11, #IMAGE_FILE_DLL
    beq.w _exe_entry

    ; DLL: call DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)
    mov r0, r4                     ; arg1: hinstDLL = PE base
    movw r1, #DLL_PROCESS_ATTACH    ; arg2: DLL_PROCESS_ATTACH
    movs r2, #0                     ; arg3: lpvReserved = NULL
    blx r10                         ; DllMain(base, DLL_PROCESS_ATTACH, NULL)
    bkpt #0                          ; DllMain should call exit(); if not, trap

_exe_entry:
    bx r10
