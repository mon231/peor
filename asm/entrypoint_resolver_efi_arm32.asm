; ARM32 (Thumb-2) EFI entrypoint resolver - scans memory for EFI_SYSTEM_TABLE_SIGNATURE.
; Assembled by keystone (KS_ARCH_ARM / KS_MODE_THUMB).
;
; The shellcode is FULLY SELF-CONTAINED: efi_loader_main calls it as `EFI_STATUS (*)(void)`,
; so r0/r1 hold no meaningful values at entry (never the firmware's ImageHandle/SystemTable).
; SystemTable is located by scanning memory for its signature, then validated via
; BootServices/ConOut.  Once found, a real EFI_HANDLE is resolved via
; BootServices->LocateHandleBuffer(AllHandles) and passed to efi_main; falls back to
; NULL for ImageHandle if SystemTable or the handle lookup can't be resolved.
;
; On entry: r4 = PE base (from relocations_resolver_arm32).
;   (r4-r11/LR were pushed to stack by ARM32_EFI_PREFIX; SP is balanced.)
;
; Scan range: the ARM32 EFI test boots QEMU "virt" (-cpu cortex-a15 -m 256M), which maps
; DRAM at 0x40000000; SCAN_START/SCAN_END cover that 256 MiB window.  This is QEMU-virt
; specific, mirroring entrypoint_resolver_efi32.asm's PC-firmware scan assumptions.
;
; Pool layout (same trick as before): uses r7 (low reg) to force T1 LDR (2 bytes).
;   offset 0: ldr r7, _ep_rva_pool   T1 (2 bytes): AlignedPC=4, pool at 4, imm8=0
;   offset 2: b.n _after_ep_rva_pool T2 (2 bytes): branch to offset 8
;   offset 4: .word 0xCECECECE       EP_RVA_MAGIC (patched by chain_builder)
;   offset 8: _after_ep_rva_pool:
;
; Register plan for the scan (r4 and r9 must survive it):
;   r4  = PE base (untouched)
;   r6  = SCAN_START (persists through loop)
;   r12 = SCAN_END (persists through loop, upper-bound checks)
;   r5  = scan cursor (decrements by EFI_POOL_ALIGN each iteration)
;   r8  = found SystemTable pointer (0 = not found)
;   r9  = OEP absolute address (stashed before the scan clobbers r7)
;   r0, r1, r10, r11 = scratch within each iteration
;
; Calls efi_main(r0=NULL, r1=SystemTable) via blx.
; After efi_main returns, pops r4-r11 and LR-as-PC to return to EFI firmware.

%define EP_RVA_MAGIC                             0xCECECECE

; EFI_SYSTEM_TABLE.Hdr.Signature = 0x5453595320494249 (LE), split into movw/movt halves.
%define EFI_SYSTEM_TABLE_SIGNATURE_LO_H16        0x2049
%define EFI_SYSTEM_TABLE_SIGNATURE_LO_L16        0x4249
%define EFI_SYSTEM_TABLE_SIGNATURE_HI_H16        0x5453
%define EFI_SYSTEM_TABLE_SIGNATURE_HI_L16        0x5953

%define EFI_HDR_REVISION_OFFSET                  0x08
%define EFI_HDR_HEADER_SIZE_OFFSET               0x0C
%define EFI_REVISION_MIN_H16                     0x0002
%define EFI_REVISION_MIN_L16                     0x0000
%define EFI_HEADER_SIZE_MIN                      0x48

; EFI_SYSTEM_TABLE.BootServices is at offset 0x3C in IA-32/ARM32 layout (32-bit pointers)
%define EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET    0x3C
%define EFI_BOOT_SERVICES_SIGNATURE_LO_H16       0x544f
%define EFI_BOOT_SERVICES_SIGNATURE_LO_L16       0x4f42
%define EFI_BOOT_SERVICES_SIGNATURE_HI_H16       0x5652
%define EFI_BOOT_SERVICES_SIGNATURE_HI_L16       0x4553

%define SCAN_START_H16                           0x4000
%define SCAN_END_H16                             0x5000
%define EFI_POOL_ALIGN                           0x10

%define EFI_SYSTEM_TABLE_CONOUT_OFFSET_32        0x2C
%define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x04
%define EFI_FIRMWARE_ADDR_MIN_H16                0x0010
%define EFI_FIRMWARE_ADDR_MIN_L16                0x0000

; EFI_BOOT_SERVICES.LocateHandleBuffer is the 37th function pointer after the
; EFI_TABLE_HEADER (24 bytes): 0x18 + 36*4 = 0xA8 (32-bit function table).
%define EFI_BS_LOCATE_HANDLE_BUFFER_OFFSET_32    0xA8

    ldr  r7, _ep_rva_pool       ; r7 = AddressOfEntryPoint RVA (T1, 2 bytes)
    b.n  _after_ep_rva_pool     ; skip pool (2 bytes)
_ep_rva_pool:
    .word 0xCECECECE            ; EP_RVA_MAGIC: patched at shellcode-build time
_after_ep_rva_pool:
    add  r7, r7, r4             ; r7 = OEP absolute address (bit 0 set = Thumb)
    mov  r9, r7                 ; stash OEP address; frees r7 as scan scratch

    movw r6, #0
    movt r6, #SCAN_START_H16    ; r6 = SCAN_START
    movw r12, #0
    movt r12, #SCAN_END_H16     ; r12 = SCAN_END
    subs r5, r12, #EFI_POOL_ALIGN ; r5 = last valid 16-byte-aligned address
    movs r8, #0                 ; r8 = found pointer (0 = not found)

_scan_loop32:
    cmp  r5, r6
    blo  _scan_done32
    ; Step 1: EFI_SYSTEM_TABLE signature check
    ldr  r0, [r5]
    movw r1, #EFI_SYSTEM_TABLE_SIGNATURE_LO_L16
    movt r1, #EFI_SYSTEM_TABLE_SIGNATURE_LO_H16
    cmp  r0, r1
    bne  _scan_next32
    ldr  r0, [r5, #4]
    movw r1, #EFI_SYSTEM_TABLE_SIGNATURE_HI_L16
    movt r1, #EFI_SYSTEM_TABLE_SIGNATURE_HI_H16
    cmp  r0, r1
    bne  _scan_next32
    ; Step 2: Revision >= 2.0 and HeaderSize >= 0x48
    ldr  r0, [r5, #EFI_HDR_REVISION_OFFSET]
    movw r1, #EFI_REVISION_MIN_L16
    movt r1, #EFI_REVISION_MIN_H16
    cmp  r0, r1
    blo  _scan_next32
    ldr  r0, [r5, #EFI_HDR_HEADER_SIZE_OFFSET]
    cmp  r0, #EFI_HEADER_SIZE_MIN
    blo  _scan_next32
    ; Step 3: validate BootServices pointer is within scan range
    ldr  r11, [r5, #EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET]
    cmp  r11, #0
    beq  _scan_next32
    cmp  r11, r6
    blo  _scan_next32
    cmp  r11, r12
    bhs  _scan_next32
    ; Step 4: verify BootServices starts with EFI_BOOT_SERVICES signature
    ldr  r0, [r11]
    movw r1, #EFI_BOOT_SERVICES_SIGNATURE_LO_L16
    movt r1, #EFI_BOOT_SERVICES_SIGNATURE_LO_H16
    cmp  r0, r1
    bne  _scan_next32
    ldr  r0, [r11, #4]
    movw r1, #EFI_BOOT_SERVICES_SIGNATURE_HI_L16
    movt r1, #EFI_BOOT_SERVICES_SIGNATURE_HI_H16
    cmp  r0, r1
    bne  _scan_next32
    ; Step 5: validate ConOut->OutputString is a high-memory function pointer
    ldr  r11, [r5, #EFI_SYSTEM_TABLE_CONOUT_OFFSET_32]
    cmp  r11, #0
    beq  _scan_next32
    cmp  r11, r6
    blo  _scan_next32
    cmp  r11, r12
    bhs  _scan_next32
    ldr  r10, [r11, #EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF]
    movw r1, #EFI_FIRMWARE_ADDR_MIN_L16
    movt r1, #EFI_FIRMWARE_ADDR_MIN_H16
    cmp  r10, r1
    blo  _scan_next32
    mov  r8, r5                 ; all checks passed - valid SystemTable
    b    _scan_done32
_scan_next32:
    subs r5, r5, #EFI_POOL_ALIGN
    b    _scan_loop32

_scan_done32:
    ; Resolve an always-available EFI_HANDLE via BootServices->LocateHandleBuffer
    ; (AllHandles search) so efi_main gets a real, registered handle instead of
    ; NULL - needed by boot-service calls that validate their handle argument.
    ; r8 (SystemTable) and r9 (OEP) are stashed on the stack rather than trusted
    ; to survive the call in-register: r7/r11 are used as a frame pointer by some
    ; ARM compilers, so no register is assumed safe across a real firmware call.
    push {r8, r9}
    movs r4, #0                  ; r4 = resolved EFI_HANDLE, default NULL
    cmp  r8, #0
    beq  _call_efi_main32        ; no SystemTable -> no handle lookup possible

    ldr  r5, [r8, #EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET]
    cmp  r5, #0
    beq  _call_efi_main32

    ldr  r6, [r5, #EFI_BS_LOCATE_HANDLE_BUFFER_OFFSET_32]
    cmp  r6, #0
    beq  _call_efi_main32

    sub  sp, sp, #16             ; [sp+0]=5th arg slot, [sp+4]=pad, [sp+8]=NoHandles, [sp+12]=Buffer
    movs r12, #0
    str  r12, [sp, #8]           ; NoHandles local = 0
    str  r12, [sp, #12]          ; Buffer local = 0
    add  r12, sp, #12            ; r12 = &Buffer local
    str  r12, [sp, #0]           ; arg5 (stack): &Buffer
    movs r0, #0                  ; arg1: SearchType = AllHandles (0)
    movs r1, #0                  ; arg2: Protocol = NULL
    movs r2, #0                  ; arg3: SearchKey = NULL
    add  r3, sp, #8              ; arg4: &NoHandles local
    blx  r6
    ldr  r1, [sp, #8]            ; NoHandles result
    ldr  r2, [sp, #12]           ; Buffer result (EFI_HANDLE*)
    cmp  r0, #0
    bne  _lhb_done32             ; EFI_STATUS != EFI_SUCCESS -> keep NULL
    cmp  r1, #0
    beq  _lhb_done32
    cmp  r2, #0
    beq  _lhb_done32
    ldr  r4, [r2]                ; r4 = Buffer[0] = first EFI_HANDLE
_lhb_done32:
    add  sp, sp, #16

_call_efi_main32:
    ; Call efi_main(ResolvedHandle, SystemTable) via blx.
    pop  {r8, r9}                 ; restore SystemTable (r8), OEP (r9)
    mov  r0, r4                   ; arg1: ImageHandle = resolved handle (NULL if unresolved)
    mov  r1, r8                   ; arg2: SystemTable
    blx  r9
    pop  {r4, r5, r6, r7, r8, r9, r10, r11, pc}
