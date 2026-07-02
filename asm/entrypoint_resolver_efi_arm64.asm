// ARM64 EFI entry-point resolver - finds EFI_SYSTEM_TABLE, then calls efi_main.
// Assembled by keystone (KS_ARCH_ARM64 / KS_MODE_LITTLE_ENDIAN).
//
// The shellcode is FULLY SELF-CONTAINED: efi_loader_main calls it as `EFI_STATUS (*)(void)`,
// so x0/x1 hold no meaningful values at entry (never the firmware's ImageHandle/SystemTable).
// ImageHandle is passed as NULL to efi_main (no caller guarantees a valid handle).
//
// SystemTable discovery, in order:
//   1. Fast path: read it from efi_loader_main's own stack frame at a fixed SP offset
//      (calibrated to tests/EFI/efi_loader/main.c compiled by clang -O0 for
//      aarch64-w64-mingw32 -- disassembly confirms `str x1, [sp, #0x70]` right after
//      `sub sp, sp, #0x90` at function entry; our own `str x30, [sp, #-16]!` below shifts
//      SP by -16 first, so the offset from OUR sp becomes 0x70+0x10 = 0x80), then
//      validated the same way the scan would before trusting it.
//   2. Fallback: memory scan from SCAN_END down to SCAN_START, checking each 16-byte
//      aligned address for EFI_SYSTEM_TABLE_SIGNATURE + Revision/HeaderSize/BootServices/
//      ConOut validity.  This scan walks through EDK2's own live memory (unlike x64/x86's
//      mostly-empty scan range) and can accept false-positive matches that pass the same
//      signature/BootServices/ConOut checks but aren't the real table -- jumping through
//      their resolved OutputString pointer then crashes with a Synchronous Exception deep
//      in EDK2.  The fast path above exists specifically to avoid ever needing this scan
//      in the common case; keep it only as a last resort.
//
// On entry (after relocations_resolver_arm64 + ctors_runner_arm64, if present):
//   x19 = PE base (set by relocations_resolver_arm64)
//   SP = 16-byte aligned; LR = return address to efi_loader_main
//
// Scan range (fallback only): the ARM64 EFI test boots QEMU "virt" (-cpu cortex-a57
// -m 256M), which maps DRAM at 0x40000000; SCAN_START/SCAN_END cover that 256 MiB window.
// Step is EFI_POOL_ALIGN (16 bytes) because EDK2 AllocatePool aligns at 16 bytes.

%define EP_RVA_MAGIC                             0xCECECECE

; efi_loader_main (ARM64, clang -O0) saves system_table (x1) at [sp+0x70] right after
; `sub sp, sp, #0x90`.  Our prologue does `str x30, [sp, #-16]!` before reading it, so the
; offset from OUR sp is 0x70 + 0x10.  Recalculate if tests/EFI/efi_loader/main.c's ARM64
; branch or its compile flags change (frame size = sub_rsp_value from the disassembly).
%define EFI_LOADER_SYSPTAB_SP_OFFSET             0x80

; EFI_SYSTEM_TABLE.Hdr.Signature = 0x5453595320494249 (LE), split into movz/movk halves.
%define EFI_SYSTEM_TABLE_SIGNATURE_LO_H16        0x2049
%define EFI_SYSTEM_TABLE_SIGNATURE_LO_L16        0x4249
%define EFI_SYSTEM_TABLE_SIGNATURE_HI_H16        0x5453
%define EFI_SYSTEM_TABLE_SIGNATURE_HI_L16        0x5953

%define EFI_HDR_REVISION_OFFSET                  0x08
%define EFI_HDR_HEADER_SIZE_OFFSET               0x0C
%define EFI_REVISION_MIN_H16                     0x0002
%define EFI_HEADER_SIZE_MIN                      0x78

; EFI_SYSTEM_TABLE.BootServices is at offset 0x60 (x64/ARM64 layout, 64-bit pointers)
%define EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET    0x60
%define EFI_BOOT_SERVICES_SIGNATURE_LO_H16       0x544f
%define EFI_BOOT_SERVICES_SIGNATURE_LO_L16       0x4f42
%define EFI_BOOT_SERVICES_SIGNATURE_HI_H16       0x5652
%define EFI_BOOT_SERVICES_SIGNATURE_HI_L16       0x4553

%define SCAN_START_H16                           0x4000
%define SCAN_END_H16                             0x5000
%define EFI_POOL_ALIGN                           0x10

%define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x40
%define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x08
%define EFI_FIRMWARE_ADDR_MIN_H16                0x0010

    ldr w0, _ep_rva_pool
    add x25, x19, x0
    b _after_ep_rva_pool
_ep_rva_pool:
    .byte 0xCE, 0xCE, 0xCE, 0xCE
_after_ep_rva_pool:

    str x30, [sp, #-16]!

    movz w9, SCAN_START_H16, lsl #16    ; x9  = SCAN_START (persists: lower bound for _validate)
    movz w15, SCAN_END_H16, lsl #16     ; x15 = SCAN_END   (persists: upper bound for _validate)

    ; Fast path: validate the candidate sitting in efi_loader_main's own stack frame.
    ldr  x14, [sp, EFI_LOADER_SYSPTAB_SP_OFFSET]
    bl   _validate
    cbnz x13, _scan_done                ; valid -> skip the scan entirely

    ; Fallback: memory scan from SCAN_END down to SCAN_START.
    sub  x14, x15, EFI_POOL_ALIGN       ; x14 = last valid 16-byte-aligned address

_scan_loop:
    cmp  x14, x9
    b.lo _scan_done
    bl   _validate
    cbnz x13, _scan_done
    sub  x14, x14, EFI_POOL_ALIGN
    b    _scan_loop

_scan_done:
    ; Call efi_main(NULL, SystemTable) - AArch64 UEFI calling convention (x0, x1).
    mov  x0, xzr                 ; arg1: ImageHandle = NULL
    mov  x1, x13                 ; arg2: SystemTable (0 if not found)
    blr  x25
    ldr  x30, [sp], #16
    ret

; _validate: checks whether x14 is a plausible EFI_SYSTEM_TABLE (signature, revision,
; header size, and that BootServices/ConOut->OutputString look sane) -- same heuristic
; either way the candidate was found (stack fast-path or memory scan).
; In:  x14 = candidate address; x9 = SCAN_START; x15 = SCAN_END (bounds for embedded pointers)
; Out: x13 = x14 if valid, x13 = 0 if not.  Clobbers x0, x1, x10, x11, x12.  Uses LR (x30).
_validate:
    mov  x13, xzr
    ; Step 1: EFI_SYSTEM_TABLE signature check
    ldr  w0, [x14]
    movz w1, EFI_SYSTEM_TABLE_SIGNATURE_LO_L16
    movk w1, EFI_SYSTEM_TABLE_SIGNATURE_LO_H16, lsl #16
    cmp  w0, w1
    b.ne _validate_done
    ldr  w0, [x14, #4]
    movz w1, EFI_SYSTEM_TABLE_SIGNATURE_HI_L16
    movk w1, EFI_SYSTEM_TABLE_SIGNATURE_HI_H16, lsl #16
    cmp  w0, w1
    b.ne _validate_done
    ; Step 2: Revision >= 2.0 and HeaderSize >= 0x78
    ldr  w0, [x14, EFI_HDR_REVISION_OFFSET]
    movz w1, EFI_REVISION_MIN_H16, lsl #16
    cmp  w0, w1
    b.lo _validate_done
    ldr  w0, [x14, EFI_HDR_HEADER_SIZE_OFFSET]
    movz w1, EFI_HEADER_SIZE_MIN
    cmp  w0, w1
    b.lo _validate_done
    ; Step 3: validate BootServices pointer is within scan range
    ldr  x12, [x14, EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET]
    cbz  x12, _validate_done
    cmp  x12, x9
    b.lo _validate_done
    cmp  x12, x15
    b.hs _validate_done
    ; Step 4: verify BootServices starts with EFI_BOOT_SERVICES signature
    ldr  w0, [x12]
    movz w1, EFI_BOOT_SERVICES_SIGNATURE_LO_L16
    movk w1, EFI_BOOT_SERVICES_SIGNATURE_LO_H16, lsl #16
    cmp  w0, w1
    b.ne _validate_done
    ldr  w0, [x12, #4]
    movz w1, EFI_BOOT_SERVICES_SIGNATURE_HI_L16
    movk w1, EFI_BOOT_SERVICES_SIGNATURE_HI_H16, lsl #16
    cmp  w0, w1
    b.ne _validate_done
    ; Step 5: validate ConOut->OutputString is a high-memory function pointer
    ldr  x11, [x14, EFI_SYSTEM_TABLE_CONOUT_OFFSET]
    cbz  x11, _validate_done
    cmp  x11, x9
    b.lo _validate_done
    cmp  x11, x15
    b.hs _validate_done
    ldr  x10, [x11, EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF]
    movz w1, EFI_FIRMWARE_ADDR_MIN_H16, lsl #16
    cmp  x10, x1
    b.lo _validate_done
    mov  x13, x14                ; all checks passed
_validate_done:
    ret
