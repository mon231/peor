; x86 EFI entry-point resolver - scans memory for EFI_SYSTEM_TABLE_SIGNATURE.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_32 / KS_OPT_SYNTAX_NASM).
;
; The shellcode is FULLY SELF-CONTAINED: it never relies on runtime parameters.
; [ESP+4] (ImageHandle) and [ESP+8] (SystemTable) from the firmware call are
; IGNORED - they may have been clobbered by relocations_resolver32, and in any
; injection scenario no caller provides them.
;
; On entry (after relocs):
;   EBX = PE base (set by relocations_resolver32)
;   [ESP] = return address to firmware/loader
;
; The resolver scans page-aligned addresses for EFI_TABLE_HEADER signature,
; then calls efi_main(NULL, SystemTable) in IA-32 cdecl.
; NULL is passed for ImageHandle because no caller guarantees it is valid.

%define EP_RVA_MAGIC                    0xcececece

%define EFI_SYSTEM_TABLE_SIGNATURE_LO           0x20494249
%define EFI_SYSTEM_TABLE_SIGNATURE_HI           0x54535953
%define EFI_HDR_REVISION_OFFSET                 0x08
%define EFI_HDR_HEADER_SIZE_OFFSET              0x0C
%define EFI_REVISION_MIN                        0x00020000
; x86 EFI_SYSTEM_TABLE is 0x48 bytes (32-bit pointers)
%define EFI_HEADER_SIZE_MIN                     0x48

; EFI_SYSTEM_TABLE.BootServices is at offset 0x3C in IA-32 layout (32-bit pointers)
%define EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET   0x3C

%define EFI_BOOT_SERVICES_SIGNATURE_LO          0x544f4f42
%define EFI_BOOT_SERVICES_SIGNATURE_HI          0x56524553

%define SCAN_START                              0x10000
%define SCAN_END                                0x10000000
%define EFI_POOL_ALIGN                          0x10

; EFI_SYSTEM_TABLE field offsets (x86 layout, 32-bit pointers)
%define EFI_SYSTEM_TABLE_CONOUT_OFFSET_32       0x2C
; EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.OutputString is the 2nd member.
; On IA-32 all function pointers are 4 bytes, so OutputString sits at offset 4.
%define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x04
; Minimum address for valid EFI firmware code pointers (below 1 MB = low/BIOS memory)
%define EFI_FIRMWARE_ADDR_MIN                   0x100000
; NULL ImageHandle to pass when invoking efi_main from self-contained shellcode
%define EFI_NULL_IMAGE_HANDLE                   0

    ; Scan top-down at 16-byte granularity; EDK2 places system table near top of RAM.
    ; Validate BootServices pointer to reject false positives.
    mov esi, SCAN_END
    sub esi, EFI_POOL_ALIGN     ; start at last valid 16-byte address

_scan_loop32:
    cmp esi, SCAN_START
    jb _scan_done32
    ; Step 1: EFI_SYSTEM_TABLE signature check
    cmp dword [esi], EFI_SYSTEM_TABLE_SIGNATURE_LO
    jne _scan_next32
    cmp dword [esi + 4], EFI_SYSTEM_TABLE_SIGNATURE_HI
    jne _scan_next32
    ; Step 2: Revision and HeaderSize
    cmp dword [esi + EFI_HDR_REVISION_OFFSET], EFI_REVISION_MIN
    jb _scan_next32
    cmp dword [esi + EFI_HDR_HEADER_SIZE_OFFSET], EFI_HEADER_SIZE_MIN
    jb _scan_next32
    ; Step 3: validate BootServices pointer within scan range
    mov edi, dword [esi + EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET]
    test edi, edi
    jz _scan_next32
    cmp edi, SCAN_START
    jb _scan_next32
    cmp edi, SCAN_END
    jae _scan_next32
    ; Step 4: verify BootServices starts with EFI_BOOT_SERVICES signature
    cmp dword [edi], EFI_BOOT_SERVICES_SIGNATURE_LO
    jne _scan_next32
    cmp dword [edi + 4], EFI_BOOT_SERVICES_SIGNATURE_HI
    jne _scan_next32
    ; Step 5: validate ConOut->OutputString is above EFI_FIRMWARE_ADDR_MIN
    mov eax, dword [esi + EFI_SYSTEM_TABLE_CONOUT_OFFSET_32]
    test eax, eax
    jz _scan_next32
    cmp eax, SCAN_START
    jb _scan_next32
    cmp eax, SCAN_END
    jae _scan_next32
    mov eax, dword [eax + EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF]
    cmp eax, EFI_FIRMWARE_ADDR_MIN
    jb _scan_next32
    jmp _scan_done32            ; ESI = valid SystemTable
_scan_next32:
    sub esi, EFI_POOL_ALIGN
    jmp _scan_loop32
_scan_done32:
    cmp esi, SCAN_START
    jae _have_st32
    xor esi, esi                ; not found: pass NULL
_have_st32:

    ; Compute entry point
    mov eax, EP_RVA_MAGIC
    add eax, ebx                ; EAX = efi_main VA

    ; Call efi_main(NULL, SystemTable) - IA-32 cdecl: right-to-left push
    push esi                    ; arg2: SystemTable
    push EFI_NULL_IMAGE_HANDLE  ; arg1: ImageHandle = NULL
    call eax
    add esp, 8                  ; cdecl caller cleanup
    ret
