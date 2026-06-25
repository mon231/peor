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

%define EFI_SYSTEM_TABLE_SIGNATURE_LO   0x20494249
%define EFI_SYSTEM_TABLE_SIGNATURE_HI   0x54535953
%define EFI_HDR_REVISION_OFFSET         0x08
%define EFI_HDR_HEADER_SIZE_OFFSET      0x0C
%define EFI_REVISION_MIN                0x00020000
%define EFI_HEADER_SIZE_MIN             0x78

%define SCAN_START                      0x10000
%define SCAN_END                        0x10000000
%define PAGE_SIZE                       0x1000

    ; Scan page-aligned memory for EFI_SYSTEM_TABLE_SIGNATURE
    mov esi, SCAN_START         ; ESI = current scan page

_scan_loop32:
    cmp esi, SCAN_END
    jae _scan_done32
    cmp dword [esi], EFI_SYSTEM_TABLE_SIGNATURE_LO
    jne _scan_next32
    cmp dword [esi + 4], EFI_SYSTEM_TABLE_SIGNATURE_HI
    jne _scan_next32
    cmp dword [esi + EFI_HDR_REVISION_OFFSET], EFI_REVISION_MIN
    jb _scan_next32
    cmp dword [esi + EFI_HDR_HEADER_SIZE_OFFSET], EFI_HEADER_SIZE_MIN
    jb _scan_next32
    jmp _scan_done32            ; ESI = valid SystemTable pointer
_scan_next32:
    add esi, PAGE_SIZE
    jmp _scan_loop32
_scan_done32:
    ; ESI = SystemTable VA (or SCAN_END if not found -> pass as-is, efi_main should handle NULL)
    cmp esi, SCAN_END
    jb _have_st32
    xor esi, esi                ; pass NULL if not found
_have_st32:

    ; Compute entry point
    mov eax, EP_RVA_MAGIC
    add eax, ebx                ; EAX = efi_main VA

    ; Call efi_main(NULL, SystemTable) - IA-32 cdecl: right-to-left push
    push esi                    ; arg2: SystemTable
    push 0                      ; arg1: ImageHandle = NULL
    call eax
    add esp, 8                  ; cdecl caller cleanup
    ret
