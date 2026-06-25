; x64 EFI entry-point resolver - scans memory for EFI_SYSTEM_TABLE_SIGNATURE.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_64 / KS_OPT_SYNTAX_NASM).
;
; The shellcode is FULLY SELF-CONTAINED: it never relies on runtime parameters
; from any caller.  RCX/RDX (firmware ImageHandle/SystemTable) are ignored -
; they are clobbered by relocations_resolver64 anyway.
;
; On entry (after relocs):
;   RBX = PE base (set by relocations_resolver64)
;   RSP = 8 (mod 16) - caller's return address on the stack
;
; The resolver scans page-aligned addresses for the EFI_TABLE_HEADER signature,
; then calls efi_main(NULL, SystemTable) with the Windows x64 ABI (UEFI MSABI).
; NULL is passed for ImageHandle because no caller guarantees it is valid.

%define EP_RVA_MAGIC                        0xcececece

; EFI_SYSTEM_TABLE.Hdr.Signature = 0x5453595320494249 (LE)
%define EFI_SYSTEM_TABLE_SIGNATURE_LO       0x20494249
%define EFI_SYSTEM_TABLE_SIGNATURE_HI       0x54535953

; EFI_TABLE_HEADER field offsets (Revision is at offset 8, HeaderSize at 12)
%define EFI_HDR_REVISION_OFFSET             0x08
%define EFI_HDR_HEADER_SIZE_OFFSET          0x0C

%define EFI_REVISION_MIN                    0x00020000
%define EFI_HEADER_SIZE_MIN                 0x78

; Scan range: 64 KB start (skip low memory), 512 MB ceiling (covers OVMF on all configs)
%define SCAN_START                          0x10000
%define SCAN_END                            0x20000000
%define PAGE_SIZE                           0x1000

    ; Compute entry point VA (EBX = PE base from relocs)
    mov eax, EP_RVA_MAGIC
    add rax, rbx                ; RAX = efi_main VA

    ; Scan page-aligned memory for the EFI_SYSTEM_TABLE_SIGNATURE
    xor r13d, r13d              ; R13 = candidate pointer; 0 means "not found"
    mov r14, SCAN_START

_scan_loop:
    cmp r14, SCAN_END
    jae _scan_done
    cmp dword [r14], EFI_SYSTEM_TABLE_SIGNATURE_LO
    jne _scan_next
    cmp dword [r14 + 4], EFI_SYSTEM_TABLE_SIGNATURE_HI
    jne _scan_next
    cmp dword [r14 + EFI_HDR_REVISION_OFFSET], EFI_REVISION_MIN
    jb _scan_next
    cmp dword [r14 + EFI_HDR_HEADER_SIZE_OFFSET], EFI_HEADER_SIZE_MIN
    jb _scan_next
    mov r13, r14                ; found a valid SystemTable candidate
    jmp _scan_done
_scan_next:
    add r14, PAGE_SIZE
    jmp _scan_loop

_scan_done:
    ; Call efi_main(NULL, SystemTable) with MSABI (Windows x64 / UEFI convention)
    ; NULL for ImageHandle: self-contained shellcode has no guaranteed handle source.
    sub rsp, 0x28               ; 32-byte shadow space + alignment; RSP = 0 (mod 16)
    xor ecx, ecx                ; arg1: ImageHandle = NULL
    mov rdx, r13                ; arg2: SystemTable (0 if not found)
    call rax
    add rsp, 0x28
    ret
