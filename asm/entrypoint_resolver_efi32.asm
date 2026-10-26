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
; The resolver scans page-aligned addresses for EFI_TABLE_HEADER signature, then
; resolves a real EFI_HANDLE via BootServices->LocateHandleBuffer(AllHandles)
; (firmware always has at least one handle registered) and calls
; efi_main(ResolvedHandle, SystemTable) in IA-32 cdecl.  Falls back to NULL for
; ImageHandle if SystemTable or the handle lookup can't be resolved.

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
; EFI_BOOT_SERVICES.LocateHandleBuffer is the 37th function pointer after the
; EFI_TABLE_HEADER (24 bytes): 0x18 + 36*4 = 0xA8 (32-bit function table).
%define EFI_BS_LOCATE_HANDLE_BUFFER_OFFSET_32   0xA8
; EFI_LOCATE_SEARCH_TYPE.AllHandles = 0 (enumerate every registered handle).
%define EFI_LOCATE_SEARCH_ALL_HANDLES           0
; LocateHandleBuffer cdecl cleanup: 5 pushed dword args * 4 bytes = 0x14.
%define LHB_CDECL_ARGS_SIZE_32                  0x14

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
    push eax                    ; stash VA on the stack (avoids relying on any
                                 ; register surviving the LocateHandleBuffer call
                                 ; below - popped back out at _call_efi_main32)

    ; Resolve an always-available EFI_HANDLE via BootServices->LocateHandleBuffer
    ; (AllHandles search) so efi_main gets a real, registered handle instead of
    ; NULL - needed by boot-service calls that validate their handle argument.
    ; Falls back to NULL (EDI stays 0) on any failure along the way.
    xor edi, edi                 ; EDI = resolved EFI_HANDLE, default NULL
    test esi, esi
    jz _call_efi_main32          ; no SystemTable -> no handle lookup possible

    mov ecx, [esi + EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET]
    test ecx, ecx
    jz _call_efi_main32

    mov edx, [ecx + EFI_BS_LOCATE_HANDLE_BUFFER_OFFSET_32]
    test edx, edx
    jz _call_efi_main32

    sub esp, 8                   ; locals: [esp+0]=NoHandles, [esp+4]=BufferPtr
    mov dword [esp], 0
    mov dword [esp+4], 0
    lea eax, [esp+4]             ; &BufferPtr
    lea ecx, [esp]               ; &NoHandles (BootServices ptr no longer needed)
    push eax                     ; arg5: &Buffer
    push ecx                     ; arg4: &NoHandles
    push 0                       ; arg3: SearchKey = NULL
    push 0                       ; arg2: Protocol = NULL
    push EFI_LOCATE_SEARCH_ALL_HANDLES  ; arg1: SearchType = AllHandles
    call edx
    add esp, LHB_CDECL_ARGS_SIZE_32  ; cdecl caller cleanup of 5 pushed args
    mov ecx, [esp]               ; NoHandles
    mov edx, [esp + 4]           ; Buffer (EFI_HANDLE*)
    test eax, eax                ; EFI_STATUS return value (cdecl: in EAX)
    jnz _lhb_done32              ; != EFI_SUCCESS -> keep NULL
    test ecx, ecx
    jz _lhb_done32
    test edx, edx
    jz _lhb_done32
    mov edi, [edx]                ; EDI = Buffer[0] = first EFI_HANDLE
_lhb_done32:
    add esp, 8                    ; free the 2 locals

_call_efi_main32:
    ; Call efi_main(ResolvedHandle, SystemTable) - IA-32 cdecl: right-to-left push.
    pop eax                      ; EAX = efi_main VA (popped back off the stack)
    push esi                     ; arg2: SystemTable
    push edi                     ; arg1: ImageHandle = resolved handle (NULL if unresolved)
    call eax
    add esp, 8                   ; cdecl caller cleanup
    ret
