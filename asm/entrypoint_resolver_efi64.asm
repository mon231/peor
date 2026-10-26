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
; then resolves a real EFI_HANDLE via BootServices->LocateHandleBuffer(AllHandles)
; (firmware always has at least one handle registered) and calls
; efi_main(ResolvedHandle, SystemTable) with the Windows x64 ABI (UEFI MSABI).
; Falls back to NULL for ImageHandle if SystemTable or the handle lookup can't be
; resolved - efi_main must tolerate that, same as before this feature existed.

%define EP_RVA_MAGIC                        0xcececece

; EFI_SYSTEM_TABLE.Hdr.Signature = 0x5453595320494249 (LE)
%define EFI_SYSTEM_TABLE_SIGNATURE_LO           0x20494249
%define EFI_SYSTEM_TABLE_SIGNATURE_HI           0x54535953

; EFI_TABLE_HEADER field offsets
%define EFI_HDR_REVISION_OFFSET                 0x08
%define EFI_HDR_HEADER_SIZE_OFFSET              0x0C

%define EFI_REVISION_MIN                        0x00020000
%define EFI_HEADER_SIZE_MIN                     0x78

; EFI_SYSTEM_TABLE.BootServices is at offset 0x60 (x64 layout)
%define EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET   0x60

; EFI_BOOT_SERVICES.Hdr.Signature = 0x56524553544f4f42 ("BOOTSRV" LE)
%define EFI_BOOT_SERVICES_SIGNATURE_LO          0x544f4f42
%define EFI_BOOT_SERVICES_SIGNATURE_HI          0x56524553

; Scan range: 64 KB start (skip low memory), 512 MB ceiling (covers OVMF on all configs).
; Step is EFI_POOL_ALIGN (16 bytes) because EDK2 AllocatePool aligns at 16 bytes,
; so EFI_SYSTEM_TABLE can sit at any 16-byte boundary within a page.
%define SCAN_START                              0x10000
%define SCAN_END                                0x20000000
%define EFI_POOL_ALIGN                          0x10

; EFI_SYSTEM_TABLE field offsets (x64 layout, 64-bit pointers)
%define EFI_SYSTEM_TABLE_CONOUT_OFFSET          0x40
; EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL field offsets
%define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x08
; Minimum address for valid EFI firmware code pointers (below 1 MB = low/BIOS memory)
%define EFI_FIRMWARE_ADDR_MIN                   0x100000

; Stack offset to the system_table pointer saved by efi_loader_main.
; efi_loader_main (GCC MS-ABI, -O0) saves system_table (rdx) at [rbp+0x18].
; With `push rbp + sub rsp, 0x50 + call SHELLCODE`, RSP at shellcode entry satisfies:
;   [RSP + EFI_LOADER_SYSPTAB_RSP_OFFSET] = system_table
;   offset = 0x50 (frame alloc) + 8 (push rbp) + 8 (call ret addr) + 0x10 (param offset) = 0x70
; IMPORTANT: This offset depends on the exact size of the efi_loader_main stack frame.
; The frame size is 0x50 when efi_loader_main has 5 local pointer variables.
; If locals are added/removed from efi_loader_main, this offset must be recalculated as:
;   (sub_rsp_value) + 8 + 8 + 0x10, where sub_rsp_value = frame alloc from `subq $N, %rsp`.
%define EFI_LOADER_SYSPTAB_RSP_OFFSET           0x70

; Windows x64 ABI shadow space (32 bytes) + 8-byte alignment slot = 40 bytes.
%define MSABI_SHADOW_ALLOC                      0x28

; EFI_BOOT_SERVICES.LocateHandleBuffer is the 37th function pointer after the
; EFI_TABLE_HEADER (24 bytes): 0x18 + 36*8 = 0x138 (64-bit function table).
%define EFI_BS_LOCATE_HANDLE_BUFFER_OFFSET      0x138
; EFI_LOCATE_SEARCH_TYPE.AllHandles = 0 (enumerate every registered handle).
%define EFI_LOCATE_SEARCH_ALL_HANDLES           0
; LocateHandleBuffer MSABI frame: shadow space (0x20) + arg5 stack slot (8) +
; two 8-byte locals (NoHandles, Buffer) = 0x38; 0x38 (mod 16) == 8, matching the
; (mod-16)==8 RSP this block starts at, so after `sub rsp, LHB_FRAME_SIZE` RSP
; lands 16-aligned for the call, exactly like MSABI_SHADOW_ALLOC does below.
%define LHB_FRAME_SIZE                          0x38
%define LHB_ARG5_SLOT_OFF                       0x20   ; &BufferPtr local (arg5, on stack)
%define LHB_NOHANDLES_LOCAL_OFF                 0x28   ; UINTN NoHandles local
%define LHB_BUFFERPTR_LOCAL_OFF                 0x30   ; EFI_HANDLE *Buffer local

    ; Compute entry point VA (EBX = PE base from relocs)
    mov eax, EP_RVA_MAGIC
    add rax, rbx                ; RAX = efi_main VA
    mov rsi, rax                ; stash VA (RSI is MSABI callee-saved - survives the
                                 ; LocateHandleBuffer call below)

    ; Fast path: the EFI loader (efi_loader_main) compiled with GCC MS-ABI saves the
    ; system table pointer it received from firmware at [rbp+0x18].  The RELOCS_64
    ; stub is RSP-neutral (call+pop only), so RSP here equals the RSP at the moment
    ; the loader called SHELLCODE_BYTES.
    mov r13, [rsp + EFI_LOADER_SYSPTAB_RSP_OFFSET]
    test r13, r13
    jz _do_scan
    cmp r13, SCAN_START
    jb _do_scan
    cmp r13, SCAN_END
    jae _do_scan
    cmp dword [r13], EFI_SYSTEM_TABLE_SIGNATURE_LO
    jne _do_scan
    cmp dword [r13 + 4], EFI_SYSTEM_TABLE_SIGNATURE_HI
    je _scan_done               ; signature valid - skip memory scan

_do_scan:
    ; Memory-scan fallback: top-down at EFI_POOL_ALIGN granularity.
    ; EDK2/OVMF places the system table near the top of physical RAM, so a
    ; top-down scan finds it quickly and before coincidental false positives.
    xor r13d, r13d              ; R13 = found pointer (0 = not found)
    mov r14, SCAN_END
    sub r14, EFI_POOL_ALIGN     ; start at last valid 16-byte address

_scan_loop:
    cmp r14, SCAN_START
    jb _scan_done
    ; Step 1: EFI_SYSTEM_TABLE signature check
    cmp dword [r14], EFI_SYSTEM_TABLE_SIGNATURE_LO
    jne _scan_next
    cmp dword [r14 + 4], EFI_SYSTEM_TABLE_SIGNATURE_HI
    jne _scan_next
    ; Step 2: Revision >= 2.0 and HeaderSize >= 0x78
    cmp dword [r14 + EFI_HDR_REVISION_OFFSET], EFI_REVISION_MIN
    jb _scan_next
    cmp dword [r14 + EFI_HDR_HEADER_SIZE_OFFSET], EFI_HEADER_SIZE_MIN
    jb _scan_next
    ; Step 3: validate BootServices pointer is within scan range
    mov r12, [r14 + EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET]
    test r12, r12
    jz _scan_next
    cmp r12, SCAN_START
    jb _scan_next
    cmp r12, SCAN_END
    jae _scan_next
    ; Step 4: verify BootServices starts with EFI_BOOT_SERVICES signature
    cmp dword [r12], EFI_BOOT_SERVICES_SIGNATURE_LO
    jne _scan_next
    cmp dword [r12 + 4], EFI_BOOT_SERVICES_SIGNATURE_HI
    jne _scan_next
    ; Step 5: validate ConOut->OutputString is a high-memory function pointer
    ; (real EFI driver code is above EFI_FIRMWARE_ADDR_MIN; stale/shadow copies have low-mem pointers)
    mov r11, [r14 + EFI_SYSTEM_TABLE_CONOUT_OFFSET]
    test r11, r11
    jz _scan_next
    cmp r11, SCAN_START
    jb _scan_next
    cmp r11, SCAN_END
    jae _scan_next
    mov r10, [r11 + EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF]
    cmp r10, EFI_FIRMWARE_ADDR_MIN
    jb _scan_next
    mov r13, r14                ; all checks passed - valid SystemTable
    jmp _scan_done
_scan_next:
    sub r14, EFI_POOL_ALIGN
    jmp _scan_loop

_scan_done:
    ; Resolve an always-available EFI_HANDLE via BootServices->LocateHandleBuffer
    ; (AllHandles search) so efi_main gets a real, registered handle instead of
    ; NULL - needed by boot-service calls that validate their handle argument.
    ; Falls back to NULL (R15 stays 0) on any failure along the way.
    xor r15d, r15d               ; R15 = resolved EFI_HANDLE, default NULL
    test r13, r13
    jz _call_efi_main            ; no SystemTable -> no handle lookup possible

    ; NOTE: BootServices is NOT bounds-checked against SCAN_START/SCAN_END - that
    ; range only bounds the SystemTable *memory scan* heuristic; BootServices
    ; itself can legitimately live anywhere (same as 05_efi_memory_services's C
    ; code, which dereferences it unconditionally once SystemTable is trusted).
    mov r12, [r13 + EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET]
    test r12, r12
    jz _call_efi_main

    mov r11, [r12 + EFI_BS_LOCATE_HANDLE_BUFFER_OFFSET]
    test r11, r11
    jz _call_efi_main

    sub rsp, LHB_FRAME_SIZE       ; shadow+arg5+locals; RSP = 0 (mod 16) for the call
    lea rax, [rsp + LHB_BUFFERPTR_LOCAL_OFF]
    mov [rsp + LHB_ARG5_SLOT_OFF], rax            ; arg5 (stack): &Buffer local
    mov qword [rsp + LHB_NOHANDLES_LOCAL_OFF], 0
    mov qword [rsp + LHB_BUFFERPTR_LOCAL_OFF], 0
    mov ecx, EFI_LOCATE_SEARCH_ALL_HANDLES        ; arg1: SearchType = AllHandles
    xor edx, edx                                  ; arg2: Protocol = NULL
    xor r8d, r8d                                  ; arg3: SearchKey = NULL
    lea r9, [rsp + LHB_NOHANDLES_LOCAL_OFF]       ; arg4: &NoHandles local
    call r11
    mov r10, [rsp + LHB_NOHANDLES_LOCAL_OFF]      ; NoHandles
    mov r9,  [rsp + LHB_BUFFERPTR_LOCAL_OFF]      ; Buffer (EFI_HANDLE*)
    test rax, rax
    jnz _lhb_done                                 ; EFI_STATUS != EFI_SUCCESS -> keep NULL
    test r10, r10
    jz _lhb_done
    test r9, r9
    jz _lhb_done
    mov r15, [r9]                                 ; R15 = Buffer[0] = first EFI_HANDLE
_lhb_done:
    add rsp, LHB_FRAME_SIZE

_call_efi_main:
    ; Call efi_main(ResolvedHandle, SystemTable) with MSABI (Windows x64 / UEFI convention).
    mov rax, rsi                 ; RAX = efi_main VA (stashed earlier)
    sub rsp, MSABI_SHADOW_ALLOC  ; shadow space + alignment; RSP = 0 (mod 16)
    mov rcx, r15                 ; arg1: ImageHandle = resolved handle (NULL if unresolved)
    mov rdx, r13                 ; arg2: SystemTable (0 if not found)
    call rax
    add rsp, MSABI_SHADOW_ALLOC
    ret
