// ARM64 entry-point resolver - dispatches to DllMain or OEP.
// Assembled by keystone (KS_ARCH_ARM64 / KS_MODE_LITTLE_ENDIAN).
// Shared by every non-EFI ARM64 chain (Linux usermode today; the generic
// Windows ARM64 chain reuses this same file once it lands - this is the
// direct ARM64 analog of entrypoint_resolver64.asm, which x64 already
// shares between its Windows and Linux platform entries unmodified).
//
// On entry: x19 = PE base (set by relocations_resolver_arm64.asm).
// Detects IMAGE_FILE_DLL and calls DllMain(base, DLL_PROCESS_ATTACH, NULL),
// otherwise branches to AddressOfEntryPoint. AAPCS64 needs no shadow space
// (that is an x64 Windows ABI quirk) - only 16-byte SP alignment at the call,
// already satisfied since this stub does not touch SP.

%define DLL_PROCESS_ATTACH   0x01
%define IMAGE_FILE_DLL       0x2000
%define EP_RVA_MAGIC         0xCECECECE   ; patched by peor: actual AddressOfEntryPoint RVA (or --entry override)
%define PE_E_LFANEW_OFFSET   0x3C
%define NT_CHARACTERISTICS_OFFSET 0x16

    ldr w0, [x19, PE_E_LFANEW_OFFSET]
    add x9, x19, x0                 ; x9 = NT headers

    ; EP_RVA_MAGIC must be a raw 4-byte literal (not folded into a mov/movz
    ; opcode's immediate bits) because peor finds-and-replaces it as bytes
    ; after assembly - same literal-pool technique relocations_resolver_arm64.asm
    ; already uses for its own patched PE_OFFSET.
    b _after_ep_pool
_ep_rva_pool:
    .byte 0xCE,0xCE,0xCE,0xCE        ; patched by peor at conversion time -> real AddressOfEntryPoint RVA
_after_ep_pool:
    ldr w10, _ep_rva_pool
    add x10, x10, x19                ; x10 = OEP VA

    ldrh w11, [x9, NT_CHARACTERISTICS_OFFSET]
    tst w11, IMAGE_FILE_DLL
    b.eq _exe_entry

    ; DLL: call DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)
    mov x0, x19                       ; arg1: hinstDLL = PE base
    mov x1, DLL_PROCESS_ATTACH        ; arg2: DLL_PROCESS_ATTACH
    mov x2, 0                         ; arg3: lpvReserved = NULL
    blr x10                           ; DllMain(base, DLL_PROCESS_ATTACH, NULL)
    brk #0                            ; DllMain should call exit(); if not, trap

_exe_entry:
    br x10
