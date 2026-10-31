// ARM64 (AArch64) Windows usermode import resolver - position-independent shellcode.
// Assembled by keystone (KS_ARCH_ARM64 / KS_MODE_LITTLE_ENDIAN).
// Direct ARM64 analog of imports_resolver64.asm: same real-Windows-loader
// algorithm (PEB walk to kernel32, export-table walk for GetProcAddress,
// GetProcAddress(kernel32,"LoadLibraryA") for LoadLibraryA, then the target
// PE's IMAGE_IMPORT_DESCRIPTOR table via LoadLibraryA+GetProcAddress) - NOT
// the dlopen/dlsym approach imports_resolver_arm64_linux.asm uses, since this
// is the real Windows PE chain, not the Linux ELF chain.
//
// Runs BEFORE relocs in the chain (see peor/_chain_builder.py's
// _build_shellcode_chain concatenation order: imports + relocs + ...), same
// as imports_resolver64.asm, so it cannot rely on x19=PE base (that is set
// by relocations_resolver_arm64.asm, which has not run yet). This stub
// self-locates the PE image by scanning forward in memory past its own
// code, exactly like imports_resolver64.asm's x64 "_here"/scan-forward
// technique and imports_resolver_arm64_linux.asm's _pe_scan_start.
//
// TEB access: on ARM64 Windows, x18 directly HOLDS the TEB pointer (the
// platform register - no memory read needed to get the base, unlike x64's
// "mov rax, [gs:0x60]"). From there, TEB->PEB, PEB->Ldr, Ldr->module-list,
// and the PE export/import directory offsets are the SAME OS-structure
// offsets imports_resolver64.asm already uses - these are generic Windows
// data structures (TEB/PEB/LDR_DATA_TABLE_ENTRY, IMAGE_EXPORT_DIRECTORY,
// IMAGE_IMPORT_DESCRIPTOR), not ISA-dependent; only the register used to
// reach the TEB differs between x64 and ARM64. Verified against
// imports_resolver64.asm's own offset comments field-by-field (see each
// %define below, each commented with its x64-resolver analog).
//
// No registers need saving/restoring at entry or exit: like
// entrypoint_resolver_arm64.asm, this stub never touches SP, and AAPCS64
// needs no shadow space (an x64-Windows-ABI-only quirk), so SP stays
// 16-byte-aligned (as the OS guarantees at process entry) across every
// internal `blr` call into GetProcAddress/LoadLibraryA. Nothing downstream
// (relocations_resolver_arm64.asm) depends on any of this stub's registers,
// so x19-x29 are used freely as scratch/persistent state.
//
// Register map (persistent across this stub's body):
//   x20 = current IAT write-destination cursor (thunk-walk phase)
//   x21 = kernel32 DllBase (phase 1/2), then current library handle's module scratch
//   x22 = kernel32 export directory VA (phase 2)
//   x24 = GetProcAddress VA
//   x25 = LoadLibraryA VA
//   x26 = target PE image base
//   x27 = current IMAGE_IMPORT_DESCRIPTOR pointer
//   x28 = current INT/FirstThunk name-source cursor
//   x29 = current library module handle (thunk-walk phase)
//
// Keystone notes (gotchas already documented by this session's other ARM64
// files, confirmed again here): string data must be embedded via
// `.byte` (not `db`), with explicit padding to a 4-byte boundary before the
// next instruction (keystone's LLVM backend aborts with "fixup not
// sufficiently aligned" otherwise); a 32-bit immediate needing both
// halfwords non-zero must be split `movz`+`movk`, but every immediate used
// here fits in a single 16-bit halfword so a plain `mov` suffices (keystone
// picks `movz` automatically).

%define TEB_PEB_OFFSET                0x60   ; TEB.ProcessEnvironmentBlock (same offset x64 reaches via gs:[0x60])
%define PEB_LDR_OFFSET                0x18   ; PEB.Ldr (matches imports_resolver64.asm's "[rax+0x18]")
%define LDR_INMEMORYORDER_OFFSET      0x20   ; PEB_LDR_DATA.InMemoryOrderModuleList.Flink
%define LDR_DLLBASE_OFFSET            0x20   ; LDR_DATA_TABLE_ENTRY.DllBase, offset from the Flink
                                              ; pointer (which lands on InMemoryOrderLinks, struct+0x10;
                                              ; DllBase is struct+0x30, so +0x20 from Flink) - same
                                              ; relationship imports_resolver64.asm's "[rsi+0x20]" uses.
%define PE_E_LFANEW_OFFSET            0x3C
%define NT64_EXPORT_DIR_RVA_OFF       0x88   ; NT headers DataDir[0].VA (PE32+, matches imports_resolver64.asm)
%define NT64_IMPORT_DIR_RVA_OFF       0x90   ; NT headers DataDir[1].VA (PE32+, matches imports_resolver64.asm)
%define EXPORT_NUM_NAMES_OFF          0x18   ; IMAGE_EXPORT_DIRECTORY.NumberOfNames
%define EXPORT_ADDR_FUNCTIONS_OFF     0x1C   ; IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
%define EXPORT_ADDR_NAMES_OFF         0x20   ; IMAGE_EXPORT_DIRECTORY.AddressOfNames
%define EXPORT_ADDR_NAME_ORDINALS_OFF 0x24   ; IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
%define GPA_STR_LEN                   0xF    ; len("GetProcAddress\0")
%define MZ_SIGNATURE_WORD             0x5A4D
%define PE_SIGNATURE_DWORD            0x4550
%define MAX_E_LFANEW                  0x400  ; reject false-positive "MZ" matches with a huge e_lfanew
%define PE_SCAN_SKIP                  0x100  ; skip past this stub's own bytes before scanning for "MZ"
%define IMPORT_DESC_INT_RVA_OFF       0x00   ; IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk
%define IMPORT_DESC_NAME_RVA_OFF      0x0C   ; IMAGE_IMPORT_DESCRIPTOR.Name
%define IMPORT_DESC_FT_RVA_OFF        0x10   ; IMAGE_IMPORT_DESCRIPTOR.FirstThunk
%define IMAGE_IMPORT_DESC_SIZE        0x14
%define IAT_SLOT_SIZE                 0x08   ; PE32+ thunk entry size (64-bit)
%define IMPORT_BY_NAME_HINT_SIZE      0x02   ; skip IMAGE_IMPORT_BY_NAME.Hint to reach its Name
%define IMAGE_ORDINAL_FLAG64_BIT      63     ; high bit of a PE32+ thunk entry = import-by-ordinal
%define ORDINAL_NUMBER_MASK           0xFFFF

    ; -- Phase 1: PEB walk (x18 = TEB pointer, already valid on ARM64 -
    ; no memory read needed for the base, unlike x64's "mov rax,[gs:0x60]")
    ; -> kernel32 DllBase in x21. Same three-hop module-list walk (skip exe,
    ; skip ntdll, land on kernel32) imports_resolver64.asm uses.
    ldr x9, [x18, TEB_PEB_OFFSET]             ; x9 = PEB
    ldr x9, [x9, PEB_LDR_OFFSET]              ; x9 = PEB.Ldr
    ldr x10, [x9, LDR_INMEMORYORDER_OFFSET]   ; x10 = InMemoryOrderModuleList.Flink (exe entry)
    ldr x10, [x10]                             ; skip exe -> ntdll entry
    ldr x10, [x10]                             ; skip ntdll -> kernel32 entry
    ldr x21, [x10, LDR_DLLBASE_OFFSET]        ; x21 = kernel32 DllBase

    ; -- Phase 2: locate kernel32's export directory -------------------------
    ldr w9, [x21, PE_E_LFANEW_OFFSET]
    add x9, x9, x21                             ; x9 = NT headers VA
    ldr w10, [x9, NT64_EXPORT_DIR_RVA_OFF]     ; export dir RVA
    add x22, x10, x21                           ; x22 = export dir VA

    ldr w9, [x22, EXPORT_NUM_NAMES_OFF]        ; w9 = NumberOfNames
    ldr w10, [x22, EXPORT_ADDR_NAMES_OFF]      ; AddressOfNames RVA
    add x10, x10, x21                            ; x10 = AddressOfNames VA (array of name RVAs)

    b _after_gpa_str
_gpa_str:
    .byte 0x47,0x65,0x74,0x50,0x72,0x6F,0x63,0x41,0x64,0x64,0x72,0x65,0x73,0x73,0x00
    .byte 0x00                                   ; pad "GetProcAddress\0" (15B) to 16B (4-aligned)
_after_gpa_str:
    adr x11, _gpa_str                            ; x11 = "GetProcAddress\0"

_gpa_loop:
    subs x9, x9, 1
    b.lt _done                                   ; exhausted without a match: bail out silently
                                                  ; (same silent-fail path imports_resolver64.asm's
                                                  ; "dec ecx; js _done" takes)
    ldr w12, [x10, x9, lsl 2]                   ; name RVA = AddressOfNames[x9]
    add x12, x12, x21                             ; x12 = candidate name VA
    mov x13, 0
_gpa_cmp:
    ldrb w14, [x12, x13]
    ldrb w15, [x11, x13]
    cmp w14, w15
    bne _gpa_loop
    add x13, x13, 1
    cmp x13, GPA_STR_LEN
    blo _gpa_cmp

    ; Match: resolve ordinal -> function VA (x9 still holds the matched index)
    ldr w10, [x22, EXPORT_ADDR_NAME_ORDINALS_OFF]
    add x10, x10, x21
    ldrh w12, [x10, x9, lsl 1]                  ; ordinal = NameOrdinals[x9]
    ldr w10, [x22, EXPORT_ADDR_FUNCTIONS_OFF]
    add x10, x10, x21
    ldr w13, [x10, x12, lsl 2]                  ; function RVA
    add x24, x13, x21                             ; x24 = GetProcAddress VA

    ; GetProcAddress(kernel32, "LoadLibraryA") -> x25
    b _after_lla_str
_lla_str:
    .byte 0x4C,0x6F,0x61,0x64,0x4C,0x69,0x62,0x72,0x61,0x72,0x79,0x41,0x00
    .byte 0x00,0x00,0x00                         ; pad "LoadLibraryA\0" (13B) to 16B (4-aligned)
_after_lla_str:
    adr x1, _lla_str                             ; arg2: "LoadLibraryA"
    mov x0, x21                                  ; arg1: kernel32 handle
    blr x24                                       ; GetProcAddress(kernel32, "LoadLibraryA")
    mov x25, x0                                   ; x25 = LoadLibraryA VA

    ; -- Phase 3: self-locate the target PE (scan forward past this stub) ----
_pe_scan_start:
    adr x9, _pe_scan_start
    add x9, x9, PE_SCAN_SKIP                     ; skip ahead past this stub's own bytes
    mov x10, x9
_scan_mz:
    add x10, x10, 1
    ldrh w11, [x10]
    mov w12, MZ_SIGNATURE_WORD
    cmp w11, w12
    bne _scan_mz
    ldr w11, [x10, PE_E_LFANEW_OFFSET]
    cmp w11, MAX_E_LFANEW
    b.hi _scan_mz
    add x12, x10, x11                             ; NT headers VA (candidate)
    ldr w13, [x12]
    mov w14, PE_SIGNATURE_DWORD
    cmp w13, w14
    bne _scan_mz
    mov x26, x10                                   ; x26 = target PE image base

    ; -- Phase 4: walk IMAGE_IMPORT_DESCRIPTOR table --------------------------
    ldr w11, [x26, PE_E_LFANEW_OFFSET]
    add x11, x11, x26
    ldr w11, [x11, NT64_IMPORT_DIR_RVA_OFF]
    cbz w11, _done
    add x27, x11, x26                              ; x27 = first IMAGE_IMPORT_DESCRIPTOR

_desc_loop:
    ldr w11, [x27, IMPORT_DESC_NAME_RVA_OFF]
    cbz w11, _done                                 ; null descriptor = end of table
    add x0, x11, x26                                ; arg1: DLL name VA
    blr x25                                          ; LoadLibraryA(dll_name) -> x0 = module handle
    cbz x0, _next_desc
    mov x29, x0                                      ; x29 = module handle

    ; Choose INT (OriginalFirstThunk) or fall back to FirstThunk for names
    ldr w11, [x27, IMPORT_DESC_INT_RVA_OFF]
    cbz w11, _use_ft
    add x28, x11, x26                                ; x28 = INT VA (name source)
    ldr w11, [x27, IMPORT_DESC_FT_RVA_OFF]
    add x20, x11, x26                                ; x20 = IAT VA (write destination)
    b _thunk_loop
_use_ft:
    ldr w11, [x27, IMPORT_DESC_FT_RVA_OFF]
    add x28, x11, x26
    mov x20, x28

_thunk_loop:
    ldr x0, [x28]
    cbz x0, _next_desc                               ; null = end of thunk array
    tbnz x0, IMAGE_ORDINAL_FLAG64_BIT, _by_ordinal
    add x0, x0, x26                                  ; VA of IMAGE_IMPORT_BY_NAME
    add x1, x0, IMPORT_BY_NAME_HINT_SIZE             ; arg2: skip Hint WORD -> function name
    mov x0, x29                                       ; arg1: module handle
    blr x24                                           ; GetProcAddress(module, name)
    b _save_func
_by_ordinal:
    and x1, x0, ORDINAL_NUMBER_MASK                   ; arg2: ordinal number
    mov x0, x29                                       ; arg1: module handle
    blr x24                                           ; GetProcAddress(module, ordinal)
_save_func:
    str x0, [x20]                                     ; write resolved address to IAT slot
    add x28, x28, IAT_SLOT_SIZE
    add x20, x20, IAT_SLOT_SIZE
    b _thunk_loop

_next_desc:
    add x27, x27, IMAGE_IMPORT_DESC_SIZE
    b _desc_loop

_done:
    ret                                               ; terminal (c0 03 5f d6) - stripped by peor
                                                        ; (_IMPORTS_TAIL_ARM64, already defined in
                                                        ; _chain_builder.py for the Linux ARM64 chain)
