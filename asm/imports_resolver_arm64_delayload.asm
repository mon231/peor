// ARM64 (AArch64) Windows delay-load import resolver - position-independent shellcode.
// Assembled by keystone (KS_ARCH_ARM64 / KS_MODE_LITTLE_ENDIAN).
// Direct ARM64 analog of imports_resolver64_delayload.asm: same real-Windows-loader
// algorithm (PEB walk to kernel32, export-table walk for GetProcAddress,
// GetProcAddress(kernel32,"LoadLibraryA") for LoadLibraryA, then the target PE's
// IMAGE_DELAYLOAD_DESCRIPTOR table in DataDir[13] via LoadLibraryA+GetProcAddress).
// Unlike imports_resolver64_delayload.asm this stub does NOT need to self-locate the
// PE by scanning for MZ: it runs AFTER relocations_resolver_arm64.asm in the chain
// (see peor/_chain_builder.py's _build_shellcode_chain concatenation order:
// imports + relocs + delay_imports + ...), so x19 = PE base is already established
// by the ARM64 chain's register convention. The x64 analog keeps every register
// callee-saved because x86 stubs downstream depend on them; here nothing downstream
// (cxx_eh_fixer/seh/tls/ctors/entrypoint) depends on x20-x28, and AAPCS64 needs no
// shadow space, so the same free use of x20-x29 as imports_resolver_arm64.asm applies.
// Exception: x30 carries the loader's return address and every `blr` below clobbers
// it, so it is stashed on the stack at entry and reloaded in _done before the
// fall-through (same x30 discipline imports_resolver_arm64.asm's header documents;
// without it a leaf-main PE loops forever between its ret and the entrypoint stub).
//
// ImgDelayDescr layout (grAttrs=1, RVA format, modern MSVC - same struct the x64
// resolver documents):
//   +0x00 DWORD grAttrs
//   +0x04 DWORD rvaDLLName
//   +0x08 DWORD rvaHmod
//   +0x0C DWORD rvaIAT
//   +0x10 DWORD rvaINT
//   Total: 0x20 bytes
//
// Register map (persistent across this stub's body):
//   x20 = current delay-load IAT write-destination cursor
//   x21 = kernel32 DllBase (phases 1/2)
//   x22 = kernel32 export directory VA (phase 2)
//   x24 = GetProcAddress VA
//   x25 = LoadLibraryA VA
//   x27 = current ImgDelayDescr pointer
//   x28 = current INT walk cursor
//   x29 = current DLL module handle
//   x19 = target PE base (input from relocs resolver, PRESERVED for the chain).
//
// keystone notes: string data via `.byte` with explicit padding to a 4-byte
// boundary before the next instruction (see imports_resolver_arm64.asm).

%define TEB_PEB_OFFSET                0x60   ; TEB.ProcessEnvironmentBlock (x18 = TEB on ARM64)
%define PEB_LDR_OFFSET                0x18   ; PEB.Ldr
%define LDR_INMEMORYORDER_OFFSET      0x20   ; PEB_LDR_DATA.InMemoryOrderModuleList.Flink
%define LDR_DLLBASE_OFFSET            0x20   ; LDR_DATA_TABLE_ENTRY.DllBase (offset from InMemoryOrderLinks)
%define PE_E_LFANEW_OFFSET            0x3C
%define NT64_EXPORT_DIR_RVA_OFF       0x88   ; NT headers DataDir[0].VA (PE32+)
%define NT64_DELAY_DIR_RVA_OFF        0xF0   ; NT headers DataDir[13].VA (PE32+, 0x88 + 13*8)
%define EXPORT_NUM_NAMES_OFF          0x18   ; IMAGE_EXPORT_DIRECTORY.NumberOfNames
%define EXPORT_ADDR_FUNCTIONS_OFF     0x1C   ; IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
%define EXPORT_ADDR_NAMES_OFF         0x20   ; IMAGE_EXPORT_DIRECTORY.AddressOfNames
%define EXPORT_ADDR_NAME_ORDINALS_OFF 0x24   ; IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
%define GPA_STR_LEN                   0xF    ; len("GetProcAddress\0")
%define DELAY_NAME_RVA_OFF            0x04   ; ImgDelayDescr.rvaDLLName
%define DELAY_IAT_RVA_OFF             0x0C   ; ImgDelayDescr.rvaIAT
%define DELAY_INT_RVA_OFF             0x10   ; ImgDelayDescr.rvaINT
%define DELAY_DESC_SIZE               0x20   ; sizeof(ImgDelayDescr)
%define IAT_SLOT_SIZE                 0x08   ; PE32+ thunk entry size (64-bit)
%define IMPORT_BY_NAME_HINT_SIZE      0x02   ; skip IMAGE_IMPORT_BY_NAME.Hint to reach its Name
%define IMAGE_ORDINAL_FLAG64_BIT      63     ; high bit of a PE32+ thunk entry = import-by-ordinal
%define ORDINAL_NUMBER_MASK           0xFFFF

    ; -- x30 save (see header): loader return address must survive the blrs.
    sub sp, sp, #0x10
    str x30, [sp]

    ; -- Phase 1: PEB walk (x18 = TEB) -> kernel32 DllBase in x21.
    ; Same three-hop module-list walk imports_resolver_arm64.asm uses (the running
    ; shellcode image is not in the loader list, so exe -> ntdll -> kernel32 holds
    ; here exactly as it did when the imports resolver ran).
    ldr x9, [x18, TEB_PEB_OFFSET]             ; x9 = PEB
    ldr x9, [x9, PEB_LDR_OFFSET]              ; x9 = PEB.Ldr
    ldr x10, [x9, LDR_INMEMORYORDER_OFFSET]   ; x10 = InMemoryOrderModuleList.Flink (exe entry)
    ldr x10, [x10]                             ; skip exe -> ntdll entry
    ldr x10, [x10]                             ; skip ntdll -> kernel32 entry
    ldr x21, [x10, LDR_DLLBASE_OFFSET]        ; x21 = kernel32 DllBase

    ; -- Phase 2: locate kernel32's export directory, resolve GetProcAddress.
    ldr w9, [x21, PE_E_LFANEW_OFFSET]
    add x9, x9, x21                             ; x9 = NT headers VA
    ldr w10, [x9, NT64_EXPORT_DIR_RVA_OFF]     ; export dir RVA
    add x22, x10, x21                           ; x22 = export dir VA

    ldr w9, [x22, EXPORT_NUM_NAMES_OFF]        ; w9 = NumberOfNames
    ldr w10, [x22, EXPORT_ADDR_NAMES_OFF]      ; AddressOfNames RVA
    add x10, x10, x21                            ; x10 = AddressOfNames VA

    b _after_gpa_str
_gpa_str:
    .byte 0x47,0x65,0x74,0x50,0x72,0x6F,0x63,0x41,0x64,0x64,0x72,0x65,0x73,0x73,0x00
    .byte 0x00                                   ; pad "GetProcAddress\0" (15B) to 16B (4-aligned)
_after_gpa_str:
    adr x11, _gpa_str                            ; x11 = "GetProcAddress\0"

_gpa_loop:
    subs x9, x9, 1
    b.lt _done                                   ; exhausted without a match: bail out silently
                                                  ; (same silent-fail path the x64 delayload
                                                  ; resolver's "dec ecx; js _done" takes)
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

    ; -- Phase 3: walk the IMAGE_DELAYLOAD_DESCRIPTOR table (DataDir[13]).
    ; x19 = PE base, already set by relocations_resolver_arm64.asm.
    ldr w11, [x19, PE_E_LFANEW_OFFSET]
    add x11, x11, x19                             ; x11 = NT headers VA
    ldr w11, [x11, NT64_DELAY_DIR_RVA_OFF]
    cbz w11, _done                                ; no delay-load table
    add x27, x11, x19                             ; x27 = first ImgDelayDescr

_desc_loop:
    ldr w11, [x27, DELAY_NAME_RVA_OFF]
    cbz w11, _done                                ; null rvaDLLName = end of table
    add x0, x11, x19                              ; arg1: DLL name VA (grAttrs=1, RVA format;
                                                  ; the legacy grAttrs=0 VA format the x64
                                                  ; resolver also ignores is not supported here)
    blr x25                                        ; LoadLibraryA(dll_name) -> x0 = module handle
    cbz x0, _next_desc
    mov x29, x0                                   ; x29 = module handle

    ldr w11, [x27, DELAY_INT_RVA_OFF]
    cbz w11, _next_desc                           ; no INT: nothing to resolve
    add x28, x11, x19                             ; x28 = INT VA (name source)
    ldr w11, [x27, DELAY_IAT_RVA_OFF]
    add x20, x11, x19                             ; x20 = delay-load IAT VA (write destination)

_thunk_loop:
    ldr x0, [x28]
    cbz x0, _next_desc                            ; null = end of thunk array
    tbnz x0, IMAGE_ORDINAL_FLAG64_BIT, _by_ordinal
    add x0, x0, x19                               ; VA of IMAGE_IMPORT_BY_NAME
    add x1, x0, IMPORT_BY_NAME_HINT_SIZE          ; arg2: skip Hint WORD -> function name
    mov x0, x29                                   ; arg1: module handle
    blr x24                                        ; GetProcAddress(module, name)
    b _save_func
_by_ordinal:
    and x1, x0, ORDINAL_NUMBER_MASK               ; arg2: ordinal number
    mov x0, x29                                   ; arg1: module handle
    blr x24                                        ; GetProcAddress(module, ordinal)
_save_func:
    str x0, [x20]                                 ; write resolved address to delay-load IAT slot
    add x28, x28, IAT_SLOT_SIZE
    add x20, x20, IAT_SLOT_SIZE
    b _thunk_loop

_next_desc:
    add x27, x27, DELAY_DESC_SIZE
    b _desc_loop

_done:
    ldr x30, [sp], #0x10                            ; restore the loader's return address
    ret                                           ; terminal (c0 03 5f d6) - stripped by peor
