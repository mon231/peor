// ARM64 (AArch64) SEH registrar - calls ntdll!RtlAddFunctionTable for the PE's .pdata.
// Assembled by keystone (KS_ARCH_ARM64 / KS_MODE_LITTLE_ENDIAN).
// Direct ARM64 analog of seh_registrar64.asm.
//
// On entry: x19 = PE base (set by relocations_resolver_arm64.asm).
// On exit:  x19 = PE base, execution falls through.
// Only chained when DataDir[3].VA != 0 (PE has exception table) - see
// peor/_chain_builder.py's _compute_required_stubs.
//
// Why runtime registration is needed at all on ARM64 (same reasoning as x64,
// documented on seh_registrar64.asm): ARM64 Windows uses .pdata/.xdata table-based
// unwind; the OS loader would normally register the image's function table
// (RtlInsertInvertedFunctionTable) at module-load time, which never happens for a
// shellcode PE placed via VirtualAlloc+call. ntdll!'s exported RtlAddFunctionTable
// (per winnt.h: present on the table-based unwind architectures, x64 and ARM64
// alike) registers a dynamic function table for exactly this case. The registration
// mechanism is shared across the table-based unwind architectures; only the
// RUNTIME_FUNCTION size differs: ARM64's IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY is two
// DWORDs (BeginAddress, UnwindData) = 8 bytes, versus x64's 12-byte
// {BeginAddress, EndAddress, UnwindData} - so EntryCount is DataDir[3].Size / 8
// here, not x64's Size / 12.
//
// TEB access: x18 directly HOLDS the TEB pointer on ARM64 Windows (see the comment
// block on imports_resolver_arm64.asm) - no memory read needed for the base.
//
// AAPCS64 needs no shadow space; x30 is stashed on the stack at entry (16-byte
// aligned SP once #0x10 is subtracted, as the OS guarantees at process entry) and
// reloaded in _done before the fall-through: the `blr` below would otherwise
// overwrite the loader's return address and strand a leaf-main PE's `ret` back in
// this stub, looping forever with the entrypoint stub (the real windows-11-arm CI
// hang behind test_19/20/21). x19 is preserved verbatim (never written) - the
// ARM64 analog of the x64 registrar preserving RBX across this stub.
//
// Register map:
//   x9, x10, x11, x12, x13, x14, x15 = lookup / loop scratch (not preserved)
//   x21 = ntdll DllBase (PEB walk phase)
//   x22 = ntdll export directory VA
//   x24 = RtlAddFunctionTable VA
//   x19 = PE base (input from relocs resolver, PRESERVED for the chain - the ARM64
//         analog of the x64 registrar preserving RBX across this stub)
//
// keystone notes: string data via `.byte` with explicit padding to a 4-byte
// boundary before the next instruction (see imports_resolver_arm64.asm);
// "RtlAddFunctionTable\0" is exactly 20 bytes, so no padding is needed.

%define TEB_PEB_OFFSET                    0x60   ; TEB.ProcessEnvironmentBlock (x18 = TEB)
%define PEB_LDR_OFFSET                    0x18   ; PEB.Ldr
%define LDR_INMEMORYORDER_OFFSET          0x20   ; PEB_LDR_DATA.InMemoryOrderModuleList.Flink
%define LDR_DLLBASE_OFFSET                0x20   ; LDR_DATA_TABLE_ENTRY.DllBase (from InMemoryOrderLinks)
%define PE_E_LFANEW_OFFSET                0x3C
%define NT64_EXPORT_DIR_RVA_OFF           0x88   ; NT headers DataDir[0].VA (PE32+)
%define NT64_EXC_DIR_RVA_OFF              0xA0   ; NT headers DataDir[3].VA (PE32+; same as x64 registrar)
%define NT64_EXC_DIR_SIZE_OFF             0xA4   ; NT headers DataDir[3].Size
%define EXPORT_NUM_NAMES_OFF              0x18
%define EXPORT_ADDR_FUNCTIONS_OFF         0x1C
%define EXPORT_ADDR_NAMES_OFF             0x20
%define EXPORT_ADDR_NAME_ORDINALS_OFF     0x24
%define RAFT_STR_LEN                      0x14   ; len("RtlAddFunctionTable\0") = 20 (19 chars + NUL)
%define ARM64_RUNTIME_FUNCTION_SIZE       0x8    ; IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY = 2 DWORDs

    ; -- x30 save: the single `blr x24` below would clobber the loader's return
    ; address; _done reloads it before the fall-through.
    sub sp, sp, #0x10
    str x30, [sp]

    ldr w9, [x19, PE_E_LFANEW_OFFSET]
    add x9, x19, x9                               ; x9 = PE's NT headers VA
    ldr w10, [x9, NT64_EXC_DIR_RVA_OFF]
    cbz w10, _done                                ; no .pdata - nothing to register

    ; -- Locate ntdll: PEB walk, the FIRST loader-list entry after the exe (the
    ; ntdll module is always second in InMemoryOrderModuleList), same walk the x64
    ; registrar performs.
    ldr x9, [x18, TEB_PEB_OFFSET]                 ; x9 = PEB
    ldr x9, [x9, PEB_LDR_OFFSET]                  ; x9 = PEB.Ldr
    ldr x10, [x9, LDR_INMEMORYORDER_OFFSET]       ; x10 = InMemoryOrderModuleList.Flink (exe entry)
    ldr x10, [x10]                                 ; ntdll entry
    ldr x21, [x10, LDR_DLLBASE_OFFSET]            ; x21 = ntdll DllBase

    ; -- Locate ntdll's export directory
    ldr w9, [x21, PE_E_LFANEW_OFFSET]
    add x9, x9, x21                               ; x9 = ntdll NT headers VA
    ldr w10, [x9, NT64_EXPORT_DIR_RVA_OFF]
    add x22, x10, x21                             ; x22 = ntdll export dir VA

    ldr w9, [x22, EXPORT_NUM_NAMES_OFF]           ; w9 = NumberOfNames
    ldr w10, [x22, EXPORT_ADDR_NAMES_OFF]         ; AddressOfNames RVA
    add x10, x10, x21                             ; x10 = AddressOfNames VA

    b _after_raft_str
_raft_str:
    .byte 0x52,0x74,0x6C,0x41,0x64,0x64,0x46,0x75,0x6E,0x63,0x74,0x69,0x6F,0x6E,0x54,0x61
    .byte 0x62,0x6C,0x65,0x00
_after_raft_str:
    adr x11, _raft_str                            ; x11 = "RtlAddFunctionTable\0" (20B, 4-aligned)

_raft_loop:
    subs x9, x9, 1
    b.lt _done                                    ; exhausted without a match: bail out silently
                                                  ; (same silent-fail path the x64 registrar's
                                                  ; "dec r9d; js _seh_skip" takes - the unwinder
                                                  ; simply finds no function table, same behavior
                                                  ; as not registering at all)
    ldr w12, [x10, x9, lsl 2]                     ; name RVA = AddressOfNames[x9]
    add x12, x12, x21                             ; x12 = candidate name VA
    mov x13, 0
_raft_cmp:
    ldrb w14, [x12, x13]
    ldrb w15, [x11, x13]
    cmp w14, w15
    bne _raft_loop
    add x13, x13, 1
    cmp x13, RAFT_STR_LEN
    blo _raft_cmp

    ; Match: resolve ordinal -> function VA (x9 still holds the matched index)
    ldr w10, [x22, EXPORT_ADDR_NAME_ORDINALS_OFF]
    add x10, x10, x21
    ldrh w12, [x10, x9, lsl 1]                    ; ordinal = NameOrdinals[x9]
    ldr w10, [x22, EXPORT_ADDR_FUNCTIONS_OFF]
    add x10, x10, x21
    ldr w13, [x10, x12, lsl 2]                    ; function RVA
    add x24, x13, x21                             ; x24 = RtlAddFunctionTable VA

    ; -- RtlAddFunctionTable(FunctionTable, EntryCount=Size/8, BaseAddress)
    ldr w11, [x19, PE_E_LFANEW_OFFSET]
    add x9, x19, x11                              ; x9 = PE's NT headers VA
    ldr w12, [x9, NT64_EXC_DIR_RVA_OFF]
    add x0, x19, x12                              ; arg1: FunctionTable VA
    ldr w11, [x9, NT64_EXC_DIR_SIZE_OFF]
    lsr x1, x11, 3                                ; arg2: EntryCount = DataDir[3].Size / 8
    mov x2, x19                                   ; arg3: BaseAddress = PE base
    blr x24                                       ; RtlAddFunctionTable(FT, count, base)

_done:
    ldr x30, [sp], #0x10                           ; restore the loader's return address