// cxx_eh_fixer_arm64.asm - Patches the PE's IAT to hook RtlPcToFileHeader so that
// _CxxThrowException gets the correct ImageBase for typed C++ exception matching.
// Assembled by keystone (KS_ARCH_ARM64 / KS_MODE_LITTLE_ENDIAN).
// Direct ARM64 analog of cxx_eh_fixer64.asm.
//
// Problem (same on ARM64 as x64, documented there): modern MSVC (exception magic
// 0x19930522) calls RtlPcToFileHeader to get the module's ImageBase, then stores
// (ThrowInfo - ImageBase) as a 32-bit RVA in ExceptionInformation[2] and ImageBase
// in ExceptionInformation[3]. __CxxFrameHandler reconstructs the pointer as
// (ImageBase + RVA). For shellcode PEs not in the loader module list,
// RtlPcToFileHeader returns NULL => the RVA calculation truncates the 64-bit
// ThrowInfo address to 32 bits => garbage pointer => handler crashes => catch
// blocks never fire. MSVC ARM64 C++ PEs reference RtlPcToFileHeader through the
// IAT exactly like their x64 counterparts (verified: the machine=0xAA64 test PEs
// compiled with C++ exceptions all carry that IAT reference), so hooking the IAT
// slot is the same single-point fix on both architectures.
//
// On entry: x19 = PE base (from relocations_resolver_arm64.asm).
// On exit:  x19 = PE base (never written); SP never touched; no x30 use.
// Only chained when the PE has imports + C++ EH + an IAT reference to
// RtlPcToFileHeader (see peor/_chain_builder.py's _compute_required_stubs).
//
// Self-location: the x64 fixer needed a FORWARD_MAGIC (patched distance from
// _setup_ip to the data area) because inline x86 code cannot cheaply take its own
// address. ARM64 has PC-relative ADR: adr computes the runtime address of a label
// directly, so _hook_data and _hook_stub are reached with plain adr and there is
// NO data magic to patch here. _build_shellcode_chain therefore patches only
// PE_SIZE_MAGIC (SizeOfImage) and IAT_RVA_MAGIC (RtlPcToFileHeader IAT RVA).
// Both patch into literal pools the way entrypoint_resolver_arm64.asm does for
// its EP RVA - raw 4-byte .byte literals, never folded into mov/movz immediate
// bits, because peor finds-and-replaces them as bytes after assembly.
//
// Data area: 32-byte zero pad inside the chain blob ([0]=pe_base, [8]=pe_end,
// [16]=orig_fn, [24..31] spare). Every write lands within the pad - the setup
// code stores exactly the three fields above - so no code bytes are ever
// overwritten. The blob is one RWX VirtualAlloc mapping (see the test loader),
// so the data pad and the IAT slot in the embedded PE's import table
// are both writable at this point.
//
// The hook is entered only via the patched IAT slot (never executed inline -
// setup branches over it). The stub's return paths: in-range => `ret` with x0
// already returned as pe_base (caller sees a real module base); out-of-range =>
// `br` tail-calls the original RtlPcToFileHeader, which returns straight to the
// original caller with the untouched original arguments. x30 is never read or
// written (the caller's `blr` provided the return address and it is the caller's
// to preserve), matching the no-SP-touch design of the ARM64 stubs around it;
// x19 is never written, preserving the PE base for the rest of the chain.
//
// Unaligned 8-byte stores to the data pad: the chain blob's start address is
// not guaranteed 8-byte aligned, so the pad's runtime address may be only
// 4-aligned. ARMv8-A Windows (SCTLR.A clear) permits unaligned ld/st on normal
// cacheable memory, and this mapping is exactly that.
//
// Register map (setup = scratch only):
//   x9  = PE size (pool literal)
//   x10 = &_hook_data
//   x11 = &IAT slot / pe_base in the hook
//   x12 = pe_end
//   x13 = orig_fn / &_hook_stub
//   x19 = PE base - input from the relocs resolver, PRESERVED verbatim

%define PE_SIZE_MAGIC  0x12345678  ; patched by peor: PE's SizeOfImage
%define IAT_RVA_MAGIC  0x87654321  ; patched by peor: IAT RVA of RtlPcToFileHeader

    ; == SETUP (runs once inline, then branches over pool + hook stub) ==
    ldr w9, _pe_size_pool             ; w9 = SizeOfImage (patched)
    add x12, x19, x9                  ; x12 = pe_end = pe_base + SizeOfImage
    ldr w11, _iat_rva_pool            ; w11 = IAT RVA (patched)
    add x11, x11, x19                 ; x11 = &IAT[RtlPcToFileHeader]
    adr x10, _hook_data               ; x10 = runtime address of the data pad
    str x19, [x10]                    ; [0]  = pe_base
    str x12, [x10, 8]                 ; [8]  = pe_end
    ldr x13, [x11]                    ; original RtlPcToFileHeader pointer
    str x13, [x10, 16]                ; [16] = orig_fn
    adr x13, _hook_stub               ; &_hook_stub
    str x13, [x11]                    ; IAT[RtlPcToFileHeader] = &_hook_stub
    b _after_stub

_pe_size_pool:
    .byte 0x78,0x56,0x34,0x12         ; patched by peor at conversion time -> SizeOfImage
_iat_rva_pool:
    .byte 0x21,0x43,0x65,0x87         ; patched by peor at conversion time -> IAT RVA

    ; == HOOK STUB (called later via the patched IAT slot) ==
    ; RtlPcToFileHeader(PVOID PcValue: x0, PVOID* BaseOfImage: x1) -> PVOID in x0
_hook_stub:
    adr x10, _hook_data               ; x10 = &data
    ldr x11, [x10]                    ; x11 = pe_base
    cmp x0, x11                       ; PcValue < pe_base?
    b.lo _tailcall
    ldr x12, [x10, 8]                 ; x12 = pe_end
    cmp x0, x12                       ; PcValue >= pe_end?
    b.hs _tailcall

    ; PcValue is inside our PE => report pe_base as the module base
    str x11, [x1]                     ; *BaseOfImage = pe_base
    mov x0, x11                       ; return pe_base
    ret

_tailcall:
    ; PcValue is outside our PE => tail-call the real RtlPcToFileHeader with the
    ; untouched original arguments; it returns straight to the original caller.
    ldr x13, [x10, 16]                ; orig_fn
    br x13

    ; == DATA PAD (never executed; setup writes [0],[8],[16] of these 32 bytes) ==
_hook_data:
    .byte 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; [0]  pe_base
    .byte 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; [8]  pe_end
    .byte 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; [16] orig_fn
    .byte 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ; [24] spare (so no write can run past the pad)

_after_stub:
    ; Execution falls through to seh_registrar_arm64 / tls_callbacks_arm64 /
    ; entrypoint_resolver_arm64 (chain order in peor/_chain_builder.py).
