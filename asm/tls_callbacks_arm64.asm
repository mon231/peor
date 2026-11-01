// ARM64 (AArch64) TLS callback invoker.
// Assembled by keystone (KS_ARCH_ARM64 / KS_MODE_LITTLE_ENDIAN).
// Direct ARM64 analog of tls_callbacks64.asm.
//
// On entry: x19 = PE base (set by relocations_resolver_arm64.asm).
// On exit:  x19 = PE base (preserved - this stub never writes it), falls through.
//
// Reads IMAGE_TLS_DIRECTORY64.AddressOfCallBacks (at TLS_dir+0x18) and calls each
// non-null entry as: callback(hModule=base, DLL_PROCESS_ATTACH=1, NULL). AAPCS64
// needs no shadow space (an x64-Windows-ABI-only quirk); SP is never touched, so
// it stays 16-byte-aligned (as the OS guarantees at process entry) across every
// internal `blr` call into a callback.
//
// NT headers DataDir[9] (TLS) RVA offset for PE32+: OptHdr at NT+24, DataDir at
// NT+24+112, entry 9 at NT+24+112+9*8 = NT+0xD0 - the same value tls_callbacks64.asm
// uses, independent of machine type.
//
// x30 is clobbered by the `blr` calls, exactly like every earlier stub in the ARM64
// chain's call-bearing pieces (imports resolver, ctors runner) that already handle
// being scheduled after such clobbering.
//
// Register map:
//   x9  = NT headers VA
//   x10 = TLS directory VA
//   x11 = current callbacks-array cursor
//   x12 = next callback pointer (loop scratch)

%define PE_E_LFANEW_OFFSET                   0x3C
%define NT64_TLS_DIR_RVA_OFF                 0xD0    ; NT headers DataDir[9].VA (PE32+)
%define IMAGE_TLS_DIRECTORY64_CALLBACKS_OFF  0x18    ; IMAGE_TLS_DIRECTORY64.AddressOfCallBacks
%define DLL_PROCESS_ATTACH                   0x01
%define CALLBACK_SLOT_SIZE                   0x08    ; 64-bit callback pointer array entries

    ldr w9, [x19, PE_E_LFANEW_OFFSET]
    add x9, x19, x9                               ; x9 = NT headers VA
    ldr w10, [x9, NT64_TLS_DIR_RVA_OFF]
    cbz w10, _done                                ; no TLS directory
    add x10, x10, x19                             ; x10 = TLS directory VA
    ldr x11, [x10, IMAGE_TLS_DIRECTORY64_CALLBACKS_OFF]
    cbz x11, _done                                ; null callbacks list

_loop:
    ldr x12, [x11]                                ; x12 = next callback VA
    cbz x12, _done                                ; null terminator
    add x11, x11, CALLBACK_SLOT_SIZE              ; advance to next entry
    mov x0, x19                                   ; arg1: hModule = PE base
    mov x1, DLL_PROCESS_ATTACH                    ; arg2: DLL_PROCESS_ATTACH
    mov x2, 0                                     ; arg3: lpvReserved = NULL
    blr x12                                       ; callback(base, 1, NULL)
    b _loop

_done:
    ; x19 = PE base; fall through to next shellcode.
