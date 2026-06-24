; x86 TLS callback invoker.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_32 / KS_OPT_SYNTAX_NASM).
;
; On entry: EBX = PE base, falls through from relocs/seh chain.
; On exit:  EBX = PE base (preserved), falls through to next shellcode.
;
; Reads IMAGE_TLS_DIRECTORY32.AddressOfCallBacks (at TLS_dir+0x0C) and
; calls each non-null entry as: callback(hModule=base, DLL_PROCESS_ATTACH=1, NULL)
; using NTAPI (__stdcall on x86) - callee cleans 12 bytes of args.
;
; DataDir[9].VirtualAddress is at NT+0xC0 (PE32: OptHdr at NT+24, DataDir at +96, entry 9 at +9*8=72 -> NT+24+96+72=NT+192=NT+0xC0).

; Named constants
%define DLL_PROCESS_ATTACH 0x01

    mov esi, [ebx + 0x3C]
    add esi, ebx                        ; ESI = NT headers
    mov eax, [esi + 0xC0]               ; DataDir[9].VirtualAddress (TLS directory)
    test eax, eax
    jz _done                            ; no TLS directory
    add eax, ebx                        ; EAX = TLS directory VA
    mov eax, [eax + 0x0C]               ; IMAGE_TLS_DIRECTORY32.AddressOfCallBacks (VA)
    test eax, eax
    jz _done                            ; null callbacks list

_loop:
    mov ecx, [eax]                      ; ECX = next callback VA
    test ecx, ecx
    jz _done                            ; null terminator
    push eax                            ; save callbacks-array pointer
    push 0x00                           ; lpvReserved = NULL
    push DLL_PROCESS_ATTACH
    push ebx                            ; hModule = PE base
    call ecx                            ; callback(base, DLL_PROCESS_ATTACH, NULL)  [callee cleans 12 bytes]
    pop eax                             ; restore array pointer
    add eax, 0x04                       ; advance to next entry (4-byte callback pointer)
    jmp _loop

_done:
    ; EBX = PE base; fall through to next shellcode.
