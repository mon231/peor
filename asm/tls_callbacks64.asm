; x64 TLS callback invoker.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_64 / KS_OPT_SYNTAX_NASM).
;
; On entry: RBX = PE base, RSP = 8 (mod 16).
; On exit:  RBX = PE base (preserved), RSP = 8 (mod 16), falls through.
;
; Reads IMAGE_TLS_DIRECTORY64.AddressOfCallBacks (at TLS_dir+0x18) and
; calls each non-null entry as: callback(hModule=base, DLL_PROCESS_ATTACH=1, NULL)
; using Windows x64 ABI (shadow space allocated by caller).
;
; DataDir[9].VirtualAddress is at NT+0xD0 (PE32+: OptHdr at NT+24, DataDir at +112, entry 9 at +9*8=72 -> NT+24+112+72=NT+208=NT+0xD0).
;
; RSP alignment trace (entry RSP = 8 mod 16):
;   sub rsp, 0x28    -> 0 mod 16  (32-byte shadow + 8-byte align)
;   call rax         -> 8 mod 16 at callee entry  (correct Windows ABI)
;   [callee RET]     -> 0 mod 16
;   [loop back]      -> 0 mod 16  (ready for next call)
;   add rsp, 0x28    -> 8 mod 16
; R15 is callee-saved (Windows x64 ABI), preserved across callbacks.

    mov esi, [rbx + 0x3C]
    add rsi, rbx                        ; RSI = NT headers
    mov eax, [rsi + 0xD0]               ; DataDir[9].VirtualAddress (TLS directory)
    test eax, eax
    jz _done                            ; no TLS directory
    add rax, rbx                        ; RAX = TLS directory VA
    mov r15, [rax + 0x18]               ; R15 = IMAGE_TLS_DIRECTORY64.AddressOfCallBacks (VA)
    test r15, r15
    jz _done                            ; null callbacks list

    sub rsp, 0x28                       ; 32-byte shadow + 8-byte align: RSP = 0 (mod 16)

_loop:
    mov rax, [r15]                      ; RAX = next callback VA
    test rax, rax
    jz _cleanup                         ; null terminator
    add r15, 8                          ; advance to next entry
    mov rcx, rbx                        ; arg1: hModule = PE base
    mov edx, 1                          ; arg2: DLL_PROCESS_ATTACH
    xor r8d, r8d                        ; arg3: lpvReserved = NULL
    call rax                            ; callback(base, 1, NULL)
    jmp _loop

_cleanup:
    add rsp, 0x28                       ; restore stack: RSP = 8 (mod 16)

_done:
    ; RBX = PE base, RSP = 8 (mod 16); fall through to next shellcode.
