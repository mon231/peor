; seh_registrar32.asm -- Register a VEH to bypass SafeSEH for x86 C++ exceptions.
;
; Background: On Windows Vista+ x86 with DEP enabled, RtlDispatchException calls
; RtlIsValidHandler before dispatching to each SEH handler address. If the handler
; is not in a module recognised by RtlPcToFileHeader (e.g. it lives in VirtualAlloc
; memory), the call is rejected and C++ try/catch blocks silently fail.
;
; On Windows 11 WoW64, RtlPcToFileHeader uses NtQueryVirtualMemory(MemoryImageInformation)
; to locate the owning module. VirtualAlloc memory (MEM_PRIVATE) always returns
; ImageBase=0, so no LDR-list injection can fix this; the VAD type is checked at
; the kernel level.
;
; Fix: register a VEH via AddVectoredExceptionHandler. VEH handlers are called
; BEFORE RtlDispatchException walks the SEH chain, and are never validated by
; RtlIsValidHandler. Our VEH:
;   1. Intercepts C++ exceptions (exception code 0xE06D7363).
;   2. Walks the SEH chain from FS:[0], calling each frame's handler directly.
;   3. When __CxxFrameHandler3 finds a matching catch: it calls RtlUnwind +
;      longjmps to the catch block internally and never returns here.
;      RtlUnwind does NOT call RtlIsValidHandler for the unwind phase.
;   4. If the chain is exhausted: returns EXCEPTION_CONTINUE_SEARCH so Windows
;      can fall back to normal (likely unhandled-exception) behaviour.
;
; Side-effect vs LDR injection: this does NOT insert a fake LDR entry, so
; GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, thread_fn) returns
; NULL. That prevents CRT _beginthreadex wrappers from calling
; FreeLibraryAndExitThread(shellcode_base), which was the test_08 regression.
;
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_32 / KS_OPT_SYNTAX_NASM).
; Keystone notes:
;   - [fs:N] not supported: use "db 0x64" before "mov reg, [N]"
;   - "times N db val" not supported: use explicit dd/db entries
;
; On entry: EBX = PE base (set by relocs_resolver, preserved here)
; On exit:  EBX unchanged, falls through to next chain component
; Clobbers: EAX, ECX, EDX, ESI, EDI

; Named constants
%define CPP_EXCEPTION_CODE           0xe06d7363  ; MSVC C++ exception magic (throw)
%define EXCEPTION_CHAIN_END          0xffffffff  ; FS:[0] end-of-chain sentinel
%define EXCEPTION_CPP_THROWINFO_OFF  0x1c        ; ExceptionInformation[2]: ThrowInfo* in EXCEPTION_RECORD (x86)
%define EXCEPTION_RECORD_DWORDS      0x14        ; sizeof(EXCEPTION_RECORD) / 4 = 80 / 4 on x86 (Keystone treats unadorned literals as hex)

    push ebx                          ; save PE_base

    ; ----------------------------------------------------------------
    ; Find RtlAddVectoredExceptionHandler in ntdll.
    ; InMemoryOrderModuleList: index 0 = exe, 1 = ntdll.
    ; kernel32!AddVectoredExceptionHandler is a forwarded export -> ntdll.
    ; ----------------------------------------------------------------
    db 0x64
    mov eax, [0x30]                   ; EAX = PEB  (FS:[0x30])
    mov eax, [eax + 0x0c]            ; PEB.Ldr
    mov esi, [eax + 0x14]            ; InMemoryOrderModuleList.Flink (exe node)
    mov esi, [esi]                    ; skip exe -> ntdll node
    mov ebx, [esi + 0x10]            ; ntdll DllBase
                                      ;   (InMemoryOrderLinks at LDR+0x08,
                                      ;    DllBase at LDR+0x18 => node+0x10)

    ; Walk ntdll export table
    mov eax, [ebx + 0x3c]
    add eax, ebx                      ; NT headers
    mov eax, [eax + 0x78]            ; DataDir[0] RVA (export dir, PE32: NT+0x78)
    add eax, ebx                      ; Export directory VA
    push eax                          ; [stack] = export dir (cleanup on failure)
    mov ecx, [eax + 0x18]            ; NumberOfNames
    mov edx, [eax + 0x20]            ; AddressOfNames RVA
    add edx, ebx                      ; AddressOfNames VA

    ; "RtlAddVectoredExceptionHandler\0" = 31 bytes
    call _aveh_str
    db 'R','t','l','A','d','d','V','e','c','t','o','r','e','d','E','x','c','e','p','t','i','o','n','H','a','n','d','l','e','r',0
_aveh_str:
    pop edi                           ; EDI = &"RtlAddVectoredExceptionHandler\0"

_search:
    dec ecx
    js _not_found                     ; exhausted names without a match
    mov esi, [edx + ecx * 4]
    add esi, ebx                      ; candidate name VA
    push esi
    push ecx
    push edi
    mov ecx, 0x1f                     ; compare 31 bytes including NUL (0x1f = 31 decimal)
    cld
    repe cmpsb
    pop edi
    pop ecx
    pop esi
    jnz _search

    ; Resolve ordinal -> VA
    pop eax                           ; export dir (success path: we pop it here)
    mov esi, [eax + 0x24]
    add esi, ebx                      ; AddressOfNameOrdinals VA
    movzx ecx, word [esi + ecx * 2]  ; ordinal
    mov esi, [eax + 0x1c]
    add esi, ebx                      ; AddressOfFunctions VA
    mov eax, [esi + ecx * 4]
    add eax, ebx                      ; RtlAddVectoredExceptionHandler VA

    ; CALL/POP trick: push AVEH VA then call forward to skip over _veh_handler.
    ; The CALL instruction pushes &_veh_handler (the next byte) as the return
    ; address, then jumps to _skip_handler. After pop edx we have &_veh_handler.
    push eax                          ; [stack+4] = AVEH VA
    call _skip_handler

; =====================================================================
; VEH HANDLER  (WINAPI = __stdcall, one pointer arg, returns LONG)
; Windows calls this with: [esp+4] = EXCEPTION_POINTERS*
; =====================================================================
_veh_handler:
    push ebp
    mov ebp, esp
    push esi
    push edi
    push ebx

    mov esi, [ebp + 8]               ; EXCEPTION_POINTERS*
    mov edi, [esi]                   ; EXCEPTION_RECORD* (on throw-site stack -- may be stale post-ZwContinue)

    ; Only intercept C++ exceptions (quick check on original pointer -- always valid here)
    cmp dword [edi], CPP_EXCEPTION_CODE
    jne _veh_search

    ; CALL/POP trick: jump over 80 bytes of inline static storage and obtain its address.
    ; The storage holds a copy of the most recent fresh C++ exception record so that
    ; __pCurrentException remains valid after ZwContinue unwinds the throw-site stack.
    call _exc_copy_ref
    ; ---- 80-byte static storage (EXCEPTION_RECORD_DWORDS * 4 = 80) ----
    dd 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
_exc_copy_ref:
    pop ebx                          ; EBX = &static_copy[0]

    ; For rethrows (throw;), ExceptionInformation[2] (ThrowInfo*) is NULL.
    ; The static copy already holds the original EXCEPTION_RECORD from the
    ; preceding fresh throw (including the real ThrowInfo).  Skip the copy so
    ; we don't overwrite the static copy with a NULL-ThrowInfo record, and jump
    ; straight to the SEH walk passing &static_copy -- _CxxFrameHandler3 will
    ; see the original ThrowInfo and can locate the correct outer catch clause.
    cmp dword [edi + EXCEPTION_CPP_THROWINFO_OFF], 0
    je _veh_use_static               ; rethrow: skip copy, use existing static_copy

    ; Fresh C++ throw: copy EXCEPTION_RECORD into the static buffer.
    ; Avoid rep movsd: Keystone confuses movsd (dword string) with SSE2 movsd.
    push ecx
    xor ecx, ecx
_copy_exc_loop:
    mov eax, [edi + ecx * 4]
    mov [ebx + ecx * 4], eax
    inc ecx
    cmp ecx, EXCEPTION_RECORD_DWORDS
    jnz _copy_exc_loop
    pop ecx

_veh_use_static:
    mov edi, ebx                     ; EDI = &static_copy (valid even after ZwContinue)

    ; Walk SEH chain (FS:[0] = top of EXCEPTION_REGISTRATION_RECORD chain).
    ; EBX is repurposed for the chain traversal; EDI holds the static-copy address.
    db 0x64
    mov ebx, [0]                     ; EBX = chain head

_veh_walk:
    cmp ebx, EXCEPTION_CHAIN_END
    je _veh_search

    mov ecx, [ebx + 4]               ; frame->Handler
    test ecx, ecx
    jz _veh_next_frame

    ; Call frame->Handler(exc_rec, frame, ctx, NULL) directly -- bypass
    ; RtlIsValidHandler.  Calling convention: __cdecl (4 args, caller cleans up).
    ;
    ; Set FS:[0] = this frame so that RtlUnwind (called internally by
    ; _CxxFrameHandler3 when it finds a matching catch) sees the target
    ; frame as the chain head and skips any stale/cleanup frames that
    ; _CxxFrameHandler3 pushed during the first ZwContinue and left in
    ; the chain on the abandoned stack.
    db 0x64
    mov [0], ebx                     ; FS:[0] = EstablisherFrame
    push 0                           ; DispatcherContext = NULL
    push dword [esi + 4]             ; CONTEXT* (EXCEPTION_POINTERS->ContextRecord)
    push ebx                         ; EstablisherFrame = EXCEPTION_REGISTRATION_RECORD*
    push edi                         ; EXCEPTION_RECORD* (&static_copy -- valid post-ZwContinue)
    call ecx
    add esp, 0x10                    ; __cdecl: caller pops 4 args * 4 bytes

    ; ExceptionContinueSearch (1): this frame cannot handle, try next
    cmp eax, 1
    je _veh_next_frame
    ; Any other return (ExceptionContinueExecution or handler never returned):
    ; fall through to CONTINUE_SEARCH so Windows re-dispatches with fixed context.
    jmp _veh_search

_veh_next_frame:
    mov ebx, [ebx]                   ; frame->Next
    jmp _veh_walk

_veh_search:
    pop ebx
    pop edi
    pop esi
    pop ebp
    xor eax, eax                     ; EXCEPTION_CONTINUE_SEARCH (0)
    ret 0x04                         ; __stdcall: callee pops the one PVOID arg
; =====================================================================
; END VEH HANDLER
; =====================================================================

_skip_handler:
    pop edx                           ; EDX = &_veh_handler  (from CALL/POP)

    pop eax                           ; EAX = AddVectoredExceptionHandler VA

    ; AddVectoredExceptionHandler(First=1, Handler=&_veh_handler)
    push edx                          ; arg2: Handler
    push 1                            ; arg1: First = TRUE (highest priority)
    call eax                          ; returns PVOID handle (non-NULL = success)
    jmp _done

_not_found:
    pop eax                           ; clean up the export-dir push

_done:
    pop ebx                           ; restore PE_base
    ; Falls through to next chain component (tls_callbacks / entrypoint).
