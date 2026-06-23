; x64 SEH registrar - calls ntdll!RtlAddFunctionTable for the PE's .pdata.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_64 / KS_OPT_SYNTAX_NASM).
;
; On entry: RBX = PE base (already relocated), RSP = 8 (mod 16).
; On exit:  RBX = PE base, execution falls through to entrypoint_resolver64.
; Only chained when DataDir[3].VA != 0 (PE has exception table).
;
; RSP alignment trace (entry RSP = 8 mod 16):
;   push rbx         -> 0 mod 16
;   [balanced loop]  -> 0 mod 16
;   pop rbx          -> 8 mod 16
;   push rcx / pop   -> net 0 -> 8 mod 16
;   sub rsp, 0x28    -> 0 mod 16  (32-byte shadow + 8-byte align)
;   call r10         -> 8 mod 16 inside callee  OK

    mov esi, [rbx + 0x3C]
    add rsi, rbx                          ; RSI = NT headers
    mov ecx, [rsi + 0xA0]                 ; DataDir[3].VA (exception table)
    test ecx, ecx
    jz _done                              ; no .pdata - nothing to register

    push rbx                              ; save PE base; RSP = 0 (mod 16)

    ; Get ntdll base from PEB (InMemoryOrderModuleList[1])
    db 0x65
    mov rax, [0x60]                       ; PEB
    mov rax, [rax + 0x18]                 ; PEB.Ldr
    mov rax, [rax + 0x20]                 ; InMemoryOrderModuleList.Flink = exe entry
    mov rax, [rax]                        ; .Flink = ntdll entry
    mov r11, [rax + 0x20]                 ; ntdll DllBase

    ; Locate ntdll export directory
    mov eax, [r11 + 0x3C]
    add rax, r11                          ; ntdll NT headers
    mov eax, [rax + 0x88]                 ; DataDir[0].VA = export dir RVA
    add rax, r11                          ; RAX = ntdll export dir
    mov rcx, rax                          ; RCX = export dir
    mov r9d, [rax + 0x18]                 ; NumberOfNames
    mov r10d, [rax + 0x20]               ; AddressOfNames RVA
    add r10, r11                          ; R10 = AddressOfNames VA

    ; Embed "RtlAddFunctionTable\0" via CALL/POP trick
    call _raft_str
    db 'R','t','l','A','d','d','F','u','n','c','t','i','o','n','T','a','b','l','e',0
_raft_str:
    pop rdi                               ; RDI = &"RtlAddFunctionTable"

_raft_loop:
    dec r9d
    js _seh_skip                          ; exhausted all names without match
    mov eax, [r10 + r9 * 4]              ; name RVA
    add rax, r11                          ; name VA in ntdll
    push rsi
    push rdi
    push r9
    push r10
    push rcx                              ; save export dir
    mov rsi, rax                          ; RSI = name VA in ntdll
    mov ecx, 0x14                         ; len("RtlAddFunctionTable\0") = 20
    cld
    repe cmpsb
    pop rcx                               ; restore export dir
    pop r10
    pop r9
    pop rdi
    pop rsi
    jnz _raft_loop

    ; Found "RtlAddFunctionTable" at name-table index R9D.
    mov eax, [rcx + 0x24]                ; AddressOfNameOrdinals RVA
    add rax, r11
    movzx eax, word [rax + r9 * 2]       ; ordinal
    mov r9d, eax
    mov eax, [rcx + 0x1C]                ; AddressOfFunctions RVA
    add rax, r11
    mov eax, [rax + r9 * 4]              ; function RVA
    add rax, r11                          ; RAX = RtlAddFunctionTable VA
    mov r10, rax

    ; RtlAddFunctionTable(FunctionTable, EntryCount, BaseAddress)
    pop rbx                               ; restore PE base; RSP = 8 (mod 16)
    mov r9d, [rbx + 0x3C]
    add r9, rbx                           ; R9 = NT headers of our PE
    mov ecx, [r9 + 0xA0]                 ; DataDir[3].VA
    add rcx, rbx                          ; arg1: FunctionTable VA
    mov r8, rbx                           ; arg3: BaseAddress = PE base

    ; EntryCount = DataDir[3].Size / 12
    mov eax, [r9 + 0xA4]                 ; DataDir[3].Size
    xor edx, edx
    push rcx                              ; save arg1; RSP = 0 (mod 16)
    mov ecx, 0xc
    div ecx                               ; EAX = Size / 12 = EntryCount
    mov edx, eax                          ; arg2: EntryCount
    pop rcx                               ; restore arg1; RSP = 8 (mod 16)

    sub rsp, 0x28                         ; 32-byte shadow + 8-byte align; RSP = 0 (mod 16)
    call r10                              ; RtlAddFunctionTable(FT, count, base)
    add rsp, 0x28                         ; RSP = 8 (mod 16)
    jmp _done

_seh_skip:
    pop rbx                               ; balance push rbx; RSP = 8 (mod 16)

_done:
    ; RBX = PE base, RSP = 8 (mod 16); fall through to entrypoint_resolver64.
