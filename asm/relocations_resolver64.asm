; x64 (64-bit) relocation + SEH-registration + DLL-entry resolver
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_64 / KS_OPT_SYNTAX_NASM).
;
; Extension over the bare reloc resolver:
;   * Registers the PE's exception table (DataDir[3]) with
;     ntdll!RtlAddFunctionTable so x64 SEH / C++ exceptions unwind correctly.
;   * Detects DLL images (IMAGE_FILE_DLL) and calls DllMain with the
;     standard DLL_PROCESS_ATTACH arguments instead of jumping to the entry
;     point directly.
;   * Correctly handles PEs with no .reloc section (DataDir[5].VA == 0).
;
; NOTE: 0x7E7E7E7E is a placeholder patched by setup.py with (shellcode_size - 5).

    call _base
_base:
    pop rbx                              ; RBX = runtime address of _base
    lea rdi, [rbx + 0x7E7E7E7E]         ; PATCHED: RDI = PE image base
    mov rbx, rdi                         ; RBX = PE base

    cmp word [rbx], 0x5A4D               ; "MZ"
    jnz _exit

    mov esi, [rbx + 0x3C]                ; e_lfanew (32-bit, zero-extends to RSI)
    add rsi, rbx                         ; NT headers
    cmp dword [rsi], 0x4550              ; "PE\0\0"
    jnz _exit

    mov rax, [rsi + 0x30]                ; ImageBase (PE64: OptHdr+0x18 = NT+0x30)
    mov rdi, rbx
    sub rdi, rax                         ; delta = actual_base - ImageBase
    test rdi, rdi
    jz _jmp_ep

    mov eax, [rsi + 0xB0]                ; DataDir[5].VA (BaseReloc at NT+0xB0 for PE64)
    test eax, eax
    jz _jmp_ep
    add rax, rbx
    mov rsi, rax                         ; RSI = first IMAGE_BASE_RELOCATION block

_block:
    mov edx, [rsi]                       ; block.VirtualAddress (32-bit)
    mov ecx, [rsi + 4]                   ; block.SizeOfBlock
    add rsi, 8
    test ecx, ecx
    jz _jmp_ep                           ; null block = end sentinel
    sub ecx, 8
    shr ecx, 1                           ; number of 16-bit entries
    jz _block

_entry:
    lodsw                                ; AX = next entry, RSI += 2
    test ax, ax
    jz _block                            ; type 0 (ABS padding) -> done with block

    movzx r8d, ax
    mov r9w, r8w
    and r8d, 0x0FFF                      ; page offset
    shr r9w, 0x0c                        ; reloc type
    cmp r9b, 0x0A                        ; IMAGE_REL_BASED_DIR64
    jnz _next_entry

    lea r10, [rbx + rdx]                 ; page VA
    add r10, r8                          ; target address
    add [r10], rdi                       ; patch QWORD at target += delta

_next_entry:
    dec ecx
    jnz _entry
    jmp _block

; ---------------------------------------------------------------------------
; _jmp_ep - Register exception table, detect DLL, transfer control.
;
; On entry:  RBX = PE base   RSI = (last reloc block ptr, unused)
;            RSP points to test_loader's return address; RSP = 8 (mod 16)
; ---------------------------------------------------------------------------
_jmp_ep:
    ; Compute OEP and push it for safe-keeping.
    ; After push: RSP = 0 (mod 16), OEP at [RSP].
    mov esi, [rbx + 0x3C]
    add rsi, rbx                         ; RSI = NT headers
    mov eax, [rsi + 0x28]               ; AddressOfEntryPoint RVA
    add rax, rbx                         ; RAX = OEP VA
    push rax                             ; save OEP

    ; ------------------------------------------------------------------
    ; SEH: register .pdata exception table via ntdll!RtlAddFunctionTable
    ; ------------------------------------------------------------------
    mov ecx, [rsi + 0xA0]               ; DataDir[3].VA (exception table)
    test ecx, ecx
    jz _dll_check                        ; no exception table -> skip SEH

    push rbx                             ; save PE base

    ; Get ntdll base from PEB (InMemoryOrderModuleList[1])
    db 0x65
    mov rax, [0x60]                      ; PEB
    mov rax, [rax + 0x18]               ; PEB.Ldr
    mov rax, [rax + 0x20]               ; InMemoryOrderModuleList.Flink = exe entry
    mov rax, [rax]                       ; .Flink = ntdll entry
    mov r11, [rax + 0x20]               ; ntdll DllBase

    ; Locate ntdll export directory
    mov eax, [r11 + 0x3C]
    add rax, r11                         ; ntdll NT headers
    mov eax, [rax + 0x88]               ; DataDir[0].VA = export dir RVA
    add rax, r11                         ; RAX = ntdll export dir
    mov rcx, rax                         ; RCX = export dir
    mov r9d, [rax + 0x18]               ; NumberOfNames
    mov r10d, [rax + 0x20]              ; AddressOfNames RVA
    add r10, r11                         ; R10 = AddressOfNames VA

    ; Embed "RtlAddFunctionTable\0" via CALL/POP trick
    call _raft_str
    db 'R','t','l','A','d','d','F','u','n','c','t','i','o','n','T','a','b','l','e',0
_raft_str:
    pop rdi                              ; RDI = &"RtlAddFunctionTable"

_raft_loop:
    dec r9d
    js _seh_skip                         ; exhausted all names without match
    mov eax, [r10 + r9 * 4]             ; name RVA
    add rax, r11                         ; name VA in ntdll
    push rsi
    push rdi
    push r9
    push r10
    push rcx                             ; save export dir
    mov rsi, rax                         ; RSI = name VA in ntdll
    mov ecx, 20                          ; len("RtlAddFunctionTable\0") = 20
    cld
    repe cmpsb
    pop rcx                              ; restore export dir
    pop r10
    pop r9
    pop rdi
    pop rsi
    jnz _raft_loop

    ; Found "RtlAddFunctionTable" at name-table index R9D.
    mov eax, [rcx + 0x24]               ; AddressOfNameOrdinals RVA
    add rax, r11
    movzx eax, word [rax + r9 * 2]      ; ordinal
    mov r9d, eax
    mov eax, [rcx + 0x1C]               ; AddressOfFunctions RVA
    add rax, r11
    mov eax, [rax + r9 * 4]             ; function RVA
    add rax, r11                         ; RAX = RtlAddFunctionTable VA
    mov r10, rax

    ; Build call: RtlAddFunctionTable(FunctionTable, EntryCount, BaseAddress)
    pop rbx                              ; restore PE base  (OEP now at [RSP])
    mov r9d, [rbx + 0x3C]
    add r9, rbx                          ; R9 = NT headers of our PE
    mov ecx, [r9 + 0xA0]                ; DataDir[3].VA
    add rcx, rbx                         ; arg1: FunctionTable VA
    mov r8, rbx                          ; arg3: BaseAddress = PE base

    ; EntryCount = DataDir[3].Size / 12
    mov eax, [r9 + 0xA4]                ; DataDir[3].Size
    xor edx, edx
    push rcx                             ; save arg1
    mov ecx, 12
    div ecx                              ; EAX = Size / 12 = EntryCount
    mov edx, eax                         ; arg2: EntryCount
    pop rcx                              ; restore arg1

    sub rsp, 0x20                        ; shadow space (RSP stays 0 mod 16 before call)
    call r10                             ; RtlAddFunctionTable(FT, count, base)
    add rsp, 0x20
    jmp _dll_check

_seh_skip:
    pop rbx                              ; restore PE base  (OEP now at [RSP])

; ------------------------------------------------------------------
; DLL check: detect IMAGE_FILE_DLL and call DllMain vs jmp to OEP.
; On entry: RSP = 0 (mod 16), OEP at [RSP], RBX = PE base.
; ------------------------------------------------------------------
_dll_check:
    ; Reload NT headers (RSI may have been clobbered above)
    mov esi, [rbx + 0x3C]
    add rsi, rbx
    test word [rsi + 0x16], 0x2000       ; IMAGE_FILE_DLL?
    jz _exe_entry

    ; DLL: call DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)
    pop rax                              ; OEP = DllMain entry  (RSP = 8 mod 16)
    mov rcx, rbx                         ; arg1: hinstDLL = PE base
    mov edx, 1                           ; arg2: DLL_PROCESS_ATTACH
    xor r8d, r8d                         ; arg3: lpvReserved = NULL
    sub rsp, 0x28                        ; shadow space + align  (RSP = 0 before call)
    call rax                             ; DllMain(base, DLL_PROCESS_ATTACH, NULL)
    add rsp, 0x28
    hlt                                  ; DllMain should call ExitProcess; if not, halt

_exe_entry:
    pop rax                              ; OEP  (RSP = 8 mod 16)
    jmp rax

_exit:
    hlt

_pe_start:
