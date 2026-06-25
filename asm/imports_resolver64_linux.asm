; x64 Linux usermode import resolver - position-independent shellcode
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_64 / KS_OPT_SYNTAX_NASM).
;
; Algorithm:
;   1. On entry RDI = dlopen, RSI = dlsym (passed by the Linux test_loader)
;   2. Save them in R12 (dlopen) and R13 (dlsym)
;   3. Scan forward from current IP for "MZ" + "PE" signature -> PE base in R14
;   4. Walk IMAGE_IMPORT_DESCRIPTOR (pointer in RBP); for each DLL:
;      dlopen(libname, RTLD_LAZY) -> handle in RBX
;   5. For each INT/FT thunk (pointer in R15): dlsym(handle, funcname) -> write to IAT
;   6. Fall through to relocs resolver (terminal JMP RAX stripped by peor)
;
; Register map (callee-saved in System V AMD64 ABI):
;   R12 = dlopen function pointer
;   R13 = dlsym function pointer
;   R14 = PE image base
;   R15 = current INT (thunk name) slot pointer
;   RBX = current library handle (from dlopen)
;   RBP = current IMAGE_IMPORT_DESCRIPTOR pointer
;
; RDI / RSI are used only as System V arg1 / arg2 when making calls.
;
; Named constants
%define RTLD_LAZY                         0x01
%define IMAGE_IMPORT_DESC_SIZE            0x14
%define IAT_SLOT_SIZE                     0x08
%define IMPORT_BY_NAME_HINT_SIZE          0x02
%define E_LFANEW_OFFSET                   0x3C
%define PE_SIGNATURE_DWORD                0x4550
%define MZ_SIGNATURE_WORD                 0x5A4D
%define NT64_IMPORT_DIR_RVA_OFF           0x90
%define MAX_E_LFANEW                      0x400
%define IMPORT_DESC_INT_RVA_OFF           0x00
%define IMPORT_DESC_NAME_RVA_OFF          0x0C
%define IMPORT_DESC_FT_RVA_OFF            0x10

    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0x28                          ; shadow + align (6 pushes + sub = RSP 0 mod 16)

    ; Save dlopen and dlsym (passed in RDI, RSI by the Linux loader)
    mov r12, rdi                           ; R12 = dlopen
    mov r13, rsi                           ; R13 = dlsym

    ; Scan forward from current IP for PE image (MZ + valid PE sig)
    call _here
_here:
    pop rax                                ; RAX = runtime address of _here
    add rax, 0x100                         ; skip ahead past shellcode start
    mov rsi, rax

_scan_mz:
    inc rsi
    cmp word [rsi], MZ_SIGNATURE_WORD
    jnz _scan_mz
    mov eax, [rsi + E_LFANEW_OFFSET]
    cmp eax, MAX_E_LFANEW
    ja _scan_mz
    lea rax, [rsi + rax]
    cmp dword [rax], PE_SIGNATURE_DWORD
    jnz _scan_mz

    mov r14, rsi                           ; R14 = PE image base

    ; Walk IMAGE_IMPORT_DESCRIPTOR table
    mov eax, [rsi + E_LFANEW_OFFSET]
    add rax, rsi                           ; NT headers VA
    mov eax, [rax + NT64_IMPORT_DIR_RVA_OFF]  ; DataDir[1].VA
    test eax, eax
    jz _done
    add rax, r14                           ; Import dir VA
    mov rbp, rax                           ; RBP = current IMAGE_IMPORT_DESCRIPTOR

_desc_loop:
    mov eax, [rbp + IMPORT_DESC_NAME_RVA_OFF]  ; Name RVA
    test eax, eax
    jz _done                               ; null descriptor = end of table
    add rax, r14                           ; Name VA (dll name string)

    ; dlopen(dll_name, RTLD_LAZY) - System V AMD64 ABI: arg1=RDI, arg2=RSI
    mov rdi, rax                           ; arg1: dll name string
    mov esi, RTLD_LAZY                     ; arg2: RTLD_LAZY
    call r12                               ; dlopen(dll_name, RTLD_LAZY) -> RAX = handle
    test rax, rax
    jz _next_desc
    mov rbx, rax                           ; RBX = library handle

    ; Choose INT (OriginalFirstThunk) or fall back to FT (FirstThunk)
    mov eax, [rbp + IMPORT_DESC_INT_RVA_OFF]   ; OriginalFirstThunk RVA (zero-extends)
    test eax, eax
    jz _use_ft
    add rax, r14                           ; INT VA
    mov r15, rax                           ; R15 = INT ptr (thunk name array)
    mov eax, [rbp + IMPORT_DESC_FT_RVA_OFF]    ; FirstThunk RVA (IAT)
    add rax, r14                           ; IAT VA
    push rax                               ; stack: IAT ptr (we use R15 for INT, stack for IAT)
    jmp _thunk_loop

_use_ft:
    mov eax, [rbp + IMPORT_DESC_FT_RVA_OFF]
    add rax, r14
    mov r15, rax                           ; R15 = INT ptr (same array used for both)
    push rax                               ; stack: IAT ptr = same as INT ptr

_thunk_loop:
    mov rax, [r15]                         ; 64-bit thunk entry (name or ordinal)
    test rax, rax
    jz _thunk_done                         ; null = end of thunk array

    ; check ordinal flag (bit 63)
    bt rax, 63
    jc _by_ordinal

    ; Import by name: RAX = RVA of IMAGE_IMPORT_BY_NAME
    add rax, r14                           ; VA of IMAGE_IMPORT_BY_NAME
    add rax, IMPORT_BY_NAME_HINT_SIZE      ; skip Hint WORD -> function name string
    ; dlsym(handle, name) - System V AMD64 ABI: arg1=RDI, arg2=RSI
    mov rsi, rax                           ; arg2: function name string
    mov rdi, rbx                           ; arg1: library handle
    call r13                               ; dlsym(handle, name) -> RAX
    jmp _save_func

_by_ordinal:
    ; dlsym does not support ordinals directly - resolve as NULL (ordinal imports rare on Linux)
    xor eax, eax

_save_func:
    mov rcx, [rsp]                         ; peek IAT ptr from stack
    mov [rcx], rax                         ; write resolved address to IAT slot

_next_thunk:
    add r15, IAT_SLOT_SIZE                 ; advance INT ptr
    mov rax, [rsp]
    add rax, IAT_SLOT_SIZE
    mov [rsp], rax                         ; advance IAT ptr on stack
    jmp _thunk_loop

_thunk_done:
    pop rax                                ; discard IAT ptr from stack

_next_desc:
    add rbp, IMAGE_IMPORT_DESC_SIZE        ; next IMAGE_IMPORT_DESCRIPTOR (20 bytes)
    jmp _desc_loop

_done:
    add rsp, 0x28
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    jmp rax                                ; terminal bytes (ff e0) - stripped by peor
