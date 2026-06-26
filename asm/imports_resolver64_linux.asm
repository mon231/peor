; x64 Linux usermode import resolver - self-contained dlsym/dlopen finder.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_64 / KS_OPT_SYNTAX_NASM).
;
; Algorithm:
;   1. Find dlopen/dlsym via /proc/self/maps ELF64 parsing (raw syscalls, no params needed).
;   2. Walk PE IMAGE_IMPORT_DESCRIPTOR using the found functions.
;   3. Fall through to relocs resolver (terminal JMP RAX stripped by peor).
;
; dlsym/dlopen finding:
;   a. openat(AT_FDCWD, "/proc/self/maps", O_RDONLY)
;   b. read(fd, stack_buf, MAPS_BUF_SIZE)
;   c. close(fd)
;   d. Scan buf for line containing "libc.so" -> back up to start of line, parse hex base
;   e. At ELF base: walk e_phoff phdrs for PT_DYNAMIC -> read DT_SYMTAB, DT_STRTAB, DT_HASH
;   f. Linear-scan symbol table for "dlopen" and "dlsym"; use DT_HASH.nchain as symbol count
;   g. Fall back: scan up to MAX_SYM_SCAN entries if DT_HASH absent
;
; Register map (find_dlsym phase - before R12/R13/R14 take their final values):
;   R15 = string table base (embedded strings)
;   RBX = libc ELF base / current symbol pointer
;   RBP = DT_STRTAB pointer / dlopen candidate
;   R12 = DT_HASH pointer (temporary; becomes dlopen after find phase)
;   R13 = dlsym candidate (becomes final dlsym after find phase)
;   R14 = DT_SYMTAB pointer (temporary; becomes PE base after find phase)
;
; Register map (import_loop phase):
;   R12 = dlopen function pointer
;   R13 = dlsym function pointer
;   R14 = PE image base
;   R15 = current INT thunk pointer
;   RBX = current library handle
;   RBP = current IMAGE_IMPORT_DESCRIPTOR pointer

%define SYS_READ                    0x00
%define SYS_CLOSE                   0x03
%define SYS_OPENAT                  0x101
%define AT_FDCWD                    -0x64
%define O_RDONLY                    0x00
%define RTLD_DEFAULT                0x00
%define RTLD_LAZY                   0x01

%define ELF_MAGIC                   0x464C457F
%define PT_DYNAMIC                  0x02
%define DT_HASH                     0x04
%define DT_STRTAB                   0x05
%define DT_SYMTAB                   0x06
%define ELF64_EHDR_PHOFF            0x20
%define ELF64_EHDR_PHENTSIZE        0x36
%define ELF64_EHDR_PHNUM            0x38
%define ELF64_PHDR_TYPE             0x00
%define ELF64_PHDR_VADDR            0x10
%define ELF64_PHDR_SIZE             0x38
%define ELF64_DYN_SIZE              0x10
%define ELF64_SYM_ST_VALUE          0x08
%define ELF64_SYM_SIZE              0x18
%define ELF_HASH_NCHAIN_OFF         0x04
%define MAX_SYM_SCAN                0x8000
%define MAPS_BUF_SIZE               0x2000

%define IMAGE_IMPORT_DESC_SIZE      0x14
%define IAT_SLOT_SIZE               0x08
%define IMPORT_BY_NAME_HINT_SIZE    0x02
%define E_LFANEW_OFFSET             0x3C
%define PE_SIGNATURE_DWORD          0x4550
%define MZ_SIGNATURE_WORD           0x5A4D
%define NT64_IMPORT_DIR_RVA_OFF     0x90
%define MAX_E_LFANEW                0x400
%define IMPORT_DESC_INT_RVA_OFF     0x00
%define IMPORT_DESC_NAME_RVA_OFF    0x0C
%define IMPORT_DESC_FT_RVA_OFF      0x10

; String offsets from embedded table base (R15)
%define STR_PROC_SELF_MAPS          0x00
%define STR_DLOPEN                  0x10
%define STR_DLSYM                   0x17
%define STR_LIBC_SO                 0x1D

    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0x28               ; align (6 pushes + sub = 0x58; entry RSP was 8 mod 16; 0x58+8=0x60, 0x60 mod 16=0)

    ; Embed string data via call-over-data trick; pop gives address of first byte.
    ; keystone NASM does not support db "string"; use explicit hex bytes.
    call _after_strings
    ; "/proc/self/maps\0"  (STR_PROC_SELF_MAPS = 0, 16 bytes)
    db 0x2F,0x70,0x72,0x6F,0x63,0x2F,0x73,0x65,0x6C,0x66,0x2F,0x6D,0x61,0x70,0x73,0x00
    ; "dlopen\0"           (STR_DLOPEN = 16, 7 bytes)
    db 0x64,0x6C,0x6F,0x70,0x65,0x6E,0x00
    ; "dlsym\0"            (STR_DLSYM = 23, 6 bytes)
    db 0x64,0x6C,0x73,0x79,0x6D,0x00
    ; "libc.so\0"          (STR_LIBC_SO = 29, 8 bytes)
    db 0x6C,0x69,0x62,0x63,0x2E,0x73,0x6F,0x00
_after_strings:
    pop r15                     ; R15 = &strings[0]

    ; -- Allocate maps buffer on stack (below saved data) ---------------------
    sub rsp, MAPS_BUF_SIZE      ; RSP = buffer start (8192 bytes)

    ; -- Open /proc/self/maps -------------------------------------------------
    mov rax, SYS_OPENAT
    mov rdi, AT_FDCWD           ; -100 (sign-extended)
    lea rsi, [r15 + STR_PROC_SELF_MAPS]
    xor edx, edx                ; O_RDONLY
    xor r10d, r10d              ; mode = 0 (unused for O_RDONLY)
    syscall
    test rax, rax
    js _find_done               ; negative fd = error

    mov rbx, rax                ; RBX = fd

    ; -- Read maps into buffer -------------------------------------------------
    xor eax, eax                ; SYS_READ
    mov rdi, rbx
    mov rsi, rsp                ; buffer at bottom of frame
    mov edx, MAPS_BUF_SIZE
    syscall
    mov r14, rax                ; R14 = bytes_read (temp)

    ; -- Close fd -------------------------------------------------------------
    mov eax, SYS_CLOSE
    mov rdi, rbx
    syscall

    test r14, r14
    js _find_done

    ; Null-terminate buffer
    cmp r14, MAPS_BUF_SIZE
    jae _scan_maps
    mov byte [rsp + r14], 0

_scan_maps:
    ; -- Search for "libc.so" in buffer ---------------------------------------
    mov rbx, rsp                ; RBX scans through buffer
    lea rcx, [rsp + MAPS_BUF_SIZE - 7]  ; safe scan end (7 = len("libc.so"))
_scan_byte:
    cmp rbx, rcx
    jae _find_done
    cmp dword [rbx], 0x6362696C ; "libc" LE: 'l'=6C 'i'=69 'b'=62 'c'=63
    jne _next_byte
    cmp byte [rbx + 4], 0x2E   ; '.'
    jne _next_byte
    cmp byte [rbx + 5], 0x73   ; 's'
    jne _next_byte
    cmp byte [rbx + 6], 0x6F   ; 'o'
    jne _next_byte
    jmp _found_libc_so
_next_byte:
    inc rbx
    jmp _scan_byte

_found_libc_so:
    ; Back up RBX to the start of the line containing "libc.so"
    mov rcx, rbx
_back_to_newline:
    cmp rcx, rsp
    je _parse_base
    dec rcx
    cmp byte [rcx], 0x0A        ; '\n'
    jne _back_to_newline
    inc rcx                     ; skip past '\n'
_parse_base:
    ; Parse hex address at start of the line into RBX
    xor rbx, rbx
_parse_hex:
    movzx eax, byte [rcx]
    cmp al, 0x2D                ; '-'
    je _hex_done
    cmp al, 0x61                ; 'a'
    jae _hex_alpha
    cmp al, 0x30                ; '0'
    jb _hex_done
    cmp al, 0x39                ; '9'
    ja _hex_done
    sub al, 0x30
    jmp _hex_add
_hex_alpha:
    cmp al, 0x66                ; 'f'
    ja _hex_done
    sub al, 0x57                ; 'a' - 10 = 0x57
_hex_add:
    shl rbx, 4
    or rbx, rax
    inc rcx
    jmp _parse_hex
_hex_done:
    ; RBX = libc base address (or 0 on failure)
    test rbx, rbx
    jz _find_done

    ; Verify ELF magic at base
    cmp dword [rbx], ELF_MAGIC
    jne _find_done

    ; -- Walk ELF64 phdrs for PT_DYNAMIC --------------------------------------
    mov rsi, rbx                ; RSI = libc base (preserved throughout)
    mov rcx, [rbx + ELF64_EHDR_PHOFF]
    add rcx, rbx                ; RCX = first phdr VA
    movzx edx, word [rbx + ELF64_EHDR_PHNUM]  ; RDX = phnum

    ; DT_SYMTAB -> R14 (temp), DT_STRTAB -> RBP, DT_HASH -> R12 (temp), dlopen -> stored in RBP after scan, dlsym -> R13
    xor r14d, r14d
    xor ebp, ebp
    xor r12d, r12d
    xor r13d, r13d

_phdr_loop:
    test edx, edx
    jz _find_done               ; PT_DYNAMIC not found
    cmp dword [rcx + ELF64_PHDR_TYPE], PT_DYNAMIC
    je _got_dynamic
    movzx eax, word [rsi + ELF64_EHDR_PHENTSIZE]
    add rcx, rax
    dec edx
    jmp _phdr_loop

_got_dynamic:
    mov rax, [rcx + ELF64_PHDR_VADDR]
    add rax, rsi                ; RAX = .dynamic section VA

    ; -- Walk DT entries -------------------------------------------------------
_dyn_loop:
    mov r8, [rax]               ; d_tag
    test r8, r8                 ; DT_NULL
    jz _dyn_done
    cmp r8, DT_STRTAB
    jne _chk_symtab
    mov rbp, [rax + 8]          ; RBP = DT_STRTAB VA
    jmp _dyn_next
_chk_symtab:
    cmp r8, DT_SYMTAB
    jne _chk_hash
    mov r14, [rax + 8]          ; R14 = DT_SYMTAB VA
    jmp _dyn_next
_chk_hash:
    cmp r8, DT_HASH
    jne _dyn_next
    mov r12, [rax + 8]          ; R12 = DT_HASH VA
_dyn_next:
    add rax, ELF64_DYN_SIZE
    jmp _dyn_loop

_dyn_done:
    ; Need at least DT_STRTAB and DT_SYMTAB to scan symbols
    test rbp, rbp
    jz _find_done
    test r14, r14
    jz _find_done

    ; Determine symbol count from DT_HASH.nchain (or use MAX_SYM_SCAN)
    mov ecx, MAX_SYM_SCAN
    test r12, r12
    jz _do_sym_scan
    mov ecx, [r12 + ELF_HASH_NCHAIN_OFF]  ; DT_HASH.nchain = total symbol count
    test ecx, ecx
    jz _find_done

_do_sym_scan:
    ; R14 = DT_SYMTAB, RBP = DT_STRTAB, ECX = symbol count
    ; Scan for "dlopen" (7 chars+null) and "dlsym" (5 chars+null)
    ; Results: R13 = dlsym VA, R12 = dlopen VA (0 if not found)
    xor r12d, r12d              ; reset dlopen (was DT_HASH ptr)
    xor r13d, r13d              ; reset dlsym

_sym_loop:
    test ecx, ecx
    jz _sym_scan_done
    ; sym.st_name -> index into strtab
    mov eax, [r14]              ; st_name (4 bytes)
    test eax, eax
    jz _sym_next
    add rax, rbp                ; RAX = name string VA

    ; Compare with "dlsym\0" (DWORD "dlsy" + byte 'm' + byte '\0')
    test r13, r13               ; already found?
    jnz _skip_dlsym_check
    cmp dword [rax], 0x79736C64 ; "dlsy" LE
    jne _skip_dlsym_check
    cmp byte [rax + 4], 0x6D   ; 'm'
    jne _skip_dlsym_check
    cmp byte [rax + 5], 0x00   ; null terminator
    jne _skip_dlsym_check
    ; Found "dlsym" - st_value gives offset; add libc base for absolute VA
    mov r13, [r14 + ELF64_SYM_ST_VALUE]
    test r13, r13
    jz _skip_dlsym_check       ; undefined symbol
    ; Check if already absolute VA or needs base added
    cmp r13, rsi
    jae _skip_dlsym_check      ; already >= base, treat as absolute
    add r13, rsi                ; R13 = dlsym VA
_skip_dlsym_check:

    ; Compare with "dlopen\0"
    test r12, r12
    jnz _skip_dlopen_check
    cmp dword [rax], 0x706F6C64 ; "dlop" LE
    jne _skip_dlopen_check
    cmp byte [rax + 4], 0x65   ; 'e'
    jne _skip_dlopen_check
    cmp byte [rax + 5], 0x6E   ; 'n'
    jne _skip_dlopen_check
    cmp byte [rax + 6], 0x00   ; null terminator
    jne _skip_dlopen_check
    mov r12, [r14 + ELF64_SYM_ST_VALUE]
    test r12, r12
    jz _skip_dlopen_check
    cmp r12, rsi
    jae _skip_dlopen_check
    add r12, rsi                ; R12 = dlopen VA
_skip_dlopen_check:

    ; Stop early if both found
    test r12, r12
    jz _sym_next
    test r13, r13
    jz _sym_next
    jmp _sym_scan_done

_sym_next:
    add r14, ELF64_SYM_SIZE
    dec ecx
    jmp _sym_loop

_sym_scan_done:
    ; R13 = dlsym VA (or 0 if not found)
    ; R12 = dlopen VA (or 0 if not found)
    ; If dlsym not found, we can't resolve anything
    test r13, r13
    jz _find_done
    ; If dlopen not found, try dlsym(RTLD_DEFAULT, "dlopen")
    test r12, r12
    jnz _find_done
    mov rdi, RTLD_DEFAULT       ; handle = NULL (RTLD_DEFAULT)
    lea rsi, [r15 + STR_DLOPEN]
    call r13                    ; dlsym(RTLD_DEFAULT, "dlopen")
    mov r12, rax                ; R12 = dlopen (or 0 if still not found)

_find_done:
    ; Restore RSP (free maps buffer)
    add rsp, MAPS_BUF_SIZE

    ; R12 = dlopen (may be 0), R13 = dlsym (may be 0)
    ; If neither found, skip import resolution entirely
    test r13, r13
    jz _done

    ; -- Scan forward for PE image (MZ + valid PE sig) ------------------------
    call _here
_here:
    pop rax
    add rax, 0x100              ; skip past shellcode start
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

    mov r14, rsi                ; R14 = PE base

    ; -- Walk IMAGE_IMPORT_DESCRIPTOR -----------------------------------------
    mov eax, [rsi + E_LFANEW_OFFSET]
    add rax, rsi
    mov eax, [rax + NT64_IMPORT_DIR_RVA_OFF]
    test eax, eax
    jz _done
    add rax, r14
    mov rbp, rax                ; RBP = first IMAGE_IMPORT_DESCRIPTOR

_desc_loop:
    mov eax, [rbp + IMPORT_DESC_NAME_RVA_OFF]
    test eax, eax
    jz _done
    add rax, r14                ; DLL name VA

    ; dlopen(dll_name, RTLD_LAZY) if dlopen is available; else use RTLD_DEFAULT handle
    test r12, r12
    jz _no_dlopen
    mov rdi, rax
    mov esi, RTLD_LAZY
    call r12                    ; dlopen(dll_name, RTLD_LAZY)
    test rax, rax
    jz _next_desc
    mov rbx, rax                ; RBX = handle
    jmp _got_handle
_no_dlopen:
    xor ebx, ebx                ; RBX = RTLD_DEFAULT (0)
_got_handle:

    ; Choose INT or FirstThunk array
    mov eax, [rbp + IMPORT_DESC_INT_RVA_OFF]
    test eax, eax
    jz _use_ft
    add rax, r14
    mov r15, rax
    mov eax, [rbp + IMPORT_DESC_FT_RVA_OFF]
    add rax, r14
    push rax                    ; IAT ptr on stack
    jmp _thunk_loop
_use_ft:
    mov eax, [rbp + IMPORT_DESC_FT_RVA_OFF]
    add rax, r14
    mov r15, rax
    push rax

_thunk_loop:
    mov rax, [r15]
    test rax, rax
    jz _thunk_done
    bt rax, 63
    jc _ordinal
    add rax, r14
    add rax, IMPORT_BY_NAME_HINT_SIZE
    mov rsi, rax
    mov rdi, rbx
    ; RSP is 8 mod 16 here (IAT ptr on stack); SysV requires 0 mod 16 before call.
    sub rsp, 0x08
    call r13                    ; dlsym(handle, name)
    add rsp, 0x08
    jmp _save_fn
_ordinal:
    xor eax, eax                ; dlsym has no ordinal API; resolve to NULL
_save_fn:
    mov rcx, [rsp]
    mov [rcx], rax
_next_thunk:
    add r15, IAT_SLOT_SIZE
    mov rax, [rsp]
    add rax, IAT_SLOT_SIZE
    mov [rsp], rax
    jmp _thunk_loop
_thunk_done:
    pop rax

_next_desc:
    add rbp, IMAGE_IMPORT_DESC_SIZE
    jmp _desc_loop

_done:
    add rsp, 0x28
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    jmp rax                     ; terminal bytes (FF E0) stripped by peor
