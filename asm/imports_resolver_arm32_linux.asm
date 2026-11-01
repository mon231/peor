; ARM32 (Thumb-2) Linux usermode import resolver - self-contained dlsym/dlopen finder.
; Assembled by keystone (KS_ARCH_ARM / KS_MODE_THUMB).
; Ports asm/imports_resolver_arm64_linux.asm's algorithm to AArch32/EABI: same
; forward-MZ/PE-scan self-location technique and overall ELF-walking algorithm,
; but ELF32 (not ELF64) struct offsets, ARM EABI syscall numbers (different from
; both x64 and ARM64 - verified against the Linux kernel's own
; arch/arm/tools/syscall.tbl), AAPCS32 register conventions, and Thumb-2
; immediate-encoding rules (movw/movt splits for any 32-bit constant with both
; halves nonzero, same as relocations_resolver_arm32.asm already established).
;
; Algorithm (identical structure to the x64/ARM64 Linux resolvers):
;   1. Find dlopen/dlsym via /proc/self/maps ELF32 parsing (raw EABI syscalls,
;      svc #0 with the syscall number in r7 and args in r0-r3).
;   2. Walk PE IMAGE_IMPORT_DESCRIPTOR using the found functions.
;   3. Fall through to relocs resolver (terminal bytes stripped by peor).
;
; This stub runs BEFORE relocs in the chain (see peor/_chain_builder.py's
; _build_shellcode_chain concatenation order: imports + relocs + ...), so, like
; the x64/ARM64 Linux resolvers, it self-locates the PE image by scanning forward
; in memory past its own code rather than relying on a chain-convention register
; (relocations_resolver_arm32.asm computes r4 = PE base itself from its own
; literal pool, independent of any predecessor - same "either self-location
; mechanism would work; forward-scan chosen for consistency with x64/x86/ARM64"
; reasoning already recorded for the ARM64 sibling file and this plan's ledger).
;
; Register map (find_dlsym phase):
;   r4  = embedded string table base
;   r5  = libc ELF base
;   r6  = DT_STRTAB VA
;   r8  = DT_SYMTAB VA (also sym-scan cursor, advances through the symbol table)
;   r9  = DT_HASH VA (temporary; only ever read once, to get DT_HASH.nchain)
;   r10 = dlopen VA (0 until found)
;   r11 = dlsym VA (0 until found)
;   r7  = syscall number ONLY (EABI svc convention) - reloaded before every
;         svc #0 and never expected to survive across one
;   r0-r3, r12 = scratch (syscall args / local temporaries)
;
; Register map (import_loop phase - registers reused once phase 1 is done):
;   r10 = dlopen function pointer (carried over unchanged from phase 1)
;   r11 = dlsym function pointer (carried over unchanged from phase 1)
;   r5  = PE image base (was libc ELF base - no longer needed)
;   r6  = current IMAGE_IMPORT_DESCRIPTOR pointer (was DT_STRTAB)
;   r8  = current INT/FirstThunk name-source cursor (was DT_SYMTAB)
;   r9  = current IAT write-destination cursor (was DT_HASH)
;   r4  = current library handle (was string table base - the one string still
;         needed past this point, STR_DLOPEN, is only used by the
;         dlsym(RTLD_DEFAULT,"dlopen") fallback, which always runs, if at all,
;         before phase 2 begins)
;
; No callee-saved registers (r4-r11) are preserved across this stub's own
; boundary - same convention asm/imports_resolver_arm64_linux.asm already
; established (nothing downstream reads r4-r11 as an input; relocations_resolver_arm32.asm
; computes everything it needs fresh via its own literal pool, freely clobbering
; r4-r12). Only LR (r14) is explicitly saved/restored: bl/blx (unlike x86's call)
; stores the return address in a register rather than pushing it to the stack, so
; this stub's two blx calls to dlopen/dlsym would otherwise permanently clobber
; the original caller's return address - the exact critical lesson already
; recorded for the ARM64 sibling and entrypoint_resolver_efi_arm32.asm.

%define SYS_READ                    0x3      ; verified: arch/arm/tools/syscall.tbl "read"
%define SYS_CLOSE                   0x6      ; verified: arch/arm/tools/syscall.tbl "close"
%define SYS_OPENAT                  0x142    ; verified: arch/arm/tools/syscall.tbl "openat" (322)
%define AT_FDCWD_LO16               0xFF9C   ; AT_FDCWD = -100 = 0xFFFFFF9C, split for movw/movt
%define AT_FDCWD_HI16                0xFFFF
%define O_RDONLY                    0x00
%define RTLD_DEFAULT                0x00
%define RTLD_LAZY                   0x01

%define ELF_MAGIC_LO16              0x457F   ; ELF_MAGIC = 0x464C457F, split for movw/movt
%define ELF_MAGIC_HI16              0x464C
%define PT_DYNAMIC                  0x02
%define DT_HASH                     0x04
%define DT_STRTAB                   0x05
%define DT_SYMTAB                   0x06
%define ELF32_EHDR_PHOFF            0x1C     ; verified vs linux/include/uapi/linux/elf.h Elf32_Ehdr
%define ELF32_EHDR_PHENTSIZE        0x2A
%define ELF32_EHDR_PHNUM            0x2C
%define ELF32_PHDR_TYPE             0x00     ; verified vs Elf32_Phdr
%define ELF32_PHDR_VADDR            0x08
%define ELF32_DYN_SIZE              0x08     ; verified vs Elf32_Dyn (d_tag + d_un, 4+4 bytes)
%define ELF32_SYM_ST_VALUE          0x04     ; verified vs Elf32_Sym
%define ELF32_SYM_SIZE              0x10
%define ELF_HASH_NCHAIN_OFF         0x04
%define MAX_SYM_SCAN                0x8000
%define MAPS_BUF_SIZE               0x2000

%define IMAGE_IMPORT_DESC_SIZE      0x14
%define IAT_SLOT_SIZE               0x04
%define IMPORT_BY_NAME_HINT_SIZE    0x02
%define E_LFANEW_OFFSET             0x3C
%define PE_SIGNATURE_DWORD          0x4550
%define MZ_SIGNATURE_WORD           0x5A4D
%define NT32_IMPORT_DIR_RVA_OFF     0x80
%define MAX_E_LFANEW                0x400
%define IMPORT_DESC_INT_RVA_OFF     0x00
%define IMPORT_DESC_NAME_RVA_OFF    0x0C
%define IMPORT_DESC_FT_RVA_OFF      0x10
%define ORDINAL_FLAG32              0x80000000

%define PE_SCAN_SKIP                0x100

    ; Save the original caller's return address (LR) before our own dlopen/dlsym
    ; blx calls below overwrite it - bl/blx on ARM, like AArch64's bl/blr, puts
    ; the return address in a register, not on the stack like x86's call.
    push {r14}

    ; -- Embed string data: branch over it, address it with a (backward) adr ---
    b.w _after_strings
_strings_start:
    ; "/proc/self/maps\0"  (16 bytes)
    .byte 0x2F,0x70,0x72,0x6F,0x63,0x2F,0x73,0x65,0x6C,0x66,0x2F,0x6D,0x61,0x70,0x73,0x00
    ; "dlopen\0"           (7 bytes)
    .byte 0x64,0x6C,0x6F,0x70,0x65,0x6E,0x00
    ; "dlsym\0"            (6 bytes)
    .byte 0x64,0x6C,0x73,0x79,0x6D,0x00
    ; "libc.so\0"          (8 bytes)
    .byte 0x6C,0x69,0x62,0x63,0x2E,0x73,0x6F,0x00
    ; Pad to a 4-byte boundary (37 bytes above) - defensive, mirrors the fix
    ; already required for the ARM64 sibling file's embedded string table.
    .byte 0x00,0x00,0x00
_after_strings:
    adr r4, _strings_start
%define STR_PROC_SELF_MAPS          0x00
%define STR_DLOPEN                  0x10
%define STR_DLSYM                   0x17
%define STR_LIBC_SO                 0x1D

    sub sp, sp, #MAPS_BUF_SIZE   ; stack buffer for /proc/self/maps contents

    ; -- Open /proc/self/maps -------------------------------------------------
    movw r0, #AT_FDCWD_LO16
    movt r0, #AT_FDCWD_HI16
    add r1, r4, #STR_PROC_SELF_MAPS
    movw r2, #O_RDONLY
    movw r3, #0                   ; mode (unused for O_RDONLY)
    movw r7, #SYS_OPENAT
    svc #0
    cmp r0, #0
    blt.w _find_done

    mov r9, r0                  ; r9 = fd (temporary; DT_HASH not needed yet)

    ; -- Read maps into buffer -------------------------------------------------
    movw r7, #SYS_READ
    mov r0, r9
    mov r1, sp
    movw r2, #MAPS_BUF_SIZE
    svc #0
    mov r12, r0                 ; r12 = bytes_read (temp)

    ; -- Close fd -------------------------------------------------------------
    movw r7, #SYS_CLOSE
    mov r0, r9
    svc #0

    cmp r12, #0
    blt.w _find_done

    ; Null-terminate buffer
    cmp r12, #MAPS_BUF_SIZE
    bge.w _scan_maps
    mov r0, sp
    add r0, r0, r12
    movs r1, #0
    strb r1, [r0]

_scan_maps:
    ; -- Search for "libc.so" in buffer ---------------------------------------
    mov r5, sp                  ; r5 scans through buffer
    add r2, sp, #MAPS_BUF_SIZE
    sub r2, r2, #7               ; safe scan end (7 = len("libc.so"))
_scan_byte:
    cmp r5, r2
    bhs.w _find_done
    ldr r0, [r5]
    movw r1, #0x696C             ; "libc" LE lo/hi split (movs can't take a full
    movt r1, #0x6362              ; 32-bit immediate with both halves set)
    cmp r0, r1
    bne.w _next_byte
    ldrb r0, [r5, #4]
    cmp r0, #0x2E                ; '.'
    bne.w _next_byte
    ldrb r0, [r5, #5]
    cmp r0, #0x73                ; 's'
    bne.w _next_byte
    ldrb r0, [r5, #6]
    cmp r0, #0x6F                ; 'o'
    bne.w _next_byte
    b.w _found_libc_so
_next_byte:
    add r5, r5, #1
    b.w _scan_byte

_found_libc_so:
    ; Back up r5 to the start of the line containing "libc.so"
    mov r0, r5
_back_to_newline:
    mov r1, sp
    cmp r0, r1
    beq.w _parse_base
    sub r0, r0, #1
    ldrb r2, [r0]
    cmp r2, #0x0A                ; '\n'
    bne.w _back_to_newline
    add r0, r0, #1               ; skip past '\n'
_parse_base:
    ; Parse hex address at start of the line into r5
    movs r5, #0
_parse_hex:
    ldrb r2, [r0]
    cmp r2, #0x2D                ; '-'
    beq.w _hex_done
    cmp r2, #0x61                ; 'a'
    bhs.w _hex_alpha
    cmp r2, #0x30                ; '0'
    blo.w _hex_done
    cmp r2, #0x39                ; '9'
    bhi.w _hex_done
    sub r2, r2, #0x30
    b.w _hex_add
_hex_alpha:
    cmp r2, #0x66                ; 'f'
    bhi.w _hex_done
    sub r2, r2, #0x57            ; 'a' - 10 = 0x57
_hex_add:
    lsl r5, r5, #4
    and r3, r2, #0xFF
    orr r5, r5, r3
    add r0, r0, #1
    b.w _parse_hex
_hex_done:
    ; r5 = libc base address (or 0 on failure)
    cmp r5, #0
    beq.w _find_done

    ; Verify ELF magic at base
    ldr r0, [r5]
    movw r1, #ELF_MAGIC_LO16
    movt r1, #ELF_MAGIC_HI16
    cmp r0, r1
    bne.w _find_done

    ; -- Walk ELF32 phdrs for PT_DYNAMIC --------------------------------------
    ldr r0, [r5, #ELF32_EHDR_PHOFF]
    add r0, r0, r5                ; r0 = first phdr VA
    ldrh r1, [r5, #ELF32_EHDR_PHNUM]      ; r1 = phnum
    ldrh r2, [r5, #ELF32_EHDR_PHENTSIZE]  ; r2 = phentsize (constant per loop)

    movs r8, #0                   ; DT_SYMTAB
    movs r6, #0                   ; DT_STRTAB
    movs r9, #0                   ; DT_HASH

_phdr_loop:
    cmp r1, #0
    beq.w _find_done               ; PT_DYNAMIC not found
    ldr r3, [r0, #ELF32_PHDR_TYPE]
    cmp r3, #PT_DYNAMIC
    beq.w _got_dynamic
    add r0, r0, r2
    sub r1, r1, #1
    b.w _phdr_loop

_got_dynamic:
    ldr r3, [r0, #ELF32_PHDR_VADDR]
    add r3, r3, r5                ; r3 = .dynamic section VA

    ; -- Walk DT entries -------------------------------------------------------
_dyn_loop:
    ldr r0, [r3]                  ; d_tag
    cmp r0, #0                    ; DT_NULL
    beq.w _dyn_done
    cmp r0, #DT_STRTAB
    bne.w _chk_symtab
    ldr r6, [r3, #4]               ; r6 = DT_STRTAB VA
    b.w _dyn_next
_chk_symtab:
    cmp r0, #DT_SYMTAB
    bne.w _chk_hash
    ldr r8, [r3, #4]               ; r8 = DT_SYMTAB VA
    b.w _dyn_next
_chk_hash:
    cmp r0, #DT_HASH
    bne.w _dyn_next
    ldr r9, [r3, #4]               ; r9 = DT_HASH VA
_dyn_next:
    add r3, r3, #ELF32_DYN_SIZE
    b.w _dyn_loop

_dyn_done:
    ; Need at least DT_STRTAB and DT_SYMTAB to scan symbols
    cmp r6, #0
    beq.w _find_done
    cmp r8, #0
    beq.w _find_done

    ; Determine symbol count from DT_HASH.nchain (or use MAX_SYM_SCAN)
    movw r1, #MAX_SYM_SCAN
    cmp r9, #0
    beq.w _do_sym_scan
    ldr r1, [r9, #ELF_HASH_NCHAIN_OFF]   ; DT_HASH.nchain = total symbol count
    cmp r1, #0
    beq.w _find_done

_do_sym_scan:
    ; r8 = DT_SYMTAB, r6 = DT_STRTAB, r1 = symbol count
    ; Scan for "dlopen" (6 chars+null) and "dlsym" (5 chars+null)
    ; Results: r11 = dlsym VA, r10 = dlopen VA (0 if not found)
    movs r10, #0                  ; dlopen
    movs r11, #0                  ; dlsym

_sym_loop:
    cmp r1, #0
    beq.w _sym_scan_done
    ; sym.st_name -> index into strtab
    ldr r2, [r8]                  ; st_name (4 bytes)
    cmp r2, #0
    beq.w _sym_next
    add r2, r2, r6                 ; r2 = name string VA

    ; Compare with "dlsym\0" (word "dlsy" + byte 'm' + byte '\0')
    cmp r11, #0                    ; already found?
    bne.w _skip_dlsym_check
    ldr r3, [r2]
    movw r0, #0x6C64                ; "dlsy" LE lo/hi split
    movt r0, #0x7973
    cmp r3, r0
    bne.w _skip_dlsym_check
    ldrb r3, [r2, #4]
    cmp r3, #0x6D                  ; 'm'
    bne.w _skip_dlsym_check
    ldrb r3, [r2, #5]
    cmp r3, #0x00                  ; null terminator
    bne.w _skip_dlsym_check
    ; Found "dlsym" - st_value gives offset; add libc base for absolute VA
    ldr r11, [r8, #ELF32_SYM_ST_VALUE]
    cmp r11, #0
    beq.w _skip_dlsym_check         ; undefined symbol
    ; Check if already absolute VA or needs base added
    cmp r11, r5
    bhs.w _skip_dlsym_check         ; already >= base, treat as absolute
    add r11, r11, r5                ; r11 = dlsym VA
_skip_dlsym_check:

    ; Compare with "dlopen\0"
    cmp r10, #0
    bne.w _skip_dlopen_check
    ldr r3, [r2]
    movw r0, #0x6C64                 ; "dlop" LE lo/hi split
    movt r0, #0x706F
    cmp r3, r0
    bne.w _skip_dlopen_check
    ldrb r3, [r2, #4]
    cmp r3, #0x65                   ; 'e'
    bne.w _skip_dlopen_check
    ldrb r3, [r2, #5]
    cmp r3, #0x6E                   ; 'n'
    bne.w _skip_dlopen_check
    ldrb r3, [r2, #6]
    cmp r3, #0x00                   ; null terminator
    bne.w _skip_dlopen_check
    ldr r10, [r8, #ELF32_SYM_ST_VALUE]
    cmp r10, #0
    beq.w _skip_dlopen_check
    cmp r10, r5
    bhs.w _skip_dlopen_check
    add r10, r10, r5                ; r10 = dlopen VA
_skip_dlopen_check:

    ; Stop early if both found
    cmp r10, #0
    beq.w _sym_next
    cmp r11, #0
    beq.w _sym_next
    b.w _sym_scan_done

_sym_next:
    add r8, r8, #ELF32_SYM_SIZE
    sub r1, r1, #1
    b.w _sym_loop

_sym_scan_done:
    ; r11 = dlsym VA (or 0 if not found)
    ; r10 = dlopen VA (or 0 if not found)
    ; If dlsym not found, we can't resolve anything
    cmp r11, #0
    beq.w _find_done
    ; If dlopen not found, try dlsym(RTLD_DEFAULT, "dlopen")
    cmp r10, #0
    bne.w _find_done
    movw r0, #RTLD_DEFAULT          ; handle = NULL (RTLD_DEFAULT)
    add r1, r4, #STR_DLOPEN
    blx r11                          ; dlsym(RTLD_DEFAULT, "dlopen")
    mov r10, r0                      ; r10 = dlopen (or 0 if still not found)

_find_done:
    ; Restore SP (free maps buffer)
    add sp, sp, #MAPS_BUF_SIZE

    ; r10 = dlopen (may be 0), r11 = dlsym (may be 0)
    ; If neither found, skip import resolution entirely
    cmp r11, #0
    beq.w _done

    ; -- Scan forward for PE image (MZ + valid PE sig) ------------------------
_pe_scan_start:
    adr r12, _pe_scan_start
    add r12, r12, #PE_SCAN_SKIP     ; skip past shellcode start
    mov r0, r12

_scan_mz:
    add r0, r0, #1
    ldrh r1, [r0]
    movw r2, #MZ_SIGNATURE_WORD
    cmp r1, r2
    bne.w _scan_mz
    ldr r1, [r0, #E_LFANEW_OFFSET]
    cmp r1, #MAX_E_LFANEW
    bhi.w _scan_mz
    add r2, r0, r1
    ldr r3, [r2]
    movw r12, #PE_SIGNATURE_DWORD
    cmp r3, r12
    bne.w _scan_mz

    mov r5, r0                      ; r5 = PE base

    ; -- Walk IMAGE_IMPORT_DESCRIPTOR -----------------------------------------
    ; Phase-2 register map:
    ;   r10 = dlopen, r11 = dlsym, r5 = PE base
    ;   r6  = current IMAGE_IMPORT_DESCRIPTOR pointer
    ;   r8  = name-source cursor (INT array if present, else FT array)
    ;   r9  = IAT write-destination cursor (FT array; advances with r8)
    ;   r4  = current library handle
    ldr r1, [r0, #E_LFANEW_OFFSET]
    add r1, r1, r0
    ldr r1, [r1, #NT32_IMPORT_DIR_RVA_OFF]
    cmp r1, #0
    beq.w _done
    add r6, r1, r5                   ; r6 = first IMAGE_IMPORT_DESCRIPTOR

_desc_loop:
    ldr r1, [r6, #IMPORT_DESC_NAME_RVA_OFF]
    cmp r1, #0
    beq.w _done
    add r0, r1, r5                   ; r0 = DLL name VA

    ; dlopen(dll_name, RTLD_LAZY) if dlopen is available; else RTLD_DEFAULT handle
    cmp r10, #0
    beq.w _no_dlopen
    movw r1, #RTLD_LAZY
    blx r10                           ; dlopen(dll_name, RTLD_LAZY)
    cmp r0, #0
    beq.w _next_desc
    mov r4, r0                       ; r4 = handle
    b.w _got_handle
_no_dlopen:
    movw r4, #RTLD_DEFAULT            ; r4 = RTLD_DEFAULT (0)
_got_handle:

    ; Choose INT or FirstThunk array
    ldr r1, [r6, #IMPORT_DESC_INT_RVA_OFF]
    cmp r1, #0
    beq.w _use_ft
    add r8, r1, r5                    ; r8 = INT array (name source)
    ldr r1, [r6, #IMPORT_DESC_FT_RVA_OFF]
    add r9, r1, r5                    ; r9 = FT array (write destination)
    b.w _thunk_loop
_use_ft:
    ldr r1, [r6, #IMPORT_DESC_FT_RVA_OFF]
    add r8, r1, r5                    ; r8 = FT array (name source AND write dest)
    mov r9, r8

_thunk_loop:
    ldr r0, [r8]
    cmp r0, #0
    beq.w _thunk_done
    tst r0, #ORDINAL_FLAG32
    bne.w _ordinal
    add r0, r0, r5
    add r1, r0, #IMPORT_BY_NAME_HINT_SIZE  ; name ptr, 2nd dlsym arg
    mov r0, r4                              ; handle, 1st dlsym arg
    blx r11                                 ; dlsym(handle, name)
    b.w _save_fn
_ordinal:
    movs r0, #0                              ; dlsym has no ordinal API; resolve to NULL
_save_fn:
    str r0, [r9]
_next_thunk:
    add r8, r8, #IAT_SLOT_SIZE
    add r9, r9, #IAT_SLOT_SIZE
    b.w _thunk_loop
_thunk_done:

_next_desc:
    add r6, r6, #IMAGE_IMPORT_DESC_SIZE
    b.w _desc_loop

_done:
    pop {r14}    ; restore the original caller's return address
    bx lr
