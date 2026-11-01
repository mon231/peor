// ARM64 Linux usermode import resolver - self-contained dlsym/dlopen finder.
// Assembled by keystone (KS_ARCH_ARM64 / KS_MODE_LITTLE_ENDIAN).
// Ports asm/imports_resolver64_linux.asm's algorithm to AArch64: same ELF64
// layout (identical offsets - aarch64 is also 64-bit ELF), different syscall
// numbers, different embedding trick (adr instead of call/pop - AArch64 has
// native PC-relative addressing), and AAPCS64 registers instead of SysV x64.
//
// Algorithm:
//   1. Find dlopen/dlsym via /proc/self/maps ELF64 parsing (raw syscalls, no params needed).
//   2. Walk PE IMAGE_IMPORT_DESCRIPTOR using the found functions.
//   3. Fall through to relocs resolver (terminal bytes stripped by peor).
//
// This stub runs BEFORE relocs in the chain (see peor/_chain_builder.py's
// _build_shellcode_chain concatenation order: imports + relocs + ...), so it
// cannot rely on a chain-convention register for the PE base the way
// relocations_resolver_arm64.asm does (that stub computes PE base itself via
// an adr-patched literal, independent of any predecessor). This stub instead
// self-locates the PE image by scanning forward in memory past its own code,
// exactly like the x64 version does - no register handoff needed either way.
//
// Register map (find_dlsym phase):
//   x19 = embedded string table base
//   x20 = libc ELF base (preserved as "rsi" was in the x64 version)
//   x21 = DT_STRTAB VA
//   x22 = DT_SYMTAB VA
//   x23 = DT_HASH VA (temporary; reused as dlopen VA after the find phase)
//   x24 = dlopen VA (0 until found)
//   x25 = dlsym VA (0 until found)
//
// Register map (import_loop phase):
//   x24 = dlopen function pointer
//   x25 = dlsym function pointer
//   x26 = PE image base
//   x27 = current INT/FirstThunk pointer (thunk array cursor)
//   x28 = current library handle
//   x29 = current IAT slot pointer (repurposed as scratch - this stub is
//         raw position-independent shellcode, not an AAPCS-called function,
//         so there is no frame chain to preserve; relocations_resolver_arm64.asm
//         already establishes this same convention by freely using x19-x23)
//
// No callee-saved registers are preserved across this stub's boundary -
// nothing downstream reads any of x19-x29 as an input (confirmed against
// relocations_resolver_arm64.asm, which computes everything it needs from
// its own position). Only SP is kept balanced: the maps-scan stack buffer
// is allocated and freed within this stub, net zero by the time control
// falls through to the next stub.

%define SYS_READ                    0x3F
%define SYS_CLOSE                   0x39
%define SYS_OPENAT                  0x38
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
%define ELF64_DYN_SIZE              0x10
%define ELF64_SYM_ST_VALUE          0x08
%define ELF64_SYM_SIZE              0x18
%define ELF_HASH_NCHAIN_OFF         0x04
%define MAX_SYM_SCAN                0x8000
%define MAPS_BUF_SIZE                0x2000

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

%define PE_SCAN_SKIP                0x100

    ; Save the original caller's return address (x30/LR) before our own dlopen/dlsym
    ; blr calls below overwrite it - same idiom entrypoint_resolver_efi_arm64.asm
    ; already uses. Without this, main()'s eventual `ret` (back in the Linux test
    ; loader's C caller) would land inside this stub instead of back in the loader,
    ; since AArch64's bl/blr (unlike x86 call) stores the return address in a single
    ; register, not on the stack, so nested calls must explicitly save/restore it.
    str x30, [sp, -16]!

    ; -- Embed string data: branch over it, point at it with adr -----------
    b _after_strings
_strings_start:
    ; "/proc/self/maps\0"  (16 bytes)
    .byte 0x2F,0x70,0x72,0x6F,0x63,0x2F,0x73,0x65,0x6C,0x66,0x2F,0x6D,0x61,0x70,0x73,0x00
    ; "dlopen\0"           (7 bytes)
    .byte 0x64,0x6C,0x6F,0x70,0x65,0x6E,0x00
    ; "dlsym\0"            (6 bytes)
    .byte 0x64,0x6C,0x73,0x79,0x6D,0x00
    ; "libc.so\0"          (8 bytes)
    .byte 0x6C,0x69,0x62,0x63,0x2E,0x73,0x6F,0x00
    ; Pad to a 4-byte boundary (37 bytes of strings above - ARM64 instructions
    ; that follow must stay 4-byte aligned, or keystone's LLVM backend aborts
    ; with "fixup not sufficiently aligned" on later branch-target fixups).
    .byte 0x00,0x00,0x00
_after_strings:
    adr x19, _strings_start
%define STR_PROC_SELF_MAPS          0x00
%define STR_DLOPEN                  0x10
%define STR_DLSYM                   0x17
%define STR_LIBC_SO                 0x1D

    sub sp, sp, MAPS_BUF_SIZE   ; stack buffer for /proc/self/maps contents

    ; -- Open /proc/self/maps -------------------------------------------------
    mov x8, SYS_OPENAT
    mov x0, AT_FDCWD
    add x1, x19, STR_PROC_SELF_MAPS
    mov x2, O_RDONLY
    mov x3, 0
    svc 0
    cmp x0, 0
    b.lt _find_done

    mov x9, x0                  ; x9 = fd

    ; -- Read maps into buffer -------------------------------------------------
    mov x8, SYS_READ
    mov x0, x9
    mov x1, sp
    mov x2, MAPS_BUF_SIZE
    svc 0
    mov x10, x0                 ; x10 = bytes_read (temp)

    ; -- Close fd -------------------------------------------------------------
    mov x8, SYS_CLOSE
    mov x0, x9
    svc 0

    cmp x10, 0
    b.lt _find_done

    ; Null-terminate buffer
    cmp x10, MAPS_BUF_SIZE
    b.ge _scan_maps
    mov x11, sp
    add x11, x11, x10
    strb wzr, [x11]

_scan_maps:
    ; -- Search for "libc.so" in buffer ---------------------------------------
    mov x20, sp                 ; x20 scans through buffer
    add x11, sp, MAPS_BUF_SIZE
    sub x11, x11, 7              ; safe scan end (7 = len("libc.so"))
_scan_byte:
    cmp x20, x11
    b.hs _find_done
    ldr w12, [x20]
    movz w13, 0x696C              ; "libc" LE (0x6362696C split lo/hi - mov can't take a
    movk w13, 0x6362, lsl 16       ; full 32-bit immediate with both halves set)
    cmp w12, w13
    bne _next_byte
    ldrb w12, [x20, 4]
    cmp w12, 0x2E                ; '.'
    bne _next_byte
    ldrb w12, [x20, 5]
    cmp w12, 0x73                ; 's'
    bne _next_byte
    ldrb w12, [x20, 6]
    cmp w12, 0x6F                ; 'o'
    bne _next_byte
    b _found_libc_so
_next_byte:
    add x20, x20, 1
    b _scan_byte

_found_libc_so:
    ; Back up x20 to the start of the line containing "libc.so"
    mov x12, x20
_back_to_newline:
    mov x13, sp
    cmp x12, x13
    b.eq _parse_base
    sub x12, x12, 1
    ldrb w14, [x12]
    cmp w14, 0x0A                ; '\n'
    bne _back_to_newline
    add x12, x12, 1              ; skip past '\n'
_parse_base:
    ; Parse hex address at start of the line into x20
    mov x20, 0
_parse_hex:
    ldrb w14, [x12]
    cmp w14, 0x2D                ; '-'
    b.eq _hex_done
    cmp w14, 0x61                ; 'a'
    b.hs _hex_alpha
    cmp w14, 0x30                ; '0'
    b.lo _hex_done
    cmp w14, 0x39                ; '9'
    b.hi _hex_done
    sub w14, w14, 0x30
    b _hex_add
_hex_alpha:
    cmp w14, 0x66                ; 'f'
    b.hi _hex_done
    sub w14, w14, 0x57           ; 'a' - 10 = 0x57
_hex_add:
    lsl x20, x20, 4
    and x15, x14, 0xFF
    orr x20, x20, x15
    add x12, x12, 1
    b _parse_hex
_hex_done:
    ; x20 = libc base address (or 0 on failure)
    cmp x20, 0
    b.eq _find_done

    ; Verify ELF magic at base
    ldr w12, [x20]
    movz w13, 0x457F               ; ELF_MAGIC lo/hi split (both halves nonzero)
    movk w13, 0x464C, lsl 16
    cmp w12, w13
    bne _find_done

    ; -- Walk ELF64 phdrs for PT_DYNAMIC --------------------------------------
    ldr x12, [x20, ELF64_EHDR_PHOFF]
    add x12, x12, x20            ; x12 = first phdr VA
    ldrh w13, [x20, ELF64_EHDR_PHNUM]   ; x13 = phnum
    ldrh w14, [x20, ELF64_EHDR_PHENTSIZE] ; x14 = phentsize (constant per loop)

    mov x22, 0                   ; DT_SYMTAB
    mov x21, 0                   ; DT_STRTAB
    mov x23, 0                   ; DT_HASH

_phdr_loop:
    cmp x13, 0
    b.eq _find_done               ; PT_DYNAMIC not found
    ldr w15, [x12, ELF64_PHDR_TYPE]
    cmp w15, PT_DYNAMIC
    b.eq _got_dynamic
    add x12, x12, x14
    sub x13, x13, 1
    b _phdr_loop

_got_dynamic:
    ldr x0, [x12, ELF64_PHDR_VADDR]
    add x0, x0, x20               ; x0 = .dynamic section VA

    ; -- Walk DT entries -------------------------------------------------------
_dyn_loop:
    ldr x1, [x0]                  ; d_tag
    cmp x1, 0                     ; DT_NULL
    b.eq _dyn_done
    cmp x1, DT_STRTAB
    b.ne _chk_symtab
    ldr x21, [x0, 8]               ; x21 = DT_STRTAB VA
    b _dyn_next
_chk_symtab:
    cmp x1, DT_SYMTAB
    b.ne _chk_hash
    ldr x22, [x0, 8]               ; x22 = DT_SYMTAB VA
    b _dyn_next
_chk_hash:
    cmp x1, DT_HASH
    b.ne _dyn_next
    ldr x23, [x0, 8]               ; x23 = DT_HASH VA
_dyn_next:
    add x0, x0, ELF64_DYN_SIZE
    b _dyn_loop

_dyn_done:
    ; Need at least DT_STRTAB and DT_SYMTAB to scan symbols
    cmp x21, 0
    b.eq _find_done
    cmp x22, 0
    b.eq _find_done

    ; Determine symbol count from DT_HASH.nchain (or use MAX_SYM_SCAN)
    mov w1, MAX_SYM_SCAN
    cmp x23, 0
    b.eq _do_sym_scan
    ldr w1, [x23, ELF_HASH_NCHAIN_OFF]   ; DT_HASH.nchain = total symbol count
    cmp w1, 0
    b.eq _find_done

_do_sym_scan:
    ; x22 = DT_SYMTAB, x21 = DT_STRTAB, w1 = symbol count
    ; Scan for "dlopen" (7 chars+null) and "dlsym" (5 chars+null)
    ; Results: x25 = dlsym VA, x24 = dlopen VA (0 if not found)
    mov x24, 0                   ; dlopen (was DT_HASH ptr, now reset)
    mov x25, 0                   ; dlsym

_sym_loop:
    cmp w1, 0
    b.eq _sym_scan_done
    ; sym.st_name -> index into strtab
    ldr w2, [x22]                ; st_name (4 bytes)
    cmp w2, 0
    b.eq _sym_next
    add x2, x2, x21               ; x2 = name string VA

    ; Compare with "dlsym\0" (word "dlsy" + byte 'm' + byte '\0')
    cmp x25, 0                    ; already found?
    b.ne _skip_dlsym_check
    ldr w3, [x2]
    movz w4, 0x6C64                ; "dlsy" LE lo/hi split
    movk w4, 0x7973, lsl 16
    cmp w3, w4
    b.ne _skip_dlsym_check
    ldrb w3, [x2, 4]
    cmp w3, 0x6D                  ; 'm'
    b.ne _skip_dlsym_check
    ldrb w3, [x2, 5]
    cmp w3, 0x00                  ; null terminator
    b.ne _skip_dlsym_check
    ; Found "dlsym" - st_value gives offset; add libc base for absolute VA
    ldr x25, [x22, ELF64_SYM_ST_VALUE]
    cmp x25, 0
    b.eq _skip_dlsym_check        ; undefined symbol
    ; Check if already absolute VA or needs base added
    cmp x25, x20
    b.hs _skip_dlsym_check        ; already >= base, treat as absolute
    add x25, x25, x20             ; x25 = dlsym VA
_skip_dlsym_check:

    ; Compare with "dlopen\0"
    cmp x24, 0
    b.ne _skip_dlopen_check
    ldr w3, [x2]
    movz w4, 0x6C64                 ; "dlop" LE lo/hi split
    movk w4, 0x706F, lsl 16
    cmp w3, w4
    b.ne _skip_dlopen_check
    ldrb w3, [x2, 4]
    cmp w3, 0x65                   ; 'e'
    b.ne _skip_dlopen_check
    ldrb w3, [x2, 5]
    cmp w3, 0x6E                   ; 'n'
    b.ne _skip_dlopen_check
    ldrb w3, [x2, 6]
    cmp w3, 0x00                   ; null terminator
    b.ne _skip_dlopen_check
    ldr x24, [x22, ELF64_SYM_ST_VALUE]
    cmp x24, 0
    b.eq _skip_dlopen_check
    cmp x24, x20
    b.hs _skip_dlopen_check
    add x24, x24, x20              ; x24 = dlopen VA
_skip_dlopen_check:

    ; Stop early if both found
    cmp x24, 0
    b.eq _sym_next
    cmp x25, 0
    b.eq _sym_next
    b _sym_scan_done

_sym_next:
    add x22, x22, ELF64_SYM_SIZE
    sub w1, w1, 1
    b _sym_loop

_sym_scan_done:
    ; x25 = dlsym VA (or 0 if not found)
    ; x24 = dlopen VA (or 0 if not found)
    ; If dlsym not found, we can't resolve anything
    cmp x25, 0
    b.eq _find_done
    ; If dlopen not found, try dlsym(RTLD_DEFAULT, "dlopen")
    cmp x24, 0
    b.ne _find_done
    mov x0, RTLD_DEFAULT            ; handle = NULL (RTLD_DEFAULT)
    add x1, x19, STR_DLOPEN
    blr x25                          ; dlsym(RTLD_DEFAULT, "dlopen")
    mov x24, x0                      ; x24 = dlopen (or 0 if still not found)

_find_done:
    ; Restore SP (free maps buffer)
    add sp, sp, MAPS_BUF_SIZE

    ; x24 = dlopen (may be 0), x25 = dlsym (may be 0)
    ; If neither found, skip import resolution entirely
    cmp x25, 0
    b.eq _done

    ; -- Scan forward for PE image (MZ + valid PE sig) ------------------------
_pe_scan_start:
    adr x9, _pe_scan_start
    add x9, x9, PE_SCAN_SKIP        ; skip past shellcode start
    mov x10, x9

_scan_mz:
    add x10, x10, 1
    ldrh w11, [x10]
    mov w12, MZ_SIGNATURE_WORD
    cmp w11, w12
    bne _scan_mz
    ldr w11, [x10, E_LFANEW_OFFSET]
    cmp w11, MAX_E_LFANEW
    b.hi _scan_mz
    add x12, x10, x11
    ldr w13, [x12]
    mov w14, PE_SIGNATURE_DWORD
    cmp w13, w14
    bne _scan_mz

    mov x26, x10                     ; x26 = PE base

    ; -- Walk IMAGE_IMPORT_DESCRIPTOR -----------------------------------------
    ; Phase-2 register map:
    ;   x24 = dlopen, x25 = dlsym, x26 = PE base
    ;   x27 = current IMAGE_IMPORT_DESCRIPTOR pointer
    ;   x28 = name-source cursor (INT array if present, else FT array)
    ;   x20 = IAT write-destination cursor (FT array; advances in lockstep with x28)
    ;   x29 = current library handle
    ldr w11, [x10, E_LFANEW_OFFSET]
    add x11, x11, x10
    ldr w11, [x11, NT64_IMPORT_DIR_RVA_OFF]
    cmp w11, 0
    b.eq _done
    add x27, x11, x26                ; x27 = first IMAGE_IMPORT_DESCRIPTOR

_desc_loop:
    ldr w11, [x27, IMPORT_DESC_NAME_RVA_OFF]
    cmp w11, 0
    b.eq _done
    add x0, x11, x26                 ; x0 = DLL name VA

    ; dlopen(dll_name, RTLD_LAZY) if dlopen is available; else RTLD_DEFAULT handle
    cmp x24, 0
    b.eq _no_dlopen
    mov x1, RTLD_LAZY
    blr x24                           ; dlopen(dll_name, RTLD_LAZY)
    cmp x0, 0
    b.eq _next_desc
    mov x29, x0                       ; x29 = handle
    b _got_handle
_no_dlopen:
    mov x29, RTLD_DEFAULT             ; x29 = RTLD_DEFAULT (0)
_got_handle:

    ; Choose INT or FirstThunk array
    ldr w11, [x27, IMPORT_DESC_INT_RVA_OFF]
    cmp w11, 0
    b.eq _use_ft
    add x28, x11, x26                 ; x28 = INT array (name source)
    ldr w11, [x27, IMPORT_DESC_FT_RVA_OFF]
    add x20, x11, x26                 ; x20 = FT array (write destination)
    b _thunk_loop
_use_ft:
    ldr w11, [x27, IMPORT_DESC_FT_RVA_OFF]
    add x28, x11, x26                 ; x28 = FT array (name source AND write dest)
    mov x20, x28

_thunk_loop:
    ldr x0, [x28]
    cmp x0, 0
    b.eq _thunk_done
    tbnz x0, 63, _ordinal
    add x0, x0, x26
    add x1, x0, IMPORT_BY_NAME_HINT_SIZE  ; name ptr, 2nd dlsym arg
    mov x0, x29                            ; handle, 1st dlsym arg
    blr x25                                ; dlsym(handle, name)
    b _save_fn
_ordinal:
    mov x0, 0                              ; dlsym has no ordinal API; resolve to NULL
_save_fn:
    str x0, [x20]
_next_thunk:
    add x28, x28, IAT_SLOT_SIZE
    add x20, x20, IAT_SLOT_SIZE
    b _thunk_loop
_thunk_done:

_next_desc:
    add x27, x27, IMAGE_IMPORT_DESC_SIZE
    b _desc_loop

_done:
    ldr x30, [sp], 16    ; restore the original caller's return address
    ret
