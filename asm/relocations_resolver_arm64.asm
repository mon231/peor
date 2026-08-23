// ARM64 relocation resolver - applies base relocations only.
// Assembled by keystone (KS_ARCH_ARM64 / KS_MODE_LITTLE_ENDIAN).
//
// On entry: (none required).
// On exit:  x19 = PE base, execution falls through to the next shellcode.
//
// Register convention across stub chain: x19 = PE base.
//
// Literal pool design:
//   offset 0:  _base: adr x0, _base    x0 = address of _base (this instruction)
//   offset 4:         b _code           skip 8-byte literal pool
//   offset 8:  _pool: nop               lower 4 bytes of PE_OFFSET (patched by setup.py)
//   offset 12:        nop               upper 4 bytes of PE_OFFSET (patched by setup.py)
//   offset 16: _code: ldr x1, _pool    x1 = PE_OFFSET (8-byte value at _pool)
//   offset 20:        add x19, x0, x1  x19 = PE base = _base + PE_OFFSET

%define IMAGE_REL_BASED_DIR64  0xA
%define PE_MAGIC_MZ            0x5A4D
%define PE_MAGIC_PE            0x4550
%define PE_E_LFANEW_OFFSET     0x3C
%define PE64_IMAGE_BASE_OFFSET 0x30
%define PE64_BASERELOC_DIR_OFF 0xB0
%define BLOCK_HEADER_SIZE      0x8
%define RELOC_TYPE_SHIFT       0xC
%define RELOC_OFFSET_MASK      0xFFF

_base:
    adr x0, _base
    b _code
_pool:
    nop
    nop
_code:
    ldr x1, _pool
    add x19, x0, x1

    ldrh w0, [x19]
    movz w1, PE_MAGIC_MZ
    cmp w0, w1
    b.eq _valid_mz
    brk #0
_valid_mz:
    ldr w0, [x19, PE_E_LFANEW_OFFSET]
    add x21, x19, x0
    ldr w0, [x21]
    movz w1, PE_MAGIC_PE
    cmp w0, w1
    b.eq _valid_pe
    brk #0
_valid_pe:
    ldr x0, [x21, PE64_IMAGE_BASE_OFFSET]
    subs x20, x19, x0
    b.eq _done
    ldr w0, [x21, PE64_BASERELOC_DIR_OFF]
    cbz w0, _done
    add x21, x19, x0

_block:
    ldr w22, [x21]
    ldr w0, [x21, #4]
    cbz w0, _done
    add x21, x21, BLOCK_HEADER_SIZE
    sub w23, w0, BLOCK_HEADER_SIZE
    lsr w23, w23, #1
    cbz w23, _block

_entry:
    ldrh w9, [x21], #2
    cbz w9, _block
    lsr w10, w9, RELOC_TYPE_SHIFT
    and w9, w9, RELOC_OFFSET_MASK
    cmp w10, IMAGE_REL_BASED_DIR64
    b.ne _next_entry
    add x9, x9, x22
    add x9, x19, x9
    ldr x10, [x9]
    add x10, x10, x20
    str x10, [x9]
_next_entry:
    subs w23, w23, #1
    b.ne _entry
    b _block

_done:
