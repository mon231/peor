; ARM32 (Thumb-2) relocation resolver - applies base relocations to the embedded PE.
; Assembled by keystone (KS_ARCH_ARM / KS_MODE_THUMB).
;
; On entry: r9 = image_handle, r10 = system_table (saved by ARM32_EFI_PREFIX before this runs).
; On exit:  r4 = PE base; r9/r10 unchanged; falls through to next shellcode.
;
; Literal-pool layout (pool at offset 8, 4-byte aligned):
;   offset  0: mov r0, pc    r0 = _base + 4  (Thumb PC = instr_addr + 4)
;   offset  2: b.w _code     skip 6 bytes to _code
;   offset  6: nop           2-byte alignment pad so pool lands at offset 8
;   offset  8: .word 0       PE_OFFSET placeholder (patched by setup.py to len(blob)-4)
;   offset 12: _code:        ldr r1, _pool; add r4, r0, r1  → r4 = PE base
;
; r4 = (_base+4) + (len(relocs_blob)-4 + extra) = _base + len(relocs_blob) + extra = PE base.
; setup.py patches offset 8; _build_shellcode_chain() adds extra (ctors+ep+align_pad) to it.
;
; Registers (must NOT clobber r9/r10 — set by EFI prefix before this runs):
;   r4  = PE base (output, preserved for the chain)
;   r5  = relocation delta (actual_base - ImageBase)
;   r6  = current IMAGE_BASE_RELOCATION block pointer
;   r7  = current block.VirtualAddress
;   r8  = remaining entry count for current block
;   r11 = current entry value / target address (scratch)
;   r12 = scratch for MOVW/MOVT decode/re-encode

%define IMAGE_REL_BASED_HIGHLOW      0x3
%define IMAGE_REL_BASED_ARM_MOV32    0xD
%define IMAGE_REL_BASED_THUMB_MOV32  0xE
%define PE_MAGIC_MZ                  0x5A4D
%define PE_MAGIC_PE                  0x4550
%define PE_E_LFANEW_OFFSET           0x3C
%define PE32_IMAGE_BASE_OFFSET       0x34
%define PE32_BASERELOC_DIR_OFFSET    0xA0
%define IMAGE_BASE_RELOCATION_SIZE   0x8
%define RELOC_TYPE_SHIFT             0xC
%define MOVW_IMM4_LSB                0x0
%define MOVW_IMM4_WIDTH              0x4
%define MOVW_I_LSB                   0xA
%define MOVW_I_WIDTH                 0x1
%define MOVW_IMM3_LSB                0xC
%define MOVW_IMM3_WIDTH              0x3
%define MOVW_IMM8_LSB                0x0
%define MOVW_IMM8_WIDTH              0x8

_base:
    mov r0, pc              ; r0 = _base + 4
    b.w _code               ; skip alignment nop + pool (4-byte T4 branch)
    nop                     ; 2-byte alignment pad -- pool at offset 8
_pool:
    .word 0x00000000        ; PE_OFFSET pool (patched by setup.py / chain_builder)
_code:
    ldr r1, _pool           ; r1 = PE_OFFSET (T2 backward load, pool at offset 8)
    add r4, r0, r1          ; r4 = PE base

    ldrh r0, [r4]
    movw r1, #PE_MAGIC_MZ
    cmp r0, r1
    beq _valid_mz
    bkpt #0
_valid_mz:
    ldr r0, [r4, #PE_E_LFANEW_OFFSET]
    add r3, r4, r0              ; r3 = NT headers (PE\0\0 signature)
    ldr r0, [r3]
    movw r1, #PE_MAGIC_PE
    cmp r0, r1
    beq _valid_pe
    bkpt #0
_valid_pe:
    ldr r0, [r3, #PE32_IMAGE_BASE_OFFSET]  ; r0 = ImageBase (PE32 at NT+0x34)
    subs r5, r4, r0                         ; r5 = delta = actual_base - ImageBase
    beq _done
    ldr r0, [r3, #PE32_BASERELOC_DIR_OFFSET] ; r0 = BaseReloc.VirtualAddress
    cmp r0, #0
    beq.w _done
    add r6, r4, r0                           ; r6 = first IMAGE_BASE_RELOCATION

_block:
    ldr r7, [r6]                         ; r7 = block.VirtualAddress
    ldr r0, [r6, #4]                     ; r0 = block.SizeOfBlock
    cmp r0, #0
    beq.w _done                          ; null block = terminator
    add r6, r6, #IMAGE_BASE_RELOCATION_SIZE
    sub r0, r0, #IMAGE_BASE_RELOCATION_SIZE
    lsr r8, r0, #1                       ; r8 = entry count
    cmp r8, #0
    beq _block

_entry:
    ldrh r11, [r6], #2                   ; r11 = entry halfword, r6 += 2
    lsr r0, r11, #RELOC_TYPE_SHIFT       ; r0 = type (upper 4 bits)
    bfc r11, #12, #20                    ; r11 = page offset (lower 12 bits, clear [31:12])
    add r11, r11, r7                      ; r11 = target RVA
    add r11, r11, r4                      ; r11 = target absolute address

    cmp r0, #IMAGE_REL_BASED_HIGHLOW
    beq _highlow
    cmp r0, #IMAGE_REL_BASED_ARM_MOV32
    beq _mov32
    cmp r0, #IMAGE_REL_BASED_THUMB_MOV32
    beq _mov32

_next_entry:
    subs r8, r8, #1
    bne _entry
    b _block

_highlow:
    ldr r0, [r11]
    add r0, r0, r5
    str r0, [r11]
    b _next_entry

_mov32:
    ; r11 = address of MOVW instruction; MOVT is at r11+4.
    ; Decode MOVW: extract imm16 = {imm4[3:0], i[10], imm3[14:12], imm8[7:0]}
    ldrh r0, [r11]               ; r0 = MOVW hw1
    ldrh r1, [r11, #2]           ; r1 = MOVW hw2
    ubfx r2, r0, #MOVW_IMM4_LSB, #MOVW_IMM4_WIDTH   ; r2 = imm4
    lsl  r2, r2, #12                                  ; r2 = imm4<<12
    ubfx r3, r0, #MOVW_I_LSB, #MOVW_I_WIDTH          ; r3 = i
    orr  r2, r2, r3, lsl #11                          ; r2 |= i<<11
    ubfx r3, r1, #MOVW_IMM3_LSB, #MOVW_IMM3_WIDTH    ; r3 = imm3
    orr  r2, r2, r3, lsl #8                           ; r2 |= imm3<<8
    ubfx r3, r1, #MOVW_IMM8_LSB, #MOVW_IMM8_WIDTH    ; r3 = imm8
    orr  r2, r2, r3              ; r2 = imm16_lo (MOVW value)

    ; Decode MOVT: same bit layout
    ldrh r0, [r11, #4]           ; r0 = MOVT hw1
    ldrh r1, [r11, #6]           ; r1 = MOVT hw2
    ubfx r3, r0, #MOVW_IMM4_LSB, #MOVW_IMM4_WIDTH
    lsl  r3, r3, #12
    ubfx r12, r0, #MOVW_I_LSB, #MOVW_I_WIDTH
    orr  r3, r3, r12, lsl #11
    ubfx r12, r1, #MOVW_IMM3_LSB, #MOVW_IMM3_WIDTH
    orr  r3, r3, r12, lsl #8
    ubfx r12, r1, #MOVW_IMM8_LSB, #MOVW_IMM8_WIDTH
    orr  r3, r3, r12             ; r3 = imm16_hi (MOVT value)

    ; Combine to 32-bit value, add delta, split back
    orr  r2, r2, r3, lsl #16    ; r2 = current 32-bit absolute address
    add  r2, r2, r5              ; r2 = relocated 32-bit address
    uxth r12, r2                 ; r12 = new MOVW imm16 (low 16 bits)
    lsr  r3, r2, #16             ; r3 = new MOVT imm16 (high 16 bits)

    ; Re-encode MOVW at r11
    ldrh r0, [r11]
    ldrh r1, [r11, #2]
    ubfx r2, r12, #12, #MOVW_IMM4_WIDTH
    bfi  r0, r2, #MOVW_IMM4_LSB, #MOVW_IMM4_WIDTH   ; hw1[3:0] = new_imm4
    ubfx r2, r12, #11, #MOVW_I_WIDTH
    bfi  r0, r2, #MOVW_I_LSB, #MOVW_I_WIDTH          ; hw1[10] = new_i
    ubfx r2, r12, #8, #MOVW_IMM3_WIDTH
    bfi  r1, r2, #MOVW_IMM3_LSB, #MOVW_IMM3_WIDTH    ; hw2[14:12] = new_imm3
    ubfx r2, r12, #0, #MOVW_IMM8_WIDTH
    bfi  r1, r2, #MOVW_IMM8_LSB, #MOVW_IMM8_WIDTH    ; hw2[7:0] = new_imm8
    strh r0, [r11]
    strh r1, [r11, #2]

    ; Re-encode MOVT at r11+4
    ldrh r0, [r11, #4]
    ldrh r1, [r11, #6]
    ubfx r2, r3, #12, #MOVW_IMM4_WIDTH
    bfi  r0, r2, #MOVW_IMM4_LSB, #MOVW_IMM4_WIDTH
    ubfx r2, r3, #11, #MOVW_I_WIDTH
    bfi  r0, r2, #MOVW_I_LSB, #MOVW_I_WIDTH
    ubfx r2, r3, #8, #MOVW_IMM3_WIDTH
    bfi  r1, r2, #MOVW_IMM3_LSB, #MOVW_IMM3_WIDTH
    ubfx r2, r3, #0, #MOVW_IMM8_WIDTH
    bfi  r1, r2, #MOVW_IMM8_LSB, #MOVW_IMM8_WIDTH
    strh r0, [r11, #4]
    strh r1, [r11, #6]

    b _next_entry

_done:
    ; r4 = PE base; r9 = image_handle; r10 = system_table (all preserved)
