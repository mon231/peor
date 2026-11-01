; x64 kernel-mode import resolver - position-independent shellcode.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_64 / KS_OPT_SYNTAX_NASM).
;
; Runs as the first resolving stub of the kernel chain (after the always-present
; callee-save prologue: PUSH RBX/RBP/RSI/RDI/R12-R15 - those registers are saved
; on the stack by the prologue and restored by entrypoint_resolver_km64; they
; are free scratch here, but RBX is later owned by relocations_resolver64).
; Falls through into the relocations resolver.
;
; Algorithm:
;   1. SIDT -> IDT base; IDT gate 0's handler lies inside ntoskrnl's mapped
;      image.
;   2. Scan pages backwards from that handler for an MZ + "PE\0\0" image ->
;      ntoskrnl base.
;   3. Forward-scan for this driver's own image (MZ + PE, same trick as the
;      usermode resolver) and walk its IMAGE_IMPORT_DESCRIPTOR table.
;   4. Only descriptors whose module name starts with "ntoskrnl" (the "ntoskrnl
;      .exe" prefix; ntkrnl*.exe names of old builds are NOT covered) are
;      resolved, by walking ntoskrnl's own export table and writing the
;      absolute function address into the IAT slot. Imports from any other
;      module (HAL.dll etc.) and ordinal imports are left unresolved.
;
; No external CALL is ever used: the shellcode stays freestanding and reads
; every structure directly.
;
; Keystone notes:
;   - SIDT is used because it works on every Windows kernel without depending
;     on the (implementation-defined) KPCR internal layout.
;   - "db 0x65"-style segment prefixes are not needed here: the IDT is found
;     via the CPU register, not via GS/FS.
;   - "js near label" not supported: use bare "js label".

%define MZ_SIG               0x5A4D      ; 'MZ'
%define PE_SIG               0x00004550  ; "PE\0\0"
%define E_LFANEW_OFFSET      0x3C        ; DOS header e_lfanew offset
%define MAX_E_LFANEW         0x400       ; reject false-positive MZ matches
%define PAGE_SIZE            0x1000
%define MAX_BASE_SCAN_PAGES  0x0800      ; backward MZ scan guard (pages)
%define NT64_EXPORT_DIR_RVA  0x88        ; PE64: NT headers + 0x88 = DataDir[0]
%define NT64_IMPORT_DIR_RVA  0x90        ; PE64: NT headers + 0x90 = DataDir[1]
%define EXP_NUMNAMES_RVA     0x18        ; export dir: NumberOfNames
%define EXP_FUNCS_RVA        0x1C        ; export dir: AddressOfFunctions
%define EXP_ORLP_RVA         0x24        ; export dir: AddressOfNameOrdinals
%define EXP_NAMES_RVA        0x20        ; export dir: AddressOfNames
%define IDT64_GATE_SIZE      0x10
%define GATE_LOW_OFF         0x00        ; gate: handler offset bits [15:0]
%define GATE_MID_OFF         0x06        ; gate: handler offset bits [31:16]
%define GATE_HIGH_OFF        0x08        ; gate: handler offset bits [63:32]
%define DESC_NEXT_PTR        0x14        ; sizeof(IMAGE_IMPORT_DESCRIPTOR)
%define DESC_DLL_NAME_RVA    0x0C        ; desc: Name (RVA)
%define DESC_INT_RVA         0x00        ; desc: OriginalFirstThunk
%define DESC_FT_RVA          0x10        ; desc: FirstThunk
%define THUNK_SIZE64         0x08
%define IIBN_NAME_OFFSET     0x02        ; IMAGE_IMPORT_BY_NAME: hint WORD, name
%define NTKRNL_PREFIX_LEN    0x08        ; len("ntoskrnl")
%define LOWERCASE_BIT        0x20

; Persistent register map (never clobbered inside a loop):
;   R8  = ntoskrnl image base
;   R11 = ntoskrnl export directory VA
;   R10 = "ntoskrnl" needle pointer
;   R14 = driver PE image base
;   R15 = current IAT slot pointer
;   RSI = current INT/FT walk pointer
;   RDI = current IMAGE_IMPORT_DESCRIPTOR pointer
;   RCX/RDX/RAX/RBP/R9 = scratch

    ; ---- 1. SIDT -> IDT base ----
    sub  rsp, 0x20
    sidt [rsp]
    mov  rax, [rsp + 0x02]               ; IDTR base field
    add  rsp, 0x20

    ; ---- 2. ntoskrnl base from IDT gate 0's handler ----
    movzx ecx, word [rax + GATE_LOW_OFF]
    movzx edx, word [rax + GATE_MID_OFF]
    shl   rdx, 0x10
    or    rdx, rcx                       ; handler bits [31:0]
    mov   r8d, dword [rax + GATE_HIGH_OFF]
    shl   r8, 0x20
    or    r8, rdx                        ; R8 = handler VA (inside ntoskrnl)
    and   r8, 0xFFFFFFFFFFFFF000         ; page align

    call _prefix_str
    db 'n','t','o','s','k','r','n','l'
_prefix_str:
    pop  r10                             ; R10 = "ntoskrnl" needle

    xor  r9, r9                          ; page counter
km_base_scan:
    cmp  word [r8], MZ_SIG
    jnz  km_base_next
    mov  eax, dword [r8 + E_LFANEW_OFFSET]
    cmp  eax, MAX_E_LFANEW
    ja   km_base_next
    mov  rcx, r8
    add  rcx, rax                        ; NT headers VA
    cmp  dword [rcx], PE_SIG
    jz   km_base_found
km_base_next:
    sub  r8, PAGE_SIZE
    inc  r9
    cmp  r9, MAX_BASE_SCAN_PAGES
    jb   km_base_scan

    ; ntoskrnl not found: leave all imports unresolved, continue the chain.
    jmp  km_done

km_base_found:
    mov  eax, dword [r8 + E_LFANEW_OFFSET]
    mov  rdx, r8
    add  rdx, rax                        ; NT headers VA
    mov  r11d, dword [rdx + NT64_EXPORT_DIR_RVA]
    test r11d, r11d
    jz   km_done                         ; ntoskrnl without exports: bail
    add  r11, r8                         ; R11 = export dir VA

    ; ---- 3. forward scan for this driver's image ----
    call _here
_here:
    pop  rsi                             ; RSI = runtime address of this pop

km_img_scan:
    inc  rsi
    cmp  word [rsi], MZ_SIG
    jnz  km_img_scan
    mov  eax, dword [rsi + E_LFANEW_OFFSET]
    cmp  eax, MAX_E_LFANEW
    ja   km_img_scan
    mov  rdx, rsi
    add  rdx, rax
    cmp  dword [rdx], PE_SIG
    jnz  km_img_scan

    mov  r14, rsi                        ; R14 = driver image base

    mov  eax, dword [rsi + E_LFANEW_OFFSET]
    add  rax, rsi                        ; NT headers VA
    mov  eax, dword [rax + NT64_IMPORT_DIR_RVA]
    test eax, eax
    jz   km_done
    add  rax, r14
    mov  rdi, rax                        ; RDI = IMAGE_IMPORT_DESCRIPTOR cur

km_desc_loop:
    mov  eax, dword [rdi + DESC_DLL_NAME_RVA]
    test eax, eax
    jz   km_done                         ; null descriptor = end of table
    mov  rcx, r14
    add  rcx, rax                        ; RCX = DLL name VA

    ; module gate: first NTKRNL_PREFIX_LEN bytes == "ntoskrnl" (case-insens.)
    xor  r9, r9                          ; byte index
km_gate_cmp:
    mov  al, [rcx + r9]
    or   al, LOWERCASE_BIT
    cmp  al, [r10 + r9]
    jnz  km_desc_next                    ; not ntoskrnl: skip this module
    inc  r9
    cmp  r9, NTKRNL_PREFIX_LEN
    jb   km_gate_cmp

    ; choose INT (OriginalFirstThunk) or fall back to FT (FirstThunk)
    mov  eax, dword [rdi + DESC_INT_RVA]
    test eax, eax
    jz   km_use_ft
    add  rax, r14                        ; RAX = INT VA
    mov  edx, dword [rdi + DESC_FT_RVA]
    add  rdx, r14                        ; RDX = IAT VA
    mov  r15, rdx
    mov  rsi, rax
    jmp  km_thunk_loop

km_use_ft:
    mov  eax, dword [rdi + DESC_FT_RVA]
    add  rax, r14
    mov  rsi, rax                        ; RSI = FT VA (names live in FT too)
    mov  r15, rax                        ; R15 = IAT ptr (same address)

km_thunk_loop:
    mov  rax, [rsi]
    test rax, rax
    jz   km_desc_next                    ; null = end of thunk array
    js   km_by_ordinal                   ; bit 63 set = ordinal import

    ; import by name: RAX = RVA of IMAGE_IMPORT_BY_NAME
    add  rax, r14
    add  rax, IIBN_NAME_OFFSET           ; skip the hint WORD
    mov  rdx, rax                        ; RDX = function name VA
    jmp  km_resolve

km_by_ordinal:
    add  rsi, THUNK_SIZE64
    add  r15, THUNK_SIZE64
    jmp  km_thunk_loop

    ; ---- 4. resolve RDX (NUL-terminated name) inside ntoskrnl exports ----
km_resolve:
    mov  r9d, dword [r11 + EXP_NUMNAMES_RVA]  ; NumberOfNames
    mov  ecx, dword [r11 + EXP_NAMES_RVA]     ; AddressOfNames RVA
    add  rcx, r8                              ; names array VA

km_exp_loop:
    dec  r9
    js   km_desc_next                    ; exhausted: leave slot unresolved
    mov  eax, dword [rcx + r9*4]         ; candidate name RVA
    add  rax, r8                         ; candidate name VA
    mov  r12, rax                        ; R12 = candidate cursor
    mov  r13, rdx                        ; R13 = wanted-name cursor
km_strcmp:
    mov  al, [r12]
    cmp  al, [r13]
    jnz  km_exp_loop                     ; mismatch -> next candidate
    test al, al
    jz   km_exp_hit                      ; matched through the NUL
    inc  r12
    inc  r13
    jmp  km_strcmp

km_exp_hit:
    mov  ecx, dword [r11 + EXP_ORLP_RVA] ; AddressOfNameOrdinals RVA (zero-ext.)
    add   rcx, r8                        ; ordinals array VA
    movzx ecx, word [rcx + r9*2]         ; ordinal (r9 = candidate index)
    mov   edx, dword [r11 + EXP_FUNCS_RVA]
    add   rdx, r8                        ; AddressOfFunctions VA
    mov   eax, dword [rdx + rcx*4]       ; function RVA
    add   rax, r8                        ; function VA
    mov   [r15], rax                     ; write the IAT slot (64-bit)

    add  rsi, THUNK_SIZE64
    add  r15, THUNK_SIZE64
    jmp  km_thunk_loop

km_desc_next:
    add  rdi, DESC_NEXT_PTR
    jmp  km_desc_loop

km_done:
    ret                                  ; terminal bytes stripped by peor

