; x86 (32-bit) kernel-mode import resolver - position-independent shellcode.
; Assembled by keystone (KS_ARCH_X86 / KS_MODE_32 / KS_OPT_SYNTAX_NASM).
;
; Same algorithm as imports_resolver64_km.asm (see its header for the full
; description): SIDT -> IDT gate 0 -> backward MZ scan for ntoskrnl, forward
; MZ scan for this driver, then every "ntoskrnl"-prefixed import is resolved
; by walking ntoskrnl's export table and writing the absolute address into
; the IAT slot. Runs after the 4-push callee-save prologue (EBX/EBP/ESI/EDI,
; restored by entrypoint_resolver_km32) and falls through into
; relocations_resolver32 (which overwrites EBX with the PE base).
;
; Register map (persistent):
;   EBP = ntoskrnl image base
;   ECX = ntoskrnl export directory VA
;   EDX = "ntoskrnl" needle pointer (module-name gate)
;   EDI = current IMAGE_IMPORT_DESCRIPTOR pointer
;   ESI = current INT/FT walk pointer
;   EBX = current IAT slot pointer
;   EAX = scratch
;
; The per-thunk resolve loop keeps its own state in a small [ESP]-relative
; stack frame (32-bit registers are too few otherwise).
;
; Keystone notes:
;   - SIDT works unprivileged and reads the CPU IDTR, so no FS-segment or
;     KPCR layout knowledge is needed.
;   - "js near label" not supported: use bare "js label".

%define MZ_SIG               0x5A4D      ; 'MZ'
%define PE_SIG               0x00004550  ; "PE\0\0"
%define E_LFANEW_OFFSET      0x3C        ; DOS header e_lfanew offset
%define MAX_E_LFANEW         0x400       ; reject false-positive MZ matches
%define PAGE_SIZE            0x1000
%define MAX_BASE_SCAN_PAGES  0x0800      ; backward MZ scan guard (pages)
%define NT32_EXPORT_DIR_RVA  0x78        ; PE32: NT headers + 0x78 = DataDir[0]
%define NT32_IMPORT_DIR_RVA  0x80        ; PE32: NT headers + 0x80 = DataDir[1]
%define EXP_NUMNAMES_RVA     0x18        ; export dir: NumberOfNames
%define EXP_FUNCS_RVA        0x1C        ; export dir: AddressOfFunctions
%define EXP_NAMES_RVA        0x20        ; export dir: AddressOfNames
%define EXP_ORLP_RVA         0x24        ; export dir: AddressOfNameOrdinals
%define IDT32_GATE_SIZE      0x08
%define GATE_LOW_OFF         0x00        ; gate: handler offset bits [15:0]
%define GATE_HIGH_OFF        0x06        ; gate: handler offset bits [31:16]
%define DESC_NEXT_PTR        0x14        ; sizeof(IMAGE_IMPORT_DESCRIPTOR)
%define DESC_DLL_NAME_RVA    0x0C        ; desc: Name (RVA)
%define DESC_INT_RVA         0x00        ; desc: OriginalFirstThunk
%define DESC_FT_RVA          0x10        ; desc: FirstThunk
%define THUNK_SIZE32         0x04
%define IIBN_NAME_OFFSET     0x02        ; IMAGE_IMPORT_BY_NAME: hint WORD, name
%define NTKRNL_PREFIX_LEN    0x08        ; len("ntoskrnl")
%define LOWERCASE_BLOCK      0x20202020  ; lowercases 4 bytes at once

%define KM32_LOCAL_IDX       0x00        ; [esp+0x00] = candidate index counter
%define KM32_LOCAL_NAMES     0x04        ; [esp+0x04] = AddressOfNames array VA
%define KM32_LOCAL_WANTED    0x08        ; [esp+0x08] = wanted import name VA
%define KM32_LOCAL_EXPDIR    0x0C        ; [esp+0x0C] = ntoskrnl export dir VA
%define KM32_LOCAL_SIZE      0x10
%define KM32_SAVED_EBX       0x10        ; after SUB ESP: EBX/ESI/EDI pushed below
%define KM32_SAVED_ESI       0x14
%define KM32_SAVED_EDI       0x18

    ; ---- 1. SIDT -> IDT base ----
    sub  esp, KM32_LOCAL_SIZE
    sidt [esp]
    mov  eax, [esp + 0x02]               ; IDTR base field
    add  esp, KM32_LOCAL_SIZE

    ; ---- 2. ntoskrnl base from IDT gate 0's handler ----
    movzx edx, word [eax + GATE_LOW_OFF]
    movzx ecx, word [eax + GATE_HIGH_OFF]
    shl   ecx, 0x10
    or    edx, ecx                       ; EDX = handler VA (inside ntoskrnl)
    and   edx, 0xFFFFF000                ; page align
    mov   ebp, edx                       ; EBP = scan pointer

    call _prefix_str
    db 'n','t','o','s','k','r','n','l'
_prefix_str:
    pop  edx                             ; EDX = "ntoskrnl" needle

    xor  ecx, ecx                        ; page counter
km_base_scan:
    cmp  word [ebp], MZ_SIG
    jnz  km_base_next
    mov  eax, dword [ebp + E_LFANEW_OFFSET]
    cmp  eax, MAX_E_LFANEW
    ja   km_base_next
    mov  ebx, ebp
    add  ebx, eax                        ; NT headers VA
    cmp  dword [ebx], PE_SIG
    jz   km_base_found
km_base_next:
    sub  ebp, PAGE_SIZE
    inc  ecx
    cmp  ecx, MAX_BASE_SCAN_PAGES
    jb   km_base_scan

    ; ntoskrnl not found: leave all imports unresolved, continue the chain.
    jmp  km_done

km_base_found:
    mov  eax, dword [ebp + E_LFANEW_OFFSET]
    add  eax, ebp                        ; NT headers VA
    mov  eax, dword [eax + NT32_EXPORT_DIR_RVA]
    test eax, eax
    jz   km_done                         ; ntoskrnl without exports: bail
    add  eax, ebp
    mov  ecx, eax                        ; ECX = export dir VA

    ; ---- 3. forward scan for this driver's image ----
    call _here
_here:
    pop  esi                             ; ESI = runtime address of this pop

km_img_scan:
    inc  esi
    cmp  word [esi], MZ_SIG
    jnz  km_img_scan
    mov  eax, dword [esi + E_LFANEW_OFFSET]
    cmp  eax, MAX_E_LFANEW
    ja   km_img_scan
    mov  ebx, esi
    add  ebx, eax                        ; NT headers VA
    ; NOTE: EBX is free scratch here; relocations_resolver32 re-owns it later.
    cmp  dword [ebx], PE_SIG
    jnz  km_img_scan

    mov  edi, esi                        ; EDI = driver image base

    mov  eax, dword [esi + E_LFANEW_OFFSET]
    add  eax, esi                        ; NT headers VA
    mov  eax, dword [eax + NT32_IMPORT_DIR_RVA]
    test eax, eax
    jz   km_done
    add  eax, edi
    mov  edi, eax                        ; EDI = IMAGE_IMPORT_DESCRIPTOR cur

km_desc_loop:
    mov  eax, dword [edi + DESC_DLL_NAME_RVA]
    test eax, eax
    jz   km_done                         ; null descriptor = end of table
    mov  ebx, edi
    add  ebx, eax                        ; EBX = DLL name VA (guard: NTOS only)

    ; module gate: first NTKRNL_PREFIX_LEN bytes == "ntoskrnl" (case-insens.),
    ; as two 4-byte compares with LOWERCASE_BLOCK as the lowercase mask. A NUL
    ; (shorter name) lowcased to 0x20 never matches "ntoskrnl" bytes.
    mov  eax, dword [ebx]
    or   eax, LOWERCASE_BLOCK
    cmp  eax, dword [edx]
    jnz  km_desc_next                    ; not ntoskrnl: skip this module
    mov  eax, dword [ebx + 0x04]
    or   eax, LOWERCASE_BLOCK
    cmp  eax, dword [edx + 0x04]
    jnz  km_desc_next

    ; choose INT (OriginalFirstThunk) or fall back to FT (FirstThunk)
    mov  eax, dword [edi + DESC_INT_RVA]
    test eax, eax
    jz   km_use_ft
    add  eax, edi                        ; EAX = INT VA
    mov  esi, eax
    mov  eax, dword [edi + DESC_FT_RVA]
    add  eax, edi                        ; EAX = IAT VA
    mov  ebx, eax
    jmp  km_thunk_loop

km_use_ft:
    mov  eax, dword [edi + DESC_FT_RVA]
    add  eax, edi
    mov  esi, eax                        ; ESI = FT VA (names live in FT too)
    mov  ebx, eax                        ; EBX = IAT ptr (same address)

km_thunk_loop:
    mov  eax, dword [esi]
    test eax, eax
    jz   km_desc_next                    ; null = end of thunk array
    js   km_by_ordinal                   ; bit 31 set = ordinal import

    ; import by name: EAX = RVA of IMAGE_IMPORT_BY_NAME
    add  eax, edi
    add  eax, IIBN_NAME_OFFSET           ; skip the hint WORD
    jmp  km_resolve                      ; EAX = wanted import name VA

km_by_ordinal:
    add  esi, THUNK_SIZE32
    add  ebx, THUNK_SIZE32
    jmp  km_thunk_loop

    ; ---- 4. resolve EAX (NUL-terminated name) inside ntoskrnl exports ----
km_resolve:
    push ebx                             ; KM32_SAVED_EBX  (IAT slot ptr)
    push esi                             ; KM32_SAVED_ESI  (thunk walk ptr)
    push edi                             ; KM32_SAVED_EDI  (desc ptr)
    sub  esp, KM32_LOCAL_SIZE
    mov  dword [esp + KM32_LOCAL_WANTED], eax

    ; export dir base from the persistent ntoskrnl base (EBP)
    mov  eax, dword [ebp + E_LFANEW_OFFSET]
    add  eax, ebp
    mov  eax, dword [eax + NT32_EXPORT_DIR_RVA]
    test eax, eax
    jz   km_no_resolve
    add  eax, ebp
    mov  dword [esp + KM32_LOCAL_EXPDIR], eax
    mov  edx, dword [eax + EXP_NUMNAMES_RVA]   ; idx counter = NumberOfNames
    mov  ecx, dword [eax + EXP_NAMES_RVA]
    add  ecx, ebp                              ; ECX = names array VA
    mov  dword [esp + KM32_LOCAL_NAMES], ecx

km_exp_loop:
    mov  edx, dword [esp + KM32_LOCAL_IDX]
    dec  edx
    mov  dword [esp + KM32_LOCAL_IDX], edx
    js   km_no_resolve                   ; exhausted: leave slot unresolved
    mov  ecx, dword [esp + KM32_LOCAL_NAMES]
    mov  eax, dword [ecx + edx*4]        ; candidate name RVA
    add  eax, ebp                        ; candidate name VA
    mov  ecx, dword [esp + KM32_LOCAL_WANTED]
    ; EAX = candidate cursor, ECX = wanted cursor
km_strcmp:
    mov  dl, [eax]
    cmp  dl, [ecx]
    jnz  km_exp_loop                     ; mismatch -> next candidate
    test dl, dl
    jz   km_exp_hit                      ; matched through the NUL
    inc  eax
    inc  ecx
    jmp  km_strcmp

km_exp_hit:
    mov  edx, dword [esp + KM32_LOCAL_IDX]
    mov  eax, dword [esp + KM32_LOCAL_EXPDIR]
    mov  ecx, dword [eax + EXP_ORLP_RVA]
    add  ecx, ebp                        ; ordinals array VA
    movzx edx, word [ecx + edx*2]        ; ordinal
    mov  eax, dword [esp + KM32_LOCAL_EXPDIR]
    mov  ecx, dword [eax + EXP_FUNCS_RVA]
    add  ecx, ebp                        ; AddressOfFunctions VA
    mov  eax, dword [ecx + edx*4]        ; function RVA
    add  eax, ebp                        ; function VA
    mov  ebx, dword [esp + KM32_SAVED_EBX]
    mov  dword [ebx], eax                ; write the IAT slot (32-bit)
    jmp  km_thunk_next

km_no_resolve:
    add  esp, KM32_LOCAL_SIZE
    pop  edi
    pop  esi
    pop  ebx
    jmp  km_thunk_next_skip

km_thunk_next:
    add  esp, KM32_LOCAL_SIZE
    pop  edi
    pop  esi
    pop  ebx

km_thunk_next_skip:
    add  esi, THUNK_SIZE32
    add  ebx, THUNK_SIZE32
    jmp  km_thunk_loop

km_desc_next:
    add  edi, DESC_NEXT_PTR
    jmp  km_desc_loop

km_done:
    ret                                  ; terminal bytes stripped by peor

