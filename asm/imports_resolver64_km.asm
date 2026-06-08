; imports_resolver64_km.asm
; x64 kernelmode import resolver

option casemap:none

; Windows kernel structures
PsLoadedModuleList EQU 0  ; This will be patched at runtime with the actual address

KLDR_DATA_TABLE_ENTRY STRUCT
    InLoadOrderLinks          QWORD ?
    _Padding                  QWORD ?
    ExceptionTable           QWORD ?
    ExceptionTableSize       QWORD ?
    GpValue                  QWORD ?
    NonPagedDebugInfo        QWORD ?
    DllBase                  QWORD ?
    EntryPoint               QWORD ?
    SizeOfImage              QWORD ?
    FullDllName              BYTE 512 DUP(?)
    BaseDllName              BYTE 64 DUP(?)
    Flags                    DWORD ?
    LoadCount                WORD ?
    TlsIndex                 WORD ?
    HashLinks                QWORD 2 DUP(?)
    SectionPointer           QWORD ?
    CheckSum                 DWORD ?
    TimeDateStamp            DWORD ?
    LoadedImports            QWORD ?
    EntryPointActivationContext QWORD ?
    PatchInformation         QWORD ?
    ForwarderLinks           QWORD 2 DUP(?)
    ServiceTagLinks          QWORD 2 DUP(?)
    StaticLinks              QWORD 2 DUP(?)
    ContextInformation       QWORD ?
    OriginalBase             QWORD ?
    LoadTime                 QWORD ?
KLDR_DATA_TABLE_ENTRY ENDS

IMAGE_DOS_HEADER STRUCT
    e_magic                  WORD ?
    e_cblp                   WORD ?
    e_cp                     WORD ?
    e_crlc                   WORD ?
    e_cparhdr                WORD ?
    e_minalloc               WORD ?
    e_maxalloc               WORD ?
    e_ss                     WORD ?
    e_sp                     WORD ?
    e_csum                   WORD ?
    e_ip                     WORD ?
    e_cs                     WORD ?
    e_lfarlc                 WORD ?
    e_ovno                   WORD ?
    e_res                    WORD 4 DUP(?)
    e_oemid                  WORD ?
    e_oeminfo                WORD ?
    e_res2                   WORD 10 DUP(?)
    e_lfanew                 DWORD ?
IMAGE_DOS_HEADER ENDS

IMAGE_FILE_HEADER STRUCT
    Machine                  WORD ?
    NumberOfSections         WORD ?
    TimeDateStamp            DWORD ?
    PointerToSymbolTable     DWORD ?
    NumberOfSymbols          DWORD ?
    SizeOfOptionalHeader     WORD ?
    Characteristics          WORD ?
IMAGE_FILE_HEADER ENDS

IMAGE_DATA_DIRECTORY STRUCT
    VirtualAddress           DWORD ?
    Size                     DWORD ?
IMAGE_DATA_DIRECTORY ENDS

IMAGE_OPTIONAL_HEADER64 STRUCT
    Magic                    WORD ?
    MajorLinkerVersion       BYTE ?
    MinorLinkerVersion       BYTE ?
    SizeOfCode               DWORD ?
    SizeOfInitializedData    DWORD ?
    SizeOfUninitializedData  DWORD ?
    AddressOfEntryPoint      DWORD ?
    BaseOfCode               DWORD ?
    ImageBase                QWORD ?
    SectionAlignment         DWORD ?
    FileAlignment            DWORD ?
    MajorOperatingSystemVersion WORD ?
    MinorOperatingSystemVersion WORD ?
    MajorImageVersion        WORD ?
    MinorImageVersion        WORD ?
    MajorSubsystemVersion    WORD ?
    MinorSubsystemVersion    WORD ?
    Win32VersionValue        DWORD ?
    SizeOfImage              DWORD ?
    SizeOfHeaders            DWORD ?
    CheckSum                 DWORD ?
    Subsystem                WORD ?
    DllCharacteristics       WORD ?
    SizeOfStackReserve       QWORD ?
    SizeOfStackCommit        QWORD ?
    SizeOfHeapReserve        QWORD ?
    SizeOfHeapCommit         QWORD ?
    LoaderFlags              DWORD ?
    NumberOfRvaAndSizes      DWORD ?
    DataDirectory            IMAGE_DATA_DIRECTORY 16 DUP(<>)
IMAGE_OPTIONAL_HEADER64 ENDS

IMAGE_NT_HEADERS64 STRUCT
    Signature                DWORD ?
    FileHeader               IMAGE_FILE_HEADER <>
    OptionalHeader           IMAGE_OPTIONAL_HEADER64 <>
IMAGE_NT_HEADERS64 ENDS

IMAGE_EXPORT_DIRECTORY STRUCT
    Characteristics          DWORD ?
    TimeDateStamp            DWORD ?
    MajorVersion             WORD ?
    MinorVersion             WORD ?
    Name                     DWORD ?
    Base                     DWORD ?
    NumberOfFunctions        DWORD ?
    NumberOfNames            DWORD ?
    AddressOfFunctions       DWORD ?
    AddressOfNames           DWORD ?
    AddressOfNameOrdinals    DWORD ?
IMAGE_EXPORT_DIRECTORY ENDS

IMAGE_IMPORT_DESCRIPTOR STRUCT
    OriginalFirstThunk       DWORD ?
    TimeDateStamp            DWORD ?
    ForwarderChain           DWORD ?
    Name                     DWORD ?
    FirstThunk               DWORD ?
IMAGE_IMPORT_DESCRIPTOR ENDS

; Constants
IMAGE_DIRECTORY_ENTRY_EXPORT     EQU 0
IMAGE_DIRECTORY_ENTRY_IMPORT     EQU 1
MZ_SIGNATURE                     EQU 5A4Dh
PE_SIGNATURE                     EQU 00004550h

.code
start PROC
    ; Save registers
    push    rbp
    mov     rbp, rsp
    sub     rsp, 80h
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    
    ; Get current address
    lea     rbx, start
    
    ; Find ntoskrnl.exe in loaded module list
    mov     rsi, [PsLoadedModuleList]  ; This will be patched with actual address
    
find_ntoskrnl:
    ; Get module base
    mov     rax, [rsi + KLDR_DATA_TABLE_ENTRY.DllBase]
    
    ; Check if this is ntoskrnl.exe
    lea     rdi, [rsi + KLDR_DATA_TABLE_ENTRY.BaseDllName]
    push    rax                         ; Save module base
    
    ; Compare with "ntoskrnl.exe" (case insensitive)
    ; This is a simplified check - in real code, do a proper string comparison
    mov     eax, 'ntso'
    cmp     dword ptr [rdi], eax
    jne     next_module
    
    mov     eax, 'krnl'
    cmp     dword ptr [rdi + 4], eax
    jne     next_module
    
    ; Found ntoskrnl.exe
    pop     rax                         ; Restore module base
    jmp     found_ntoskrnl
    
next_module:
    pop     rax                         ; Restore module base
    mov     rsi, [rsi + KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks]
    sub     rsi, KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks
    cmp     rsi, [PsLoadedModuleList]   ; Check if we've gone full circle
    jne     find_ntoskrnl
    jmp     exit                        ; Not found, exit
    
found_ntoskrnl:
    ; rax contains ntoskrnl.exe base address
    
    ; Check MZ signature
    cmp     word ptr [rax], MZ_SIGNATURE
    jne     exit
    
    ; Get PE header
    mov     esi, [rax + IMAGE_DOS_HEADER.e_lfanew]
    add     rsi, rax                    ; rsi = PE header address
    
    ; Check PE signature
    cmp     dword ptr [rsi], PE_SIGNATURE
    jne     exit
    
    ; Get export directory
    mov     edi, [rsi + IMAGE_NT_HEADERS64.OptionalHeader.DataDirectory + \
                 (IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof IMAGE_DATA_DIRECTORY).VirtualAddress]
    add     rdi, rax                    ; rdi = Export directory address
    
    ; Get function addresses
    mov     r12d, [rdi + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
    add     r12, rax                    ; r12 = Function addresses array
    
    ; Get function names
    mov     r13d, [rdi + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
    add     r13, rax                    ; r13 = Function names array
    
    ; Get function ordinals
    mov     r14d, [rdi + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
    add     r14, rax                    ; r14 = Function ordinals array
    
    ; Find MmGetSystemRoutineAddress
    xor     r15, r15                    ; Initialize counter
    mov     r8d, [rdi + IMAGE_EXPORT_DIRECTORY.NumberOfNames]
    
find_mmgetsystemroutineaddress:
    cmp     r15, r8
    jge     exit                        ; Not found, exit
    
    ; Get function name RVA
    mov     r9d, [r13 + r15*4]
    add     r9, rax                     ; r9 = Function name string
    
    ; Check if this is MmGetSystemRoutineAddress
    ; This is a simplified check - in real code, do a proper string comparison
    cmp     dword ptr [r9], 'MmGe'
    jne     next_function
    
    cmp     dword ptr [r9 + 4], 'tSys'
    jne     next_function
    
    cmp     dword ptr [r9 + 8], 'temR'
    jne     next_function
    
    ; Found MmGetSystemRoutineAddress
    ; Get its ordinal
    movzx   r10w, word ptr [r14 + r15*2]
    
    ; Get function address
    mov     r11d, [r12 + r10*4]
    add     r11, rax                    ; r11 = MmGetSystemRoutineAddress
    
    ; Store MmGetSystemRoutineAddress
    lea     rax, MmGetSystemRoutineAddress
    mov     [rax], r11
    
    ; Process imports
    ; Get import directory
    mov     eax, [rbx + IMAGE_NT_HEADERS64.OptionalHeader.DataDirectory + \
                 (IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof IMAGE_DATA_DIRECTORY).VirtualAddress]
    add     rax, rbx                    ; rax = Import directory address
    
    ; Process each import descriptor
process_imports:
    mov     ecx, [rax + IMAGE_IMPORT_DESCRIPTOR.Name]
    test    ecx, ecx
    jz      exit                        ; End of import descriptors
    
    ; Get DLL name
    add     rcx, rbx                    ; rcx = DLL name
    
    ; Create UNICODE_STRING for module name
    push    rax                         ; Save import descriptor
    sub     rsp, 16                     ; Allocate UNICODE_STRING
    mov     rax, rsp
    
    ; Fill in UNICODE_STRING
    push    rcx                         ; Save module name
    
    ; Calculate string length
    mov     rdi, rcx
    xor     al, al
    mov     rcx, -1
    repne   scasb
    not     rcx
    dec     rcx                         ; rcx = string length
    
    pop     rdi                         ; Restore module name
    
    ; Convert to Unicode
    push    rdi                         ; Save module name
    sub     rsp, rcx*2                  ; Allocate Unicode buffer
    mov     rsi, rsp
    
    ; Fill Unicode buffer
    xor     eax, eax
convert_loop:
    lodsb
    stosw
    loop    convert_loop
    
    ; Set UNICODE_STRING fields
    pop     rcx                         ; Restore module name length
    shl     rcx, 1                      ; Convert to bytes
    mov     [rax], cx                   ; Length
    mov     [rax+2], cx                 ; MaximumLength
    mov     [rax+8], rsp                ; Buffer
    
    ; Call MmGetSystemRoutineAddress
    mov     rcx, rax                    ; UNICODE_STRING
    lea     rax, MmGetSystemRoutineAddress
    call    qword ptr [rax]
    add     rsp, 16                     ; Clean up UNICODE_STRING
    
    ; Process each import
    pop     rax                         ; Restore import descriptor
    mov     ecx, [rax + IMAGE_IMPORT_DESCRIPTOR.FirstThunk]
    add     rcx, rbx                    ; rcx = Import Address Table
    
    mov     edx, [rax + IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk]
    test    edx, edx
    jz      use_first_thunk
    add     rdx, rbx                    ; rdx = Import Name Table
    jmp     process_thunks
    
use_first_thunk:
    mov     rdx, rcx                    ; Use FirstThunk as Import Name Table
    
process_thunks:
    mov     rsi, [rdx]                  ; Get next thunk
    add     rdx, 8
    test    rsi, rsi
    jz      next_descriptor             ; End of thunks
    
    ; Check if import by ordinal
    test    rsi, 8000000000000000h
    jnz     import_by_ordinal
    
    ; Import by name
    add     rsi, rbx                    ; rsi = Import name
    add     rsi, 2                      ; Skip hint
    jmp     resolve_import
    
import_by_ordinal:
    and     rsi, 7FFFFFFFFFFFFFFFh      ; Clear ordinal flag
    
resolve_import:
    ; Create UNICODE_STRING for function name
    sub     rsp, 16                     ; Allocate UNICODE_STRING
    mov     rax, rsp
    
    ; Fill in UNICODE_STRING
    push    rsi                         ; Save function name
    
    ; Calculate string length
    mov     rdi, rsi
    xor     al, al
    mov     rcx, -1
    repne   scasb
    not     rcx
    dec     rcx                         ; rcx = string length
    
    pop     rdi                         ; Restore function name
    
    ; Convert to Unicode
    push    rdi                         ; Save function name
    sub     rsp, rcx*2                  ; Allocate Unicode buffer
    mov     rsi, rsp
    
    ; Fill Unicode buffer
    xor     eax, eax
convert_func_loop:
    lodsb
    stosw
    loop    convert_func_loop
    
    ; Set UNICODE_STRING fields
    pop     rcx                         ; Restore function name length
    shl     rcx, 1                      ; Convert to bytes
    mov     [rax], cx                   ; Length
    mov     [rax+2], cx                 ; MaximumLength
    mov     [rax+8], rsp                ; Buffer
    
    ; Call MmGetSystemRoutineAddress
    mov     rcx, rax                    ; UNICODE_STRING
    lea     rax, MmGetSystemRoutineAddress
    call    qword ptr [rax]
    add     rsp, 16                     ; Clean up UNICODE_STRING
    
    ; Store function address in IAT
    mov     [rcx], rax
    add     rcx, 8
    jmp     process_thunks
    
next_descriptor:
    add     rax, sizeof IMAGE_IMPORT_DESCRIPTOR
    jmp     process_imports
    
next_function:
    inc     r15
    jmp     find_mmgetsystemroutineaddress
    
exit:
    ; Restore registers and return
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    add     rsp, 80h
    pop     rbp
    ret
start ENDP

; Data section
MmGetSystemRoutineAddress DQ 0

END
