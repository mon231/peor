; imports_resolver32_km.asm
; x86 kernelmode import resolver

.model flat, stdcall
option casemap:none

; Windows kernel structures
PsLoadedModuleList EQU 0  ; This will be patched at runtime with the actual address

KLDR_DATA_TABLE_ENTRY STRUCT
    InLoadOrderLinks          QWORD ?
    ExceptionTable           DWORD ?
    ExceptionTableSize       DWORD ?
    GpValue                  DWORD ?
    NonPagedDebugInfo        DWORD ?
    DllBase                  DWORD ?
    EntryPoint               DWORD ?
    SizeOfImage              DWORD ?
    FullDllName              BYTE 256 DUP(?)
    BaseDllName              BYTE 32 DUP(?)
    Flags                    DWORD ?
    LoadCount                WORD ?
    TlsIndex                 WORD ?
    HashLinks                QWORD ?
    SectionPointer           DWORD ?
    CheckSum                 DWORD ?
    TimeDateStamp            DWORD ?
    LoadedImports            DWORD ?
    EntryPointActivationContext DWORD ?
    PatchInformation         DWORD ?
    ForwarderLinks           QWORD ?
    ServiceTagLinks          QWORD ?
    StaticLinks              QWORD ?
    ContextInformation       DWORD ?
    OriginalBase             DWORD ?
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

IMAGE_OPTIONAL_HEADER32 STRUCT
    Magic                    WORD ?
    MajorLinkerVersion       BYTE ?
    MinorLinkerVersion       BYTE ?
    SizeOfCode               DWORD ?
    SizeOfInitializedData    DWORD ?
    SizeOfUninitializedData  DWORD ?
    AddressOfEntryPoint      DWORD ?
    BaseOfCode               DWORD ?
    BaseOfData               DWORD ?
    ImageBase                DWORD ?
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
    SizeOfStackReserve       DWORD ?
    SizeOfStackCommit        DWORD ?
    SizeOfHeapReserve        DWORD ?
    SizeOfHeapCommit         DWORD ?
    LoaderFlags              DWORD ?
    NumberOfRvaAndSizes      DWORD ?
    DataDirectory            IMAGE_DATA_DIRECTORY 16 DUP(<>)
IMAGE_OPTIONAL_HEADER32 ENDS

IMAGE_NT_HEADERS32 STRUCT
    Signature                DWORD ?
    FileHeader               IMAGE_FILE_HEADER <>
    OptionalHeader           IMAGE_OPTIONAL_HEADER32 <>
IMAGE_NT_HEADERS32 ENDS

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
start:
    ; Save registers
    pushad
    
    ; Get current address
    call    get_eip
get_eip:
    pop     ebx
    sub     ebx, offset get_eip
    
    ; Find ntoskrnl.exe in loaded module list
    mov     esi, [PsLoadedModuleList]  ; This will be patched with actual address
    
find_ntoskrnl:
    ; Get module base
    mov     eax, [esi + KLDR_DATA_TABLE_ENTRY.DllBase]
    
    ; Check if this is ntoskrnl.exe
    lea     edi, [esi + KLDR_DATA_TABLE_ENTRY.BaseDllName]
    push    eax                         ; Save module base
    
    ; Compare with "ntoskrnl.exe" (case insensitive)
    ; This is a simplified check - in real code, do a proper string comparison
    mov     eax, 'ntso'
    cmp     dword ptr [edi], eax
    jne     next_module
    
    mov     eax, 'krnl'
    cmp     dword ptr [edi + 4], eax
    jne     next_module
    
    ; Found ntoskrnl.exe
    pop     eax                         ; Restore module base
    jmp     found_ntoskrnl
    
next_module:
    pop     eax                         ; Restore module base
    mov     esi, [esi + KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks]
    sub     esi, KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks
    cmp     esi, [PsLoadedModuleList]   ; Check if we've gone full circle
    jne     find_ntoskrnl
    jmp     exit                        ; Not found, exit
    
found_ntoskrnl:
    ; eax contains ntoskrnl.exe base address
    
    ; Check MZ signature
    cmp     word ptr [eax], MZ_SIGNATURE
    jne     exit
    
    ; Get PE header
    mov     esi, [eax + IMAGE_DOS_HEADER.e_lfanew]
    add     esi, eax                    ; esi = PE header address
    
    ; Check PE signature
    cmp     dword ptr [esi], PE_SIGNATURE
    jne     exit
    
    ; Get export directory
    mov     edi, [esi + IMAGE_NT_HEADERS32.OptionalHeader.DataDirectory + \
                 (IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof IMAGE_DATA_DIRECTORY).VirtualAddress]
    add     edi, eax                    ; edi = Export directory address
    
    ; Get function addresses
    mov     ecx, [edi + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
    add     ecx, eax                    ; ecx = Function addresses array
    
    ; Get function names
    mov     edx, [edi + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
    add     edx, eax                    ; edx = Function names array
    
    ; Get function ordinals
    mov     esi, [edi + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
    add     esi, eax                    ; esi = Function ordinals array
    
    ; Find MmGetSystemRoutineAddress
    xor     ebp, ebp                    ; Initialize counter
    mov     edi, [edi + IMAGE_EXPORT_DIRECTORY.NumberOfNames]
    
find_mmgetsystemroutineaddress:
    cmp     ebp, edi
    jge     exit                        ; Not found, exit
    
    ; Get function name RVA
    mov     edx, [edx + ebp*4]
    add     edx, eax                    ; edx = Function name string
    
    ; Check if this is MmGetSystemRoutineAddress
    ; This is a simplified check - in real code, do a proper string comparison
    cmp     dword ptr [edx], 'MmGe'
    jne     next_function
    
    cmp     dword ptr [edx + 4], 'tSys'
    jne     next_function
    
    cmp     dword ptr [edx + 8], 'temR'
    jne     next_function
    
    ; Found MmGetSystemRoutineAddress
    ; Get its ordinal
    movzx   esi, word ptr [esi + ebp*2]
    
    ; Get function address
    mov     ecx, [ecx + esi*4]
    add     ecx, eax                    ; ecx = MmGetSystemRoutineAddress
    
    ; Store MmGetSystemRoutineAddress
    mov     [ebx + offset MmGetSystemRoutineAddress], ecx
    
    ; Process imports
    ; Get import directory
    mov     eax, [ebx + offset IMAGE_NT_HEADERS32.OptionalHeader.DataDirectory + \
                 (IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof IMAGE_DATA_DIRECTORY).VirtualAddress]
    add     eax, ebx                    ; eax = Import directory address
    
    ; Process each import descriptor
process_imports:
    mov     ecx, [eax + IMAGE_IMPORT_DESCRIPTOR.Name]
    test    ecx, ecx
    jz      exit                        ; End of import descriptors
    
    ; Get DLL name
    add     ecx, ebx                    ; ecx = DLL name
    
    ; Create UNICODE_STRING for module name
    push    eax                         ; Save import descriptor
    sub     esp, 8                      ; Allocate UNICODE_STRING
    mov     eax, esp
    
    ; Fill in UNICODE_STRING
    push    ecx                         ; Save module name
    
    ; Calculate string length
    mov     edi, ecx
    xor     al, al
    mov     ecx, -1
    repne   scasb
    not     ecx
    dec     ecx                         ; ecx = string length
    
    pop     edi                         ; Restore module name
    
    ; Convert to Unicode
    push    edi                         ; Save module name
    sub     esp, ecx*2                  ; Allocate Unicode buffer
    mov     esi, esp
    
    ; Fill Unicode buffer
    xor     eax, eax
convert_loop:
    lodsb
    stosw
    loop    convert_loop
    
    ; Set UNICODE_STRING fields
    pop     ecx                         ; Restore module name length
    shl     ecx, 1                      ; Convert to bytes
    mov     [eax], cx                   ; Length
    mov     [eax+2], cx                 ; MaximumLength
    mov     [eax+4], esp                ; Buffer
    
    ; Call MmGetSystemRoutineAddress
    push    eax                         ; UNICODE_STRING
    call    [ebx + offset MmGetSystemRoutineAddress]
    add     esp, 8                      ; Clean up UNICODE_STRING
    
    ; Process each import
    pop     eax                         ; Restore import descriptor
    mov     ecx, [eax + IMAGE_IMPORT_DESCRIPTOR.FirstThunk]
    add     ecx, ebx                    ; ecx = Import Address Table
    
    mov     edx, [eax + IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk]
    test    edx, edx
    jz      use_first_thunk
    add     edx, ebx                    ; edx = Import Name Table
    jmp     process_thunks
    
use_first_thunk:
    mov     edx, ecx                    ; Use FirstThunk as Import Name Table
    
process_thunks:
    mov     esi, [edx]                  ; Get next thunk
    add     edx, 4
    test    esi, esi
    jz      next_descriptor             ; End of thunks
    
    ; Check if import by ordinal
    test    esi, 80000000h
    jnz     import_by_ordinal
    
    ; Import by name
    add     esi, ebx                    ; esi = Import name
    add     esi, 2                      ; Skip hint
    jmp     resolve_import
    
import_by_ordinal:
    and     esi, 7FFFFFFFh              ; Clear ordinal flag
    
resolve_import:
    ; Create UNICODE_STRING for function name
    sub     esp, 8                      ; Allocate UNICODE_STRING
    mov     eax, esp
    
    ; Fill in UNICODE_STRING
    push    esi                         ; Save function name
    
    ; Calculate string length
    mov     edi, esi
    xor     al, al
    mov     ecx, -1
    repne   scasb
    not     ecx
    dec     ecx                         ; ecx = string length
    
    pop     edi                         ; Restore function name
    
    ; Convert to Unicode
    push    edi                         ; Save function name
    sub     esp, ecx*2                  ; Allocate Unicode buffer
    mov     esi, esp
    
    ; Fill Unicode buffer
    xor     eax, eax
convert_func_loop:
    lodsb
    stosw
    loop    convert_func_loop
    
    ; Set UNICODE_STRING fields
    pop     ecx                         ; Restore function name length
    shl     ecx, 1                      ; Convert to bytes
    mov     [eax], cx                   ; Length
    mov     [eax+2], cx                 ; MaximumLength
    mov     [eax+4], esp                ; Buffer
    
    ; Call MmGetSystemRoutineAddress
    push    eax                         ; UNICODE_STRING
    call    [ebx + offset MmGetSystemRoutineAddress]
    add     esp, 8                      ; Clean up UNICODE_STRING
    
    ; Store function address in IAT
    mov     [ecx], eax
    add     ecx, 4
    jmp     process_thunks
    
next_descriptor:
    add     eax, sizeof IMAGE_IMPORT_DESCRIPTOR
    jmp     process_imports
    
next_function:
    inc     ebp
    jmp     find_mmgetsystemroutineaddress
    
exit:
    ; Restore registers and return
    popad
    ret
    
; Data section
MmGetSystemRoutineAddress dd 0

end start
