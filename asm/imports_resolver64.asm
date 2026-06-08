; imports_resolver64.asm
; x64 import resolver using MASM syntax and Windows API structs

; Windows structures
LIST_ENTRY64 STRUCT
    Flink   QWORD ?
    Blink   QWORD ?
LIST_ENTRY64 ENDS

UNICODE_STRING64 STRUCT
    Length        WORD ?
    MaximumLength WORD ?
    _padding      DWORD ?
    Buffer        QWORD ?
UNICODE_STRING64 ENDS

PEB64 STRUCT
    InheritedAddressSpace    BYTE ?
    ReadImageFileExecOptions BYTE ?
    BeingDebugged            BYTE ?
    BitField                 BYTE ?
    Padding0                 DWORD ?
    Mutant                   QWORD ?
    ImageBaseAddress         QWORD ?
    Ldr                      QWORD ?
    ProcessParameters        QWORD ?
    ; Remaining fields omitted for brevity
PEB64 ENDS

PEB_LDR_DATA64 STRUCT
    Length                          DWORD ?
    Initialized                     DWORD ?
    SsHandle                        QWORD ?
    InLoadOrderModuleList           LIST_ENTRY64 <>
    InMemoryOrderModuleList         LIST_ENTRY64 <>
    InInitializationOrderModuleList LIST_ENTRY64 <>
    EntryInProgress                 QWORD ?
PEB_LDR_DATA64 ENDS

LDR_DATA_TABLE_ENTRY64 STRUCT
    InLoadOrderLinks                LIST_ENTRY64 <>
    InMemoryOrderLinks              LIST_ENTRY64 <>
    InInitializationOrderLinks      LIST_ENTRY64 <>
    DllBase                         QWORD ?
    EntryPoint                      QWORD ?
    SizeOfImage                     QWORD ?
    FullDllName                     UNICODE_STRING64 <>
    BaseDllName                     UNICODE_STRING64 <>
LDR_DATA_TABLE_ENTRY64 ENDS

IMAGE_DOS_HEADER STRUCT
    e_magic    WORD ?
    e_cblp     WORD ?
    e_cp       WORD ?
    e_crlc     WORD ?
    e_cparhdr  WORD ?
    e_minalloc WORD ?
    e_maxalloc WORD ?
    e_ss       WORD ?
    e_sp       WORD ?
    e_csum     WORD ?
    e_ip       WORD ?
    e_cs       WORD ?
    e_lfarlc   WORD ?
    e_ovno     WORD ?
    e_res      WORD 4 DUP(?)
    e_oemid    WORD ?
    e_oeminfo  WORD ?
    e_res2     WORD 10 DUP(?)
    e_lfanew   DWORD ?
IMAGE_DOS_HEADER ENDS

IMAGE_FILE_HEADER STRUCT
    Machine              WORD ?
    NumberOfSections     WORD ?
    TimeDateStamp        DWORD ?
    PointerToSymbolTable DWORD ?
    NumberOfSymbols      DWORD ?
    SizeOfOptionalHeader WORD ?
    Characteristics      WORD ?
IMAGE_FILE_HEADER ENDS

IMAGE_DATA_DIRECTORY STRUCT
    VirtualAddress DWORD ?
    Size           DWORD ?
IMAGE_DATA_DIRECTORY ENDS

IMAGE_OPTIONAL_HEADER64 STRUCT
    Magic                       WORD ?
    MajorLinkerVersion          BYTE ?
    MinorLinkerVersion          BYTE ?
    SizeOfCode                  DWORD ?
    SizeOfInitializedData       DWORD ?
    SizeOfUninitializedData     DWORD ?
    AddressOfEntryPoint         DWORD ?
    BaseOfCode                  DWORD ?
    ImageBase                   QWORD ?
    SectionAlignment            DWORD ?
    FileAlignment               DWORD ?
    MajorOperatingSystemVersion WORD ?
    MinorOperatingSystemVersion WORD ?
    MajorImageVersion           WORD ?
    MinorImageVersion           WORD ?
    MajorSubsystemVersion       WORD ?
    MinorSubsystemVersion       WORD ?
    Win32VersionValue           DWORD ?
    SizeOfImage                 DWORD ?
    SizeOfHeaders               DWORD ?
    CheckSum                    DWORD ?
    Subsystem                   WORD ?
    DllCharacteristics          WORD ?
    SizeOfStackReserve          QWORD ?
    SizeOfStackCommit           QWORD ?
    SizeOfHeapReserve           QWORD ?
    SizeOfHeapCommit            QWORD ?
    LoaderFlags                 DWORD ?
    NumberOfRvaAndSizes         DWORD ?
    DataDirectory               IMAGE_DATA_DIRECTORY 16 DUP(<>)
IMAGE_OPTIONAL_HEADER64 ENDS

IMAGE_NT_HEADERS64 STRUCT
    Signature      DWORD ?
    FileHeader     IMAGE_FILE_HEADER <>
    OptionalHeader IMAGE_OPTIONAL_HEADER64 <>
IMAGE_NT_HEADERS64 ENDS

IMAGE_EXPORT_DIRECTORY STRUCT
    Characteristics       DWORD ?
    TimeDateStamp         DWORD ?
    MajorVersion          WORD ?
    MinorVersion          WORD ?
    Name                  DWORD ?
    Base                  DWORD ?
    NumberOfFunctions     DWORD ?
    NumberOfNames         DWORD ?
    AddressOfFunctions    DWORD ?
    AddressOfNames        DWORD ?
    AddressOfNameOrdinals DWORD ?
IMAGE_EXPORT_DIRECTORY ENDS

IMAGE_IMPORT_DESCRIPTOR STRUCT
    OriginalFirstThunk DWORD ?
    TimeDateStamp      DWORD ?
    ForwarderChain     DWORD ?
    Name               DWORD ?
    FirstThunk         DWORD ?
IMAGE_IMPORT_DESCRIPTOR ENDS

; Constants
IMAGE_DIRECTORY_ENTRY_EXPORT     EQU 0
IMAGE_DIRECTORY_ENTRY_IMPORT     EQU 1
IMAGE_ORDINAL_FLAG64             EQU 8000000000000000h

.code
_start PROC
    ; Save registers
    push rsi
    push rdi
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; Get PEB from gs:[60h]
    mov rax, gs:[60h]
    ASSUME rax:PTR PEB64

    ; Get Ldr
    mov rax, [rax].Ldr
    ASSUME rax:PTR PEB_LDR_DATA64

    ; Get first module in memory order list
    mov rsi, [rax].InMemoryOrderModuleList.Flink
    ASSUME rsi:PTR LDR_DATA_TABLE_ENTRY64

    ; Skip first module (executable)
    mov rsi, [rsi].InMemoryOrderLinks.Flink
    ASSUME rsi:PTR LDR_DATA_TABLE_ENTRY64

    ; Skip second module (ntdll.dll)
    mov rsi, [rsi].InMemoryOrderLinks.Flink
    ASSUME rsi:PTR LDR_DATA_TABLE_ENTRY64

    ; Get kernel32.dll base address
    mov rbx, [rsi].DllBase
    ASSUME rbx:PTR IMAGE_DOS_HEADER

    ; Find kernel32.dll export directory
    mov edx, [rbx].e_lfanew
    add rdx, rbx
    ASSUME rdx:PTR IMAGE_NT_HEADERS64

    ; Get export directory RVA
    mov eax, [rdx].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT * SIZE IMAGE_DATA_DIRECTORY].VirtualAddress
    add rax, rbx
    ASSUME rax:PTR IMAGE_EXPORT_DIRECTORY

    ; Save export directory info
    push rax                     ; Save export directory base
    mov ecx, [rax].NumberOfNames ; Get number of function names
    mov rbp, [rax].AddressOfNames ; Get function names array RVA
    add rbp, rbx                 ; Get function names array address

find_getprocaddress:
    ; Find GetProcAddress by name
    dec ecx
    mov esi, [rbp + rcx*4]       ; Get function name RVA
    add rsi, rbx                 ; Get function name address
    lea rdi, [gpa_name]
    push rcx                     ; Save counter
    mov ecx, 13                  ; Length of "GetProcAddress"
    rep cmpsb
    pop rcx
    jne find_getprocaddress

    ; Get function ordinal and address
    pop rax                      ; Restore export directory base
    mov rsi, [rax].AddressOfNameOrdinals ; Get ordinal array RVA
    add rsi, rbx                 ; Get ordinal array address
    movzx ecx, WORD PTR [rsi + rcx*2] ; Get function ordinal
    mov rsi, [rax].AddressOfFunctions ; Get function addresses array RVA
    add rsi, rbx                 ; Get function addresses array address
    mov eax, [rsi + rcx*4]       ; Get function RVA
    add rax, rbx                 ; Get GetProcAddress address
    mov [gpa_addr], rax          ; Save GetProcAddress address

    ; Find LoadLibraryA
    lea rcx, [lla_name]          ; First parameter - function name
    mov rdx, rbx                 ; Second parameter - kernel32 base
    call rax                     ; Call GetProcAddress
    mov [lla_addr], rax          ; Save LoadLibraryA address

    ; Process imports
    call get_base                ; Get current module base
get_base:
    pop rsi
    sub rsi, offset get_base
    ASSUME rsi:PTR IMAGE_DOS_HEADER

    ; Get import directory
    mov eax, [rsi].e_lfanew
    add rax, rsi
    ASSUME rax:PTR IMAGE_NT_HEADERS64

    ; Get import directory RVA
    mov eax, [rax].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT * SIZE IMAGE_DATA_DIRECTORY].VirtualAddress
    test eax, eax
    jz imports_done

    add rax, rsi
    mov [imp_dir], rax
    ASSUME rax:PTR IMAGE_IMPORT_DESCRIPTOR

process_imports:
    mov rax, [imp_dir]
    ASSUME rax:PTR IMAGE_IMPORT_DESCRIPTOR

    ; Check if we reached the end of import descriptors
    mov edx, [rax].Name
    test edx, edx
    jz imports_done

    ; Load DLL
    add rdx, rsi                 ; Get DLL name address
    mov rcx, rdx                 ; First parameter - DLL name
    call [lla_addr]              ; Call LoadLibraryA
    test rax, rax
    jz next_dll

    mov r12, rax                 ; Save DLL base

    ; Get import lookup table
    mov rax, [imp_dir]
    mov edx, [rax].OriginalFirstThunk
    test edx, edx
    jz use_first_thunk
    add rdx, rsi
    jmp process_functions

use_first_thunk:
    mov edx, [rax].FirstThunk
    add rdx, rsi

process_functions:
    mov rax, [rdx]               ; Get function ordinal/name RVA
    test rax, rax
    jz next_dll

    test rax, IMAGE_ORDINAL_FLAG64 ; Check if import by ordinal
    jnz import_by_ordinal

    ; Import by name
    add rax, rsi
    add rax, 2                   ; Skip hint
    mov rcx, rax                 ; First parameter - function name
    mov rdx, r12                 ; Second parameter - DLL base
    call [gpa_addr]              ; Call GetProcAddress
    jmp save_function

import_by_ordinal:
    and rax, 0FFFFh              ; Get ordinal number
    mov rcx, rax                 ; First parameter - ordinal
    mov rdx, r12                 ; Second parameter - DLL base
    call [gpa_addr]              ; Call GetProcAddress

save_function:
    mov rcx, [imp_dir]
    mov r13d, [rcx].FirstThunk   ; Get IAT RVA
    add r13, rsi                 ; Get IAT address

    ; Calculate offset in IAT
    mov r14, rdx
    sub r14, r13
    add r13, r14

    mov [r13], rax               ; Save function address
    add rdx, 8                   ; Next import lookup entry
    add r13, 8                   ; Next IAT entry
    jmp process_functions

next_dll:
    add QWORD PTR [imp_dir], SIZE IMAGE_IMPORT_DESCRIPTOR ; Next import descriptor
    jmp process_imports

imports_done:
    ; Restore registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop rdi
    pop rsi
    ret
_start ENDP

.data
    gpa_name db 'GetProcAddress', 0
    lla_name db 'LoadLibraryA', 0
    align 8
    gpa_addr dq 0
    lla_addr dq 0
    imp_dir  dq 0

END
