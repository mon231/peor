; imports_resolver32.asm
; x86 import resolver using NASM syntax and Windows API structs

BITS 32

; Structure definitions
struc LIST_ENTRY32
    .Flink resd 1
    .Blink resd 1
endstruc

struc UNICODE_STRING32
    .Length        resw 1
    .MaximumLength resw 1
    .Buffer        resd 1
endstruc

struc PEB
    .InheritedAddressSpace    resb 1
    .ReadImageFileExecOptions resb 1
    .BeingDebugged            resb 1
    .BitField                 resb 1
    .Mutant                   resd 1
    .ImageBaseAddress         resd 1
    .Ldr                      resd 1
    ; Remaining fields omitted
endstruc

struc PEB_LDR_DATA
    .Length                          resd 1
    .Initialized                     resd 1
    .SsHandle                        resd 1
    .InLoadOrderModuleList           resb LIST_ENTRY32_size
    .InMemoryOrderModuleList         resb LIST_ENTRY32_size
    .InInitializationOrderModuleList resb LIST_ENTRY32_size
    .EntryInProgress                 resd 1
endstruc

struc LDR_DATA_TABLE_ENTRY
    .InLoadOrderLinks            resb LIST_ENTRY32_size
    .InMemoryOrderLinks          resb LIST_ENTRY32_size
    .InInitializationOrderLinks  resb LIST_ENTRY32_size
    .DllBase                     resd 1
    .EntryPoint                  resd 1
    .SizeOfImage                 resd 1
    .FullDllName                 resb UNICODE_STRING32_size
    .BaseDllName                 resb UNICODE_STRING32_size
endstruc

struc IMAGE_DOS_HEADER
    .e_magic    resw 1
    .e_cblp     resw 1
    .e_cp       resw 1
    .e_crlc     resw 1
    .e_cparhdr  resw 1
    .e_minalloc resw 1
    .e_maxalloc resw 1
    .e_ss       resw 1
    .e_sp       resw 1
    .e_csum     resw 1
    .e_ip       resw 1
    .e_cs       resw 1
    .e_lfarlc   resw 1
    .e_ovno     resw 1
    .e_res      resw 4
    .e_oemid    resw 1
    .e_oeminfo  resw 1
    .e_res2     resw 10
    .e_lfanew   resd 1
endstruc

struc IMAGE_FILE_HEADER
    .Machine              resw 1
    .NumberOfSections     resw 1
    .TimeDateStamp        resd 1
    .PointerToSymbolTable resd 1
    .NumberOfSymbols      resd 1
    .SizeOfOptionalHeader resw 1
    .Characteristics      resw 1
endstruc

struc IMAGE_DATA_DIRECTORY
    .VirtualAddress resd 1
    .Size           resd 1
endstruc

struc IMAGE_OPTIONAL_HEADER32
    .Magic                       resw 1
    .MajorLinkerVersion          resb 1
    .MinorLinkerVersion          resb 1
    .SizeOfCode                  resd 1
    .SizeOfInitializedData       resd 1
    .SizeOfUninitializedData     resd 1
    .AddressOfEntryPoint         resd 1
    .BaseOfCode                  resd 1
    .BaseOfData                  resd 1
    .ImageBase                   resd 1
    .SectionAlignment            resd 1
    .FileAlignment               resd 1
    .MajorOperatingSystemVersion resw 1
    .MinorOperatingSystemVersion resw 1
    .MajorImageVersion           resw 1
    .MinorImageVersion           resw 1
    .MajorSubsystemVersion       resw 1
    .MinorSubsystemVersion       resw 1
    .Win32VersionValue           resd 1
    .SizeOfImage                 resd 1
    .SizeOfHeaders               resd 1
    .CheckSum                    resd 1
    .Subsystem                   resw 1
    .DllCharacteristics          resw 1
    .SizeOfStackReserve          resd 1
    .SizeOfStackCommit           resd 1
    .SizeOfHeapReserve           resd 1
    .SizeOfHeapCommit            resd 1
    .LoaderFlags                 resd 1
    .NumberOfRvaAndSizes         resd 1
    .DataDirectory               resb 16 * IMAGE_DATA_DIRECTORY_size
endstruc

struc IMAGE_NT_HEADERS32
    .Signature      resd 1
    .FileHeader     resb IMAGE_FILE_HEADER_size
    .OptionalHeader resb IMAGE_OPTIONAL_HEADER32_size
endstruc

struc IMAGE_EXPORT_DIRECTORY
    .Characteristics       resd 1
    .TimeDateStamp         resd 1
    .MajorVersion          resw 1
    .MinorVersion          resw 1
    .Name                  resd 1
    .Base                  resd 1
    .NumberOfFunctions     resd 1
    .NumberOfNames         resd 1
    .AddressOfFunctions    resd 1
    .AddressOfNames        resd 1
    .AddressOfNameOrdinals resd 1
endstruc

struc IMAGE_IMPORT_DESCRIPTOR
    .OriginalFirstThunk resd 1
    .TimeDateStamp      resd 1
    .ForwarderChain     resd 1
    .Name               resd 1
    .FirstThunk         resd 1
endstruc

; Constants
IMAGE_DIRECTORY_ENTRY_EXPORT     equ 0
IMAGE_DIRECTORY_ENTRY_IMPORT     equ 1
IMAGE_ORDINAL_FLAG32             equ 0x80000000

section .text
global _start
_start:
    pushad

    ; Get PEB address from fs:[0x30]
    mov eax, [fs:0x30]

    ; Get loader data
    mov eax, [eax + PEB.Ldr]

    ; Get first module in memory order list
    mov esi, [eax + PEB_LDR_DATA.InMemoryOrderModuleList + LIST_ENTRY32.Flink]

    ; Skip first module (executable)
    mov esi, [esi + LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks + LIST_ENTRY32.Flink]

    ; Skip second module (ntdll.dll)
    mov esi, [esi + LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks + LIST_ENTRY32.Flink]

    ; Get kernel32.dll base address
    mov ebx, [esi + LDR_DATA_TABLE_ENTRY.DllBase]

    ; Find kernel32.dll export directory
    mov edx, [ebx + IMAGE_DOS_HEADER.e_lfanew]
    add edx, ebx

    ; Get export directory RVA
    mov eax, [edx + IMAGE_NT_HEADERS32.OptionalHeader + IMAGE_OPTIONAL_HEADER32.DataDirectory + (IMAGE_DIRECTORY_ENTRY_EXPORT * IMAGE_DATA_DIRECTORY_size) + IMAGE_DATA_DIRECTORY.VirtualAddress]
    add eax, ebx

    ; Save export directory info
    push eax
    mov ecx, [eax + IMAGE_EXPORT_DIRECTORY.NumberOfNames]
    mov ebp, [eax + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
    add ebp, ebx

find_getprocaddress:
    dec ecx
    mov esi, [ebp + ecx*4]
    add esi, ebx
    mov edi, gpa_name
    push ecx
    mov ecx, 13
    repe cmpsb
    pop ecx
    jne find_getprocaddress

    ; Get function ordinal and address
    pop eax
    mov esi, [eax + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
    add esi, ebx
    movzx ecx, word [esi + ecx*2]
    mov esi, [eax + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
    add esi, ebx
    mov eax, [esi + ecx*4]
    add eax, ebx
    mov [gpa_addr], eax

    ; Find LoadLibraryA
    push lla_name
    push ebx
    call eax
    mov [lla_addr], eax

    ; Process imports
    call get_base
get_base:
    pop esi
    sub esi, get_base - $$

    ; Get import directory
    mov eax, [esi + IMAGE_DOS_HEADER.e_lfanew]
    add eax, esi

    ; Get import directory RVA
    mov eax, [eax + IMAGE_NT_HEADERS32.OptionalHeader + IMAGE_OPTIONAL_HEADER32.DataDirectory + (IMAGE_DIRECTORY_ENTRY_IMPORT * IMAGE_DATA_DIRECTORY_size) + IMAGE_DATA_DIRECTORY.VirtualAddress]
    test eax, eax
    jz imports_done

    add eax, esi
    mov [imp_dir], eax

process_imports:
    mov eax, [imp_dir]
    mov edx, [eax + IMAGE_IMPORT_DESCRIPTOR.Name]
    test edx, edx
    jz imports_done

    add edx, esi
    push edx
    call [lla_addr]
    test eax, eax
    jz next_dll

    mov ebx, eax

    ; Get import lookup table
    mov eax, [imp_dir]
    mov edx, [eax + IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk]
    test edx, edx
    jz use_first_thunk
    add edx, esi
    jmp process_functions

use_first_thunk:
    mov edx, [eax + IMAGE_IMPORT_DESCRIPTOR.FirstThunk]
    add edx, esi

process_functions:
    mov eax, [edx]
    test eax, eax
    jz next_dll

    test eax, IMAGE_ORDINAL_FLAG32
    jnz import_by_ordinal

    ; Import by name
    add eax, esi
    add eax, 2
    push eax
    push ebx
    call [gpa_addr]
    jmp save_function

import_by_ordinal:
    and eax, 0xFFFF
    push eax
    push ebx
    call [gpa_addr]

save_function:
    mov ecx, [imp_dir]
    mov ebx, [ecx + IMAGE_IMPORT_DESCRIPTOR.FirstThunk]
    add ebx, esi

    mov ecx, edx
    sub ecx, ebx
    add ebx, ecx

    mov [ebx], eax
    add edx, 4
    jmp process_functions

next_dll:
    add dword [imp_dir], IMAGE_IMPORT_DESCRIPTOR_size
    jmp process_imports

imports_done:
    popad
    ret

section .data
gpa_name: db 'GetProcAddress',0
lla_name: db 'LoadLibraryA',0
gpa_addr: dd 0
lla_addr: dd 0
imp_dir:  dd 0
