import struct
import argparse
from pathlib import Path
from pefile import PE, OPTIONAL_HEADER_MAGIC_PE, OPTIONAL_HEADER_MAGIC_PE_PLUS
from peor._shellcodes import (
    RELOCS_32, RELOCS_64,
    IMPORTS_32_UM, IMPORTS_64_UM,
    ENTRYPOINT_32, ENTRYPOINT_64,
    SEH_REGISTRAR_64,
    TLS_CALLBACKS_32, TLS_CALLBACKS_64,
    CXX_EH_FIXER_32, CXX_EH_FIXER_64,
)

# Trailing bytes that terminate each import resolver so it falls through into the
# relocs resolver. We strip them at output time.
#   x86: 0xC3 (RET)         → stripped → falls through to RELOCS_32
#   x64: 0xFF 0xE0 (JMP RAX) → stripped → falls through to RELOCS_64
_IMPORTS_TAIL_32 = b'\xc3'
_IMPORTS_TAIL_64 = b'\xff\xe0'

# Magic placeholders in cxx_eh_fixer{32,64}.asm replaced at build time by peor.
# PE_SIZE_MAGIC: peor patches to pe.OPTIONAL_HEADER.SizeOfImage.
# IAT_RVA_MAGIC: peor patches to the IAT-entry RVA for the hooked function.
_CXX_EH_PE_SIZE_MAGIC_64 = b'\x78\x56\x34\x12'  # 0x12345678 LE (in ADD RCX, imm32)
_CXX_EH_IAT_RVA_MAGIC_64 = b'\x21\x43\x65\x87'  # 0x87654321 LE (in LEA RDX, [RBX+disp32])
_CXX_EH_PE_SIZE_MAGIC_32 = b'\xc4\xc3\xc2\xc1'  # 0xC1C2C3C4 LE (in ADD ECX, imm32)
_CXX_EH_IAT_RVA_MAGIC_32 = b'\xd4\xd3\xd2\xd1'  # 0xD1D2D3D4 LE (in LEA EDX, [EBX+disp32])

# Windows PE Subsystem values that peor does not yet support.
_EFI_SUBSYSTEMS = frozenset({10, 11, 12, 13})  # EFI_APPLICATION / BOOT_SERVICE / RUNTIME / ROM
_NATIVE_SUBSYSTEM = 1                           # Windows native (kernel-mode drivers)

# Per-architecture shellcode table.
# dir_array_offset: bytes from the optional-header start to the DataDirectory array
#   PE32  (0x10B): 96  bytes  (PECOFF spec §3.4.1)
#   PE32+ (0x20B): 112 bytes  (PECOFF spec §3.4.2)
# disp32_off: byte index of the LEA disp32 field inside the assembled relocs resolver
#   RELOCS_32: e8..(5) 5b(1) 8d bb <disp32>(4)       → disp32 at byte 8
#   RELOCS_64: e8..(5) 5b(1) 48 8d bb <disp32>(4)    → disp32 at byte 9
_SHELLCODES = {
    OPTIONAL_HEADER_MAGIC_PE: {
        'relocs':           RELOCS_32,
        'imports':          IMPORTS_32_UM,
        'entrypoint':       ENTRYPOINT_32,
        'seh':              None,               # x86 has no RUNTIME_FUNCTION table
        'tls':              TLS_CALLBACKS_32,
        # x86 does NOT need the GetModuleHandleExW IAT hook.
        # On x86, _CxxThrowException stores (ThrowInfo - ImageBase) as a 32-bit value.
        # When ImageBase is NULL (shellcode not in module list), this is just ThrowInfo
        # itself — a valid 32-bit pointer. __CxxFrameHandler reconstructs it as
        # (NULL + ThrowInfo) = ThrowInfo, which is correct.  No truncation occurs
        # because addresses never exceed 32 bits.  Installing the hook on x86 breaks
        # _beginthreadex, which also calls GetModuleHandleExW(FLAG_FROM_ADDRESS) and
        # passes the returned handle to FreeLibraryAndExitThread — crashing when given
        # a non-module shellcode address.
        'cxx_eh_fixer':     None,
        'cxx_eh_import':    None,
        'cxx_pe_size_magic': _CXX_EH_PE_SIZE_MAGIC_32,
        'cxx_iat_rva_magic': _CXX_EH_IAT_RVA_MAGIC_32,
        'tail':             _IMPORTS_TAIL_32,
        'dir_array_offset': 96,
        'disp32_off':       8,
    },
    OPTIONAL_HEADER_MAGIC_PE_PLUS: {
        'relocs':           RELOCS_64,
        'imports':          IMPORTS_64_UM,
        'entrypoint':       ENTRYPOINT_64,
        'seh':              SEH_REGISTRAR_64,
        'tls':              TLS_CALLBACKS_64,
        'cxx_eh_fixer':     CXX_EH_FIXER_64,
        'cxx_eh_import':    b'RtlPcToFileHeader',
        'cxx_pe_size_magic': _CXX_EH_PE_SIZE_MAGIC_64,
        'cxx_iat_rva_magic': _CXX_EH_IAT_RVA_MAGIC_64,
        'tail':             _IMPORTS_TAIL_64,
        'dir_array_offset': 112,
        'disp32_off':       9,
    },
}


def _strip_tail(shellcode: bytes, tail: bytes) -> bytes:
    if shellcode and shellcode.endswith(tail):
        return shellcode[:-len(tail)]
    return shellcode


def _find_iat_rva(pe: PE, func_name: bytes) -> int | None:
    """Return the RVA of the IAT slot for func_name, or None if not imported."""
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return None
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name == func_name:
                return imp.address - pe.OPTIONAL_HEADER.ImageBase
    return None


def _has_exception_table(pe: PE) -> bool:
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    return len(dirs) > 3 and dirs[3].VirtualAddress != 0


def _has_tls_callbacks(pe: PE) -> bool:
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    if len(dirs) <= 9 or dirs[9].VirtualAddress == 0:
        return False
    tls_rva = dirs[9].VirtualAddress
    # AddressOfCallBacks: offset 0x0C in IMAGE_TLS_DIRECTORY32, 0x18 in IMAGE_TLS_DIRECTORY64
    if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
        cb_off, ptr_size = 0x0C, 4
    else:
        cb_off, ptr_size = 0x18, 8
    raw = pe.get_data(tls_rva + cb_off, ptr_size)
    return int.from_bytes(raw, 'little') != 0


def _validate_pe(pe: PE) -> dict:
    subsystem = pe.OPTIONAL_HEADER.Subsystem
    if subsystem in _EFI_SUBSYSTEMS:
        raise ValueError(f"EFI PE (subsystem {subsystem}) is not yet supported")
    if subsystem == _NATIVE_SUBSYSTEM:
        raise ValueError(f"Kernel-mode PE (subsystem {subsystem}) is not yet supported")
    entry = _SHELLCODES.get(pe.PE_TYPE)
    if entry is None:
        raise ValueError(f"Unsupported PE type: 0x{pe.PE_TYPE:04X}")
    return entry


def _build_ram_layout(pe: PE) -> bytearray:
    ram_layout = bytearray()
    ram_layout.extend(pe.get_data(0, pe.OPTIONAL_HEADER.SizeOfHeaders))
    for section in pe.sections:
        while len(ram_layout) < section.VirtualAddress:
            ram_layout.append(0)
        ram_layout.extend(section.get_data())
    while len(ram_layout) < pe.OPTIONAL_HEADER.SizeOfImage:
        ram_layout.append(0)
    return ram_layout


def _zero_import_dir(ram_layout: bytearray, pe: PE, entry: dict) -> None:
    # Optional header starts at e_lfanew + 4 (PE sig) + 20 (file header) = e_lfanew + 24.
    opt_off = pe.DOS_HEADER.e_lfanew + 24
    import_entry_off = opt_off + entry['dir_array_offset'] + 1 * 8  # DataDir[1], 8 bytes each
    ram_layout[import_entry_off:import_entry_off + 8] = b'\x00' * 8


def _build_shellcode_chain(pe: PE, entry: dict, resolve_imports: bool) -> bytes:
    # Chain order: [imports] → relocs → [cxx_eh_fixer] → [seh] → [tls] → entrypoint → [pad]
    # cxx_eh_fixer (x64 only) hooks RtlPcToFileHeader in the IAT so that
    # _CxxThrowException gets the correct ImageBase for typed C++ exceptions.
    # x86 does not need it: 32-bit ThrowInfo − NULL = ThrowInfo, so the frame
    # handler reconstructs the pointer correctly without a hook.
    imports    = _strip_tail(entry['imports'], entry['tail']) if resolve_imports else b''
    relocs     = entry['relocs']
    seh        = entry['seh'] if (entry['seh'] and _has_exception_table(pe)) else b''
    tls        = entry['tls'] if (entry['tls'] and _has_tls_callbacks(pe)) else b''
    entrypoint = entry['entrypoint']

    if resolve_imports and entry['cxx_eh_fixer'] is not None and entry['cxx_eh_import'] is not None:
        iat_rva = _find_iat_rva(pe, entry['cxx_eh_import'])
        if iat_rva is not None:
            fixer = bytearray(entry['cxx_eh_fixer'])
            soi   = pe.OPTIONAL_HEADER.SizeOfImage
            pe_size_magic = entry['cxx_pe_size_magic']
            iat_rva_magic = entry['cxx_iat_rva_magic']
            if fixer.count(pe_size_magic) != 1:
                raise RuntimeError(f"PE_SIZE_MAGIC {pe_size_magic.hex()} not unique in cxx_eh_fixer")
            if fixer.count(iat_rva_magic) != 1:
                raise RuntimeError(f"IAT_RVA_MAGIC {iat_rva_magic.hex()} not unique in cxx_eh_fixer")
            idx = fixer.find(pe_size_magic)
            fixer[idx:idx + 4] = struct.pack('<I', soi)
            idx = fixer.find(iat_rva_magic)
            fixer[idx:idx + 4] = struct.pack('<I', iat_rva)
            cxx_fixer = bytes(fixer)
        else:
            cxx_fixer = b''
    else:
        cxx_fixer = b''

    # PE image must be 16-byte aligned in the buffer for MOVDQA/MOVAPS safety.
    align_pad = (-len(imports) - len(relocs) - len(cxx_fixer) - len(seh) - len(tls) - len(entrypoint)) % 16

    # Patch the disp32 in the relocs resolver.
    # setup.py bakes in disp32 = len(relocs_assembled) - 5 (PE follows relocs standalone).
    # At runtime we add the remaining shellcodes + alignment padding.
    extra  = len(cxx_fixer) + len(seh) + len(tls) + len(entrypoint) + align_pad
    off    = entry['disp32_off']
    relocs = bytearray(relocs)
    old    = int.from_bytes(relocs[off:off + 4], 'little')
    relocs[off:off + 4] = (old + extra).to_bytes(4, 'little')

    return imports + bytes(relocs) + cxx_fixer + seh + tls + entrypoint + (b'\x90' * align_pad)


def dump_memory_layout(pe: PE, output_file: Path, ignore_imports: bool = False,
                       resolve_imports: bool = False):
    entry      = _validate_pe(pe)
    ram_layout = _build_ram_layout(pe)
    if ignore_imports:
        _zero_import_dir(ram_layout, pe, entry)
    prefix = _build_shellcode_chain(pe, entry, resolve_imports)
    output_file.write_bytes(prefix + bytes(ram_layout))


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input-file',      required=True, type=Path, help='Path to a PE-file')
    parser.add_argument('-m', '--ignore-imports',  action='store_true',      help='Zero the import directory in the output')
    parser.add_argument('-r', '--resolve-imports', action='store_true',      help='Prepend import resolver shellcode')
    parser.add_argument('-o', '--output-file',     required=True, type=Path, help='Path to output shellcode file')
    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.ignore_imports and args.resolve_imports:
        print("Error: --ignore-imports and --resolve-imports are mutually exclusive")
        return

    pe = PE(str(args.input_file))
    dump_memory_layout(pe, args.output_file, args.ignore_imports, args.resolve_imports)


if __name__ == '__main__':
    main()
