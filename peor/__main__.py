import argparse
from pathlib import Path
from pefile import PE, OPTIONAL_HEADER_MAGIC_PE, OPTIONAL_HEADER_MAGIC_PE_PLUS
from peor._shellcodes import RELOCS_32, RELOCS_64, IMPORTS_32_UM, IMPORTS_64_UM

# Trailing bytes that terminate each import resolver so it falls through into the
# relocs resolver. We strip them at output time.
#   x86: 0xC3 (RET)  →  stripped → falls through to RELOCS_32
#   x64: 0xFF 0xE0 (JMP RAX)  →  stripped → falls through to RELOCS_64
_IMPORTS_TAIL_32 = b'\xc3'
_IMPORTS_TAIL_64 = b'\xff\xe0'

# Windows PE Subsystem values that peor does not yet support.
_EFI_SUBSYSTEMS = frozenset({10, 11, 12, 13})  # EFI_APPLICATION / BOOT_SERVICE / RUNTIME / ROM
_NATIVE_SUBSYSTEM = 1                           # Windows native (kernel-mode drivers)

# Per-architecture shellcode table.
# dir_array_offset: bytes from the optional-header start to the DataDirectory array
#   PE32  (0x10B): 96  bytes  (PECOFF spec §3.4.1)
#   PE32+ (0x20B): 112 bytes  (PECOFF spec §3.4.2)
# disp32_off: byte index of the LEA disp32 field inside the assembled relocs resolver
#   RELOCS_32: e8..(5) 5b(1) 8d bb <disp32>(4)  →  disp32 at byte 8
#   RELOCS_64: e8..(5) 5b(1) 48 8d bb <disp32>(4)  →  disp32 at byte 9
_SHELLCODES = {
    OPTIONAL_HEADER_MAGIC_PE: {
        'relocs':           RELOCS_32,
        'imports':          IMPORTS_32_UM,
        'tail':             _IMPORTS_TAIL_32,
        'dir_array_offset': 96,
        'disp32_off':       8,
    },
    OPTIONAL_HEADER_MAGIC_PE_PLUS: {
        'relocs':           RELOCS_64,
        'imports':          IMPORTS_64_UM,
        'tail':             _IMPORTS_TAIL_64,
        'dir_array_offset': 112,
        'disp32_off':       9,
    },
}


def _strip_tail(shellcode: bytes, tail: bytes) -> bytes:
    if shellcode and shellcode.endswith(tail):
        return shellcode[:-len(tail)]
    return shellcode


def dump_memory_layout(pe: PE, output_file: Path, ignore_imports: bool = False,
                       resolve_imports: bool = False):
    subsystem = pe.OPTIONAL_HEADER.Subsystem
    if subsystem in _EFI_SUBSYSTEMS:
        raise ValueError(f"EFI PE (subsystem {subsystem}) is not yet supported")
    if subsystem == _NATIVE_SUBSYSTEM:
        raise ValueError(f"Kernel-mode PE (subsystem {subsystem}) is not yet supported")

    entry = _SHELLCODES.get(pe.PE_TYPE)
    if entry is None:
        raise ValueError(f"Unsupported PE type: 0x{pe.PE_TYPE:04X}")

    # Build in-memory PE image
    ram_layout = bytearray()
    ram_layout.extend(pe.get_data(0, pe.OPTIONAL_HEADER.SizeOfHeaders))
    for section in pe.sections:
        while len(ram_layout) < section.VirtualAddress:
            ram_layout.append(0)
        ram_layout.extend(section.get_data())
    while len(ram_layout) < pe.OPTIONAL_HEADER.SizeOfImage:
        ram_layout.append(0)

    if ignore_imports:
        # Zero DataDirectory[1] (IMPORT) so the PE has no import table at runtime.
        # Optional header starts at e_lfanew + 4 (PE sig) + 20 (file header) = e_lfanew + 24.
        opt_off = pe.DOS_HEADER.e_lfanew + 24
        import_entry_off = opt_off + entry['dir_array_offset'] + 1 * 8  # index 1, 8 bytes each
        ram_layout[import_entry_off:import_entry_off + 8] = b'\x00' * 8

    relocs = entry['relocs']
    imports = b''
    if resolve_imports:
        imports = _strip_tail(entry['imports'], entry['tail'])

    # Layout: imports_resolver (tail stripped) | relocs_resolver | [align pad] | PE_image
    # PE image must be 16-byte aligned in the buffer for MOVDQA/MOVAPS safety.
    # VirtualAlloc returns 64KB-aligned memory, so only the prefix length matters.
    align_pad = (-len(imports) - len(relocs)) % 16
    if align_pad and relocs:
        off_idx = entry['disp32_off']
        relocs = bytearray(relocs)
        old = int.from_bytes(relocs[off_idx:off_idx + 4], 'little')
        relocs[off_idx:off_idx + 4] = (old + align_pad).to_bytes(4, 'little')
        relocs = bytes(relocs)

    output_file.write_bytes(imports + relocs + (b'\x90' * align_pad) + bytes(ram_layout))


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
