import argparse
from pathlib import Path
from pefile import PE, OPTIONAL_HEADER_MAGIC_PE, OPTIONAL_HEADER_MAGIC_PE_PLUS
from peor._shellcodes import RELOCS_32, RELOCS_64, IMPORTS_32_UM, IMPORTS_64_UM

# PE Magic numbers for different architectures
OPTIONAL_HEADER_MAGIC_ARM = 0x10B3    # ARM
OPTIONAL_HEADER_MAGIC_ARM64 = 0x20B3  # ARM64

# ARM relocation shellcode (Thumb mode)
RELOCS_ARM = bytes.fromhex('00482DE900B08DE2000050E30000A0131A0050E3F0FF1F0A0000A0E30090BDE8')

# ARM64 relocation shellcode
RELOCS_ARM64 = bytes.fromhex('FD7BBFA9FD030091E0031F2AF30300AAE0000010E1000054E2031F2A21000054E003102AE0000010E100005420008052E0030091C0035FD6')

# Import resolver shellcodes — resolve the PE's import table via PEB walking
# (LoadLibraryA / GetProcAddress).
#
# Chaining convention: each resolver ends with a trailing "terminal" byte/sequence
# that is stripped at output time so execution falls through into the relocs resolver:
#   x86/x86-KM: trailing 0xC3 (RET) is stripped → falls through to RELOCS_32
#   x64/x64-KM: trailing 0xFF 0xE0 (JMP RAX) is stripped → falls through to RELOCS_64
#
# Output layout: imports[:-tail] + relocs + PE_image
# The test_loader calls the buffer once; imports resolver falls through to relocs
# resolver which then applies base relocations and JMPs to the PE entry point.

# IMPORTS_32_UM and IMPORTS_64_UM are imported from peor._shellcodes (assembled at install time)
IMPORTS_ARM_UM   = bytes.fromhex('')  # Placeholder for ARM usermode import resolver
IMPORTS_ARM64_UM = bytes.fromhex('')  # Placeholder for ARM64 usermode import resolver

# Import resolution shellcode - kernelmode
IMPORTS_32_KM = bytes.fromhex('60BB7803000089D88B403C01D88B7878895DE003F88B48248B582C8B701C03DF03FB03F7FCB9130000004939C975F58B5DCC8B5E3603DE668B0C4E8B5E2803DE8B048E01D8A3000000008B3D040000005368000000008B1D00000000FFD7A3080000008D45E2E8000000005E2D000000008B463C01F08B8080000000A3100000008B3D100000008B0F85C90F84A30000008D0C368B3D080000005157FFD785C00F8488000000894424048B3D1000000083C70C8B4F0485C90F8469000000034C24048B3D040000005051FFD7894424088B7C240483C70485C90F8442000000034C24048B3D040000005051FFD7EB1C25FFFF00008B3D040000005051FFD78B4C24088B3D100000008B4F1003CE894C240C034E1C8901834C240C04834424080483C704E9B9FFFFFF83C714E958FFFFFF61C3')
IMPORTS_64_KM = bytes.fromhex('565756534154415541564157488B6C24104865488B306548AD488D68184889E64883C6204889F0488B00488B40204889C3488B5B204889DF488B3B4C8B6B084C8B63184C89E9488D3D130000004C89E2B90D0000004839C8750A49FFC1E2E04C89E1EB894C8B43304889DF4C29F94885FF74554C8B43384885C0744B4801D84889C64C8B0E4C8B4E084983C6084885C9743883E908D1E974EC66414139C074E54489C84181E0FF0F00004181F80A750A4C8D14114D01C0490132FFC975D1EB8B4C8B43284801D8FFE0')
IMPORTS_ARM_KM   = bytes.fromhex('')  # Placeholder for ARM kernelmode import resolver
IMPORTS_ARM64_KM = bytes.fromhex('')  # Placeholder for ARM64 kernelmode import resolver

# Import resolution shellcode - EFI
IMPORTS_32_EFI   = bytes.fromhex('')  # Placeholder for x86 EFI import resolver
IMPORTS_64_EFI   = bytes.fromhex('')  # Placeholder for x64 EFI import resolver
IMPORTS_ARM_EFI  = bytes.fromhex('')  # Placeholder for ARM EFI import resolver
IMPORTS_ARM64_EFI = bytes.fromhex('') # Placeholder for ARM64 EFI import resolver

# Trailing bytes that terminate each import resolver instead of chaining.
# We strip them so the resolver falls through into the relocs resolver.
_IMPORTS_TAIL_32 = b'\xc3'       # RET
_IMPORTS_TAIL_64 = b'\xff\xe0'   # JMP RAX


def _strip_tail(shellcode: bytes, tail: bytes) -> bytes:
    if shellcode and shellcode.endswith(tail):
        return shellcode[:-len(tail)]
    return shellcode


def dump_memory_layout(pe: PE, output_file: Path, ignore_imports: bool = False,
                       resolve_imports: bool = False, kernel_mode: bool = False,
                       efi_mode: bool = False):
    ram_layout = bytearray()

    # PE header (identical on disk and in memory for the header region)
    ram_layout.extend(pe.get_data(0, pe.OPTIONAL_HEADER.SizeOfHeaders))

    # Sections at their virtual addresses
    for section in pe.sections:
        while len(ram_layout) < section.VirtualAddress:
            ram_layout.append(0)
        ram_layout.extend(section.get_data())

    # Pad to SizeOfImage
    while len(ram_layout) < pe.OPTIONAL_HEADER.SizeOfImage:
        ram_layout.append(0)

    # Zero the IMAGE_DIRECTORY_ENTRY_IMPORT entry so the PE image has no import
    # table for the shellcode runtime to stumble over.
    if ignore_imports:
        # DataDirectory[1] (IMPORT) sits at a fixed offset inside the optional header.
        # Optional header starts at: e_lfanew + 4 (PE sig) + 20 (file header)
        opt_off = pe.DOS_HEADER.e_lfanew + 24
        # DataDirectory array offset within optional header:
        #   PE32  (0x10B): 96 bytes
        #   PE32+ (0x20B): 112 bytes
        if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            dir_array_off = opt_off + 96
        else:
            dir_array_off = opt_off + 112
        import_entry_off = dir_array_off + 1 * 8  # entry index 1, 8 bytes per entry
        ram_layout[import_entry_off:import_entry_off + 8] = b'\x00' * 8

    imports = b''
    relocs  = b''

    if resolve_imports:
        if efi_mode:
            if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
                relocs = RELOCS_32; imports = IMPORTS_32_EFI
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
                relocs = RELOCS_64; imports = IMPORTS_64_EFI
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM:
                relocs = RELOCS_ARM; imports = IMPORTS_ARM_EFI
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM64:
                relocs = RELOCS_ARM64; imports = IMPORTS_ARM64_EFI
            else:
                raise ValueError("Unsupported PE type")
        elif kernel_mode:
            if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
                relocs = RELOCS_32; imports = _strip_tail(IMPORTS_32_KM, _IMPORTS_TAIL_32)
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
                relocs = RELOCS_64; imports = _strip_tail(IMPORTS_64_KM, _IMPORTS_TAIL_64)
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM:
                relocs = RELOCS_ARM; imports = IMPORTS_ARM_KM
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM64:
                relocs = RELOCS_ARM64; imports = IMPORTS_ARM64_KM
            else:
                raise ValueError("Unsupported PE type")
        else:
            if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
                relocs = RELOCS_32; imports = _strip_tail(IMPORTS_32_UM, _IMPORTS_TAIL_32)
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
                relocs = RELOCS_64; imports = _strip_tail(IMPORTS_64_UM, _IMPORTS_TAIL_64)
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM:
                relocs = RELOCS_ARM; imports = IMPORTS_ARM_UM
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM64:
                relocs = RELOCS_ARM64; imports = IMPORTS_ARM64_UM
            else:
                raise ValueError("Unsupported PE type")
    else:
        if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            relocs = RELOCS_32
        elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            relocs = RELOCS_64
        elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM:
            relocs = RELOCS_ARM
        elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM64:
            relocs = RELOCS_ARM64
        else:
            raise ValueError("Unsupported PE type")

    # Layout: imports_resolver (tail stripped) | relocs_resolver | PE_image
    # The imports resolver falls through into the relocs resolver which applies
    # base relocations and JMPs to the PE entry point.
    output_file.write_bytes(imports + relocs + ram_layout)


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input-file',      required=True, type=Path, help='Path to a PE-file')
    parser.add_argument('-m', '--ignore-imports',  action='store_true',      help='Zero the import directory in the output')
    parser.add_argument('-r', '--resolve-imports', action='store_true',      help='Prepend import resolver shellcode')
    parser.add_argument('-k', '--kernel-mode',     action='store_true',      help='Use kernel-mode import resolver')
    parser.add_argument('-e', '--efi-mode',        action='store_true',      help='Use EFI import resolver')
    parser.add_argument('-o', '--output-file',     required=True, type=Path, help='Path to output shellcode file')
    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.ignore_imports and args.resolve_imports:
        print("Error: --ignore-imports and --resolve-imports are mutually exclusive")
        return
    if args.kernel_mode and not args.resolve_imports:
        print("Error: --kernel-mode requires --resolve-imports")
        return
    if args.efi_mode and not args.resolve_imports:
        print("Error: --efi-mode requires --resolve-imports")
        return
    if args.kernel_mode and args.efi_mode:
        print("Error: --kernel-mode and --efi-mode are mutually exclusive")
        return

    pe = PE(str(args.input_file))
    dump_memory_layout(pe, args.output_file, args.ignore_imports,
                       args.resolve_imports, args.kernel_mode, args.efi_mode)


if __name__ == '__main__':
    main()
