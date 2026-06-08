import argparse
from pathlib import Path
from pefile import PE, OPTIONAL_HEADER_MAGIC_PE, OPTIONAL_HEADER_MAGIC_PE_PLUS

# PE Magic numbers for different architectures
OPTIONAL_HEADER_MAGIC_ARM = 0x10B3    # ARM
OPTIONAL_HEADER_MAGIC_ARM64 = 0x20B3  # ARM64

# Existing x86 relocation shellcode
RELOCS_32 = bytes.fromhex('e8000000005b89df83c77b89fb66813b4d5a756b8b733c01de813e50450000755e89d82b463489c785ff74478b86a000000085c0743d01d889c68b168b4e0483c60885c9742d83e908d1e974ed66ad6685c074e60fb7c089c525ff0f0000c1ed0c83fd0375088d2c1301c5017d004975dcebc78b733c01de8b462801d8ffe0f4')
RELOCS_64 = bytes.fromhex('e8000000005b488dbb970000004889fb66813b4d5a0f85800000008b733c4801de813e504500007572488b46304889df4829c74885ff74558b86b800000085c0744b4801d84889c68b168b4e044883c60885c9743883e908d1e974ec66ad6685c074e5440fb7c0664589c14181e0ff0f00006641c1e90c4180f90a750a4c8d14134d01c249013affc975d1ebbb8b733c4801de8b46284801d8ffe0f4')

# ARM relocation shellcode (Thumb mode)
RELOCS_ARM = bytes.fromhex('00482DE900B08DE2000050E30000A0131A0050E3F0FF1F0A0000A0E30090BDE8')

# ARM64 relocation shellcode
RELOCS_ARM64 = bytes.fromhex('FD7BBFA9FD030091E0031F2AF30300AAE0000010E1000054E2031F2A21000054E003102AE0000010E100005420008052E0030091C0035FD6')

# Import resolution shellcode - usermode
IMPORTS_32_UM = bytes.fromhex('60648B3564A12C8B40C8B74014AD8B36AD96893E8B4010895DCCBB7803000089D88B403C01D88B7878895DE003F88B48248B582C8B701C03DF03FB03F7FCB9130000004939C975F58B5DCC8B5E3603DE668B0C4E8B5E2803DE8B048E01D8A3000000008B3D040000005368000000008B1D00000000FFD7A3080000008D45E2E8000000005E2D000000008B463C01F08B8080000000A3100000008B3D100000008B0F85C90F84A30000008D0C368B3D080000005157FFD785C00F8488000000894424048B3D1000000083C70C8B4F0485C90F8469000000034C24048B3D040000005051FFD7894424088B7C240483C70485C90F8442000000034C24048B3D040000005051FFD7EB1C25FFFF00008B3D040000005051FFD78B4C24088B3D100000008B4F1003CE894C240C034E1C8901834C240C04834424080483C704E9B9FFFFFF83C714E958FFFFFF61C3')
IMPORTS_64_UM = bytes.fromhex('565756534154415541564157488B6C24104865488B306548AD488D68184889E64883C6204889F0488B00488B40204889C3488B5B204889DF488B3B4C8B6B084C8B63184C89E9488D3D130000004C89E2B90D0000004839C8750A49FFC1E2E04C89E1EB894C8B43304889DF4C29F94885FF74554C8B43384885C0744B4801D84889C64C8B0E4C8B4E084983C6084885C9743883E908D1E974EC66414139C074E54489C84181E0FF0F00004181F80A750A4C8D14114D01C0490132FFC975D1EB8B4C8B43284801D8FFE0')
IMPORTS_ARM_UM = bytes.fromhex('') # Placeholder for ARM usermode import resolver
IMPORTS_ARM64_UM = bytes.fromhex('') # Placeholder for ARM64 usermode import resolver

# Import resolution shellcode - kernelmode
IMPORTS_32_KM = bytes.fromhex('60BB7803000089D88B403C01D88B7878895DE003F88B48248B582C8B701C03DF03FB03F7FCB9130000004939C975F58B5DCC8B5E3603DE668B0C4E8B5E2803DE8B048E01D8A3000000008B3D040000005368000000008B1D00000000FFD7A3080000008D45E2E8000000005E2D000000008B463C01F08B8080000000A3100000008B3D100000008B0F85C90F84A30000008D0C368B3D080000005157FFD785C00F8488000000894424048B3D1000000083C70C8B4F0485C90F8469000000034C24048B3D040000005051FFD7894424088B7C240483C70485C90F8442000000034C24048B3D040000005051FFD7EB1C25FFFF00008B3D040000005051FFD78B4C24088B3D100000008B4F1003CE894C240C034E1C8901834C240C04834424080483C704E9B9FFFFFF83C714E958FFFFFF61C3')
IMPORTS_64_KM = bytes.fromhex('565756534154415541564157488B6C24104865488B306548AD488D68184889E64883C6204889F0488B00488B40204889C3488B5B204889DF488B3B4C8B6B084C8B63184C89E9488D3D130000004C89E2B90D0000004839C8750A49FFC1E2E04C89E1EB894C8B43304889DF4C29F94885FF74554C8B43384885C0744B4801D84889C64C8B0E4C8B4E084983C6084885C9743883E908D1E974EC66414139C074E54489C84181E0FF0F00004181F80A750A4C8D14114D01C0490132FFC975D1EB8B4C8B43284801D8FFE0')
IMPORTS_ARM_KM = bytes.fromhex('') # Placeholder for ARM kernelmode import resolver
IMPORTS_ARM64_KM = bytes.fromhex('') # Placeholder for ARM64 kernelmode import resolver

# Import resolution shellcode - EFI
IMPORTS_32_EFI = bytes.fromhex('') # Placeholder for x86 EFI import resolver
IMPORTS_64_EFI = bytes.fromhex('') # Placeholder for x64 EFI import resolver
IMPORTS_ARM_EFI = bytes.fromhex('') # Placeholder for ARM EFI import resolver
IMPORTS_ARM64_EFI = bytes.fromhex('') # Placeholder for ARM64 EFI import resolver

def dump_memory_layout(pe: PE, output_file: Path, ignore_imports: bool = False, resolve_imports: bool = False, kernel_mode: bool = False, efi_mode: bool = False):
    # Get the memory layout
    ram_layout = bytearray()

    # Add PE header
    ram_layout.extend(pe.get_data(0, pe.OPTIONAL_HEADER.SizeOfHeaders))

    # Add sections
    for section in pe.sections:
        # Align to virtual address
        while len(ram_layout) < section.VirtualAddress:
            ram_layout.append(0)

        # Add section data
        ram_layout.extend(section.get_data())

    # Pad to SizeOfImage
    while len(ram_layout) < pe.OPTIONAL_HEADER.SizeOfImage:
        ram_layout.append(0)

    # Add shellcode
    imports = b''
    relocs = b''

    if resolve_imports:
        if efi_mode:
            # EFI mode import resolution
            if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:  # x86
                relocs = RELOCS_32
                imports = IMPORTS_32_EFI
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:  # x64
                relocs = RELOCS_64
                imports = IMPORTS_64_EFI
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM:  # ARM
                relocs = RELOCS_ARM
                imports = IMPORTS_ARM_EFI
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM64:  # ARM64
                relocs = RELOCS_ARM64
                imports = IMPORTS_ARM64_EFI
            else:
                raise ValueError("Unsupported PE file type. Supported types: x86, x64, ARM, ARM64")
        elif kernel_mode:
            # Kernel mode import resolution
            if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:  # x86
                relocs = RELOCS_32
                imports = IMPORTS_32_KM
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:  # x64
                relocs = RELOCS_64
                imports = IMPORTS_64_KM
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM:  # ARM
                relocs = RELOCS_ARM
                imports = IMPORTS_ARM_KM
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM64:  # ARM64
                relocs = RELOCS_ARM64
                imports = IMPORTS_ARM64_KM
            else:
                raise ValueError("Unsupported PE file type. Supported types: x86, x64, ARM, ARM64")
        else:
            # User mode import resolution
            if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:  # x86
                relocs = RELOCS_32
                imports = IMPORTS_32_UM
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:  # x64
                relocs = RELOCS_64
                imports = IMPORTS_64_UM
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM:  # ARM
                relocs = RELOCS_ARM
                imports = IMPORTS_ARM_UM
            elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM64:  # ARM64
                relocs = RELOCS_ARM64
                imports = IMPORTS_ARM64_UM
            else:
                raise ValueError("Unsupported PE file type. Supported types: x86, x64, ARM, ARM64")
    else:
        if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:  # x86
            relocs = RELOCS_32
        elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:  # x64
            relocs = RELOCS_64
        elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM:  # ARM
            relocs = RELOCS_ARM
        elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_ARM64:  # ARM64
            relocs = RELOCS_ARM64
        else:
            raise ValueError("Unsupported PE file type. Supported types: x86, x64, ARM, ARM64")

    # Write shellcode in order: import resolver (if needed), relocation resolver, PE image
    output_file.write_bytes(imports + relocs + ram_layout)


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input-file', required=True, type=Path, help='Path to a PE-file')
    parser.add_argument('-m', '--ignore-imports', action='store_true', help='Ignore imports in the PE file')
    parser.add_argument('-r', '--resolve-imports', action='store_true', help='Add import resolver shellcode')
    parser.add_argument('-k', '--kernel-mode', action='store_true', help='Use kernel-mode import resolver')
    parser.add_argument('-e', '--efi-mode', action='store_true', help='Use EFI import resolver')
    parser.add_argument('-o', '--output-file', required=True, type=Path, help='Path to output shellcode file')

    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.ignore_imports and args.resolve_imports:
        print("Error: Cannot use both --ignore-imports and --resolve-imports at the same time")
        return

    if args.kernel_mode and not args.resolve_imports:
        print("Error: --kernel-mode option requires --resolve-imports")
        return

    if args.efi_mode and not args.resolve_imports:
        print("Error: --efi-mode option requires --resolve-imports")
        return

    if args.kernel_mode and args.efi_mode:
        print("Error: Cannot use both --kernel-mode and --efi-mode at the same time")
        return

    pe = PE(args.input_file)
    dump_memory_layout(pe, args.output_file, args.ignore_imports, args.resolve_imports, args.kernel_mode, args.efi_mode)


if __name__ == '__main__':
    main()
