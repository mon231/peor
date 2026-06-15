import argparse
from pathlib import Path
from pefile import PE, OPTIONAL_HEADER_MAGIC_PE, OPTIONAL_HEADER_MAGIC_PE_PLUS

# PE Magic numbers for different architectures
OPTIONAL_HEADER_MAGIC_ARM = 0x10B3    # ARM
OPTIONAL_HEADER_MAGIC_ARM64 = 0x20B3  # ARM64

# Relocation resolver shellcodes — each does CALL/POP to get its own address,
# locates the PE image appended immediately after itself, applies base relocations,
# then JMPs to the PE entry point.
RELOCS_32 = bytes.fromhex('e8000000005b89df83c77b89fb66813b4d5a756b8b733c01de813e50450000755e89d82b463489c785ff74478b86a000000085c0743d01d889c68b168b4e0483c60885c9742d83e908d1e974ed66ad6685c074e60fb7c089c525ff0f0000c1ed0c83fd0375088d2c1301c5017d004975dcebc78b733c01de8b462801d8ffe0f4')
RELOCS_64 = bytes.fromhex('e8000000005b488dbb970000004889fb66813b4d5a0f85800000008b733c4801de813e504500007572488b46304889df4829c74885ff74558b86b000000085c0744b4801d84889c68b168b4e044883c60885c9743883e908d1e974ec66ad6685c074e5440fb7c0664589c14181e0ff0f00006641c1e90c4180f90a750a4c8d14134d01c249013affc975d1ebbb8b733c4801de8b46284801d8ffe0f4')

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

# Import resolution shellcode - usermode
IMPORTS_32_UM = bytes.fromhex('6089e583ec0864a1300000008b400c8b70148b368b368b5e108b433c01d88b407801d8508b48188b502001dae80f00000047657450726f6341646472657373005f490f88e70000008b348a01de565157b90f000000fcf3a65f595e75e4588b702401de0fb70c4e8b701c01de8b048e01d88945fce80d0000004c6f61644c6962726172794100595153ff55fc8945f8e8000000005e81c6000100004666813e4d5a75f88b463c8d1406813a5045000075ea8b463c01f08b808000000085c00f846b00000001f089c78b470c85c00f845c00000001f050ff55f885c0744d89c38b1785d2740901f28b4f1001f1eb078b571001f289d18b0285c0742fa9000000807510515201f083c0025053ff55fc5a59eb0e515225ffff00005053ff55fc5a59890183c20483c104ebcb83c714eb9989ec61c3')
IMPORTS_64_UM = bytes.fromhex('5657535541544155415641574883ec2865488b042560000000488b4018488b7020488b36488b36488b5e208b433c4801d88b80880000004801d84889c58b48188b50204801dae80f00000047657450726f6341646472657373005fffc90f880a0100008b348a4801de56515257b90f000000fcf3a65f5a595e75e08b75244801de0fb70c4e8b751c4801de8b048e4801d84989c4e80d0000004c6f61644c69627261727941005a4889d941ffd44989c5e8000000005e4881c60001000048ffc666813e4d5a75f68b463c488d1406813a5045000075e74989f68b463c4801f08b809000000085c00f84800000004c01f04889c78b470c85c00f846f0000004c01f04889c141ffd54885c0745b4889c38b3785f6740e4c01f68b47104c01f04989c7eb098b77104c01f64989f7488b064885c074334885c078124c01f04883c0024889c24889d941ffd4eb0f4825ffff00004889c24889d941ffd44989074883c6084983c708ebc54883c714eb864883c428415f415e415d415c5d5b5f5effe0')
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
