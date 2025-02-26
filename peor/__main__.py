import argparse
from pathlib import Path
from pefile import PE, OPTIONAL_HEADER_MAGIC_PE, OPTIONAL_HEADER_MAGIC_PE_PLUS


RELOCS_32 = bytes.fromhex('e8000000005b89df83c77b89fb66813b4d5a756b8b733c01de813e50450000755e89d82b463489c785ff74478b86a000000085c0743d01d889c68b168b4e0483c60885c9742d83e908d1e974ed66ad6685c074e60fb7c089c525ff0f0000c1ed0c83fd0375088d2c1301c5017d004975dcebc78b733c01de8b462801d8ffe0f4')
RELOCS_64 = bytes.fromhex('e8000000005b488dbb970000004889fb66813b4d5a0f85800000008b733c4801de813e504500007572488b46304889df4829c74885ff74558b86b800000085c0744b4801d84889c68b168b4e044883c60885c9743883e908d1e974ec66ad6685c074e5440fb7c0664589c14181e0ff0f00006641c1e90c4180f90a750a4c8d14134d01c249013affc975d1ebbb8b733c4801de8b46284801d8ffe0f4')


def dump_memory_layout(pe: PE, output_file: Path, ignore_imports: bool = False):
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') and not ignore_imports:
        raise ValueError("PE file contains imports")

    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    ram_layout = bytearray(size_of_image)

    headers_size = pe.OPTIONAL_HEADER.SizeOfHeaders
    ram_layout[:headers_size] = pe.__data__[:headers_size]

    for section in pe.sections:
        raw_data = section.get_data()
        virtual_address = section.VirtualAddress
        size = min(len(raw_data), section.Misc_VirtualSize)
        ram_layout[virtual_address : (virtual_address + size)] = raw_data

        if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            relocs = RELOCS_32
        elif pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            relocs = RELOCS_64
        else:
            raise ValueError("Unsupported PE file type")

        output_file.write_bytes(relocs + ram_layout)


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input-file', required=True, type=Path, help='Path to a PE-file')
    parser.add_argument('-m', '--ignore-imports', action='store_true', help='Ignore imports in the PE file')
    parser.add_argument('-o', '--output-file', required=True, type=Path, help='Path to output shellcode file')

    return parser.parse_args()


def main():
    args = parse_arguments()

    pe = PE(args.input_file)
    dump_memory_layout(pe, args.output_file, args.ignore_imports)


if __name__ == '__main__':
    main()
