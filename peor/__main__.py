import shutil
import argparse
from pefile import PE
from pathlib import Path


def dump_memory_layout(pe: PE, output_file: Path):
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    ram_layout = bytearray(size_of_image)

    headers_size = pe.OPTIONAL_HEADER.SizeOfHeaders
    ram_layout[:headers_size] = pe.__data__[:headers_size]

    for section in pe.sections:
        raw_data = section.get_data()
        virtual_address = section.VirtualAddress
        size = min(len(raw_data), section.Misc_VirtualSize)
        ram_layout[virtual_address : (virtual_address + size)] = raw_data

    # TODO: get per arch, embedded resource
    output_file.write_bytes(Path('./relocations_resolver32').read_bytes() + ram_layout)


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input-file', required=True, type=Path, help='Path to a PE-file')
    parser.add_argument('-o', '--output-file', required=True, type=Path, help='Path to output shellcode file')

    return parser.parse_args()


def main():
    args = parse_arguments()

    pe = PE(args.input_file)
    dump_memory_layout(pe, args.output_file)


if __name__ == '__main__':
    main()
