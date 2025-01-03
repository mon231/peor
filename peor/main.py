import pefile
import argparse
from pathlib import Path


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input-file', required=True, type=Path, help='Path to a PE-file')
    parser.add_argument('-o', '--output-file', required=True, type=Path, help='Path to output shellcode file')

    return parser.parse_args()


def main():
    args = parse_arguments()
    raise NotImplementedError('Tools is in WIP state')


if __name__ == '__main__':
    main()
