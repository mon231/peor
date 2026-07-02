import sys
import argparse
from pathlib import Path
from pefile import PE

from peor._pe_features import (
    PeFeatures,
    PeorUnsupportedError,
    _detect_pe_features,
    _validate_pe_features,
    _find_export_rva,
    _PLATFORM_LINUX,
    _PLATFORM_EFI,
)
from peor._chain_builder import (
    _select_chain,
    _compute_required_stubs,
    _shellcode_info,
    _make_shellcode,
    dump_memory_layout,
    _validate_pe,
    _build_shellcode_chain,
    _SHELLCODES,
)

_SUPPORTED_PLATFORMS = (_PLATFORM_LINUX, _PLATFORM_EFI)


def _print_features(f: PeFeatures, required_stubs: "list | None" = None) -> None:
    _YN = {True: 'yes', False: 'no'}
    rows = [
        ('arch',              f.arch),
        ('subsystem',         str(f.subsystem)),
        ('has_relocs',        _YN[f.has_relocs]),
        ('has_imports',       _YN[f.has_imports]),
        ('has_delay_imports', _YN[f.has_delay_imports]),
        ('has_tls',           _YN[f.has_tls]),
        ('has_seh',           _YN[f.has_seh]),
        ('has_cxx_eh',        _YN[f.has_cxx_eh]),
        ('has_ctors',         _YN[f.has_ctors]),
        ('packed',            _YN[f.packed]),
        ('bss_sections',      ', '.join(f.bss_sections) if f.bss_sections else 'none'),
        ('ordinal_imports',   ', '.join(f.ordinal_imports) if f.ordinal_imports else 'none'),
        ('api_set_imports',   ', '.join(f.api_set_imports) if f.api_set_imports else 'none'),
        ('forwarded_exports', _YN[f.forwarded_exports]),
    ]
    if required_stubs is not None:
        rows.append(('required_stubs', ' -> '.join(required_stubs) if required_stubs else 'none'))
    rows.append(('issues', '; '.join(f.issues) if f.issues else 'none'))
    key_w = max(len(k) for k, _ in rows)
    print("PE features:")
    for k, v in rows:
        print(f"  {k:<{key_w}}  {v}")


def _print_info(info: dict, pe_name: str, features: "PeFeatures | None" = None,
                required_stubs: "list | None" = None) -> None:
    if features is not None:
        _print_features(features, required_stubs)
        print()
    rows  = [(k, v) for k, v in info.items() if k != 'total']
    key_w = max(len(k) for k, _ in rows)
    num_w = max((len(str(v)) for _, v in rows if v is not None), default=1)
    num_w = max(num_w, len(str(info['total'])))
    for key, val in rows:
        if val is not None:
            print(f"  {key:<{key_w}}  {val:>{num_w}} B")
        else:
            print(f"  {key:<{key_w}}  {'—':>{num_w + 2}}")
    print(f"  {'-' * (key_w + num_w + 4)}")
    print(f"  {'total':<{key_w}}  {info['total']:>{num_w}} B  ({pe_name})")


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input-file',    required=True,  type=Path, help='Path to a PE-file')
    parser.add_argument('-m', '--ignore-imports', action='store_true',      help='Zero the import directory in the output')
    parser.add_argument('--no-imports',           action='store_true',      help='Skip import resolvers even if PE has imports')
    parser.add_argument('-e', '--entry',           type=str, default=None,  help='Call named export (or ordinal) instead of OEP')
    parser.add_argument('-o', '--output-file',    required=False, type=str, help='Output path, or "-" for stdout')
    parser.add_argument(      '--info',            action='store_true',     help='Print resolver sizes without writing output')
    parser.add_argument('--platform',              type=str, default=None,
                        choices=_SUPPORTED_PLATFORMS,
                        help='Override target platform (linux | efi); auto-detected from subsystem otherwise')
    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.ignore_imports and args.no_imports:
        print("Error: --ignore-imports and --no-imports are mutually exclusive")
        return

    if args.info and args.output_file:
        print("Error: --info and --output-file are mutually exclusive")
        return

    if not args.info and not args.output_file:
        print("Error: --output-file is required (use '-' for stdout, or --info for dry-run)")
        return

    pe = PE(str(args.input_file))

    override_ep_rva = None
    if args.entry:
        override_ep_rva = _find_export_rva(pe, args.entry)

    features = _detect_pe_features(pe)

    try:
        _validate_pe_features(features, platform=args.platform)
    except PeorUnsupportedError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    entry = _select_chain(features, platform=args.platform)

    if args.info:
        required_stubs = _compute_required_stubs(features, entry)
        info           = _shellcode_info(features, entry, skip_imports=args.no_imports)
        _print_info(info, args.input_file.name, features=features, required_stubs=required_stubs)
        return

    try:
        shellcode = _make_shellcode(pe, features, entry, args.ignore_imports, args.no_imports,
                                    override_ep_rva)
    except (PeorUnsupportedError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.output_file == '-':
        sys.stdout.buffer.write(shellcode)
    else:
        Path(args.output_file).write_bytes(shellcode)


if __name__ == '__main__':
    main()
