import sys
import struct
import argparse
from pathlib import Path
from pefile import PE, OPTIONAL_HEADER_MAGIC_PE, OPTIONAL_HEADER_MAGIC_PE_PLUS
from peor._shellcodes import (
    RELOCS_32, RELOCS_64,
    IMPORTS_32_UM, IMPORTS_64_UM,
    IMPORTS_64_LINUX, IMPORTS_32_LINUX,
    DELAY_IMPORTS_32_UM, DELAY_IMPORTS_64_UM,
    ENTRYPOINT_32, ENTRYPOINT_64,
    ENTRYPOINT_EFI64, ENTRYPOINT_EFI32,
    SEH_REGISTRAR_32, SEH_REGISTRAR_64,
    TLS_CALLBACKS_32, TLS_CALLBACKS_64,
    CXX_EH_FIXER_64,
    CTORS_RUNNER_64, CTORS_RUNNER_32,
)

# PE Optional Header Data Directory indices (PECOFF spec §3.4)
IMAGE_DIRECTORY_ENTRY_EXPORT         = 0
IMAGE_DIRECTORY_ENTRY_IMPORT         = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3
IMAGE_DIRECTORY_ENTRY_SECURITY       = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5
IMAGE_DIRECTORY_ENTRY_DEBUG          = 6
IMAGE_DIRECTORY_ENTRY_TLS            = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

# Trailing bytes that terminate each import resolver so it falls through into the
# relocs resolver. We strip them at output time.
#   x86: 0xC3 (RET)          → stripped → falls through to next resolver
#   x64: 0xFF 0xE0 (JMP RAX) → stripped → falls through to next resolver
_IMPORTS_TAIL_32 = b'\xc3'
_IMPORTS_TAIL_64 = b'\xff\xe0'

# Magic placeholders in cxx_eh_fixer64.asm replaced at build time by peor.
# PE_SIZE_MAGIC: patched to pe.OPTIONAL_HEADER.SizeOfImage.
# IAT_RVA_MAGIC: patched to the IAT-entry RVA for the hooked function.
_CXX_EH_PE_SIZE_MAGIC_64 = b'\x78\x56\x34\x12'  # 0x12345678 LE (in ADD RCX, imm32)
_CXX_EH_IAT_RVA_MAGIC_64 = b'\x21\x43\x65\x87'  # 0x87654321 LE (in LEA RDX, [RBX+disp32])

# Magic placeholder in entrypoint_resolver{32,64}.asm for AddressOfEntryPoint RVA.
# peor patches this to the actual OEP RVA (or a named-export RVA for --entry).
_EP_RVA_MAGIC = b'\xce\xce\xce\xce'  # 0xCECECECE LE (in MOV EAX, imm32)

# Magic placeholders in ctors_runner{32,64}.asm for .init_array section RVA and size.
# Patched at conversion time when a .init_array or .ctors section is found.
_CTORS_RVA_MAGIC  = b'\xfd\xfc\xfb\xfa'   # 0xFAFBFCFD LE
_CTORS_SIZE_MAGIC = b'\xe4\xe3\xe2\xe1'   # 0xE1E2E3E4 LE

# Maximum signed 32-bit displacement for the LEA disp32 field in the relocs resolver.
_MAX_SHELLCODE_DISP32 = 0x7FFFFFFF

# Windows PE Subsystem constants (PECOFF/UEFI spec).
_NATIVE_SUBSYSTEM       = 1   # Windows native (kernel-mode drivers)
_POSIX_CUI_SUBSYSTEM    = 7   # POSIX CUI — auto-selects Linux shellcode chain
_EFI_SUBSYSTEMS = frozenset({10, 11, 12, 13})   # EFI_APPLICATION / BOOT_SERVICE / RUNTIME / ROM

# Platform keys used to select a shellcode chain in _SHELLCODES.
# User-facing platform names (_PLATFORM_LINUX / _PLATFORM_EFI) select the
# architecture-specific variant based on pe.PE_TYPE at validation time.
_PLATFORM_LINUX    = 'linux'
_PLATFORM_EFI      = 'efi'
_PLATFORM_LINUX_32 = 'linux32'   # internal key for x86 Linux chain
_PLATFORM_EFI_32   = 'efi32'     # internal key for x86 EFI chain

# Per-architecture shellcode table.
# dir_array_offset: bytes from the optional-header start to the DataDirectory array
#   PE32  (0x10B): 96  bytes  (PECOFF spec §3.4.1)
#   PE32+ (0x20B): 112 bytes  (PECOFF spec §3.4.2)
# disp32_off: byte index of the LEA disp32 field inside the assembled relocs resolver
#   RELOCS_32: e8..(5) 5b(1) 8d bb <disp32>(4)    → disp32 at byte 8
#   RELOCS_64: e8..(5) 5b(1) 48 8d bb <disp32>(4) → disp32 at byte 9
_SHELLCODES = {
    OPTIONAL_HEADER_MAGIC_PE: {
        'relocs':            RELOCS_32,
        'imports':           IMPORTS_32_UM,
        'delay_imports':     DELAY_IMPORTS_32_UM,
        'entrypoint':        ENTRYPOINT_32,
        'seh':               SEH_REGISTRAR_32,
        'seh_always':        True,               # x86 uses FS:[0] SEH chains — always needed
        'tls':               TLS_CALLBACKS_32,
        'tail':              _IMPORTS_TAIL_32,
        'dir_array_offset':  96,
        'disp32_off':        8,
        'ep_rva_magic':      _EP_RVA_MAGIC,
    },
    OPTIONAL_HEADER_MAGIC_PE_PLUS: {
        'relocs':            RELOCS_64,
        'imports':           IMPORTS_64_UM,
        'delay_imports':     DELAY_IMPORTS_64_UM,
        'entrypoint':        ENTRYPOINT_64,
        'seh':               SEH_REGISTRAR_64,
        'seh_always':        False,              # x64: only needed when .pdata (DataDir[3]) is present
        'tls':               TLS_CALLBACKS_64,
        'cxx_eh_fixer':      CXX_EH_FIXER_64,
        'cxx_eh_import':     b'RtlPcToFileHeader',
        'cxx_pe_size_magic': _CXX_EH_PE_SIZE_MAGIC_64,
        'cxx_iat_rva_magic': _CXX_EH_IAT_RVA_MAGIC_64,
        'tail':              _IMPORTS_TAIL_64,
        'dir_array_offset':  112,
        'disp32_off':        9,
        'ep_rva_magic':      _EP_RVA_MAGIC,
    },
    # Linux x64 user-mode: self-contained dlsym/dlopen finder via /proc/self/maps.
    # Selected when Subsystem == _POSIX_CUI_SUBSYSTEM (7) and PE_TYPE == PE32+, or --platform linux.
    _PLATFORM_LINUX: {
        'relocs':            RELOCS_64,
        'imports':           IMPORTS_64_LINUX,
        'delay_imports':     b'',
        'entrypoint':        ENTRYPOINT_64,
        'seh':               b'',
        'seh_always':        False,
        'tls':               b'',
        'ctors':             CTORS_RUNNER_64,
        'ctors_rva_magic':   _CTORS_RVA_MAGIC,
        'ctors_size_magic':  _CTORS_SIZE_MAGIC,
        'tail':              _IMPORTS_TAIL_64,
        'dir_array_offset':  112,
        'disp32_off':        9,
        'ep_rva_magic':      _EP_RVA_MAGIC,
    },
    # Linux x86 user-mode: self-contained dlsym/dlopen finder via /proc/self/maps (int 0x80, ELF32).
    # Selected when Subsystem == _POSIX_CUI_SUBSYSTEM (7) and PE_TYPE == PE32, or --platform linux.
    _PLATFORM_LINUX_32: {
        'relocs':            RELOCS_32,
        'imports':           IMPORTS_32_LINUX,
        'delay_imports':     b'',
        'entrypoint':        ENTRYPOINT_32,
        'seh':               b'',
        'seh_always':        False,
        'tls':               b'',
        'ctors':             CTORS_RUNNER_32,
        'ctors_rva_magic':   _CTORS_RVA_MAGIC,
        'ctors_size_magic':  _CTORS_SIZE_MAGIC,
        'tail':              _IMPORTS_TAIL_32,
        'dir_array_offset':  96,
        'disp32_off':        8,
        'ep_rva_magic':      _EP_RVA_MAGIC,
    },
    # EFI x64: self-contained — entrypoint resolver scans memory for EFI_SYSTEM_TABLE_SIGNATURE.
    # Selected when Subsystem in _EFI_SUBSYSTEMS and PE_TYPE == PE32+, or --platform efi.
    _PLATFORM_EFI: {
        'relocs':            RELOCS_64,
        'imports':           b'',
        'delay_imports':     b'',
        'entrypoint':        ENTRYPOINT_EFI64,
        'seh':               b'',
        'seh_always':        False,
        'tls':               b'',
        'ctors':             CTORS_RUNNER_64,
        'ctors_rva_magic':   _CTORS_RVA_MAGIC,
        'ctors_size_magic':  _CTORS_SIZE_MAGIC,
        'tail':              _IMPORTS_TAIL_64,
        'dir_array_offset':  112,
        'disp32_off':        9,
        'ep_rva_magic':      _EP_RVA_MAGIC,
    },
    # EFI x86: self-contained — entrypoint resolver scans memory for EFI_SYSTEM_TABLE_SIGNATURE.
    # Selected when Subsystem in _EFI_SUBSYSTEMS and PE_TYPE == PE32, or --platform efi.
    _PLATFORM_EFI_32: {
        'relocs':            RELOCS_32,
        'imports':           b'',
        'delay_imports':     b'',
        'entrypoint':        ENTRYPOINT_EFI32,
        'seh':               b'',
        'seh_always':        False,
        'tls':               b'',
        'ctors':             CTORS_RUNNER_32,
        'ctors_rva_magic':   _CTORS_RVA_MAGIC,
        'ctors_size_magic':  _CTORS_SIZE_MAGIC,
        'tail':              _IMPORTS_TAIL_32,
        'dir_array_offset':  96,
        'disp32_off':        8,
        'ep_rva_magic':      _EP_RVA_MAGIC,
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
    return (len(dirs) > IMAGE_DIRECTORY_ENTRY_EXCEPTION
            and dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress != 0)


def _has_tls_callbacks(pe: PE) -> bool:
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    if len(dirs) <= IMAGE_DIRECTORY_ENTRY_TLS or dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0:
        return False
    tls_rva = dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
    # AddressOfCallBacks: offset 0x0C in IMAGE_TLS_DIRECTORY32, 0x18 in IMAGE_TLS_DIRECTORY64
    if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
        cb_off, ptr_size = 0x0C, 4
    else:
        cb_off, ptr_size = 0x18, 8
    raw = pe.get_data(tls_rva + cb_off, ptr_size)
    return int.from_bytes(raw, 'little') != 0


def _has_imports(pe: PE) -> bool:
    """Return True only when the PE contains actual import descriptors to resolve.

    A DataDir[1].VirtualAddress != 0 is not sufficient: some toolchains (MinGW,
    lld) emit a null-sentinel-only .idata section with no real entries.  Use
    pefile's parsed DIRECTORY_ENTRY_IMPORT list as the authoritative source.
    """
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    if not (len(dirs) > IMAGE_DIRECTORY_ENTRY_IMPORT
            and dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0):
        return False
    return bool(getattr(pe, 'DIRECTORY_ENTRY_IMPORT', None))


def _has_delay_imports(pe: PE) -> bool:
    """Return True when DataDir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] is non-zero."""
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    return (len(dirs) > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
            and dirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress != 0)


def _find_export_rva(pe: PE, name_or_ordinal: str) -> int:
    """Look up a PE export by name or ordinal, return its RVA."""
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        raise ValueError("PE has no export directory; cannot use --entry")
    if name_or_ordinal.isdigit():
        ordinal = int(name_or_ordinal)
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.ordinal == ordinal:
                return exp.address
        raise ValueError(f"Export ordinal {ordinal} not found")
    name_bytes = name_or_ordinal.encode()
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name == name_bytes:
            return exp.address
    raise ValueError(f"Export '{name_or_ordinal}' not found in PE")


def _find_ctors_section(pe: PE) -> "tuple[int, int] | None":
    """Return (rva, size) of .init_array or .ctors section, or None if absent."""
    for section in pe.sections:
        name = section.Name.rstrip(b'\x00')
        if name in (b'.init_array', b'.ctors'):
            size = section.Misc_VirtualSize
            if size > 0:
                return section.VirtualAddress, size
    return None


def _validate_pe(pe: PE, platform: str | None = None) -> dict:
    """Return the shellcode-chain entry dict for pe, or raise ValueError.

    platform overrides subsystem-based auto-detection when explicitly provided
    (e.g. '--platform linux' or '--platform efi').
    """
    subsystem = pe.OPTIONAL_HEADER.Subsystem

    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    if (len(dirs) > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
            and dirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0):
        raise ValueError("CLR/managed PE is not supported")

    if subsystem == _NATIVE_SUBSYSTEM and platform is None:
        raise ValueError(f"Kernel-mode PE (subsystem {subsystem}) is not yet supported")

    # Explicit --platform overrides subsystem-based detection.
    if platform == _PLATFORM_LINUX:
        if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            return _SHELLCODES[_PLATFORM_LINUX_32]
        return _SHELLCODES[_PLATFORM_LINUX]

    if platform == _PLATFORM_EFI:
        if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            return _SHELLCODES[_PLATFORM_EFI_32]
        return _SHELLCODES[_PLATFORM_EFI]

    # Auto-detect EFI or Linux from subsystem.
    if subsystem in _EFI_SUBSYSTEMS:
        if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            return _SHELLCODES[_PLATFORM_EFI_32]
        return _SHELLCODES[_PLATFORM_EFI]

    if subsystem == _POSIX_CUI_SUBSYSTEM:
        if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            return _SHELLCODES[_PLATFORM_LINUX_32]
        return _SHELLCODES[_PLATFORM_LINUX]

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
    opt_off          = pe.DOS_HEADER.e_lfanew + 24
    import_entry_off = opt_off + entry['dir_array_offset'] + IMAGE_DIRECTORY_ENTRY_IMPORT * 8
    ram_layout[import_entry_off:import_entry_off + 8] = b'\x00' * 8


def _build_shellcode_chain(pe: PE, entry: dict, skip_imports: bool = False,
                            override_ep_rva: int | None = None) -> bytes:
    # Chain order: [imports] → relocs → [delay_imports] → [cxx_eh_fixer] → [seh] → [tls] → [ctors] → entrypoint → [pad]
    # delay_imports runs AFTER relocs so the relocs resolver doesn't overwrite the patched delay-load IAT
    # (delay-load IAT slots have DIR64 relocations; running delay_imports before relocs would get clobbered).
    # imports: skipped when skip_imports=True or when the PE has no import directory.
    imports       = (_strip_tail(entry['imports'], entry['tail'])
                     if not skip_imports and _has_imports(pe) else b'')
    delay_imports = (_strip_tail(entry['delay_imports'], entry['tail'])
                     if not skip_imports and _has_delay_imports(pe) else b'')
    relocs        = entry['relocs']
    seh           = entry['seh'] if (entry['seh'] and (entry.get('seh_always') or _has_exception_table(pe))) else b''
    tls           = entry['tls'] if (entry['tls'] and _has_tls_callbacks(pe)) else b''
    entrypoint    = bytearray(entry['entrypoint'])

    # cxx_eh_fixer: only when we resolved regular imports (needed for IAT lookup)
    if imports and entry.get('cxx_eh_fixer') is not None and entry.get('cxx_eh_import') is not None:
        iat_rva = _find_iat_rva(pe, entry['cxx_eh_import'])
        if iat_rva is not None:
            fixer = bytearray(entry['cxx_eh_fixer'])
            soi           = pe.OPTIONAL_HEADER.SizeOfImage
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

    # ctors runner: only for Linux and EFI chains (entry has 'ctors' key) and only when
    # the PE has a .init_array or .ctors section.  Patch the RVA and size magic values.
    ctors_info = _find_ctors_section(pe) if entry.get('ctors') is not None else None
    if ctors_info is not None:
        ctors_rva, ctors_sz = ctors_info
        ctors_bytes = bytearray(entry['ctors'])
        rva_magic  = entry['ctors_rva_magic']
        size_magic = entry['ctors_size_magic']
        if ctors_bytes.count(rva_magic) != 1:
            raise RuntimeError(f"CTORS_RVA_MAGIC {rva_magic.hex()} not unique in ctors runner")
        if ctors_bytes.count(size_magic) != 1:
            raise RuntimeError(f"CTORS_SIZE_MAGIC {size_magic.hex()} not unique in ctors runner")
        idx = ctors_bytes.find(rva_magic)
        ctors_bytes[idx:idx + 4] = struct.pack('<I', ctors_rva)
        idx = ctors_bytes.find(size_magic)
        ctors_bytes[idx:idx + 4] = struct.pack('<I', ctors_sz)
        ctors = bytes(ctors_bytes)
    else:
        ctors = b''

    # Patch the EP RVA magic in the entrypoint resolver.
    ep_rva = override_ep_rva if override_ep_rva is not None else pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_magic = entry.get('ep_rva_magic', b'')
    if ep_magic:
        if entrypoint.count(ep_magic) != 1:
            raise RuntimeError(f"EP_RVA_MAGIC {ep_magic.hex()} not unique in entrypoint resolver")
        idx = bytes(entrypoint).find(ep_magic)
        entrypoint[idx:idx + 4] = struct.pack('<I', ep_rva)
    entrypoint = bytes(entrypoint)

    # PE image must be 16-byte aligned in the buffer for MOVDQA/MOVAPS safety.
    align_pad = (
        -len(imports) - len(relocs) - len(delay_imports)
        - len(cxx_fixer) - len(seh) - len(tls) - len(ctors) - len(entrypoint)
    ) % 16

    # Patch the disp32 in the relocs resolver.
    # setup.py bakes in disp32 = len(relocs_assembled) - 5 (PE follows relocs standalone).
    # We add the remaining shellcodes + alignment padding that come after relocs.
    # delay_imports comes after relocs so it is included in extra.
    extra    = len(delay_imports) + len(cxx_fixer) + len(seh) + len(tls) + len(ctors) + len(entrypoint) + align_pad
    off      = entry['disp32_off']
    relocs   = bytearray(relocs)
    old      = int.from_bytes(relocs[off:off + 4], 'little')
    new_disp = old + extra
    if new_disp > _MAX_SHELLCODE_DISP32:
        raise ValueError(
            f"shellcode chain too large: relocs resolver disp32 {new_disp:#010x} "
            f"would overflow the signed 32-bit LEA field (max {_MAX_SHELLCODE_DISP32:#010x})"
        )
    relocs[off:off + 4] = new_disp.to_bytes(4, 'little')

    return (imports + bytes(relocs) + delay_imports + cxx_fixer + seh
            + tls + ctors + entrypoint + (b'\x90' * align_pad))


def _shellcode_info(pe: PE, entry: dict, skip_imports: bool = False) -> dict:
    """Return per-component byte sizes for --info display; no shellcode is assembled."""
    imports       = (_strip_tail(entry['imports'], entry['tail'])
                     if not skip_imports and _has_imports(pe) else b'')
    delay_imports = (_strip_tail(entry['delay_imports'], entry['tail'])
                     if not skip_imports and _has_delay_imports(pe) else b'')
    relocs        = entry['relocs']
    seh           = entry['seh'] if (entry['seh'] and (entry.get('seh_always') or _has_exception_table(pe))) else b''
    tls           = entry['tls'] if (entry['tls'] and _has_tls_callbacks(pe)) else b''
    entrypoint    = entry['entrypoint']

    if imports and entry.get('cxx_eh_fixer') and entry.get('cxx_eh_import'):
        iat_rva   = _find_iat_rva(pe, entry['cxx_eh_import'])
        cxx_fixer = entry['cxx_eh_fixer'] if iat_rva is not None else b''
    else:
        cxx_fixer = b''

    ctors_info = _find_ctors_section(pe) if entry.get('ctors') is not None else None
    ctors = entry['ctors'] if ctors_info is not None else b''

    align_pad = (
        -len(imports) - len(relocs) - len(delay_imports)
        - len(cxx_fixer) - len(seh) - len(tls) - len(ctors) - len(entrypoint)
    ) % 16
    pe_image_size = pe.OPTIONAL_HEADER.SizeOfImage
    total         = (len(imports) + len(relocs) + len(delay_imports) + len(cxx_fixer)
                     + len(seh) + len(tls) + len(ctors) + len(entrypoint) + align_pad + pe_image_size)

    return {
        'imports':       len(imports)       if imports       else None,
        'delay_imports': len(delay_imports) if delay_imports else None,
        'relocs':        len(relocs),
        'cxx_eh':        len(cxx_fixer)     if cxx_fixer     else None,
        'seh':           len(seh)           if seh           else None,
        'tls':           len(tls)           if tls           else None,
        'ctors':         len(ctors)         if ctors         else None,
        'entrypoint':    len(entrypoint),
        'align_pad':     align_pad          if align_pad     else None,
        'PE image':      pe_image_size,
        'total':         total,
    }


def _print_info(info: dict, pe_name: str) -> None:
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


def _make_shellcode(pe: PE, ignore_imports: bool = False, no_imports: bool = False,
                    override_ep_rva: int | None = None,
                    platform: str | None = None) -> bytes:
    entry      = _validate_pe(pe, platform=platform)
    ram_layout = _build_ram_layout(pe)
    if ignore_imports:
        _zero_import_dir(ram_layout, pe, entry)
    prefix = _build_shellcode_chain(pe, entry, skip_imports=no_imports, override_ep_rva=override_ep_rva)
    return prefix + bytes(ram_layout)


def dump_memory_layout(pe: PE, output_file: Path, ignore_imports: bool = False,
                       no_imports: bool = False, override_ep_rva: int | None = None,
                       platform: str | None = None):
    output_file.write_bytes(_make_shellcode(pe, ignore_imports, no_imports, override_ep_rva,
                                            platform=platform))


_SUPPORTED_PLATFORMS = (_PLATFORM_LINUX, _PLATFORM_EFI)


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

    if args.info:
        entry = _validate_pe(pe, platform=args.platform)
        info  = _shellcode_info(pe, entry, skip_imports=args.no_imports)
        _print_info(info, args.input_file.name)
        return

    shellcode = _make_shellcode(pe, args.ignore_imports, args.no_imports, override_ep_rva,
                                platform=args.platform)
    if args.output_file == '-':
        sys.stdout.buffer.write(shellcode)
    else:
        Path(args.output_file).write_bytes(shellcode)


if __name__ == '__main__':
    main()
