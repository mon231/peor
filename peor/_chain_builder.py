import struct
from pathlib import Path
from pefile import PE, OPTIONAL_HEADER_MAGIC_PE, OPTIONAL_HEADER_MAGIC_PE_PLUS

from peor._pe_features import (
    PeFeatures,
    PeorUnsupportedError,
    _validate_pe_features,
    _detect_pe_features,
    IMAGE_DIRECTORY_ENTRY_IMPORT,
    _PLATFORM_LINUX, _PLATFORM_EFI,
    _PLATFORM_LINUX_32, _PLATFORM_EFI_32, _PLATFORM_EFI_ARM64, _PLATFORM_EFI_ARM32,
    _POSIX_CUI_SUBSYSTEM, _EFI_SUBSYSTEMS, _MACHINE_ARM64, _MACHINE_ARMNT, _MACHINE_ARMTHUMB,
)
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
    RELOCS_ARM64, CTORS_RUNNER_ARM64, ENTRYPOINT_EFI_ARM64,
    ARM64_EFI_PREFIX,
    RELOCS_ARM32, CTORS_RUNNER_ARM32, ENTRYPOINT_EFI_ARM32,
    ARM32_EFI_PREFIX,
)

# Trailing bytes stripped from import resolvers so they fall through into the next stub.
_IMPORTS_TAIL_32 = b'\xc3'        # RET
_IMPORTS_TAIL_64 = b'\xff\xe0'    # JMP RAX

# Magic placeholders in cxx_eh_fixer64.asm patched at build time.
_CXX_EH_PE_SIZE_MAGIC_64 = b'\x78\x56\x34\x12'   # 0x12345678 LE
_CXX_EH_IAT_RVA_MAGIC_64 = b'\x21\x43\x65\x87'   # 0x87654321 LE

# Magic placeholder for AddressOfEntryPoint in entrypoint_resolver{32,64}.asm.
_EP_RVA_MAGIC = b'\xce\xce\xce\xce'   # 0xCECECECE LE

# Magic placeholders for .init_array/ctors section RVA and size.
_CTORS_RVA_MAGIC  = b'\xfd\xfc\xfb\xfa'   # 0xFAFBFCFD LE
_CTORS_SIZE_MAGIC = b'\xe4\xe3\xe2\xe1'   # 0xE1E2E3E4 LE

# Maximum signed 32-bit LEA disp32 in the relocs resolver.
_MAX_SHELLCODE_DISP32 = 0x7FFFFFFF

# Per-architecture shellcode chain table.
_SHELLCODES = {
    OPTIONAL_HEADER_MAGIC_PE: {
        'relocs':            RELOCS_32,
        'imports':           IMPORTS_32_UM,
        'delay_imports':     DELAY_IMPORTS_32_UM,
        'entrypoint':        ENTRYPOINT_32,
        'seh':               SEH_REGISTRAR_32,
        'seh_always':        True,
        'tls':               TLS_CALLBACKS_32,
        'ctors':             CTORS_RUNNER_32,
        'ctors_rva_magic':   _CTORS_RVA_MAGIC,
        'ctors_size_magic':  _CTORS_SIZE_MAGIC,
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
        'seh_always':        False,
        'tls':               TLS_CALLBACKS_64,
        'ctors':             CTORS_RUNNER_64,
        'ctors_rva_magic':   _CTORS_RVA_MAGIC,
        'ctors_size_magic':  _CTORS_SIZE_MAGIC,
        'cxx_eh_fixer':      CXX_EH_FIXER_64,
        'cxx_pe_size_magic': _CXX_EH_PE_SIZE_MAGIC_64,
        'cxx_iat_rva_magic': _CXX_EH_IAT_RVA_MAGIC_64,
        'tail':              _IMPORTS_TAIL_64,
        'dir_array_offset':  112,
        'disp32_off':        9,
        'ep_rva_magic':      _EP_RVA_MAGIC,
    },
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
    _PLATFORM_EFI_ARM64: {
        'prefix':            ARM64_EFI_PREFIX,
        'relocs':            RELOCS_ARM64,
        'imports':           b'',
        'delay_imports':     b'',
        'entrypoint':        ENTRYPOINT_EFI_ARM64,
        'seh':               b'',
        'seh_always':        False,
        'tls':               b'',
        'ctors':             CTORS_RUNNER_ARM64,
        'ctors_rva_magic':   _CTORS_RVA_MAGIC,
        'ctors_size_magic':  _CTORS_SIZE_MAGIC,
        'tail':              b'',
        'dir_array_offset':  112,
        'disp64_off':        8,
        'ep_rva_magic':      _EP_RVA_MAGIC,
        'pe_align':          4096,
    },
    _PLATFORM_EFI_ARM32: {
        'prefix':            ARM32_EFI_PREFIX,
        'relocs':            RELOCS_ARM32,
        'imports':           b'',
        'delay_imports':     b'',
        'entrypoint':        ENTRYPOINT_EFI_ARM32,
        'seh':               b'',
        'seh_always':        False,
        'tls':               b'',
        'ctors':             CTORS_RUNNER_ARM32,
        'ctors_rva_magic':   _CTORS_RVA_MAGIC,
        'ctors_size_magic':  _CTORS_SIZE_MAGIC,
        'tail':              b'',
        'dir_array_offset':  96,
        'disp32_off':        8,
        'ep_rva_magic':      _EP_RVA_MAGIC,
        'pe_align':          4096,
    },
}


def _strip_tail(shellcode: bytes, tail: bytes) -> bytes:
    if shellcode and shellcode.endswith(tail):
        return shellcode[:-len(tail)]
    return shellcode


def _select_chain(features: PeFeatures, platform: "str | None" = None) -> dict:
    """Return the _SHELLCODES entry for this PE, or raise ValueError."""
    if platform == _PLATFORM_LINUX:
        return _SHELLCODES[_PLATFORM_LINUX_32 if features.pe_type == OPTIONAL_HEADER_MAGIC_PE else _PLATFORM_LINUX]
    if platform == _PLATFORM_EFI:
        if features.machine == _MACHINE_ARM64:
            return _SHELLCODES[_PLATFORM_EFI_ARM64]
        if features.machine in (_MACHINE_ARMNT, _MACHINE_ARMTHUMB):
            return _SHELLCODES[_PLATFORM_EFI_ARM32]
        return _SHELLCODES[_PLATFORM_EFI_32 if features.pe_type == OPTIONAL_HEADER_MAGIC_PE else _PLATFORM_EFI]
    if features.subsystem in _EFI_SUBSYSTEMS:
        if features.machine == _MACHINE_ARM64:
            return _SHELLCODES[_PLATFORM_EFI_ARM64]
        if features.machine in (_MACHINE_ARMNT, _MACHINE_ARMTHUMB):
            return _SHELLCODES[_PLATFORM_EFI_ARM32]
        return _SHELLCODES[_PLATFORM_EFI_32 if features.pe_type == OPTIONAL_HEADER_MAGIC_PE else _PLATFORM_EFI]
    if features.subsystem == _POSIX_CUI_SUBSYSTEM:
        return _SHELLCODES[_PLATFORM_LINUX_32 if features.pe_type == OPTIONAL_HEADER_MAGIC_PE else _PLATFORM_LINUX]
    entry = _SHELLCODES.get(features.pe_type)
    if entry is None:
        raise ValueError(f"Unsupported PE type: 0x{features.pe_type:04X}")
    return entry


def _validate_pe(pe: PE, platform: "str | None" = None) -> dict:
    """Detect features, validate, and return chain entry. Raises on hard errors."""
    features = _detect_pe_features(pe)
    _validate_pe_features(features, platform)
    return _select_chain(features, platform)


def _compute_required_stubs(features: PeFeatures, entry: dict) -> list:
    stubs = []
    if entry.get('prefix'):
        stubs.append('prefix')
    if features.has_imports and entry.get('imports'):
        stubs.append('imports')
    stubs.append('relocs')
    if features.has_delay_imports and entry.get('delay_imports'):
        stubs.append('delay_imports')
    if (features.has_imports and features.has_cxx_eh
            and features.iat_rva_rtlpctofileheader is not None
            and entry.get('cxx_eh_fixer') is not None):
        stubs.append('cxx_eh_fixer')
    if entry.get('seh') and (entry.get('seh_always') or features.has_seh):
        stubs.append('seh')
    if entry.get('tls') and features.has_tls:
        stubs.append('tls')
    if entry.get('ctors') is not None and features.has_ctors:
        stubs.append('ctors')
    stubs.append('entrypoint')
    return stubs


def _build_shellcode_chain(features: PeFeatures, entry: dict, skip_imports: bool = False,
                            override_ep_rva: "int | None" = None) -> bytes:
    imports = (_strip_tail(entry['imports'], entry['tail'])
               if not skip_imports and features.has_imports and entry.get('imports') else b'')
    delay_imports = (_strip_tail(entry['delay_imports'], entry['tail'])
                     if not skip_imports and features.has_delay_imports and entry.get('delay_imports') else b'')
    relocs     = entry['relocs']
    seh        = entry['seh'] if (entry['seh'] and (entry.get('seh_always') or features.has_seh)) else b''
    tls        = entry['tls'] if (entry['tls'] and features.has_tls) else b''
    entrypoint = bytearray(entry['entrypoint'])

    if (imports and entry.get('cxx_eh_fixer') is not None
            and features.has_cxx_eh and features.iat_rva_rtlpctofileheader is not None):
        fixer         = bytearray(entry['cxx_eh_fixer'])
        pe_size_magic = entry['cxx_pe_size_magic']
        iat_rva_magic = entry['cxx_iat_rva_magic']
        if fixer.count(pe_size_magic) != 1:
            raise RuntimeError(f"PE_SIZE_MAGIC {pe_size_magic.hex()} not unique in cxx_eh_fixer")
        if fixer.count(iat_rva_magic) != 1:
            raise RuntimeError(f"IAT_RVA_MAGIC {iat_rva_magic.hex()} not unique in cxx_eh_fixer")
        idx = fixer.find(pe_size_magic)
        fixer[idx:idx + 4] = struct.pack('<I', features.size_of_image)
        idx = fixer.find(iat_rva_magic)
        fixer[idx:idx + 4] = struct.pack('<I', features.iat_rva_rtlpctofileheader)
        cxx_fixer = bytes(fixer)
    else:
        cxx_fixer = b''

    use_ctors = entry.get('ctors') is not None and features.has_ctors
    if use_ctors:
        ctors_bytes = bytearray(entry['ctors'])
        rva_magic   = entry['ctors_rva_magic']
        size_magic  = entry['ctors_size_magic']
        if ctors_bytes.count(rva_magic) != 1:
            raise RuntimeError(f"CTORS_RVA_MAGIC {rva_magic.hex()} not unique in ctors runner")
        if ctors_bytes.count(size_magic) != 1:
            raise RuntimeError(f"CTORS_SIZE_MAGIC {size_magic.hex()} not unique in ctors runner")
        idx = ctors_bytes.find(rva_magic)
        ctors_bytes[idx:idx + 4] = struct.pack('<I', features.ctors_rva)
        idx = ctors_bytes.find(size_magic)
        ctors_bytes[idx:idx + 4] = struct.pack('<I', features.ctors_size)
        ctors = bytes(ctors_bytes)
    else:
        ctors = b''

    ep_rva  = override_ep_rva if override_ep_rva is not None else features.address_of_entry_point
    ep_magic = entry.get('ep_rva_magic', b'')
    if ep_magic:
        if entrypoint.count(ep_magic) != 1:
            raise RuntimeError(f"EP_RVA_MAGIC {ep_magic.hex()} not unique in entrypoint resolver")
        idx = bytes(entrypoint).find(ep_magic)
        entrypoint[idx:idx + 4] = struct.pack('<I', ep_rva)
    entrypoint = bytes(entrypoint)

    prefix   = bytes(entry.get('prefix', b''))
    pe_align = entry.get('pe_align', 16)
    align_pad = (
        -len(prefix) - len(imports) - len(relocs) - len(delay_imports)
        - len(cxx_fixer) - len(seh) - len(tls) - len(ctors) - len(entrypoint)
    ) % pe_align

    extra  = len(delay_imports) + len(cxx_fixer) + len(seh) + len(tls) + len(ctors) + len(entrypoint) + align_pad
    relocs = bytearray(relocs)
    if 'disp64_off' in entry:
        off = entry['disp64_off']
        old = int.from_bytes(relocs[off:off + 8], 'little')
        relocs[off:off + 8] = (old + extra).to_bytes(8, 'little')
    else:
        off      = entry['disp32_off']
        old      = int.from_bytes(relocs[off:off + 4], 'little')
        new_disp = old + extra
        if new_disp > _MAX_SHELLCODE_DISP32:
            raise ValueError(
                f"shellcode chain too large: relocs resolver disp32 {new_disp:#010x} "
                f"would overflow the signed 32-bit LEA field (max {_MAX_SHELLCODE_DISP32:#010x})"
            )
        relocs[off:off + 4] = new_disp.to_bytes(4, 'little')

    return (prefix + imports + bytes(relocs) + delay_imports + cxx_fixer + seh
            + tls + ctors + entrypoint + (b'\x90' * align_pad))


def _shellcode_info(features: PeFeatures, entry: dict, skip_imports: bool = False) -> dict:
    imports = (_strip_tail(entry['imports'], entry['tail'])
               if not skip_imports and features.has_imports and entry.get('imports') else b'')
    delay_imports = (_strip_tail(entry['delay_imports'], entry['tail'])
                     if not skip_imports and features.has_delay_imports and entry.get('delay_imports') else b'')
    relocs     = entry['relocs']
    seh        = entry['seh'] if (entry['seh'] and (entry.get('seh_always') or features.has_seh)) else b''
    tls        = entry['tls'] if (entry['tls'] and features.has_tls) else b''
    entrypoint = entry['entrypoint']

    if (imports and entry.get('cxx_eh_fixer') and features.has_cxx_eh
            and features.iat_rva_rtlpctofileheader is not None):
        cxx_fixer = entry['cxx_eh_fixer']
    else:
        cxx_fixer = b''

    ctors = entry['ctors'] if (entry.get('ctors') is not None and features.has_ctors) else b''

    align_pad = (
        -len(imports) - len(relocs) - len(delay_imports)
        - len(cxx_fixer) - len(seh) - len(tls) - len(ctors) - len(entrypoint)
    ) % 16
    total = (len(imports) + len(relocs) + len(delay_imports) + len(cxx_fixer)
             + len(seh) + len(tls) + len(ctors) + len(entrypoint) + align_pad
             + features.size_of_image)

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
        'PE image':      features.size_of_image,
        'total':         total,
    }


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


def _zero_import_dir(ram_layout: bytearray, e_lfanew: int, dir_array_offset: int) -> None:
    opt_off          = e_lfanew + 24
    import_entry_off = opt_off + dir_array_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8
    ram_layout[import_entry_off:import_entry_off + 8] = b'\x00' * 8


def _make_shellcode(pe: PE, features: PeFeatures, entry: dict, ignore_imports: bool = False,
                    no_imports: bool = False, override_ep_rva: "int | None" = None) -> bytes:
    ram_layout = _build_ram_layout(pe)
    if ignore_imports:
        _zero_import_dir(ram_layout, features.e_lfanew, entry['dir_array_offset'])
    prefix = _build_shellcode_chain(features, entry, skip_imports=no_imports,
                                    override_ep_rva=override_ep_rva)
    return prefix + bytes(ram_layout)


def dump_memory_layout(pe: PE, output_file: Path, ignore_imports: bool = False,
                       no_imports: bool = False, override_ep_rva: "int | None" = None,
                       platform: "str | None" = None) -> None:
    features = _detect_pe_features(pe)
    _validate_pe_features(features, platform)
    entry = _select_chain(features, platform)
    output_file.write_bytes(_make_shellcode(pe, features, entry, ignore_imports, no_imports,
                                            override_ep_rva))
