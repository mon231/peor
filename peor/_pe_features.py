from dataclasses import dataclass
from pefile import PE, OPTIONAL_HEADER_MAGIC_PE, OPTIONAL_HEADER_MAGIC_PE_PLUS

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

# Windows PE Subsystem constants (PECOFF/UEFI spec).
_NATIVE_SUBSYSTEM    = 1
_POSIX_CUI_SUBSYSTEM = 7
_EFI_SUBSYSTEMS      = frozenset({10, 11, 12, 13})

# Machine types (PECOFF spec §2.3.1).
_MACHINE_I386      = 0x014C
_MACHINE_AMD64     = 0x8664
_MACHINE_ARM64     = 0xAA64
_MACHINE_ARMNT     = 0x01C4
_MACHINE_ARMTHUMB  = 0x01C2  # ARM/Thumb interworking; used by EDK2 ARM32 EFI

# Known packer section names — PE with any of these is rejected.
_PACKER_SECTION_NAMES = frozenset({
    b'.upx0', b'.upx1', b'UPX0', b'UPX1',
    b'.aspack', b'.adata', b'ASPack',
    b'.packed', b'pebundle',
})

# Platform keys used to select a shellcode chain in _chain_builder._SHELLCODES.
_PLATFORM_LINUX     = 'linux'
_PLATFORM_EFI       = 'efi'
_PLATFORM_LINUX_32  = 'linux32'
_PLATFORM_EFI_32    = 'efi32'
_PLATFORM_EFI_ARM64 = 'efi_arm64'
_PLATFORM_EFI_ARM32 = 'efi_arm32'


class PeorUnsupportedError(ValueError):
    pass


@dataclass
class PeFeatures:
    arch: str
    pe_type: int
    subsystem: int
    machine: int
    size_of_image: int
    address_of_entry_point: int
    e_lfanew: int
    has_relocs: bool
    has_imports: bool
    has_delay_imports: bool
    has_tls: bool
    has_seh: bool
    has_cxx_eh: bool
    has_ctors: bool
    is_clr: bool
    iat_rva_rtlpctofileheader: "int | None"
    ctors_rva: "int | None"
    ctors_size: "int | None"
    ordinal_imports: list
    forwarded_exports: bool
    packed: bool
    api_set_imports: list
    bss_sections: list
    issues: list


def _has_exception_table(pe: PE) -> bool:
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    return (len(dirs) > IMAGE_DIRECTORY_ENTRY_EXCEPTION
            and dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress != 0)


def _has_tls_callbacks(pe: PE) -> bool:
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    if len(dirs) <= IMAGE_DIRECTORY_ENTRY_TLS or dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0:
        return False
    tls_rva = dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
    if pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
        cb_off, ptr_size = 0x0C, 4
    else:
        cb_off, ptr_size = 0x18, 8
    raw = pe.get_data(tls_rva + cb_off, ptr_size)
    return int.from_bytes(raw, 'little') != 0


def _has_imports(pe: PE) -> bool:
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    if not (len(dirs) > IMAGE_DIRECTORY_ENTRY_IMPORT
            and dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0):
        return False
    return bool(getattr(pe, 'DIRECTORY_ENTRY_IMPORT', None))


def _has_delay_imports(pe: PE) -> bool:
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    return (len(dirs) > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
            and dirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress != 0)


def _find_iat_rva(pe: PE, func_name: bytes) -> "int | None":
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return None
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name == func_name:
                return imp.address - pe.OPTIONAL_HEADER.ImageBase
    return None


def _find_ctors_section(pe: PE) -> "tuple[int, int] | None":
    _CTORS_NAMES = {b'.init_array', b'.init_ar', b'.ctors'}
    for section in pe.sections:
        name = section.Name.rstrip(b'\x00')
        if name in _CTORS_NAMES:
            size = section.Misc_VirtualSize
            if size > 0:
                return section.VirtualAddress, size
    return None


def _find_export_rva(pe: PE, name_or_ordinal: str) -> int:
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


def _detect_pe_features(pe: PE) -> PeFeatures:
    machine = pe.FILE_HEADER.Machine
    if machine == _MACHINE_I386:
        arch = 'x86'
    elif machine == _MACHINE_AMD64:
        arch = 'x64'
    elif machine == _MACHINE_ARM64:
        arch = 'arm64'
    elif machine in (_MACHINE_ARMNT, _MACHINE_ARMTHUMB):
        arch = 'arm32'
    else:
        arch = f'unknown(0x{machine:04X})'

    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY

    has_relocs   = (len(dirs) > IMAGE_DIRECTORY_ENTRY_BASERELOC
                    and dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
    has_imp      = _has_imports(pe)
    has_delay    = _has_delay_imports(pe)
    has_tls      = _has_tls_callbacks(pe)
    has_seh      = _has_exception_table(pe)
    iat_rva      = _find_iat_rva(pe, b'RtlPcToFileHeader')
    has_cxx      = iat_rva is not None
    ctors_info   = _find_ctors_section(pe)
    has_ctors    = ctors_info is not None
    ctors_rva, ctors_size = ctors_info if ctors_info else (None, None)

    is_clr = (len(dirs) > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
              and dirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0)

    ordinal_imports: list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for mod in pe.DIRECTORY_ENTRY_IMPORT:
            dll = mod.dll.decode('ascii', errors='replace') if mod.dll else ''
            for imp in mod.imports:
                if imp.name is None:
                    ordinal_imports.append(f"{dll}!#{imp.ordinal}")

    forwarded_exports = False
    if (hasattr(pe, 'DIRECTORY_ENTRY_EXPORT')
            and len(dirs) > IMAGE_DIRECTORY_ENTRY_EXPORT
            and dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0):
        exp_rva  = dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        exp_size = dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].Size
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if sym.address is not None and exp_rva <= sym.address < exp_rva + exp_size:
                forwarded_exports = True
                break

    packed = any(
        section.Name.rstrip(b'\x00') in _PACKER_SECTION_NAMES
        for section in pe.sections
    )

    api_set_imports: list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for mod in pe.DIRECTORY_ENTRY_IMPORT:
            if mod.dll is None:
                continue
            dll_lower = mod.dll.lower()
            if dll_lower.startswith(b'api-') or dll_lower.startswith(b'ext-'):
                api_set_imports.append(mod.dll.decode('ascii', errors='replace'))

    bss_sections: list = [
        section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        for section in pe.sections
        if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0
    ]

    issues: list = []
    if packed:
        packer_sec = next(
            section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            for section in pe.sections
            if section.Name.rstrip(b'\x00') in _PACKER_SECTION_NAMES
        )
        issues.append(f"packed PE detected: packer section '{packer_sec}' found")

    return PeFeatures(
        arch=arch,
        pe_type=pe.PE_TYPE,
        subsystem=pe.OPTIONAL_HEADER.Subsystem,
        machine=machine,
        size_of_image=pe.OPTIONAL_HEADER.SizeOfImage,
        address_of_entry_point=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        e_lfanew=pe.DOS_HEADER.e_lfanew,
        has_relocs=has_relocs,
        has_imports=has_imp,
        has_delay_imports=has_delay,
        has_tls=has_tls,
        has_seh=has_seh,
        has_cxx_eh=has_cxx,
        has_ctors=has_ctors,
        is_clr=is_clr,
        iat_rva_rtlpctofileheader=iat_rva,
        ctors_rva=ctors_rva,
        ctors_size=ctors_size,
        ordinal_imports=ordinal_imports,
        forwarded_exports=forwarded_exports,
        packed=packed,
        api_set_imports=api_set_imports,
        bss_sections=bss_sections,
        issues=issues,
    )


def _validate_pe_features(features: PeFeatures, platform: "str | None" = None) -> None:
    """Raise PeorUnsupportedError or ValueError for hard incompatibilities."""
    if features.packed:
        msg = features.issues[0] if features.issues else "packed PE detected"
        raise PeorUnsupportedError(msg)
    if features.is_clr:
        raise ValueError("CLR/managed PE is not supported")
    if features.subsystem == _NATIVE_SUBSYSTEM and platform is None:
        raise ValueError(f"Kernel-mode PE (subsystem {features.subsystem}) is not yet supported")
