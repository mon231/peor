"""Kernel-mode (ring-0) PE->shellcode chain tests.

The whole kernel x64 chain is executed under Unicorn with:
  * a synthetic driver PE (subsystem 1 NATIVE, imports from "ntoskrnl.exe"),
  * a fake IDT whose gate 0 handler points into a fake ntoskrnl image,
  * a fake ntoskrnl export table exposing exactly one API stub:
      - 'RtlUlongAdd'           -> returns a + b in EAX (the "calc a+b" test),
      - 'PsCreateSystemProcess' -> writes a 0xDEADBEEF marker (create-process
        API test).
  * a fake ntoskrnl export table exposing RtlPcToFileHeader (C++ EH test on x64),
    the kernel's exception fixer equivalent to its EFI version.

Addresses (identical for x86 and x64; the fake-ntoskrnl sheet serves both):
    SC_BASE   0x00400000   shellcode blob (chain + driver image)
    STACK_*                  stack; final `ret` pops a sentinel word at INIT_RSP
    IDT_BASE  0x00200000   fake IDT page (head of SIDT)
    NT_BASE   0x002D0000   fake ntoskrnl image (4 pages, MZ at its base)
    SINK      0x00300000   sentinel "return address" for the chain's final ret
                             (code hook stops emulation there)
"""

import struct
import pytest

from pefile import PE
from pefile import OPTIONAL_HEADER_MAGIC_PE  # noqa: F401 (API parity with test_shellcode)

from unicorn import (Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_HOOK_CODE,
                     UC_HOOK_MEM_WRITE, UcError)
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RSI,
    UC_X86_REG_RDI, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
    UC_X86_REG_R15, UC_X86_REG_RSP, UC_X86_REG_RIP,
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_EBP, UC_X86_REG_ESI,
    UC_X86_REG_EDI, UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_IDTR,
)

try:  # Unicorn >= 2: descriptor object for the register-class (M/X/S) fields.
    from unicorn.unicorn_py3.arch.intel import UcRegMMR as _UcRegMMR
except ImportError:  # pragma: no cover - older bindings
    _UcRegMMR = None

from peor._pe_features import (
    _detect_pe_features,
    _PLATFORM_KERNEL, _PLATFORM_KERNEL_32,
    _NATIVE_SUBSYSTEM,
    _MACHINE_AMD64, _MACHINE_I386, _MACHINE_ARM64,
    PeorUnsupportedError,
)
from peor._chain_builder import (
    dump_memory_layout,
    _SHELLCODES,
    _select_chain,
    _validate_pe,
)


def _to(tmp_path, kind, raw: bytes):
    """Write the synthetic driver PE under tmp_path (for feature detection)."""
    p = tmp_path / f"driver_{kind}_x64.sys"
    p.write_bytes(raw)
    return p


SC_BASE    = 0x00400000
SC_SIZE    = 0x00040000          # 256 KB: ample for chain + driver image
STACK_BASE = 0x00100000
STACK_SIZE = 0x000C0000
INIT_RSP   = STACK_BASE + STACK_SIZE - 0x1000
INIT_RBP   = STACK_BASE + STACK_SIZE - 0x2000
IDT_BASE   = 0x00200000
NT_BASE    = 0x002D0000
HANDLER    = NT_BASE + 0x40
SINK       = 0x00300000

DEADBEEF       = 0xDEADBEEF
CALC_RESULT    = 5                # RtlUlongAdd(3, 2) fake-stub return
PROC_NTSTATUS  = 0
EH_ATTENTION   = 0xCAFEBABE       # passthrough fake-kernel stub return
EH_SENTINEL    = 0xCDCDCDCDCDCDCDCD   # qword unchanged by the outside call
EH_STUB        = b'\xb8\xba\xfe\xca\x00\xc3'   # mov eax,0xCAFEBABE; ret

KERNEL_DLL_NAME = b'ntoskrnl.exe\x00'

# Fake ntoskrnl image layout: export dir RVA 0x800; the resolver reads it from
# e_lfanew+0x78 (PE32) and e_lfanew+0x88 (PE32+), so the RVA is written at both.
_NT_E_LFANEW     = 0x40
_NT_DIR_RVA      = 0x800
_NT_NT32_DIR_OFF = _NT_E_LFANEW + 0x78
_NT_NT64_DIR_OFF = _NT_E_LFANEW + 0x88
_NT_FUNCS_RVA    = _NT_DIR_RVA + 0x80
_NT_NAMES_RVA    = _NT_DIR_RVA + 0x84
_NT_ORDS_RVA     = _NT_DIR_RVA + 0x88
_NT_NAME_RVA     = _NT_DIR_RVA + 0x90
_NT_STUB_RVA     = _NT_DIR_RVA + 0xB0

# Synthetic driver image layout (same RVAs for both arches; .text at 0x1000):
_TEXT_RVA    = 0x1000
_IAT_RVA     = 0x1080
_MARKER_RVA  = 0x1088
_INT_RVA     = 0x1090
_IIBN_RVA    = 0x10A0
_DLLNAME_RVA = 0x10C0
_DESC_RVA    = 0x10D0
_IMPORT_SIZE = 0x28                    # one descriptor + null terminator
_EH_R1_RVA   = 0x1100                  # eh: *BaseOfImage written here
_EH_R2_RVA   = 0x1108                  # eh: untouched by the outside call
_EH_PC_RVA   = 0x1150                  # eh: inside-PE PcValue target
E_LFANEW     = 0x80
_HEADERS_SIZE = 0x400                  # file-aligned SizeOfHeaders


def _build_fake_ntoskrnl(export_name: bytes, stub: bytes):
    """Fake ntoskrnl (4 KB) with exactly one name-resolved export."""
    img = bytearray(0x1000)
    img[0:2] = b'MZ'
    struct.pack_into('<I', img, 0x3C, _NT_E_LFANEW)
    img[_NT_E_LFANEW:_NT_E_LFANEW + 4] = b'PE\x00\x00'
    # Export-directory RVA in both PE32 and PE32+ DataDir[0] offsets.
    struct.pack_into('<I', img, _NT_NT32_DIR_OFF, _NT_DIR_RVA)
    struct.pack_into('<I', img, _NT_NT64_DIR_OFF, _NT_DIR_RVA)
    struct.pack_into('<I', img, _NT_DIR_RVA + 0x18, 1)          # NumberOfNames
    struct.pack_into('<I', img, _NT_DIR_RVA + 0x1C, _NT_FUNCS_RVA)
    struct.pack_into('<I', img, _NT_DIR_RVA + 0x20, _NT_NAMES_RVA)
    struct.pack_into('<I', img, _NT_DIR_RVA + 0x24, _NT_ORDS_RVA)
    struct.pack_into('<I', img, _NT_FUNCS_RVA, _NT_STUB_RVA)    # funcs[0]
    struct.pack_into('<I', img, _NT_NAMES_RVA, _NT_NAME_RVA)    # names[0]
    struct.pack_into('<H', img, _NT_ORDS_RVA, 0)                # ords[0]
    name_len = len(export_name) + 1
    assert _NT_NAME_RVA + name_len <= _NT_STUB_RVA, "fake ntoskrnl string overflow"
    img[_NT_NAME_RVA:_NT_NAME_RVA + name_len] = export_name
    img[_NT_STUB_RVA:_NT_STUB_RVA + len(stub)] = stub
    return bytes(img), _NT_STUB_RVA


# Per-kind fake ntoskrnl API stubs (x64 ABI).
CALC_STUB = b'\x89\xc8\x01\xd0\xc3'                       # mov eax,ecx; add eax,edx; ret
PROC_STUB = b'\xc7\x01\xef\xbe\xad\xde\x31\xc0\xc3'       # mov dword [rcx],0xDEADBEEF; xor eax,eax; ret
EH_OUT_STUB = b'\xb8\xba\xfe\xca\x00\xc3'                 # mov eax,0xCAFEBABE; ret
_STUBS = {'calc': CALC_STUB, 'proc': PROC_STUB, 'eh': EH_OUT_STUB}


def _build_driver(kind: str, arch: str) -> bytes:
    """Synthetic NATIVE-subsystem driver PE importing one ntoskrnl API."""
    is64    = arch == 'x64'
    machine = 0x8664 if is64 else 0x014C
    image_base = 0x140000000 if is64 else 0x01400000
    size_of_image = 0x3000
    size_opt = 240 if is64 else 224
    assert is64, 'kernel32 (x32) synthetic driver is tested separately'

    if kind == 'calc':
        code = (b'\xb9\x03\x00\x00\x00',
                b'\xba\x02\x00\x00\x00',
                b'\xff\x15' + struct.pack('<i', _IAT_RVA - 0x1010),
                b'\xc3')
    elif kind == 'proc':
        code = (b'\x48\x8d\x0d' + struct.pack('<i', _MARKER_RVA - 0x1007),
                b'\xff\x15' + struct.pack('<i', _IAT_RVA - 0x100D),
                b'\x31\xc0',
                b'\xc3')
    else:
        assert kind == 'eh'
        code = (b'\x48\x8d\x0d' + struct.pack('<i', _EH_PC_RVA - 0x1007),
                b'\x48\x8d\x15' + struct.pack('<i', _EH_R1_RVA - 0x100E),
                b'\xff\x15' + struct.pack('<i', _IAT_RVA - 0x1014),
                b'\x31\xf6',
                b'\x48\x3b\xd8',
                b'\x74\x03',
                b'\x83\xce\x01',
                b'\x48\x8d\x15' + struct.pack('<i', _EH_R2_RVA - 0x1025),
                b'\xb9' + struct.pack('<I', NT_BASE + 0x40),
                b'\xff\x15' + struct.pack('<i', _IAT_RVA - 0x1030),
                b'\x48\x85\xc0',                                    # test rax,rax
                b'\x75\x03',                                        # jnz: pe_base passthrough good
                b'\x83\xce\x02',                                    # or esi,2 (failure)
                b'\x48\x89\xf0',
                b'\xc3')
    code = b''.join(code)
    assert len(code) <= 0x60

    hdr = bytearray(_HEADERS_SIZE)
    hdr[0:2] = b'MZ'
    struct.pack_into('<I', hdr, 0x3C, E_LFANEW)
    hdr[E_LFANEW:E_LFANEW + 4] = b'PE\x00\x00'
    struct.pack_into('<HHIIIHH', hdr, E_LFANEW + 4,
                     machine, 2, 0, 0, _HEADERS_SIZE, size_opt, 0x0022)
    opt = E_LFANEW + 4 + 20
    struct.pack_into('<H', hdr, opt + 0x00, 0x20B)
    struct.pack_into('<I', hdr, opt + 0x04, 0x400)              # SizeOfCode
    struct.pack_into('<I', hdr, opt + 0x10, _TEXT_RVA)          # AddressOfEntryPoint
    struct.pack_into('<I', hdr, opt + 0x14, _TEXT_RVA)          # BaseOfCode
    struct.pack_into('<Q', hdr, opt + 0x18, image_base)
    struct.pack_into('<II', hdr, opt + 0x20, 0x1000, 0x400)     # Section/FileAlignment
    struct.pack_into('<HHHHI', hdr, opt + 0x28, 6, 0, 6, 0, 0)  # versions
    struct.pack_into('<II', hdr, opt + 0x38, size_of_image, _HEADERS_SIZE)
    struct.pack_into('<IH', hdr, opt + 0x40, 0, _NATIVE_SUBSYSTEM)  # checksum, Subsystem
    struct.pack_into('<H', hdr, opt + 0x46, 0)                  # DllCharacteristics
    struct.pack_into('<QQ', hdr, opt + 0x48, 0x40000, 0x1000)   # stack res/commit
    struct.pack_into('<QQ', hdr, opt + 0x58, 0x40000, 0x1000)   # heap res/commit
    struct.pack_into('<II', hdr, opt + 0x68, 0, 16)             # LoaderFlags / RvaCount
    dd = [(0, 0)] * 16
    dd[1] = (_DESC_RVA, _IMPORT_SIZE)
    for i, (rva, size) in enumerate(dd):
        struct.pack_into('<II', hdr, opt + 0x70 + i * 8, rva, size)
    sec = struct.pack('<8sIIIIIIHHI', b'.text\x00\x00\x00', _TEXT_RVA,
                      _TEXT_RVA, 0x400, 0x400, 0, 0, 0, 0, 0x60000020)
    dta = struct.pack('<8sIIIIIIHHI', b'.data\x00\x00\x00', 0x2000,
                      0x2000, 0x200, 0x800, 0, 0, 0, 0, 0xC0000040)
    sec_off = opt + size_opt                 # PE+ table right after optional header
    hdr[sec_off:sec_off + 40] = sec
    hdr[sec_off + 40:sec_off + 80] = dta

    text = bytearray(0x400)
    text[0:len(code)] = code
    # Eh's inside-PE sentinel PC slot value must not shadow the sentinel other
    # stubs use; stored values themselves are read back from _EH_R1_RVA.
    struct.pack_into('<Q', text, _EH_R2_RVA - _TEXT_RVA, EH_SENTINEL)

    # IAT slot @ + INT slot: one positive-neutral thunk to IMAGE_IMPORT_BY_NAME.
    struct.pack_into('<QQ', text, _IAT_RVA - _TEXT_RVA, _IIBN_RVA, 0)
    struct.pack_into('<QQ', text, _INT_RVA - _TEXT_RVA, _IIBN_RVA, 0)

    name = {'calc': b'RtlUlongAdd', 'proc': b'PsCreateSystemProcess',
            'eh':   b'RtlPcToFileHeader'}[kind]
    struct.pack_into('<H', text, _IIBN_RVA - _TEXT_RVA, 0)
    text[_IIBN_RVA + 2 - _TEXT_RVA:
         _IIBN_RVA + 2 - _TEXT_RVA + len(name)] = name
    text[_DLLNAME_RVA - _TEXT_RVA:
         _DLLNAME_RVA - _TEXT_RVA + len(KERNEL_DLL_NAME)] = KERNEL_DLL_NAME

    struct.pack_into('<IIIII', text, _DESC_RVA - _TEXT_RVA,
                     _INT_RVA, 0, 0, _DLLNAME_RVA, _IAT_RVA)

    file_bytes = bytes(hdr) + bytes(text) + b'\x00' * 0x400
    file_bytes += b'\x00' * 0x400                              # .data raw @ 0x800
    file_bytes += b'\x00' * (size_of_image - len(file_bytes))  # pad up to image size
    return bytes(file_bytes[:_HEADERS_SIZE + 0x400 + 0x200])


def _write_idtr(uc, base, limit=0xFFF):
    try:
        uc.reg_write(UC_X86_REG_IDTR, (0, base, limit, 0))
    except (TypeError, UcError):
        if _UcRegMMR is not None:  # pragma: no cover
            m = _UcRegMMR()
            m.selector = 0
            m.base     = base
            m.limit    = limit
            m.flags    = 0
            uc.reg_write(UC_X86_REG_IDTR, m)
        else:  # pragma: no cover
            raise


_ARCH_SETUP = {
    'x64': dict(mode=UC_MODE_64, sp=UC_X86_REG_RSP, ip=UC_X86_REG_RIP,
                ax=UC_X86_REG_RAX, is64=True,
                saved=(UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
                       UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15)),
}


def _run_kernel_chain(kind: str, blob: bytes, features, tmp_path):
    setup = _ARCH_SETUP['x64']
    is64  = setup['is64']
    fake_nt, stub_rva = _build_fake_ntoskrnl(_EXPORT_KIND_NAME[kind], _STUBS[kind])
    stub_va = NT_BASE + stub_rva

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(SC_BASE, SC_SIZE)
    uc.mem_write(SC_BASE, blob)
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_map(IDT_BASE, 0x1000)
    uc.mem_map(NT_BASE, 0x2000)
    uc.mem_write(NT_BASE, fake_nt)
    uc.mem_map(SINK, 0x1000)
    uc.mem_write(SINK, b'\xc3')

    chain_len = len(blob) - features.size_of_image
    assert blob[chain_len:chain_len + 2] == b'MZ', 'no contiguous driver image'
    pe_base = SC_BASE + chain_len

    uc.mem_write(INIT_RSP, struct.pack('<Q', SINK))
    uc.reg_write(UC_X86_REG_RSP, INIT_RSP)

    saved_sentinels = {}
    for i, reg in enumerate(setup['saved']):
        val = 0x0000000D000000B0 + (i + 1)
        saved_sentinels[reg] = val
        uc.reg_write(reg, val)

    _write_idtr(uc, IDT_BASE)
    gate = bytearray(16)                                     # x64 gate = 16 bytes
    struct.pack_into('<H', gate, 0x00, HANDLER & 0xFFFF)     # low16
    struct.pack_into('<H', gate, 0x06, (HANDLER >> 16) & 0xFFFF)
    uc.mem_write(IDT_BASE, bytes(gate))

    hits = []
    def _stop(uc_, address, size=0, user=None):
        hits.append(address)
        uc_.emu_stop()
    uc.hook_add(UC_HOOK_CODE, _stop, begin=SINK, end=SINK)

    try:
        uc.emu_start(SC_BASE, 0, 0, 2_000_000)
    except UcError as e:
        pytest.fail(
            f"kernel chain fault ({kind}/x64): {e}; "
            f"RIP={uc.reg_read(setup['ip']):#x} RSP={uc.reg_read(setup['sp']):#x}"
        )
    assert hits == [SINK], f"chain did not land on SINK; hits={hits}"
    for reg, want in saved_sentinels.items():
        got = uc.reg_read(reg)
        assert got == want, (
            f"kernel chain clobbered callee-save {reg}: want {want:#x}, got {got:#x}"
        )
    assert uc.reg_read(setup['sp']) == INIT_RSP + 8, \
        f"RSP {uc.reg_read(setup['sp']):#x} != INIT_RSP+8 after final ret"
    return uc, chain_len, stub_va, setup['ax']


_EXPORT_KIND_NAME = {
    'calc': b'RtlUlongAdd',
    'proc': b'PsCreateSystemProcess',
    'eh':   b'RtlPcToFileHeader',
}


def _shellcodify(kind: str, blob: bytes, tmp_path) -> bytes:
    pe_path = tmp_path / f"driver_{kind}_x64.in.sys"
    pe_path.write_bytes(blob)
    sc_path = tmp_path / f"driver_{kind}_x64.sc.bin"
    dump_memory_layout(PE(str(pe_path)), sc_path)
    blob = sc_path.read_bytes()
    det = tmp_path / f"driver_{kind}_x64.sc.det.bin"
    dump_memory_layout(PE(str(pe_path)), det)
    assert blob == det.read_bytes(), f"{kind}: shellcode output is non-deterministic"
    return blob


def _read_chunk(uc, addr, size):
    return bytes(uc.mem_read(addr, size))


def _assert_iat_slot(uc, chain_len, want):
    base = SC_BASE + chain_len + _IAT_RVA
    got  = int.from_bytes(_read_chunk(uc, base, 8), 'little')
    assert got == want, f"IAT slot @{base:#x} = {got:#x}, want {want:#x}"


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------

def test_kernel_calc(tmp_path):
    """calc: import resolver patches IAT; DriverEntry returns 3+2 == 5."""
    raw = _build_driver('calc', 'x64')
    features = _detect_pe_features(PE(str(_to(tmp_path, 'calc', raw))))
    assert features.subsystem == _NATIVE_SUBSYSTEM
    sc = _shellcodify('calc', raw, tmp_path)
    uc, chain_len, stub_va, ax_reg = _run_kernel_chain('calc', sc, features, tmp_path)
    assert uc.reg_read(ax_reg) == CALC_RESULT, (
        f"calc result {uc.reg_read(ax_reg):#x} != 5"
    )
    _assert_iat_slot(uc, chain_len, NT_BASE + _NT_STUB_RVA)


def test_kernel_create_process(tmp_path):
    """proc: DriverEntry calls PsCreateSystemProcess; marker written."""
    raw = _build_driver('proc', 'x64')
    features = _detect_pe_features(PE(str(_to(tmp_path, 'proc', raw))))
    sc = _shellcodify('proc', raw, tmp_path)
    uc, chain_len, stub_va, ax_reg = _run_kernel_chain('proc', sc, features, tmp_path)
    assert uc.reg_read(ax_reg) == PROC_NTSTATUS
    marker = int.from_bytes(
        _read_chunk(uc, SC_BASE + chain_len + _MARKER_RVA, 4), 'little')
    assert marker == DEADBEEF, f"stub never wrote marker ({marker:#x})"
    _assert_iat_slot(uc, chain_len, stub_va)


def test_kernel_cpp_exception_fixer(tmp_path):
    """x64: cxx_eh_fixer must hook RtlPcToFileHeader on the kernel chain.

    * PcValue inside the PE -> returns runtime PE base and writes [rdx] = base;
    * PcValue outside the PE -> must forward to the resolved stub (0xCAFEBABE);
    * the *BaseOfImage slot for the outside call must be untouched;
    * driver asserts both statuses so RAX == 0.
    """
    raw = _build_driver('eh', 'x64')
    features = _detect_pe_features(PE(str(_to(tmp_path, 'eh', raw))))
    assert features.has_cxx_eh
    assert features.iat_rva_rtlpctofileheader == _IAT_RVA
    sc = _shellcodify('eh', raw, tmp_path)
    uc, chain_len, stub_va, ax_reg = _run_kernel_chain('eh', sc, features, tmp_path)

    pe_base = SC_BASE + chain_len
    assert uc.reg_read(ax_reg) == 0, "driver EH status flags != 0"
    inside_out = int.from_bytes(_read_chunk(uc, pe_base + _EH_R1_RVA, 8), 'little')
    assert inside_out == pe_base, (
        f"inside-PE call: want base {pe_base:#x} in *rdx, got {inside_out:#x}"
    )
    outside_out = int.from_bytes(_read_chunk(uc, pe_base + _EH_R2_RVA, 8), 'little')
    assert outside_out == EH_SENTINEL, (
        f"outside call must not write *BaseOfImage, got {outside_out:#x}"
    )
    iat_pointer = int.from_bytes(_read_chunk(uc, pe_base + _IAT_RVA, 8), 'little')
    assert iat_pointer != stub_va, "IAT hook not installed"
    assert SC_BASE <= iat_pointer < pe_base, (
        f"hook must live in the chain region, got {iat_pointer:#x}"
    )


def test_kernel_arm_native_features_rejected(tmp_path):
    """ARM machine with NATIVE subsystem: kernel auto-select raises ValueError."""
    hdr = bytearray(0x400)
    hdr[0:2] = b'MZ'
    struct.pack_into('<I', hdr, 0x3C, E_LFANEW)
    hdr[E_LFANEW:E_LFANEW + 4] = b'PE\x00\x00'
    struct.pack_into('<HHIIIHH', hdr, E_LFANEW + 4,
                     _MACHINE_ARM64, 1, 0, 0, _HEADERS_SIZE, 240, 0x0022)
    opt = E_LFANEW + 24
    struct.pack_into('<H', hdr, opt + 0x44, _NATIVE_SUBSYSTEM)
    p = tmp_path / 'arm_native.sys'
    p.write_bytes(bytes(hdr))
    features = _detect_pe_features(PE(str(p)))
    assert features.machine == _MACHINE_ARM64
    assert features.subsystem == _NATIVE_SUBSYSTEM
    with pytest.raises(ValueError):
        _select_chain(features)


def test_kernel64_rejects_non_native_subsystem(tmp_path):
    raw = bytearray(_build_driver('calc', 'x64'))
    struct.pack_into('<H', raw, E_LFANEW + 24 + 0x44, 2)   # Subsystem = WINDOWS_GUI
    p = tmp_path / 'kernel64_rej.sys'
    p.write_bytes(bytes(raw))
    features = _detect_pe_features(PE(str(p)))
    assert features.subsystem == 2
    with pytest.raises(PeorUnsupportedError, match='kernel-mode'):
        _validate_pe(PE(str(p)), platform=_PLATFORM_KERNEL)


def test_kernel32_rejects_non_native_subsystem(tmp_path):
    raw = bytearray(_build_driver('proc', 'x64'))
    struct.pack_into('<H', raw, E_LFANEW + 24 + 0x44, 2)
    p = tmp_path / 'kernel32_rej.sys'
    p.write_bytes(bytes(raw))
    features = _detect_pe_features(PE(str(p)))
    assert features.subsystem == 2
    with pytest.raises(PeorUnsupportedError, match='kernel-mode'):
        _validate_pe(PE(str(p)), platform=_PLATFORM_KERNEL_32)


def test_kernel_chain_selection(tmp_path):
    raw = _build_driver('calc', 'x64')
    p = _to(tmp_path, 'calc', raw)
    features = _detect_pe_features(PE(str(p)))
    entry = _select_chain(features, platform=_PLATFORM_KERNEL)
    assert entry is _SHELLCODES[_PLATFORM_KERNEL]
    assert entry['imports']
