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
from pefile import OPTIONAL_HEADER_MAGIC_PE, OPTIONAL_HEADER_MAGIC_PE_PLUS  # noqa: F401

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


def _to(tmp_path, kind, arch, raw: bytes):
    """Write the synthetic driver PE under tmp_path (for feature detection)."""
    p = tmp_path / f"driver_{kind}_{arch}.sys"
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

# The real VM's IDT base lives in the shadow-memory KSEG (nt base minus ~2 GiB),
# so the resolver's anchor is the gate-0 HANDLER, which sits deep inside
# ntoskrnl .text: RVA 0xBCB100 on Win11 26100 (measured with kd).  The fake
# default layout keeps the handler right next to the fake nt base (0x40), so a
# deep-handler variant is built separately below: the backward MZ walk must
# cover the whole handler-to-base distance, and the emulated guard limit is
# exercised with an eight-megabyte-plus-one-page spacing.
DEEP_NT_BASE  = 0x00F00000
DEEP_NT_PAGES = 0x00900             # mapped pages of the deep fake nt image
DEEP_HANDLER_RVA = 0x00810000       # gate-0 offset: 0x810 pages (> old 0x800)
DEEP_HANDLER  = DEEP_NT_BASE + DEEP_HANDLER_RVA
DEEP_NT_MAP   = DEEP_HANDLER_RVA + 0x2000

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


# Per-kind fake ntoskrnl API stubs.
# x64 Microsoft x64 ABI (fastcall): args in RCX/RDX, no stack cleanup.
# x86 stdcall: args on the stack, callee cleans them with `ret imm16`.
CALC_STUB = {
    'x64': b'\x89\xc8\x01\xd0\xc3',            # mov eax,ecx; add eax,edx; ret
    'x86': b'\x8b\x44\x24\x04'                 # mov eax,[esp+4]
           b'\x03\x44\x24\x08'                 # add eax,[esp+8]
           b'\xc2\x08\x00',                    # ret 8 (stdcall, 2 args)
}
PROC_STUB = {
    'x64': b'\xc7\x01\xef\xbe\xad\xde\x31\xc0\xc3',
    # x64: mov dword [rcx],0xDEADBEEF; xor eax,eax; ret
    'x86': b'\x8b\x44\x24\x04'                 # mov eax,[esp+4]
           b'\xc7\x00\xef\xbe\xad\xde'         # mov dword [eax],0xDEADBEEF
           b'\x31\xc0'                         # xor eax,eax
           b'\xc2\x0c\x00',                    # ret 12 (stdcall, 3 args)
}
EH_OUT_STUB = b'\xb8\xba\xfe\xca\x00\xc3'      # mov eax,0xCAFEBABE; ret (x64 only)
_STUBS = {'calc': CALC_STUB, 'proc': PROC_STUB, 'eh': {'x64': EH_OUT_STUB}}


def _build_driver(kind: str, arch: str) -> bytes:
    """Synthetic NATIVE-subsystem driver PE importing one ntoskrnl API.

    x86 layout differences from the PE32+ builder:
      * optional header: BaseOfData at +0x18, ImageBase (dword) at +0x1C, and
        LoaderFlags/NumberOfRvaAndSizes/DataDirectory shifted to +0x58/+0x5C/+0x60
        (x64: ImageBase qword at +0x18, DataDirectory at +0x70);
      * section table at opt+224 (x64: opt+240);
      * 4-byte IAT/INT thunks;
      * absolute-address code operands need a HIGHLOW base-relocation block
        (PageRVA 0x1000) in a .reloc section at RVA 0x2000, declared in
        DataDir[5] — the chain's x86 relocs resolver applies it at runtime;
      * stdcall: argument pushes + `ret imm16` in driver and stubs.
    """
    is64    = arch == 'x64'
    machine = 0x8664 if is64 else 0x014C
    image_base = 0x140000000 if is64 else 0x01400000
    size_of_image = 0x3000
    size_opt = 240 if is64 else 224

    if kind == 'calc':
        if is64:
            code = (b'\xb9\x03\x00\x00\x00',
                    b'\xba\x02\x00\x00\x00',
                    b'\xff\x15' + struct.pack('<i', _IAT_RVA - 0x1010),
                    b'\xc3')
            reloc_offsets = []                      # RIP-relative, no relocations
        else:
            code = (b'\x68\x02\x00\x00\x00',        # push 2          (arg2: b)
                    b'\x68\x03\x00\x00\x00',        # push 3          (arg1: a)
                    b'\xff\x15' + struct.pack('<I', image_base + _IAT_RVA),
                    b'\xc2\x08\x00')                # ret 8 (stdcall)
            reloc_offsets = (0x100C,)               # call [iat] operand
    elif kind == 'proc':
        if is64:
            code = (b'\x48\x8d\x0d' + struct.pack('<i', _MARKER_RVA - 0x1007),
                    b'\xff\x15' + struct.pack('<i', _IAT_RVA - 0x100D),
                    b'\x31\xc0',
                    b'\xc3')
            reloc_offsets = []
        else:
            code = (b'\x68\x00\x00\x00\x00',        # push 0          (arg3)
                    b'\x68\x00\x00\x00\x00',        # push 0          (arg2)
                    b'\x68' + struct.pack('<I', image_base + _MARKER_RVA),
                    b'\xff\x15' + struct.pack('<I', image_base + _IAT_RVA),
                    b'\x31\xc0',                    # xor eax,eax
                    b'\xc2\x08\x00')                # ret 8 (stdcall, 2 args)
            reloc_offsets = (0x100B, 0x1011)    # push &marker, call [iat] operand
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
        reloc_offsets = []
    code = b''.join(code)
    assert len(code) <= 0x60

    hdr = bytearray(_HEADERS_SIZE)
    hdr[0:2] = b'MZ'
    struct.pack_into('<I', hdr, 0x3C, E_LFANEW)
    hdr[E_LFANEW:E_LFANEW + 4] = b'PE\x00\x00'
    struct.pack_into('<HHIIIHH', hdr, E_LFANEW + 4,
                     machine, 2, 0, 0, _HEADERS_SIZE, size_opt, 0x0022)
    opt = E_LFANEW + 4 + 20
    struct.pack_into('<H', hdr, opt + 0x00, 0x20B if is64 else 0x10B)
    struct.pack_into('<I', hdr, opt + 0x04, 0x400)              # SizeOfCode
    struct.pack_into('<I', hdr, opt + 0x10, _TEXT_RVA)          # AddressOfEntryPoint
    struct.pack_into('<I', hdr, opt + 0x14, _TEXT_RVA)          # BaseOfCode
    if is64:
        struct.pack_into('<Q', hdr, opt + 0x18, image_base)
    else:
        struct.pack_into('<I', hdr, opt + 0x18, 0)              # BaseOfData
        struct.pack_into('<I', hdr, opt + 0x1C, image_base)
    struct.pack_into('<II', hdr, opt + 0x20, 0x1000, 0x400)     # Section/FileAlignment
    struct.pack_into('<HHHHI', hdr, opt + 0x28, 6, 0, 6, 0, 0)  # versions
    struct.pack_into('<II', hdr, opt + 0x38, size_of_image, _HEADERS_SIZE)
    struct.pack_into('<IH', hdr, opt + 0x40, 0, _NATIVE_SUBSYSTEM)  # checksum, Subsystem
    struct.pack_into('<H', hdr, opt + 0x46, 0)                  # DllCharacteristics
    if is64:
        struct.pack_into('<QQ', hdr, opt + 0x48, 0x40000, 0x1000)   # stack res/commit
        struct.pack_into('<QQ', hdr, opt + 0x58, 0x40000, 0x1000)   # heap res/commit
        struct.pack_into('<II', hdr, opt + 0x68, 0, 16)             # LoaderFlags / RvaCount
        dd_off = opt + 0x70
    else:
        struct.pack_into('<II', hdr, opt + 0x48, 0x40000, 0x1000)   # stack res/commit
        struct.pack_into('<II', hdr, opt + 0x50, 0x40000, 0x1000)   # heap res/commit
        struct.pack_into('<II', hdr, opt + 0x58, 0, 16)             # LoaderFlags / RvaCount
        dd_off = opt + 0x60

    dd = [(0, 0)] * 16
    dd[1] = (_DESC_RVA, _IMPORT_SIZE)
    if not is64:
        dd[5] = (0x2000, 12)                                    # BASE_RELOC block
    for i, (rva, size) in enumerate(dd):
        struct.pack_into('<II', hdr, dd_off + i * 8, rva, size)

    sec = struct.pack('<8sIIIIIIHHI', b'.text\x00\x00\x00', _TEXT_RVA,
                      _TEXT_RVA, 0x400, 0x400, 0, 0, 0, 0, 0x60000020)
    dta = struct.pack('<8sIIIIIIHHI',
                      b'.data\x00\x00\x00' if is64 else b'.reloc\x00\x00',
                      0x2000, 0x2000, 0x200, 0x800, 0, 0, 0, 0,
                      0xC0000040 if is64 else 0x42000040)
    sec_off = opt + size_opt                    # table right after optional header
    hdr[sec_off:sec_off + 40] = sec
    hdr[sec_off + 40:sec_off + 80] = dta

    text = bytearray(0x400)
    text[0:len(code)] = code
    # Eh's inside-PE sentinel PC slot value must not shadow the sentinel other
    # stubs use; stored values themselves are read back from _EH_R1_RVA.
    if kind == 'eh':
        struct.pack_into('<Q', text, _EH_R2_RVA - _TEXT_RVA, EH_SENTINEL)
    else:
        struct.pack_into('<Q', text, _EH_R2_RVA - _TEXT_RVA, 0)

    pointer_size = 8 if is64 else 4
    pack_ptr = '<QQ' if is64 else '<II'
    # IAT slot @ + INT slot: one thunk to IMAGE_IMPORT_BY_NAME + terminator.
    struct.pack_into(pack_ptr, text, _IAT_RVA - _TEXT_RVA, _IIBN_RVA, 0)
    struct.pack_into(pack_ptr, text, _INT_RVA - _TEXT_RVA, _IIBN_RVA, 0)

    data = bytearray(0x200)                     # .data @ RVA 0x2000 / raw 0x800
    if not is64:
        # .reloc: one block, PageRVA 0x1000, one HIGHLOW entry per fixup.
        block = bytearray(12)
        struct.pack_into('<II', block, 0x00, _TEXT_RVA, 12)              # PageRVA/SizeOfBlock
        for i, off in enumerate(reloc_offsets):
            struct.pack_into('<H', block, 8 + 2 * i, (0x03 << 12) | off) # HIGHLOW
        data[0:len(block)] = block

    name = {'calc': b'RtlUlongAdd', 'proc': b'PsCreateSystemProcess',
            'eh':   b'RtlPcToFileHeader'}[kind]
    struct.pack_into('<H', text, _IIBN_RVA - _TEXT_RVA, 0)
    text[_IIBN_RVA + 2 - _TEXT_RVA:
         _IIBN_RVA + 2 - _TEXT_RVA + len(name)] = name
    text[_DLLNAME_RVA - _TEXT_RVA:
         _DLLNAME_RVA - _TEXT_RVA + len(KERNEL_DLL_NAME)] = KERNEL_DLL_NAME

    struct.pack_into('<IIIII', text, _DESC_RVA - _TEXT_RVA,
                     _INT_RVA, 0, 0, _DLLNAME_RVA, _IAT_RVA)

    file_bytes = bytes(hdr) + bytes(text) + bytes(data)         # .text raw 0x400, data raw 0x800
    file_bytes += b'\x00' * (size_of_image - len(file_bytes))   # pad up to image size
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
                ax=UC_X86_REG_RAX, is64=True, ptr=8, gate_size=16,
                saved=(UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
                       UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15)),
    'x86': dict(mode=UC_MODE_32, sp=UC_X86_REG_ESP, ip=UC_X86_REG_EIP,
                ax=UC_X86_REG_EAX, is64=False, ptr=4, gate_size=8,
                saved=(UC_X86_REG_EBX, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI)),
}


def _run_kernel_chain(kind: str, arch: str, blob: bytes, features, tmp_path,
                      nt_base=NT_BASE, nt_map=0x2000, handler=HANDLER):
    setup = _ARCH_SETUP[arch]
    fake_nt, stub_rva = _build_fake_ntoskrnl(_EXPORT_KIND_NAME[kind], _STUBS[kind][arch])
    stub_va = nt_base + stub_rva

    uc = Uc(UC_ARCH_X86, setup['mode'])
    uc.mem_map(SC_BASE, SC_SIZE)
    uc.mem_write(SC_BASE, blob)
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_map(IDT_BASE, 0x1000)
    uc.mem_map(nt_base, nt_map)
    uc.mem_write(nt_base, fake_nt)
    uc.mem_map(SINK, 0x1000)
    uc.mem_write(SINK, b'\xc3')

    chain_len = len(blob) - features.size_of_image
    assert blob[chain_len:chain_len + 2] == b'MZ', 'no contiguous driver image'
    pe_base = SC_BASE + chain_len

    uc.mem_write(INIT_RSP, struct.pack('<Q' if setup['is64'] else '<I', SINK))
    uc.reg_write(setup['sp'], INIT_RSP)

    saved_sentinels = {}
    for i, reg in enumerate(setup['saved']):
        val = 0x0000000D000000B0 + (i + 1) if setup['is64'] else 0x22220022 + i
        saved_sentinels[reg] = val
        uc.reg_write(reg, val)

    _write_idtr(uc, IDT_BASE)
    gate = bytearray(setup['gate_size'])                     # x64 gate 16 B / x86 8 B
    struct.pack_into('<H', gate, 0x00, handler & 0xFFFF)     # low16
    struct.pack_into('<H', gate, 0x06, (handler >> 16) & 0xFFFF)
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
            f"kernel chain fault ({kind}/{arch}): {e}; "
            f"RIP={uc.reg_read(setup['ip']):#x} RSP={uc.reg_read(setup['sp']):#x}"
        )
    assert hits == [SINK], f"chain did not land on SINK; hits={hits}"
    for reg, want in saved_sentinels.items():
        got = uc.reg_read(reg)
        assert got == want, (
            f"kernel chain clobbered callee-save {reg}: want {want:#x}, got {got:#x}"
        )
    assert uc.reg_read(setup['sp']) == INIT_RSP + setup['ptr'], \
        f"RSP {uc.reg_read(setup['sp']):#x} != INIT_RSP+ptr after final ret"
    return uc, chain_len, stub_va, setup['ax']


_EXPORT_KIND_NAME = {
    'calc': b'RtlUlongAdd',
    'proc': b'PsCreateSystemProcess',
    'eh':   b'RtlPcToFileHeader',
}


def _shellcodify(kind: str, arch: str, blob: bytes, tmp_path) -> bytes:
    pe_path = tmp_path / f"driver_{kind}_{arch}.in.sys"
    pe_path.write_bytes(blob)
    sc_path = tmp_path / f"driver_{kind}_{arch}.sc.bin"
    dump_memory_layout(PE(str(pe_path)), sc_path)
    blob = sc_path.read_bytes()
    det = tmp_path / f"driver_{kind}_{arch}.sc.det.bin"
    dump_memory_layout(PE(str(pe_path)), det)
    assert blob == det.read_bytes(), f"{kind}/{arch}: shellcode output non-deterministic"
    return blob


def _read_chunk(uc, addr, size):
    return bytes(uc.mem_read(addr, size))


def _assert_iat_slot(uc, chain_len, arch, want):
    base = SC_BASE + chain_len + _IAT_RVA
    got  = int.from_bytes(_read_chunk(uc, base, 8 if arch == 'x64' else 4), 'little')
    assert got == want, f"IAT slot @{base:#x} = {got:#x}, want {want:#x}"


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_kernel_calc(arch, tmp_path):
    """calc: import resolver patches IAT; DriverEntry returns 3+2 == 5."""
    raw = _build_driver('calc', arch)
    features = _detect_pe_features(PE(str(_to(tmp_path, 'calc', arch, raw))))
    assert features.subsystem == _NATIVE_SUBSYSTEM
    sc = _shellcodify('calc', arch, raw, tmp_path)
    uc, chain_len, stub_va, ax_reg = _run_kernel_chain('calc', arch, sc, features, tmp_path)
    assert uc.reg_read(ax_reg) == CALC_RESULT, (
        f"calc result {uc.reg_read(ax_reg):#x} != 5"
    )
    _assert_iat_slot(uc, chain_len, arch, NT_BASE + _NT_STUB_RVA)


@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_kernel_idt_gate_far_from_nt_base(arch, tmp_path):
    """Gate-0 handler 8 MiB + 1 page above the nt base (real-VM geometry).

    Win11 26100 puts the gate-0 handler at nt RVA 0xBCB100 (~12 MiB, measured
    with kd), so the backward MZ walk must cover more than the old 0x0800
    guard.  The handler here sits 0x810 pages above the fake nt base: barely
    beyond the old guard, well inside the mapping.
    """
    raw = _build_driver('calc', arch)
    features = _detect_pe_features(PE(str(_to(tmp_path, 'calc', arch, raw))))
    sc = _shellcodify('calc', arch, raw, tmp_path)
    uc, chain_len, stub_va, ax_reg = _run_kernel_chain(
        'calc', arch, sc, features, tmp_path,
        nt_base=DEEP_NT_BASE, nt_map=DEEP_NT_MAP, handler=DEEP_HANDLER)
    assert uc.reg_read(ax_reg) == CALC_RESULT, (
        f"deep-nt calc result {uc.reg_read(ax_reg):#x} != 5"
    )
    _assert_iat_slot(uc, chain_len, arch, stub_va)


@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_kernel_create_process(arch, tmp_path):
    """proc: DriverEntry calls PsCreateSystemProcess; marker written."""
    raw = _build_driver('proc', arch)
    features = _detect_pe_features(PE(str(_to(tmp_path, 'proc', arch, raw))))
    sc = _shellcodify('proc', arch, raw, tmp_path)
    uc, chain_len, stub_va, ax_reg = _run_kernel_chain('proc', arch, sc, features, tmp_path)
    assert uc.reg_read(ax_reg) == PROC_NTSTATUS
    marker = int.from_bytes(
        _read_chunk(uc, SC_BASE + chain_len + _MARKER_RVA, 4), 'little')
    assert marker == DEADBEEF, f"stub never wrote marker ({marker:#x})"
    _assert_iat_slot(uc, chain_len, arch, stub_va)


def test_kernel_cpp_exception_fixer(tmp_path):
    """x64: cxx_eh_fixer must hook RtlPcToFileHeader on the kernel chain.

    * PcValue inside the PE -> returns runtime PE base and writes [rdx] = base;
    * PcValue outside the PE -> must forward to the resolved stub (0xCAFEBABE);
    * the *BaseOfImage slot for the outside call must be untouched;
    * driver asserts both statuses so RAX == 0.
    """
    raw = _build_driver('eh', 'x64')
    features = _detect_pe_features(PE(str(_to(tmp_path, 'eh', 'x64', raw))))
    assert features.has_cxx_eh
    assert features.iat_rva_rtlpctofileheader == _IAT_RVA
    sc = _shellcodify('eh', 'x64', raw, tmp_path)
    uc, chain_len, stub_va, ax_reg = _run_kernel_chain('eh', 'x64', sc, features, tmp_path)

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
    raw = bytearray(_build_driver('proc', 'x86'))
    struct.pack_into('<H', raw, E_LFANEW + 24 + 0x44, 2)
    p = tmp_path / 'kernel32_rej.sys'
    p.write_bytes(bytes(raw))
    features = _detect_pe_features(PE(str(p)))
    assert features.subsystem == 2
    with pytest.raises(PeorUnsupportedError, match='kernel-mode'):
        _validate_pe(PE(str(p)), platform=_PLATFORM_KERNEL_32)


def test_kernel_chain_selection(tmp_path):
    raw = _build_driver('calc', 'x64')
    p = _to(tmp_path, 'calc', 'x64', raw)
    features = _detect_pe_features(PE(str(p)))
    entry = _select_chain(features, platform=_PLATFORM_KERNEL)
    assert entry is _SHELLCODES[_PLATFORM_KERNEL]
    assert entry['imports']


def test_kernel_chain_auto_selects_kernel32(tmp_path):
    raw = _build_driver('calc', 'x86')
    p = _to(tmp_path, 'calc', 'x86', raw)
    features = _detect_pe_features(PE(str(p)))
    assert features.pe_type == OPTIONAL_HEADER_MAGIC_PE
    entry = _select_chain(features)                  # NATIVE auto-select
    assert entry is _SHELLCODES[_PLATFORM_KERNEL_32]
