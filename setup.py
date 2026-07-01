import os
import re
import struct
import setuptools
from pathlib import Path
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.develop import develop as _develop


def _get_version():
    # CI/CD tags are named "vX.Y.Z"; GITHUB_REF is "refs/tags/vX.Y.Z" on a release.
    # PyPI users install without CI variables, so fall back to 0.0.1.
    ref = os.environ.get('GITHUB_REF', '')
    if ref.startswith('refs/tags/v'):
        return ref[len('refs/tags/v'):]
    return '0.0.1'


CURRENT_FOLDER = Path(__file__).parent
README_PATH = CURRENT_FOLDER / 'README.md'
ASM_DIR = CURRENT_FOLDER / 'asm'
SHELLCODES_PY = CURRENT_FOLDER / 'peor' / '_shellcodes.py'

# Matches `%define PE_OFFSET_PLACEHOLDER 0x7E7E7E7E` in relocations_resolver{32,64}.asm.
# After assembly, setup.py patches these bytes with the actual (shellcode_size - 5).
_PE_OFFSET_PLACEHOLDER = b'\x7e\x7e\x7e\x7e'

# Matches `%define EP_RVA_MAGIC 0xCECECECE` in entrypoint_resolver{32,64}.asm.
# Verified to appear exactly once; patched by peor at conversion time (not by setup.py).
_EP_RVA_PLACEHOLDER = b'\xce\xce\xce\xce'


def _preprocess_asm(src):
    """Strip %define lines, substitute their names inline, and strip comments.

    Keystone NASM mode does not support %define; we handle it ourselves so
    asm sources can use named constants as the CONTRIBUTING guidelines require.
    Comments are stripped so non-ASCII documentation characters (em-dashes, arrows)
    do not cause UnicodeEncodeError when keystone encodes the source as ASCII.
    """
    defines = {}
    lines = []
    for line in src.split('\n'):
        m = re.match(r'\s*%define\s+(\w+)\s+(\S+)', line)
        if m:
            defines[m.group(1)] = m.group(2)
        else:
            comment_pos = line.find(';')
            if comment_pos >= 0:
                line = line[:comment_pos]
            lines.append(line)
    src = '\n'.join(lines)
    for name in sorted(defines, key=len, reverse=True):
        src = re.sub(r'\b' + re.escape(name) + r'\b', defines[name], src)
    return src


def _assemble_shellcodes():
    """Assemble all ASM resolver sources into peor/_shellcodes.py via keystone."""
    import keystone

    def assemble(asm_path, arch, mode, patch_pe_offset=False):
        ks = keystone.Ks(arch, mode)
        ks.syntax = keystone.KS_OPT_SYNTAX_NASM
        src = _preprocess_asm(Path(asm_path).read_text())
        encoding, _ = ks.asm(src)
        if encoding is None:
            raise RuntimeError(f"keystone assembly failed for {asm_path}")
        result = bytearray(encoding)

        if patch_pe_offset:
            # The shellcode starts with "CALL _base" (5 bytes), then "POP reg" leaves
            # reg pointing to _base (offset 5 from start).  We want reg + offset = PE base.
            # PE base = shellcode_start + len(shellcode), so offset = len - 5.
            pe_offset = len(result) - 5
            idx = result.find(_PE_OFFSET_PLACEHOLDER)
            if idx == -1:
                raise RuntimeError(f"PE offset placeholder {_PE_OFFSET_PLACEHOLDER.hex()} not found in {asm_path}")
            result[idx:idx + 4] = struct.pack('<I', pe_offset)

        return bytes(result)

    def assemble_arm64(asm_path, patch_pe_offset_pool=False):
        # IMPORTANT: KS_OPT_SYNTAX_NASM (set by any x86 Ks instance) permanently poisons
        # the Keystone global state for ARM64 assembly. All ARM64 files must be assembled
        # BEFORE any x86 `assemble()` call that sets KS_OPT_SYNTAX_NASM.
        ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
        src = _preprocess_asm(Path(asm_path).read_text())
        encoding, _ = ks.asm(src)
        if encoding is None:
            raise RuntimeError(f"keystone ARM64 assembly failed for {asm_path}")
        result = bytearray(encoding)
        if patch_pe_offset_pool:
            # _base is at offset 0; pool is at offsets [8:16] (two NOPs patched here).
            # Initial PE_OFFSET = len(blob) because _base + len(blob) = address of PE.
            result[8:16] = struct.pack('<Q', len(result))
        return bytes(result)

    def assemble_arm32(asm_path_or_src, patch_pe_offset_pool=False, src_is_string=False):
        # IMPORTANT: ARM32 assembly must also happen BEFORE any x86 assemble() call that
        # sets KS_OPT_SYNTAX_NASM, for the same global-state poisoning reason as ARM64.
        ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)
        if src_is_string:
            src = asm_path_or_src
        else:
            src = _preprocess_asm(Path(asm_path_or_src).read_text())
        encoding, _ = ks.asm(src)
        if encoding is None:
            raise RuntimeError(f"keystone ARM32 Thumb-2 assembly failed for {asm_path_or_src!r:.60}")
        result = bytearray(encoding)
        if patch_pe_offset_pool:
            # Pool is at offset 8 (see relocations_resolver_arm32.asm literal-pool layout).
            # r0 = _base+4 after mov r0, pc; r4 = r0 + pool_value.
            # For r4 = _base + len(blob): pool_value = len(blob) - 4.
            result[8:12] = struct.pack('<I', len(result) - 4)
        return bytes(result)

    # ARM64 + ARM32 assembly MUST happen before any x86 assemble() call.
    r_arm64     = assemble_arm64(ASM_DIR / 'relocations_resolver_arm64.asm', patch_pe_offset_pool=True)
    ctors_arm64 = assemble_arm64(ASM_DIR / 'ctors_runner_arm64.asm')
    e_efi_arm64_raw = assemble_arm64(ASM_DIR / 'entrypoint_resolver_efi_arm64.asm')

    r_arm32     = assemble_arm32(ASM_DIR / 'relocations_resolver_arm32.asm', patch_pe_offset_pool=True)
    ctors_arm32 = assemble_arm32(ASM_DIR / 'ctors_runner_arm32.asm')
    e_efi_arm32_raw = assemble_arm32(ASM_DIR / 'entrypoint_resolver_efi_arm32.asm')
    arm32_efi_prefix_raw = assemble_arm32(
        "push {r4, r5, r6, r7, r8, r9, r10, r11, lr}\nmov r9, r0\nmov r10, r1",
        src_is_string=True,
    )

    r32      = assemble(ASM_DIR / 'relocations_resolver32.asm',       keystone.KS_ARCH_X86, keystone.KS_MODE_32, patch_pe_offset=True)
    r64      = assemble(ASM_DIR / 'relocations_resolver64.asm',       keystone.KS_ARCH_X86, keystone.KS_MODE_64, patch_pe_offset=True)
    i32      = assemble(ASM_DIR / 'imports_resolver32.asm',           keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    i64      = assemble(ASM_DIR / 'imports_resolver64.asm',           keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    i64_linux = assemble(ASM_DIR / 'imports_resolver64_linux.asm',    keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    i32_linux = assemble(ASM_DIR / 'imports_resolver32_linux.asm',    keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    dl32     = assemble(ASM_DIR / 'imports_resolver32_delayload.asm', keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    dl64     = assemble(ASM_DIR / 'imports_resolver64_delayload.asm', keystone.KS_ARCH_X86, keystone.KS_MODE_64)

    e32_raw  = assemble(ASM_DIR / 'entrypoint_resolver32.asm',        keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    e64_raw  = assemble(ASM_DIR / 'entrypoint_resolver64.asm',        keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    e_efi64_raw     = assemble(ASM_DIR / 'entrypoint_resolver_efi64.asm',      keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    e_efi32_raw     = assemble(ASM_DIR / 'entrypoint_resolver_efi32.asm',      keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    # Verify EP_RVA_MAGIC appears exactly once in each entrypoint resolver (peor patches it at conversion time)
    for ep_name, ep_raw in [
        ('entrypoint_resolver32.asm',          e32_raw),
        ('entrypoint_resolver64.asm',          e64_raw),
        ('entrypoint_resolver_efi64.asm',      e_efi64_raw),
        ('entrypoint_resolver_efi32.asm',      e_efi32_raw),
        ('entrypoint_resolver_efi_arm64.asm',  e_efi_arm64_raw),
        ('entrypoint_resolver_efi_arm32.asm',  e_efi_arm32_raw),
    ]:
        if bytes(ep_raw).count(_EP_RVA_PLACEHOLDER) != 1:
            raise RuntimeError(f"Expected exactly one EP_RVA_MAGIC 0xCECECECE in {ep_name}")
    e32         = e32_raw
    e64         = e64_raw
    e_efi64     = e_efi64_raw
    e_efi32     = e_efi32_raw
    e_efi_arm64 = e_efi_arm64_raw
    e_efi_arm32 = e_efi_arm32_raw

    s64  = assemble(ASM_DIR / 'seh_registrar64.asm',         keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    s32  = assemble(ASM_DIR / 'seh_registrar32.asm',         keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    t32  = assemble(ASM_DIR / 'tls_callbacks32.asm',         keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    t64  = assemble(ASM_DIR / 'tls_callbacks64.asm',         keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    ctors64     = assemble(ASM_DIR / 'ctors_runner64.asm',       keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    ctors32     = assemble(ASM_DIR / 'ctors_runner32.asm',       keystone.KS_ARCH_X86, keystone.KS_MODE_32)

    # Verify ctors magic bytes appear exactly once in each assembled ctors runner.
    _CTORS_RVA_MAGIC_BYTES  = b'\xfd\xfc\xfb\xfa'
    _CTORS_SIZE_MAGIC_BYTES = b'\xe4\xe3\xe2\xe1'
    for _name, _raw in [('ctors_runner64.asm', ctors64), ('ctors_runner32.asm', ctors32),
                        ('ctors_runner_arm64.asm', ctors_arm64), ('ctors_runner_arm32.asm', ctors_arm32)]:
        if _raw.count(_CTORS_RVA_MAGIC_BYTES) != 1:
            raise RuntimeError(f"CTORS_RVA_MAGIC not unique in {_name}")
        if _raw.count(_CTORS_SIZE_MAGIC_BYTES) != 1:
            raise RuntimeError(f"CTORS_SIZE_MAGIC not unique in {_name}")

    # cxx_eh_fixer: patch the FORWARD_MAGIC (0xFEFEFEFE) with the runtime byte-distance
    # from _setup_ip to _data (so the setup code can find the data area via POP+ADD).
    # The distance is computed from the assembled bytes by locating the CALL instruction
    # that precedes the data area: call _data_ref has a fixed relative offset equal to
    # the data area size (24 bytes for x64, 12 bytes for x86), so it encodes as a
    # recognisable pattern.
    def _patch_forward_magic(raw, data_call_pattern, magic_bytes):
        """Patch the forward-distance magic with the actual distance from _setup_ip to _data."""
        raw = bytearray(raw)
        # _setup_ip is at byte 5 (right after the 5-byte 'call _setup_ip' at offset 0).
        setup_ip_pos = 5
        # Locate 'call _data_ref' whose push value is &_data (right after the call insn).
        call_pos = bytes(raw).find(data_call_pattern)
        if call_pos == -1:
            raise RuntimeError(f"_data call pattern {data_call_pattern.hex()} not found")
        data_pos = call_pos + 5
        forward = data_pos - setup_ip_pos
        # Patch the magic bytes in the assembled code.
        idx = bytes(raw).find(magic_bytes)
        if idx == -1 or bytes(raw).find(magic_bytes, idx + 1) != -1:
            raise RuntimeError(f"Expected exactly one {magic_bytes.hex()} (FORWARD_MAGIC) in cxx_eh_fixer")
        raw[idx:idx + 4] = struct.pack('<I', forward)
        return bytes(raw)

    f64_raw = assemble(ASM_DIR / 'cxx_eh_fixer64.asm', keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    # x64 magic: 0x5A5A5A5A (positive, fits signed int32, encoded in ADD RAX, imm32)
    f64 = _patch_forward_magic(f64_raw, b'\xe8\x18\x00\x00\x00', b'\x5a\x5a\x5a\x5a')

    SHELLCODES_PY.write_text(
        "# Auto-generated by setup.py -- do not edit. Re-run: pip install -e .\n"
        f"RELOCS_32              = bytes.fromhex('{r32.hex()}')\n"
        f"RELOCS_64              = bytes.fromhex('{r64.hex()}')\n"
        f"IMPORTS_32_UM          = bytes.fromhex('{i32.hex()}')\n"
        f"IMPORTS_64_UM          = bytes.fromhex('{i64.hex()}')\n"
        f"IMPORTS_64_LINUX       = bytes.fromhex('{i64_linux.hex()}')\n"
        f"IMPORTS_32_LINUX       = bytes.fromhex('{i32_linux.hex()}')\n"
        f"DELAY_IMPORTS_32_UM    = bytes.fromhex('{dl32.hex()}')\n"
        f"DELAY_IMPORTS_64_UM    = bytes.fromhex('{dl64.hex()}')\n"
        f"ENTRYPOINT_32          = bytes.fromhex('{e32.hex()}')\n"
        f"ENTRYPOINT_64          = bytes.fromhex('{e64.hex()}')\n"
        f"ENTRYPOINT_EFI64       = bytes.fromhex('{e_efi64.hex()}')\n"
        f"ENTRYPOINT_EFI32       = bytes.fromhex('{e_efi32.hex()}')\n"
        f"SEH_REGISTRAR_32       = bytes.fromhex('{s32.hex()}')\n"
        f"SEH_REGISTRAR_64       = bytes.fromhex('{s64.hex()}')\n"
        f"TLS_CALLBACKS_32       = bytes.fromhex('{t32.hex()}')\n"
        f"TLS_CALLBACKS_64       = bytes.fromhex('{t64.hex()}')\n"
        f"CXX_EH_FIXER_64        = bytes.fromhex('{f64.hex()}')\n"
        f"CTORS_RUNNER_64        = bytes.fromhex('{ctors64.hex()}')\n"
        f"CTORS_RUNNER_32        = bytes.fromhex('{ctors32.hex()}')\n"
        f"RELOCS_ARM64           = bytes.fromhex('{r_arm64.hex()}')\n"
        f"CTORS_RUNNER_ARM64     = bytes.fromhex('{ctors_arm64.hex()}')\n"
        f"ENTRYPOINT_EFI_ARM64   = bytes.fromhex('{e_efi_arm64.hex()}')\n"
        "ARM64_EFI_PREFIX       = bytes.fromhex('f80301aa')\n"
        f"RELOCS_ARM32           = bytes.fromhex('{r_arm32.hex()}')\n"
        f"CTORS_RUNNER_ARM32     = bytes.fromhex('{ctors_arm32.hex()}')\n"
        f"ENTRYPOINT_EFI_ARM32   = bytes.fromhex('{e_efi_arm32.hex()}')\n"
        f"ARM32_EFI_PREFIX       = bytes.fromhex('{arm32_efi_prefix_raw.hex()}')\n"
    )

    print(f"[peor] assembled shellcodes -> {SHELLCODES_PY}")


# Run assembly whenever setup.py is evaluated by pip (build env already has keystone).
# pyproject.toml lists keystone-engine in build-system.requires so it's always present here.
_assemble_shellcodes()


class build_py(_build_py):
    def run(self):
        _assemble_shellcodes()
        super().run()


class develop(_develop):
    def run(self):
        _assemble_shellcodes()
        super().run()


setuptools.setup(
    name='peor',
    version=_get_version(),
    author='Ariel Tubul',
    packages=setuptools.find_packages(),
    long_description=README_PATH.read_text(encoding='utf-8'),
    install_requires=['pefile', 'keystone-engine'],
    long_description_content_type='text/markdown',
    url='https://github.com/mon231/peor/',
    description='PortableExecutable shellcodifier',
    entry_points={'console_scripts': ['peor=peor.__main__:main']},
    cmdclass={
        'build_py': build_py,
        'develop': develop,
    },
)
