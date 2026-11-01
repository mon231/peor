// no CRT, no imports, custom entry point
// the /FIXED flag strips the .reloc section (x86/x64)
// ARM64 cannot use /FIXED (LNK1246), and this source would otherwise compile to a
// position-independent image with zero absolute fixups - so no .reloc exists to
// keep. g_selfptr adds one: a static address-of-function initializer produces an
// absolute fixup in .rdata, which MSVC's ARM64 linker must emit as a base
// relocation (the volatile read in main keeps the symbol and its fixup alive).
static void shellcode_entry(void);

static void (*volatile g_selfptr)(void) = shellcode_entry;

static void shellcode_entry(void)
{
    if (g_selfptr == 0)  // runtime volatile read; not constant-foldable
    {
        return;
    }
    // The absolute fixup satisfied its purpose; the caller (test loader) reads 99.
}

int main(void)
{
    shellcode_entry();
    return 99;
}
