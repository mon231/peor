/* Freestanding crtbegin.o replacement.
 * Link FIRST. Defines __EH_FRAME_BEGIN__ at the start of .eh_frame and
 * registers DWARF EH frames via a .init_array constructor called by peor's ctors runner.
 * No Windows API or CRT dependencies.
 *
 * On x86 (i386): DWARF-2 frame registration is required at runtime via __register_frame_info.
 * On x64: SEH unwind tables in the .pdata section are used; no explicit registration needed. */

#ifdef __i386__

/* On i386 Windows PE, C symbols get a leading underscore in the COFF object
 * file, so the C name __EH_FRAME_BEGIN__ becomes ___EH_FRAME_BEGIN__.
 * The asm label must match the decorated name. */
__asm__(".section .eh_frame,\"dr\"\n\t"
        ".global ___EH_FRAME_BEGIN__\n\t"
        "___EH_FRAME_BEGIN__:\n\t"
        ".section .text");

/* g++ treats .c files as C++; guard ensures C linkage so names match what
 * libgcc_eh.a exports (___register_frame_info) and what the .init_ar ASM
 * references (__peor_register_eh_frames). */
#ifdef __cplusplus
extern "C" {
#endif

extern char __EH_FRAME_BEGIN__[];
static char _eh_ob[64];
extern void *__register_frame_info(const void *, void *);

/* The x86 MinGW linker silently drops .ctors sections when -nostartfiles is
 * used (no crtbegin.o sentinels).  Use .init_array explicitly via an
 * attribute so the linker keeps the section.  On i686 COFF, 8-char section
 * names truncate: ".init_array" → ".init_ar" in the PE header.
 * peor's _find_ctors_section looks for both names. */
static void _peor_register_eh_frames(void) {
    __register_frame_info(__EH_FRAME_BEGIN__, _eh_ob);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

/* Place function pointer in .init_ar (8-char COFF section name, truncated
 * from .init_array) so peor's ctors_runner calls it.
 *
 * Why not .ctors: the x86 MinGW linker drops .ctors sections when there is no
 * crtbegin.o sentinel — .init_ar is an ordinary data section not subject to
 * that treatment.
 *
 * Why not .init_array: names > 8 chars are stored via the COFF string table
 * (as "/N" in the section header) which pefile returns as b'/N', not the
 * original name — peor cannot find it.
 *
 * The COFF symbol for _peor_register_eh_frames (C name with 1 leading _)
 * is __peor_register_eh_frames (2 underscores). */
__asm__(".section \".init_ar\",\"dw\"\n\t"
        ".long __peor_register_eh_frames\n\t"
        ".section .text");

#endif /* __i386__ */
