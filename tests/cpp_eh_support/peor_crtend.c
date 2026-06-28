/* Freestanding crtend.o replacement.
 * Link LAST. On x86 (i386) with DWARF-2 EH: appends a 4-byte null record at the end
 * of .eh_frame so that __register_frame_info knows where the section ends.
 * On x64 SEH is used instead of DWARF frames, so no .eh_frame terminator is needed. */
#ifdef __i386__
__asm__(".section .eh_frame,\"dr\"\n\t.long 0\n\t.section .text");
#endif
