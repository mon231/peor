/* Freestanding crtend.o replacement.
 * Link LAST. Appends a 4-byte null record at the end of .eh_frame so that
 * __register_frame_info knows where the section ends. */
__asm__(".section .eh_frame,\"dr\"\n\t.long 0\n\t.previous");
