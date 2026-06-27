/* Freestanding crtbegin.o replacement.
 * Link FIRST. Defines __EH_FRAME_BEGIN__ at the start of .eh_frame and
 * registers DWARF EH frames via a .init_array constructor called by peor's ctors runner.
 * No Windows API or CRT dependencies. */
__asm__(".section .eh_frame,\"dr\"\n\t"
        ".global __EH_FRAME_BEGIN__\n\t"
        "__EH_FRAME_BEGIN__:\n\t"
        ".previous");
extern char __EH_FRAME_BEGIN__[];
static char _eh_ob[64];
extern void *__register_frame_info(const void *, void *);
__attribute__((constructor)) static void _peor_register_eh_frames(void) {
    __register_frame_info(__EH_FRAME_BEGIN__, _eh_ob);
}
