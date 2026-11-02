/* Minimal x86 kernel CRT shim for the Win32 configurations of the local
 * test solution. The installed WDK 10.0.28000.0 dropped km\x86 entirely,
 * including BufferOverflowFastFailK.lib which supplied memset (and the
 * GsDriverEntry wrapper). Win32 builds compile /GS- /guard:cf- and link
 * against generated ntoskrnl import stubs (see win32_kernel.props), so the
 * only still-missing symbol is memset. x64 is untouched: this file is only
 * added to Win32 configurations and keeps the stock WDK behavior there.
 */
#pragma function(memset)
/* Freestanding kernel C: no CRT headers, so size_t is spelled out. On x86
 * unsigned int is the 32-bit size type callers pass. */
void *__cdecl memset(void *dst, int value, unsigned int count)
{
    unsigned char *d = (unsigned char *)dst;
    unsigned char   v = (unsigned char)value;
    while (count--) *d++ = v;
    return dst;
}
