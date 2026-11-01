/* Real-kernel 'a+b' calc payload for the peor local-test VM suite.
 *
 * Compiled by the WDK (tests/local_tests/kernelsrc, NATIVE .sys), then
 * converted into a peor kernel64 chain blob via `python -m peor`. On the
 * VM the SCM loader driver copies the blob into executable non-paged pool
 * and calls it; here, for real in ring-0:
 *
 *   dosError = RtlNtStatusToDosError(STATUS_SUCCESS);   // documented import
 *   sum      = 3 + 2 + dosError;                        // = 5
 *
 * RtlNtStatusToDosError(0) returns 0 (documented behavior), so the sum is
 * deterministic. The marker file records the computed sum:
 *   \??\C:\Windows\Temp\peor_calc_result.txt   "PEOR_CALC=0x00000005\r\n"
 * On success DriverEntry returns STATUS_SUCCESS; otherwise the marker
 * still records the bad sum for the test to fail with a clear message.
 */
#include "payload_common.h"

#define PEOR_A 3u
#define PEOR_B 2u

EXTERN_C NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT Loader, PUNICODE_STRING RegPath)
{
    UNREFERENCED_PARAMETER(Loader);
    UNREFERENCED_PARAMETER(RegPath);
    const CHAR* hexCharset = "0123456789ABCDEF";
    const CHAR* prefix      = "PEOR_CALC=";
    UNICODE_STRING path;
    CHAR           text[32];
    ULONG          dosError;
    NTSTATUS       statusProbe;
    unsigned int   sum;
    int            i, n;

    /* Real ntoskrnl call through the chain's import resolver. */
    statusProbe = STATUS_SUCCESS;
    dosError    = RtlNtStatusToDosError(statusProbe);

    sum = PEOR_A + PEOR_B + dosError;

    n = 0;
    {
        const CHAR* p;
        for (p = prefix; *p; ++p)
            text[n++] = *p;
    }
    for (i = 7; i >= 0; --i)
        text[n++] = hexCharset[(sum >> (i * 4)) & 0xF];
    text[n++] = '\r';
    text[n++] = '\n';

    PeorInitPath(&path, PEOR_MARK_ROOT L"peor_calc_result.txt");
    PeorWriteMarkerBuffer(&path, text, (ULONG)n);

    return (sum == 5) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER_1;
}
