// Tests Windows SEH (__try/__except)
#include <windows.h>

#define PROGRAM_EXIT_CODE (77)
int test_seh()
{
    __try
    {
        RaiseException(PROGRAM_EXIT_CODE, 0, 0, NULL);
    } __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }

    return 0;
}

int main()
{
    return test_seh();
}
