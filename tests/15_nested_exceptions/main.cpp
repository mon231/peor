// Test shellcode handles nested try/rethrow C++ exceptions
#include <windows.h>

static int nested_rethrow() {
    try
    {
        try
        {
            throw 123;
        }
        catch (int)
        {
            throw;
        }

        return 0;
    }
    catch (int)
    {
        return 55;
    }

    return 0;
}

int main()
{
    return nested_rethrow();
}
