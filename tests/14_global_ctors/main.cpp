// Test the shellcode runs global C++ constructors (CRT .CXX initializers)
#include <windows.h>
static int g_value = 0;

class Counter
{
public:
    explicit Counter()  { g_value = 42; }
    int get() const { return g_value; }
};

static Counter g_counter;

int main()
{
    return g_counter.get();
}
