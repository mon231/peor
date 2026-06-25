// Tests that peor runs global C++ constructors (CRT .CXX initializers).
// Counter() sets g_value = 42 before main(); main returns g_value.
#include <windows.h>

static int g_value = 0;

class Counter {
public:
    Counter()  { g_value = 42; }
    ~Counter() = default;
    int get() const { return g_value; }
};

static Counter g_counter;

int main() {
    return g_counter.get();
}
