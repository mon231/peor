// Tests that peor correctly handles nested try/rethrow C++ exceptions.
// Inner catch rethrows; outer catch must fire and return 55.
#include <windows.h>

static int nested_rethrow() {
    try {
        try {
            throw 1;
        } catch (int) {
            throw;
        }
    } catch (int) {
        return 55;
    }
    return 0;
}

int main() {
    return nested_rethrow();
}
