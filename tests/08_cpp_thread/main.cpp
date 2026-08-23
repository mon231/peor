// test multi-threaded binary
#include <thread>

#define PROGRAM_EXIT_CODE (42)
int main() {
    int result = 0;
    std::thread t([&result]() { result = PROGRAM_EXIT_CODE; });

    t.join();
    return result;
}
