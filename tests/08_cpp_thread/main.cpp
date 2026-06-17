#include <thread>

int main() {
    int result = 0;
    std::thread t([&result]() { result = 42; });
    t.join();
    return result;
}
