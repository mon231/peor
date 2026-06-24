// Tests real C++ exception handling (throw/catch with a typed exception) in shellcode context.
// On x64: relies on seh_registrar64 having called RtlAddFunctionTable so that
//   __CxxFrameHandler3 gets the correct ImageBase via DISPATCHER_CONTEXT when unwinding.
// On x86: relies on the stack-based SEH chain (no extra registration needed).
// Returns 123 if the typed catch fires, 456 if catch(...) fires, 789 if no exception caught.
// THIS FILE MUST NOT BE CHANGED!!!!

class MyCustomExceptionType final {
public:
    explicit MyCustomExceptionType(int num) : _num(num) {}
    int get_num() const { return _num; }
private:
    int _num;
};

static int test_seh() {
    try {
        throw MyCustomExceptionType{123};
    }
    catch (const MyCustomExceptionType& e) {
        return e.get_num();
    }
    catch (...) {
        return 456;
    }

    return 789;
}

int main() {
    return test_seh();
}
