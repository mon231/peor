// Test C++ ASYNC-exception handling (with a typed exception) in shellcode context

class SehModeException final
{
public:
    explicit SehModeException(int code) : _code(code) {}
    int code() const { return _code; }

private:
    int _code;
};

static int run_test()
{
    try
    {
        throw SehModeException{123};
    }
    catch (const SehModeException& e)
    {
        return e.code();
    }
    catch (...)
    {
        return 456;
    }

    return 789;
}

int main()
{
    return run_test();
}
