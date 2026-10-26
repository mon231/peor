// Test C++ SYNC-exception handling (with a typed exception) in shellcode context

class MyCustomExceptionType final
{
public:
    explicit MyCustomExceptionType(int num) : _num(num) {}
    int get_num() const { return _num; }

private:
    int _num;
};

#define PROGRAM_EXIT_CODE (123)
static int test_seh()
{
    try
    {
        throw MyCustomExceptionType{PROGRAM_EXIT_CODE};
    }
    catch (const MyCustomExceptionType& e)
    {
        return e.get_num();
    }
    catch (...)
    {
        return 456;
    }

    return 789;
}

int main()
{
    return test_seh();
}
