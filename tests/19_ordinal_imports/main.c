// Test shellcode resolves both import by func/by-ordinal

extern __declspec(dllimport) int ByNameFunc(void);
extern __declspec(dllimport) int OrdinalOnlyFunc(void);

int main(void)
{
    return ByNameFunc() + OrdinalOnlyFunc();
}
