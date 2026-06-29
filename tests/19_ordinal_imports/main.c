#define BY_NAME_RESULT    30
#define BY_ORDINAL_RESULT 12
#define EXPECTED_SUM      42

extern __declspec(dllimport) int ByNameFunc(void);
extern __declspec(dllimport) int OrdinalOnlyFunc(void);

int main(void) {
    return ByNameFunc() + OrdinalOnlyFunc();  /* BY_NAME_RESULT + BY_ORDINAL_RESULT = EXPECTED_SUM */
}
