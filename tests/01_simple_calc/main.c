// Importless, custom entrypoint (no CRT). Raw loop with embedded arithmetic.
int main(void) {
    int result = 0;
    for (int i = 0; i < 100; ++i)
        result += i;
    return result;
}
