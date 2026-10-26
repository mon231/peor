// no CRT, no imports, custom entry point
// the /FIXED flag strips the .reloc section
// the shellcodifier must handle DataDir[5].VA == 0
int main(void)
{
    return 99;
}
