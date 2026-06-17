/* No CRT, no imports. Entry point = main.
   /FIXED strips the .reloc section; the shellcodifier must handle DataDir[5].VA == 0. */
int main(void) {
    return 99;
}
