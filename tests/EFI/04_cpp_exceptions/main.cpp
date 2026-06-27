/*
 * EFI C++ exception test.
 * Throws a custom type, catches it, prints PEOR_CPP_EH_OK and returns EFI_SUCCESS.
 * Supports x64 (PE32+) and x86 (PE32).
 *
 * Compile (x64, posix-threading g++ for DWARF-2 exceptions):
 *   x86_64-w64-mingw32-g++-posix -fexceptions -nostartfiles -nodefaultlibs \
 *     $(x86_64-w64-mingw32-g++-posix -print-file-name=crtbegin.o) \
 *     main.cpp \
 *     $(x86_64-w64-mingw32-g++-posix -print-file-name=crtend.o) \
 *     -lgcc_eh -lsupc++ -lgcc \
 *     -Wl,-e,efi_main -Wl,--subsystem,10 -o 04_efi_cpp.efi
 */

#ifdef _WIN64
typedef unsigned long long EFI_STATUS;
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x40
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x08
#else
typedef unsigned int EFI_STATUS;
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x2C
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x04
#endif

typedef unsigned short CHAR16;
#define EFI_SUCCESS    ((EFI_STATUS)0)
#define EFI_LOAD_ERROR ((EFI_STATUS)1)

#define CPP_EH_MAGIC_VALUE 0x5ECC

struct PeorEfiException {
    int code;
};

static const CHAR16 MSG_OK[] = {
    'P','E','O','R','_','C','P','P','_','E','H','_','O','K','\r','\n', 0
};
static const CHAR16 MSG_FAIL[] = {
    'P','E','O','R','_','C','P','P','_','E','H','_','F','A','I','L','\r','\n', 0
};

extern "C" EFI_STATUS efi_main(void *image_handle, void *system_table) {
    typedef EFI_STATUS (*OUTPUT_FN)(void *, const CHAR16 *);
    (void)image_handle;

    void *conout = *(void **)((unsigned char *)system_table + EFI_SYSTEM_TABLE_CONOUT_OFFSET);
    OUTPUT_FN output_string = *(OUTPUT_FN *)((unsigned char *)conout
                               + EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF);

    int caught_code = 0;
    try {
        throw PeorEfiException{CPP_EH_MAGIC_VALUE};
    } catch (PeorEfiException &e) {
        caught_code = e.code;
    } catch (...) {
        caught_code = -1;
    }

    if (caught_code == CPP_EH_MAGIC_VALUE) {
        output_string(conout, MSG_OK);
        return EFI_SUCCESS;
    }
    output_string(conout, MSG_FAIL);
    return EFI_LOAD_ERROR;
}
