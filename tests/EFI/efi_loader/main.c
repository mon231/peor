// EFI loader - runs an embedded shellcode buffer, prints result, then shuts down
//
// x64/x86: the shellcode payload is NOT a per-test compile-time constant (that would
// force a compiler invocation inside test.py for every test). Instead this loader is
// compiled ONCE per architecture (by build_tests.py) with a fixed-size placeholder blob;
// the test harness locates MAGIC in the compiled loader.efi and byte-patches SIZE + BYTES
// in a copy of it before boot — no compiler runs at test time. See build_tests.py.
//
// ARM64/ARM32: this QEMU+EDK2 ARM firmware fails to boot a loader built with the blob
// above (silent hang partway through BdsDxe, root cause not identified — reproduces
// across native-Windows and WSL/Debian qemu-system-arm builds, independent of blob size
// down to ~52 KiB image size; a loader built the exact-size way below at ~40 KiB boots
// fine). So ARM keeps the original per-test compile: build_tests.py passes
// -DPEOR_ARM_LEGACY_SHELLCODE, and the test harness generates shellcode_data.h and
// recompiles this file per test (same as before this file supported x64/x86's blob
// patching) — the only place in the ARM EFI test path that still invokes a compiler.
#include <stddef.h>

#ifdef PEOR_ARM_LEGACY_SHELLCODE
#include "shellcode_data.h"
#else

#define SHELLCODE_MAX_SIZE 262144u  /* 256 KiB ceiling; C++ EH test embeds ~224 KiB observed */

/* magic[16] is a multiple of 8 bytes, so natural C struct layout already puts `size`
 * and `bytes` at fixed, gap-free offsets (16 and 24) without needing any #pragma pack —
 * deliberately not packed, since packing would drop the object's own alignment to 1 and
 * risk an unaligned 8-byte load of `size` (traps on strict-alignment ABIs). */
typedef struct {
    unsigned char magic[16];
    unsigned long long size;
    unsigned char bytes[SHELLCODE_MAX_SIZE];
} PeorShellcodeBlob;

static const PeorShellcodeBlob g_shellcode_blob = {
    { 'P','E','O','R','_','S','H','E','L','L','C','O','D','E','!','!' },
    0,
    { 0 }
};

#define SHELLCODE_SIZE  (g_shellcode_blob.size)
#define SHELLCODE_BYTES (g_shellcode_blob.bytes)

#endif  /* PEOR_ARM_LEGACY_SHELLCODE */

typedef unsigned char  UINT8;
typedef unsigned short UINT16;

#ifdef _WIN64
typedef unsigned long long UINTN;
typedef unsigned long long EFI_PHYSICAL_ADDRESS;
#define EFI_ST_CONOUT_OFF    0x40
#define EFI_ST_RUNTIME_OFF   0x58
#define EFI_ST_BOOTSVCS_OFF  0x60
#define EFI_RT_RESET_OFF     0x68
#define EFI_CONOUT_OUTSTR_OFF 0x08
#define EFI_BS_ALLOC_PAGES_OFF 0x28
#define EFI_BS_FREE_PAGES_OFF  0x30
#define EFI_BS_ALLOC_POOL_OFF 0x40
#define EFI_BS_FREE_POOL_OFF  0x48
#else
typedef unsigned int UINTN;
typedef unsigned long long EFI_PHYSICAL_ADDRESS;
#define EFI_ST_CONOUT_OFF     0x2C
#define EFI_ST_RUNTIME_OFF    0x38
#define EFI_ST_BOOTSVCS_OFF   0x3C
#define EFI_RT_RESET_OFF      0x40
#define EFI_CONOUT_OUTSTR_OFF 0x04
#define EFI_BS_ALLOC_PAGES_OFF 0x20
#define EFI_BS_FREE_PAGES_OFF  0x24
#define EFI_BS_ALLOC_POOL_OFF 0x2C
#define EFI_BS_FREE_POOL_OFF  0x30
#endif

typedef UINTN EFI_STATUS;

#define EFI_SUCCESS              ((EFI_STATUS)0)
#define EFI_RESET_SHUTDOWN       2
#define EFI_MEMORY_BOOT_SVC_CODE 3
#define EFI_PAGE_SIZE            4096

static const UINT16 OK_MSG[]   = {'P','E','O','R','_','E','F','I','_','O','K','\r','\n',0};
static const UINT16 FAIL_MSG[] = {'P','E','O','R','_','E','F','I','_','F','A','I','L','\r','\n',0};

EFI_STATUS efi_loader_main(void* image_handle, void* system_table)
{
    EFI_STATUS result;

#ifdef __aarch64__
    /* ARM64: EDK2 marks rodata XN (execute-never).  Use AllocatePages for page-aligned
     * executable memory.  Page-alignment is required because peor pads the ARM64 EFI
     * resolver chain to 4096 bytes so the PE starts at page boundary, making ADRP work. */
    typedef EFI_STATUS (*ALLOC_PAGES_FN)(int alloc_type, int mem_type, UINTN pages,
                                          EFI_PHYSICAL_ADDRESS *mem);
    typedef EFI_STATUS (*FREE_PAGES_FN)(EFI_PHYSICAL_ADDRESS mem, UINTN pages);

    void *bs = *(void **)((UINT8 *)system_table + EFI_ST_BOOTSVCS_OFF);
    ALLOC_PAGES_FN alloc_pages = *(ALLOC_PAGES_FN *)((UINT8 *)bs + EFI_BS_ALLOC_PAGES_OFF);
    FREE_PAGES_FN  free_pages  = *(FREE_PAGES_FN  *)((UINT8 *)bs + EFI_BS_FREE_PAGES_OFF);

    UINTN pages = ((UINTN)SHELLCODE_SIZE + EFI_PAGE_SIZE - 1) / EFI_PAGE_SIZE;
    EFI_PHYSICAL_ADDRESS exec_phys = 0;
    if (alloc_pages(0 /*AllocateAnyPages*/, EFI_MEMORY_BOOT_SVC_CODE, pages, &exec_phys) != EFI_SUCCESS
            || exec_phys == 0) {
        while (1) {}
    }

    UINT8 *exec_buf = (UINT8 *)exec_phys;
    const UINT8 *src = (const UINT8 *)SHELLCODE_BYTES;
    for (UINTN i = 0; i < (UINTN)SHELLCODE_SIZE; i++) {
        exec_buf[i] = src[i];
    }

    /* peor shellcodes are parameter-less: called as EFI_STATUS(void). The ARM64 EFI
     * entrypoint resolver locates EFI_SYSTEM_TABLE itself via a memory scan, so no
     * arguments are passed here (mirrors the x86/x64 EFI call below). */
    result = ((EFI_STATUS (*)(void))exec_buf)();
    free_pages(exec_phys, pages);
#elif defined(__arm__)
    /* ARM32: EDK2 enforces XN on rodata.  Use AllocatePages for page-aligned executable
     * memory (same requirement as ARM64: peor pads the chain to 4096 bytes so the PE
     * starts at a page boundary).  32-bit pointer offsets match the #else (x86) path. */
    typedef EFI_STATUS (*ALLOC_PAGES_FN32)(int alloc_type, int mem_type, UINTN pages,
                                            EFI_PHYSICAL_ADDRESS *mem);
    typedef EFI_STATUS (*FREE_PAGES_FN32)(EFI_PHYSICAL_ADDRESS mem, UINTN pages);

    void *bs32 = *(void **)((UINT8 *)system_table + EFI_ST_BOOTSVCS_OFF);
    ALLOC_PAGES_FN32 alloc_pages32 = *(ALLOC_PAGES_FN32 *)((UINT8 *)bs32 + EFI_BS_ALLOC_PAGES_OFF);
    FREE_PAGES_FN32  free_pages32  = *(FREE_PAGES_FN32  *)((UINT8 *)bs32 + EFI_BS_FREE_PAGES_OFF);

    UINTN pages32 = ((UINTN)SHELLCODE_SIZE + EFI_PAGE_SIZE - 1) / EFI_PAGE_SIZE;
    EFI_PHYSICAL_ADDRESS exec_phys32 = 0;
    if (alloc_pages32(0 /*AllocateAnyPages*/, EFI_MEMORY_BOOT_SVC_CODE, pages32, &exec_phys32) != EFI_SUCCESS
            || exec_phys32 == 0) {
        while (1) {}
    }

    UINT8 *exec_buf32 = (UINT8 *)(UINTN)exec_phys32;
    const UINT8 *src32 = (const UINT8 *)SHELLCODE_BYTES;
    for (UINTN i = 0; i < (UINTN)SHELLCODE_SIZE; i++) {
        exec_buf32[i] = src32[i];
    }

    /* peor shellcodes are parameter-less: called as EFI_STATUS(void). The ARM32 EFI
     * entrypoint resolver locates EFI_SYSTEM_TABLE itself via a memory scan, so no
     * arguments are passed here. Thumb-2 functions must be called with bit 0 of the
     * address set; the allocated page is naturally aligned (bit 0 = 0), so OR 1 to
     * enter Thumb mode. */
    result = ((EFI_STATUS (*)(void))(((UINTN)exec_buf32) | 1))();
    free_pages32(exec_phys32, pages32);
#else
    /* x86 / x64: OVMF does not enforce XN on pre-boot memory. */
    result = ((EFI_STATUS (*)(void))SHELLCODE_BYTES)();
#endif

    /* Print result via ConOut->OutputString. */
    void *conout = *(void **)((UINT8 *)system_table + EFI_ST_CONOUT_OFF);
    typedef EFI_STATUS (*OUTPUT_FN)(void *proto, const UINT16 *str);
    OUTPUT_FN output_string = *(OUTPUT_FN *)((UINT8 *)conout + EFI_CONOUT_OUTSTR_OFF);

    output_string(conout, result == EFI_SUCCESS ? OK_MSG : FAIL_MSG);

    /* Shut down the machine on success so QEMU exits 0. */
    if (result == EFI_SUCCESS) {
        void *rt = *(void **)((UINT8 *)system_table + EFI_ST_RUNTIME_OFF);
        typedef void (*RESET_FN)(int reset_type, EFI_STATUS status,
                                 UINTN data_size, void *data);
        RESET_FN reset_system = *(RESET_FN *)((UINT8 *)rt + EFI_RT_RESET_OFF);
        reset_system(EFI_RESET_SHUTDOWN, EFI_SUCCESS, 0, NULL);
    }

    /* Failure path: loop forever (QEMU will time out, test fails). */
    while (1) {}
    return result;
}
