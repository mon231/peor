#include <Windows.h>
#include <winnt.h>

#ifdef _WIN64
#define KERNEL32_BASE_ADDRESS *(uintptr_t*)(*(uintptr_t*)(*(uintptr_t*)(*(uintptr_t*)(*(uintptr_t*)((sizeof(uintptr_t) == 4 ? 0 : __readgsqword(0x60)) + (sizeof(uintptr_t) == 4 ? 12 : 24)) + (sizeof(uintptr_t) == 4 ? 12 : 16)))) + (sizeof(uintptr_t) == 4 ? 24 : 48))
#else
#define KERNEL32_BASE_ADDRESS *(uintptr_t*)(*(uintptr_t*)(*(uintptr_t*)(*(uintptr_t*)(*(uintptr_t*)((sizeof(uintptr_t) == 4 ? __readfsdword(0x30) : 0) + (sizeof(uintptr_t) == 4 ? 12 : 24)) + (sizeof(uintptr_t) == 4 ? 12 : 16)))) + (sizeof(uintptr_t) == 4 ? 24 : 48))
#endif

using LoadLibraryT = decltype(LoadLibraryA);
using GetProcAddressT = decltype(GetProcAddress);

const BYTE* rva_to_ptr(const BYTE* base, DWORD rva)
{
    return base + rva;
}

__forceinline
int mystrcmp(LPCSTR a, LPCSTR b)
{
    while (*a && (*a == *b))
    {
        ++a;
        ++b;
    }

    return (unsigned char)(*a) - (unsigned char)(*b);
}

void* my_get_proc_address(LPCBYTE nt_module, const char* funcname)
{
    if (!nt_module || !funcname) return nullptr;

    const BYTE* base = nt_module;

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    const auto& opt = nt->OptionalHeader;
    if (opt.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return nullptr;

    const auto& dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return nullptr;

    auto exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(rva_to_ptr(base, dir.VirtualAddress));

    auto names = reinterpret_cast<const DWORD*>(rva_to_ptr(base, exp->AddressOfNames));
    auto ordinals = reinterpret_cast<const WORD*>(rva_to_ptr(base, exp->AddressOfNameOrdinals));
    auto functions = reinterpret_cast<const DWORD*>(rva_to_ptr(base, exp->AddressOfFunctions));

    // Search by name
    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        const char* name = reinterpret_cast<const char*>(rva_to_ptr(base, names[i]));
        if (name && mystrcmp(name, funcname) == 0)
        {
            WORD ordIndex = ordinals[i];               // index into AddressOfFunctions
            DWORD funcRva = functions[ordIndex];
            if (!funcRva) return nullptr;

            const BYTE* funcPtr = rva_to_ptr(base, funcRva);

            // Forwarded export check:
            // Forwarders live inside the export directory region and are ASCII strings like "KERNELBASE.Sleep"
            const BYTE* expStart = rva_to_ptr(base, dir.VirtualAddress);
            const BYTE* expEnd = expStart + dir.Size;
            if (funcPtr >= expStart && funcPtr < expEnd)
            {
                // Forwarded string (not an actual code address)
                // You can choose to return nullptr or implement resolution.
                // Returning nullptr is often fine for custom loaders that don’t resolve forwarders.
                return nullptr;
            }

            return const_cast<void*>(reinterpret_cast<const void*>(funcPtr));
        }
    }

    return nullptr;
}

__forceinline
void  resolve_imports(LPBYTE nt_image, GetProcAddressT* gp, LoadLibraryT* ll)
{
    // Get DOS header
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)nt_image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    // Get NT headers
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(nt_image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    // Get import directory
    IMAGE_DATA_DIRECTORY* import_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir->VirtualAddress == 0 || import_dir->Size == 0) return;

    // Get first import descriptor
    IMAGE_IMPORT_DESCRIPTOR* import_desc = (IMAGE_IMPORT_DESCRIPTOR*)(nt_image + import_dir->VirtualAddress);

    // Loop through all import descriptors (terminated by zero-filled entry)
    while (import_desc->Name != 0)
    {
        // Get DLL name
        const char* dll_name = (const char*)(nt_image + import_desc->Name);

        // Load the DLL
        HMODULE dll_base = ll(dll_name);
        if (!dll_base)
        {
            import_desc++;
            continue;
        }

        // Process thunks
        IMAGE_THUNK_DATA* orig_first_thunk = (IMAGE_THUNK_DATA*)(nt_image + import_desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA* first_thunk = (IMAGE_THUNK_DATA*)(nt_image + import_desc->FirstThunk);

        // If OriginalFirstThunk is zero, use FirstThunk instead
        if (import_desc->OriginalFirstThunk == 0)
        {
            orig_first_thunk = first_thunk;
        }

        // Loop through all imported functions
        while (orig_first_thunk->u1.AddressOfData != 0)
        {
            // Check if import is by ordinal or by name
            if (orig_first_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                // Import by ordinal
                DWORD ordinal = orig_first_thunk->u1.Ordinal & 0xFFFF;
                void* func_addr = gp(dll_base, (LPCSTR)ordinal);
                first_thunk->u1.Function = (ULONGLONG)func_addr;
            }
            else
            {
                // Import by name
                IMAGE_IMPORT_BY_NAME* import_by_name = (IMAGE_IMPORT_BY_NAME*)(nt_image + orig_first_thunk->u1.AddressOfData);
                const char* func_name = (const char*)import_by_name->Name;
                void* func_addr = gp(dll_base, func_name);
                first_thunk->u1.Function = (ULONGLONG)func_addr;
            }

            // Move to next thunk
            orig_first_thunk++;
            first_thunk++;
        }

        // Move to next import descriptor
        import_desc++;
    }
}

int main() {
    PBYTE original_pe = (PBYTE)(void*)0xdeadbeef;
    PBYTE kernel32_base = (PBYTE)(KERNEL32_BASE_ADDRESS);


    GetProcAddressT* gp = (GetProcAddressT*)my_get_proc_address(kernel32_base, "GetProcAddress");
    LoadLibraryT* ll = (LoadLibraryT*)gp((HMODULE)kernel32_base, "LoadLibraryA");

    resolve_imports(original_pe, gp, ll);
    return 0;
}