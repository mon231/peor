# PEOR - PortableExecutable Shellcodifier
This project is made to create embedded-shellcodes out of PE files. <br />

*NOTE* that `PEOR` isn't made to easily shellcodify Windows usermode-executables, <br />
As it won't resolve imports for you. For such features, use [pe2shellcode](https://github.com/hasherezade/pe_to_shellcode).

PEOR can not (and should not) be used for any cyber-related project. <br />
Use legally, for development/educational purposes only. <br />
The project is made for you to be able to create c code, compile it to PE, and execute on any embedded env (i.e. linux/bare-metal/windows-usermode/...)

## Test Projects

The `tests/` folder contains a Visual Studio 2022 solution (`tests.sln`) with four C projects:

| Project | Description |
|---|---|
| `01_simple_calc` | Importless, custom `main` entrypoint (no CRT). Runs a 0–99 accumulation loop. |
| `02_relocs_functions` | Importless, custom entrypoint, multiple functions, r/w static globals, global pointer (`&g_value`) that forces a `.reloc` section. Built with `/DYNAMICBASE`. |
| `03_winapi_messagebox` | Custom entrypoint (no CRT startup), Windows subsystem. Calls `MessageBoxA` then `ExitProcess`. Links `user32.lib` + `kernel32.lib`. |
| `04_crt_printf_rand` | Standard CRT entrypoint (`mainCRTStartup → main`). Seeds `rand` with `time(NULL)` and `printf`s the result. |

### Build (from a Visual Studio Developer Command Prompt)

```bat
rem x86
msbuild tests\tests.sln /p:Configuration=Release /p:Platform=Win32

rem x64
msbuild tests\tests.sln /p:Configuration=Release /p:Platform=x64
```

Debug builds:

```bat
msbuild tests\tests.sln /p:Configuration=Debug /p:Platform=Win32
msbuild tests\tests.sln /p:Configuration=Debug /p:Platform=x64
```

Output binaries land in each project's subfolder under `Win32\<Config>\` or `x64\<Config>\`.

