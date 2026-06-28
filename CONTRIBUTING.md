# CONTRIBUTING
The project welcomes any contributor! <br />
You may create your own fork of the project then create a pull-request to the master branch. <br />
The project was made for low-level/embedded developers, security researchers and other educational purposes. <br />
NOTE to add a test to any feature added, and ensure your code matches the conventions! Otherwise, PRs won't be resolved.

## CONVENTIONS
1. when adding a new feature or fixing a bug, you must add a test to catch the exact cases of your changes
1. tests must have their own function in the pytest file, and have a deterministic way to measure success
1. asm code-files must "define" variables/magic/offsets, and placeholders for interaction with the pythonic code
1. use hex numbers for all magics, use parenthesis for arithmetics expressions with unclear evalution order
1. each asm file must have EXACTLY ONE responsibility. if needed, split your code to multiple asm files
1. usage of asm files has to be inferred from PE headers/... in the python code
    1. use the minimal amount of asm codes
    1. add an "opt out" flag wherever the added asm file isn't required (i.e. imports resolver is NOT really required, the PE can solve them by itself. the relocs resolver IS required - as the PE needs it to execute opcodes correctly)
    1. by default all features are usable in all implemented platforms, unless the user specified he doesn't want them in his binary
1. update the `README.md` when adding a new feature/test-case
1. remove unused variables / code lines. our goal is to have the highest test-coverage possible
1. remove unused files, we don't want the repo to be bloated
1. NEVER use magic numbers in any python/asm/c/cpp code; always use named constants or `%define`d macros (e.g. `dirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]` not `dirs[14]`)
1. whenever possible add both x86 and x64 test variants for each feature
1. do NOT create separate test folders per architecture (e.g. use one `Linux/` folder for both x86 and x64, one `EFI/` folder for both; use `#ifdef` where needed)
1. tests must use a distinctive non-trivial return code (e.g. 42, 77, 88) — never 0, 1, or -1 — to avoid false positives
1. ALL tests must pass locally (using wsl/qemu when needed); no test may be skipped on a local machine or in CI/CD
1. compile linux binaries with a `.pe` extension so they are gitignored
1. the ci/cd must have different stages for build, test, deploy
    * ALL of the building process must be completed in the build stage
    * test/build stages may be executed on different types of runners, but Windows-runner with qemu/wsl is prefered
    * in each ci/cd stage/script that has installations over it, install all at first then create a cache that contains all installation, only then do other stuff like checkout/build/...
1. whenever possible (even if takes extra-effort), prefer to use visual-studio projects for tests and add them to the tests solution
1. whenever possible, avoid creating c code stubs / functions placeholders. use compilation/likage techniques to avoid the need of signature-only symbols with falsy implementation
