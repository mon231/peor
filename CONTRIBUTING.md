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
