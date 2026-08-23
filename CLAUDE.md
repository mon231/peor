1. follow EXTREMLY STRICT the CONTRIBUTING.md guidelines
1. NEVER mark a prompt as done unless ALL the tests passed (not skipped!) locally. if needed, rebuild tests, reinstall peor, ...
1. after each prompt, make sure all tests pass and the ci/cd should work (if last job failed, figure what fixes it needs and implement them, ensure it should work)
1. whenever running a background process, limit its runtime to 50-minutes, so you won't leak it
1. tests are NOT allowed to be skipped locally. never
