# Copilot Instructions for SCA-Fuzzer (Revizor)

## Project Overview
- **Purpose:** Revizor (sca-fuzzer) is a framework for fuzzing CPUs to discover microarchitectural leaks, focusing on speculative execution vulnerabilities.
- **Main Components:**
  - `src/`: Core Python source code (fuzzer, generator, analyser, executor, config, ISA loader, postprocessor, etc.)
  - `src/x86/executor/`: Kernel module (executor) for x86, built separately (see below).
  - `demo/`, `tests/`: Example configs, test scripts, and acceptance tests.
  - `docs/`: User and developer documentation.

## Architecture & Data Flow
- **CLI Entry Point:** `revizor.py` (or `rvzr` script) is the main interface.
- **Modes:** Fuzzing, template fuzzing, minimization, analysis, and generation (see `docs/user/modes.md`).
- **Test Case Lifecycle:**
  1. **Generation:** Test cases are generated (randomly or from templates).
  2. **Execution:** Test cases are run via the kernel executor (x86: `/src/x86/executor/`).
  3. **Analysis:** Results are analyzed for contract violations.
  4. **Minimization:** Violating test cases are minimized (see `postprocessor.py`).

## Developer Workflows
- **Build Executor (Kernel Module):**
  ```sh
  cd src/x86/executor
  make clean && make && sudo make install
  ```
  Requires Linux kernel headers. See `docs/quick-start.md` for details.
- **Run Tests:**
  ```sh
  ./tests/quick-test.sh
  ./tests/pre-release.sh
  # Or run individual unit tests in tests/unit_*.py
  ```
- **Download ISA Spec:**
  ```sh
  rvzr download_spec -a x86-64 --extensions ALL_SUPPORTED --outfile base.json
  ```
- **Formatting & Linting:**
  - Python: Use `flake8` for linting, remove unused imports, and strip trailing whitespace.
  - C: Use `clang-format` (see `.clang-format`).

## Conventions & Patterns
- **Commit Messages:**
  - Format: `<scope>: [<type>] <subject>` (see `docs/development.md` for scopes/types).
  - Example: `fuzz/x86: [fix] handle edge case in test generation`
- **Minimization Passes:**
  - Implemented as classes in `postprocessor.py` (see `BaseInstructionMinimizationPass`, `FenceInsertionPass`).
- **ISA Handling:**
  - ISA specs are loaded from JSON (see `base.json`, `isa_loader.py`).
- **Executor Usage:**
  - Always use via CLI, not directly (see `src/x86/executor/readme.md`).

## Integration Points
- **External Dependencies:**
  - Python: `unicorn`, `pyyaml`, `numpy`, `pyelftools`, `xxhash`, `scipy` (see `pyproject.toml`).
  - Kernel module: Linux, x86 only.
- **Documentation:**
  - User: `docs/user/`
  - Developer: `docs/development.md`, `docs/architecture.md`

## Examples
- See `demo/` for config examples and `tests/x86_tests/` for test scripts.
- For executor build/test, see `docs/quick-start.md` and `src/x86/executor/readme.md`.

---
For unclear or missing conventions, consult `README.md`, `docs/`, or ask maintainers.
