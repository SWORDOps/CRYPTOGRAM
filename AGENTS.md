# Repository Guidelines

## Project Structure & Module Organization
`CRYPTOGRAM` is a mixed platform codebase.

- `Telegram/`: desktop client (C++/Qt) plus CMake build config.
- `telegram-android/`: Android app sources, Gradle config, and JNI/JNI-related native code.
- `build_release/`, `build/`, `build_*` artifacts/logs: build outputs for desktop and Android.
- `tests/unit/`: C++ unit tests (`test_*.cpp`).
- `docs/`, `docs/status/`, `docs/features/`: architecture, release gates, and feature/build validation notes.
- Root helper scripts: `build_all.sh`, `build_linux.sh`, `build.sh`, `build_android.sh`, `build_everything.sh`, `setup-all.sh`, plus verification scripts (`run_tests.sh`, `test_build_fixes.sh`, `check_syntax.sh`).

## Build, Test, and Development Commands
- `./setup-all.sh`: install dependencies/submodules to prepare the workspace.
- `./build_linux.sh`: canonical desktop build entrypoint.
- `./build_all.sh [--resume|--force|--prefix=PATH|--dry-run|-j N]`: full desktop orchestrator.
- `./build.sh --debug|--release --jobs N --clean`: builds a configured CMake tree in `build_release/`.
- `./build_android.sh /path/to/telegram-android`: Android build/signing flow.
- `./build_everything.sh`: interactive coordinator for desktop + Android.
- `./run_tests.sh`: static verification harness for JNI/API wiring and required test assets.
- `./test_build_fixes.sh`: quick regression checks for known build-system edge cases.
- `./check_syntax.sh`: targeted syntax/API consistency checks.

## Coding Style & Naming Conventions
- Respect existing project style in the target area; desktop/C++ and Android code use 4-space indentation and brace style consistent with existing files.
- C++: prefer descriptive PascalCase types, clear namespaces, and `snake_case` file names for implementations.
- Java/Kotlin: follow standard naming (`ClassName`, `methodName`, `snake_case` for resources/constants in XML where applicable).
- Keep changes minimal to touched areas; avoid broad reformatting.
- If you touch native build glue, validate includes and symbol names manually.

## Testing Guidelines
- Unit test files are named `test_*.cpp` and use Catch2.
- Required test targets currently include `test_cryptogram_features`, `test_double_ratchet`, and `test_mls_protocol`.
- Validate test wiring after edits with `./run_tests.sh` and inspect outputs in the script-defined logs.
- Add/modify tests near existing logic in `tests/unit/` and keep test names behavior-focused.

## Commit & Pull Request Guidelines
- Follow short, imperative commit subjects (e.g., `Fix desktop build flags`, `Add Android keystore env handling`).
- Do not commit local-only `cmake` submodule changes; this repo documents those as intentional and excluded from commits.
- PRs should include: summary, rationale, touched modules, verification commands run, and any generated logs.
- Link relevant docs (`BUILD_*.md`, `docs/status/*`, `COMMITTING.md`) and mention caveats such as platform-specific gaps.
- Never commit credentials (keystores, API keys, map keys, signing passwords).
