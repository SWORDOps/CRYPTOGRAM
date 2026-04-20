# Repository Guidelines

This file applies to the entire `CRYPTOGRAM` repository. Follow these conventions when changing code, docs, or build scripts.

## Project Structure & Modules

- Desktop client: `Telegram/` (C++/Qt), with platform build files in `CMakeLists.txt`, `cmake/`, and `build_release/`.
- Android client: `telegram-android/` (Gradle/Android Studio).
- Documentation and status: `docs/`, top-level `README*.md`, `BUILD_*.md`, and `SETUP_*.md`.
- Tests and experiments: `tests/`, `run_tests.sh`, `test_build_fixes.sh`.
- Docker and CI helpers: `docker/`, `.github/workflows/`.

## Build, Test & Development Commands

- Initial setup: `./setup-all.sh` (installs toolchains, submodules, and dependencies where possible).
- Desktop builds: `./build_all.sh` or `./build_everything.sh` (full multi-platform build); prefer platform-specific docs under `docs/building-*.md`.
- Android builds: `./build_android.sh` (CI-style build) or use Android Studio in `telegram-android/`.
- Tests: `./run_tests.sh` for core checks; `./test_build_fixes.sh` for regression build tests.

## Coding Style & Naming

- Use 2 or 4 spaces consistently with the local file; do not change indentation style globally.
- Prefer descriptive identifiers (`SecureChannelConfig`, `androidSecureClient`) over abbreviations.
- Keep filenames and directories lowercase with hyphens or underscores (e.g., `secure_channel_utils.cpp`, `android_secure_client.kt`).

## Testing Guidelines

- Add or update tests under `tests/` or the relevant platform test directory (e.g., Android unit/instrumentation tests).
- Name tests after the behavior under test (e.g., `EncryptMessage_SuccessWhenKeysValid`).
- Run `./run_tests.sh` (and platform-specific tests where applicable) before pushing.

## Commit & Pull Request Practices

- Commit messages: short, imperative, and scoped (e.g., `Fix submodule detection`, `Add desktop build guide`). Avoid long multi-topic commits.
- Group related changes per commit (build, docs, or feature) and keep diffs focused.
- Pull requests: include a one-paragraph summary, key technical notes, testing performed (`./run_tests.sh`, manual steps), and links to any relevant docs or issues. Add screenshots or logs for UI and build-related changes where useful.



## JavaScript REPL (Node)
- Use `js_repl` for Node-backed JavaScript with top-level await in a persistent kernel.
- `js_repl` is a freeform/custom tool. Direct `js_repl` calls must send raw JavaScript tool input (optionally with first-line `// codex-js-repl: timeout_ms=15000`). Do not wrap code in JSON (for example `{"code":"..."}`), quotes, or markdown code fences.
- Helpers: `codex.cwd`, `codex.homeDir`, `codex.tmpDir`, `codex.tool(name, args?)`, and `codex.emitImage(imageLike)`.
- `codex.tool` executes a normal tool call and resolves to the raw tool output object. Use it for shell and non-shell tools alike. Nested tool outputs stay inside JavaScript unless you emit them explicitly.
- `codex.emitImage(...)` adds one image to the outer `js_repl` function output each time you call it, so you can call it multiple times to emit multiple images. It accepts a data URL, a single `input_image` item, an object like `{ bytes, mimeType }`, or a raw tool response object with exactly one image and no text. It rejects mixed text-and-image content.
- `codex.tool(...)` and `codex.emitImage(...)` keep stable helper identities across cells. Saved references and persisted objects can reuse them in later cells, but async callbacks that fire after a cell finishes still fail because no exec is active.
- Request full-resolution image processing with `detail: "original"` only when the `view_image` tool schema includes a `detail` argument. The same availability applies to `codex.emitImage(...)`: if `view_image.detail` is present, you may also pass `detail: "original"` there. Use this when high-fidelity image perception or precise localization is needed, especially for CUA agents.
- Example of sharing an in-memory Playwright screenshot: `await codex.emitImage({ bytes: await page.screenshot({ type: "jpeg", quality: 85 }), mimeType: "image/jpeg", detail: "original" })`.
- Example of sharing a local image tool result: `await codex.emitImage(codex.tool("view_image", { path: "/absolute/path", detail: "original" }))`.
- When encoding an image to send with `codex.emitImage(...)` or `view_image`, prefer JPEG at about 85 quality when lossy compression is acceptable; use PNG when transparency or lossless detail matters. Smaller uploads are faster and less likely to hit size limits.
- Top-level bindings persist across cells. If a cell throws, prior bindings remain available and bindings that finished initializing before the throw often remain usable in later cells. For code you plan to reuse across cells, prefer declaring or assigning it in direct top-level statements before operations that might throw. If you hit `SyntaxError: Identifier 'x' has already been declared`, first reuse the existing binding, reassign a previously declared `let`, or pick a new descriptive name. Use `{ ... }` only for a short temporary block when you specifically need local scratch names; do not wrap an entire cell in block scope if you want those names reusable later. Reset the kernel with `js_repl_reset` only when you need a clean state.
- Top-level static import declarations (for example `import x from "./file.js"`) are currently unsupported in `js_repl`; use dynamic imports with `await import("pkg")`, `await import("./file.js")`, or `await import("/abs/path/file.mjs")` instead. Imported local files must be ESM `.js`/`.mjs` files and run in the same REPL VM context. Bare package imports always resolve from REPL-global search roots (`CODEX_JS_REPL_NODE_MODULE_DIRS`, then cwd), not relative to the imported file location. Local files may statically import only other local relative/absolute/`file://` `.js`/`.mjs` files; package and builtin imports from local files must stay dynamic. `import.meta.resolve()` returns importable strings such as `file://...`, bare package names, and `node:...` specifiers. Local file modules reload between execs, while top-level bindings persist until `js_repl_reset`.
- Avoid direct access to `process.stdout` / `process.stderr` / `process.stdin`; it can corrupt the JSON line protocol. Use `console.log`, `codex.tool(...)`, and `codex.emitImage(...)`.
