# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Rust re-creation of the unmaintained Master Password macOS app, native for Apple Silicon. It must generate the same passwords as the original and read/write the original's export files. `README.md` covers usage; `docs/CHANGES-FROM-ORIGINAL.md` records every bug and security issue fixed relative to the original, what was kept for compatibility, and known limitations — update it when behaviour deliberately diverges from the original.

The original sources are outside this repo: a partial snapshot in `../OldMacVer`, and the public upstream repos `Lyndir/MasterPassword` (C core, CLI, Objective-C Mac app) and `spectre-app/api` (full history of the C marshaller, including the later Spectre formats).

## Commands

```sh
cargo test --workspace
cargo clippy --workspace --all-targets          # kept at zero warnings
cargo test -p mpw-core --test vectors           # the official mpw_tests.xml vectors
cargo test -p mpw-model --test formats          # one integration-test file
cargo test -p mpw-cli capital_u                 # tests whose name matches
cargo build --release -p mpw-cli                # target/release/mpw

scripts/bundle-macos.sh                         # -> dist/Master Password.app (sandboxed, ad-hoc signed, arm64)
MASTERPWD_SANDBOX=0 scripts/bundle-macos.sh     # without the App Sandbox
"dist/Master Password.app/Contents/MacOS/MasterPwd" --smoke-test    # end-to-end self-test, exits 0/1
"dist/Master Password.app/Contents/MacOS/MasterPwd" --smart-cards   # what the app sees on an inserted card (no PIN, no decryption)
```

- `scripts/bundle-macos.sh` builds into `target-app/` (override with `CARGO_TARGET_DIR`), not `target/`.
- scrypt is unusable unoptimised, so the workspace compiles dependencies at `opt-level = 3` in dev and test profiles. Tests that derive keys cache them per (name, password, version); follow that pattern in new tests.
- Homebrew Rust, no rustup: only the host target exists, so the bundle is arm64-only here. The universal (`lipo`) path in the script is untested.

## Architecture

Four crates, strictly layered: `mpw-core` ← `mpw-model` ← `mpw-cli` and `masterpwd-app`.

**`mpw-core`** — the algorithm (v0–v3): scrypt master key, HMAC-SHA-256 site key, templates, stateful (stored) values, derived keys, key IDs, identicons. No I/O, `#![forbid(unsafe_code)]`. A `MasterKey` belongs to one algorithm version; a result must be requested from a key of the *site's* version.

**`mpw-model`** — owned `User`/`Site`/`Question` data, `UserKeys` (derives and caches one `MasterKey` per version), authentication by key ID, the export formats (`format/flat.rs`, `format/json.rs`), `merge`, `UserStore` (atomic 0600 files), and `second_factor`. Pure safe Rust, no platform code. Front-ends should go through `User::site_result`/`site_password`/… and never handle master keys directly.

**`mpw-cli`** — the `mpw` binary, option-compatible with the reference CLI. Keeps user files in `~/.mpw.d` like the reference (it uses `read_user_file`/`export_to` on that path, not `UserStore`, whose encoded file names would orphan existing users' files).

**`masterpwd-app`** — AppKit menu-bar app via `objc2`. Split in two:
- Safe, unit-tested logic with no AppKit types: `view_model.rs` (sites-window state machine), `core.rs` (lock policy, clipboard, menu, import/export, keychain flows), `second_factor_flow.rs`, `prompt.rs` (dialogs as data), `card.rs`/`x509.rs` (card key selection, certificate parsing).
- `platform/` — the only place `unsafe` is allowed. It renders state and forwards events; it decides nothing.

  External effects sit behind traits so the logic is testable and the smoke test has no side effects: `DataStore` (disk vs. memory), `KeyVault` (Keychain), `DeviceAuthenticator` (Touch ID), `SmartCards` (real token vs. ephemeral software keys), `Pasteboard`, `PrefsStore`. New platform capabilities should follow the same pattern.

The app and the CLI keep separate user files (the app's are in its sandbox container); import/export moves a user between them.

## Invariants that are easy to break

- **Generated passwords must never change.** All 60 cases in `crates/mpw-core/tests/mpw_tests.xml` must pass. The quirks of v0–v2 (character vs. byte lengths, v0's template-byte handling) and the weak stored-value encryption (AES-128-CBC, zero IV, no MAC, keyed by the master key) are compatibility requirements, not bugs.
- **File compatibility.** The reader accepts every upstream JSON generation (`sites`/`services`, formats 1–3, Spectre keys); the writer emits only the classic layout (format 1, `sites`) because it is the one layout every generation can read. `format/json.rs` has the generation table with upstream commit references — read it before touching key names or the `login_type` 0/30 handling. Unknown JSON members must survive a load→save round trip.
- **mpw-model's public API is additive-only**: both front-ends depend on it.
- **Second factor.** The effective master password is exactly `typed password + " " + canonical recovery code`; a test pins this because recovery in other Master Password apps depends on it. The secret is random and is *wrapped to* the card's key-encipherment certificate (RSA-OAEP-SHA256 or ECIES) — never derived from the card, never from a signature, never PKCS#1 v1.5. Only a certificate fingerprint and a generic label are persisted; subject names (which on a CAC include the holder's name and ID number) are display-only and must not be stored or logged. The CLI is the recovery path only and must not edit slots.
- **Smart card PIN safety.** A CAC locks after three wrong PINs. One user action may cause at most one unwrap attempt; never retry automatically, never handle or cache the PIN, never attempt a PIN in tests or automation.
- **Secrets**: keys and passwords live in zeroizing types; nothing secret goes into logs, error messages, `Debug` output, or the debug state file. No network code and no network entitlement.
- **Sites window focus.** It is a non-activating `NSPanel` that becomes key without activating the app; dialogs and file panels run as sheets on it. `activateIgnoringOtherApps` does not work for a background accessory app on current macOS — do not reintroduce a plain `NSWindow`. Because the app is never "active", Secure Event Input is enabled explicitly (`platform/secure_input.rs`), and the window closes on losing key status rather than on app deactivation.

## Testing the app

- `--smoke-test` builds every window and drives create user → unlock → copy → lock → import/export → saved keys → second factor against a temporary store, a private pasteboard, throwaway preferences and a throwaway Keychain service. Keep it free of side effects on the real store, clipboard and Keychain. It can fail spuriously if another app takes keyboard focus mid-run.
- Test-only environment variables: `MASTERPWD_STORE_DIR` (must be inside the sandbox container when sandboxed, e.g. `~/Library/Containers/com.github.howler4695.masterpwd/Data/tmp/...`), `MASTERPWD_ALLOW_SCREEN_CAPTURE=1` (the window is otherwise excluded from screenshots), `MASTERPWD_DEBUG_STATE_FILE` (the app writes focus and screen state, never a password, on every change), `MASTERPWD_SMOKE_HOLD_MS`.
- Live UI testing works through `osascript`/System Events and `screencapture -l <windowid>`; setting text-field values through accessibility does not work, so text goes in as keystrokes. Before sending any keystroke other than the hotkey (⌃⌘P), confirm via the debug state file that our window or sheet is key — otherwise the text lands in whatever app the person is using. Use a throwaway user in a temporary store and never trigger a copy to the real clipboard.
- Tests must pass with or without a smart card in the reader.

## Git

- Work goes on `dev`, pushed to `origin` in coherent stages.
- Commits must be authored as `Howler4695 <howler4695@gmail.com>` (set in this repo's local git config; the machine's global identity is a different address and gets no contribution credit). Check `git config user.email` in a fresh clone or worktree before the first commit.
