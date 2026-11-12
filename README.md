# MasterPwd

A Rust re-creation of the **Master Password** macOS app, built natively for
Apple Silicon.

Master Password is a *stateless* password solution: your passwords are not
stored anywhere, they are recomputed on demand from your name, your one master
password and the name of the site.

    master-key    = SCRYPT( user-name, master-password )
    site-key      = HMAC-SHA-256( site-name . site-counter, master-key )
    site-password = PW-TEMPLATE( site-key, site-template )

The original app is no longer maintained and ships only as an Intel binary.
This project re-implements it in Rust. It generates the same passwords as the
original (algorithm versions 0–3, verified against the official test
vectors), reads and writes the original's export files, and fixes the bugs and
security issues found in the original along the way — see
[`docs/CHANGES-FROM-ORIGINAL.md`](docs/CHANGES-FROM-ORIGINAL.md).

## The macOS app

A menu-bar app (no Dock icon).

- **⌃⌘P** opens the sites window from anywhere; **⌃⌥⌘P** locks.
- Pick your user (or create one), type your master password, type a site
  name, press **⏎** to copy the password. **⇧⏎** copies the login name.
- Per site: password type (including your own stored passwords), counter,
  login name, security-question answers.
- Import and export `.mpsites` / `.mpjson` files, with merge.
- Change your master password; stored passwords are re-encrypted.
- Optional *Save Password*: keeps your derived keys in the Keychain and
  unlocks with Touch ID or your Mac password.
- A copied password is cleared from the clipboard after 60 seconds.
- Locks on sleep, screen lock, fast user switch and after 15 idle minutes.

Build the app bundle:

    scripts/bundle-macos.sh
    open "dist/Master Password.app"

The bundle is arm64 (universal if an `x86_64-apple-darwin` Rust target is
installed), sandboxed, uses the hardened runtime and is ad-hoc signed. Set
`MASTERPWD_SIGN_IDENTITY` to sign with a Developer ID instead, and
`MASTERPWD_SANDBOX=0` to build without the App Sandbox.

Requires macOS 11 or later; *Open at Login* needs macOS 13.

## The command line

`mpw` is compatible with the reference CLI's options and user files
(`~/.mpw.d`).

    cargo build --release -p mpw-cli
    target/release/mpw -u "Your Full Name" example.com
    target/release/mpw -h

The master password is prompted for with echo off, or read from stdin or a
file descriptor (`-m`). It is never accepted as a command-line argument.

The app and the CLI keep separate user files (the app's are inside its
sandbox container). Use import and export to move a user between them.

## Layout

| Path | What |
| --- | --- |
| `crates/mpw-core` | The algorithm: key derivation, templates, identicons. No I/O, no `unsafe`. |
| `crates/mpw-model` | Users, sites, questions; `.mpsites` / `.mpjson` import, export and merge; atomic storage. No `unsafe`. |
| `crates/mpw-cli` | `mpw`, the command-line client. |
| `crates/masterpwd-app` | The native AppKit menu-bar app. `unsafe` is confined to `src/platform/`. |
| `assets/` | App icon and avatars from the original app. |
| `scripts/` | The app bundling script and entitlements. |
| `docs/` | What changed from the original, and why. |

## Development

    cargo test --workspace
    cargo clippy --workspace --all-targets

    # End-to-end self-test of the app: builds every window and drives
    # create user → unlock → copy → lock → import/export against a temporary
    # store and a private pasteboard.
    "dist/Master Password.app/Contents/MacOS/MasterPwd" --smoke-test

## License

GPL-3.0-or-later, as a derivative of Master Password
(Copyright © 2011–2020 Maarten Billemont / Lyndir). See `LICENSE`.
