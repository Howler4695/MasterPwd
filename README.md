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
- Optional second factor: require your smart card (CAC / PIV) as well as
  your master password — see below.
- Optional *Save Password*: keeps your derived keys in the Keychain and
  unlocks with Touch ID or your Mac password.
- A copied password is cleared from the clipboard after 60 seconds.
- Locks on sleep, screen lock, fast user switch and after 15 idle minutes.

### Smart card (CAC / PIV) second factor

*Second Factor ▸ Require Smart Card…* makes unlocking need your master
password **and** your card.

Master Password is stateless: anyone who knows your name and master password
can compute your passwords with any implementation, so a card check inside
the app alone would protect nothing. Instead, enabling the second factor
generates a random 160-bit secret and makes your effective master password
`<your master password> <recovery code>`, where the recovery code is that
secret in printable form. The secret is stored in your user file encrypted to
your card's encryption certificate (PIV slot 9D), so day to day you type your
master password, insert the card and enter its PIN in the macOS prompt.

- The secret is random. It is not derived from the card or from anything on
  it, and the app never sees the PIN.
- **Enabling it changes every generated password**, like changing your master
  password. Stored personal passwords are re-encrypted.
- Write the recovery code down. If the card is lost, expires or is reissued,
  unlock with the code and enrol the new card. The code also works in any
  other Master Password app and in `mpw`: type your master password, a space
  and the code.
- Only a fingerprint of the certificate and a generic label are stored — not
  the certificate, your name or your ID number.
- *Save Password* is unavailable while the second factor is on, since saved
  keys would bypass the card.
- Run `"dist/Master Password.app/Contents/MacOS/MasterPwd" --smart-cards` to
  see what the app finds on an inserted card.

Reading a real DoD CAC has been verified; the PIN prompt and on-card
decryption have only been tested against software keys. See the limitations
in `docs/CHANGES-FROM-ORIGINAL.md`.

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

For a user with the second factor enabled, `mpw` is the recovery path: it
asks for the recovery code (or reads it from `-k fd`). It does not talk to
the card.

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
