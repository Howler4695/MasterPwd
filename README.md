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
This project re-implements it in Rust, stays compatible with the original
algorithm (v0–v3) and export files, and fixes the bugs and security issues
found in the original along the way (see `docs/CHANGES-FROM-ORIGINAL.md`).

## Layout

| Path | What |
| --- | --- |
| `crates/mpw-core` | The algorithm: key derivation, templates, identicons. No I/O, no `unsafe`. |
| `crates/mpw-model` | Users, sites, questions; `.mpsites` / `.mpjson` import & export; storage. |
| `crates/mpw-cli` | `mpw`, a command-line client compatible with the reference CLI. |
| `crates/masterpwd-app` | The native macOS menu-bar app. |
| `assets/` | App icon and avatars from the original app. |
| `scripts/` | Build and bundling scripts. |

## Building

    cargo build --release
    cargo test --workspace

## License

GPL-3.0-or-later, as a derivative of Master Password
(Copyright © 2011–2020 Maarten Billemont / Lyndir).  See `LICENSE`.
