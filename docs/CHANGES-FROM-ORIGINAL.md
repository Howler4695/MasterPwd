# Changes from the original Master Password

This is a Rust re-creation of the Master Password macOS app. It generates the
same passwords as the original for the same inputs (all 60 official
`mpw_tests.xml` vectors pass for algorithm versions 0–3) and reads the
original's export files. This document lists what is deliberately different:
the bugs and security issues found in the original sources and what the
rewrite does instead.

"Original" means three code bases: the reference C library and CLI
(`mpw-algorithm*.c`, `mpw-marshal.c`, `mpw-cli.c`), the Objective-C macOS app
(`MPMacAppDelegate.m`, `MPSitesWindowController.m`, …) and the Swift model
that replaced it (`MPUser.swift`, `MPMarshal.swift`, …).

## Kept on purpose

- **Algorithm quirks of v0, v1 and v2.** Each old version counts name lengths
  or reads template bytes in a way that was later considered a bug. They
  define those versions; changing them would change users' passwords.
- **Stored-password encryption.** Personal ("stateful") passwords are
  encrypted with the first 16 bytes of the master key, AES-128-CBC, a zero IV
  and no integrity check. The same plaintext therefore produces the same
  ciphertext on every site, and tampering is not detected. Fixing this needs
  a new state format that the original apps could not read, so the format is
  unchanged. The rewrite is stricter when *reading*: bad padding or invalid
  UTF-8 is an error instead of garbage output.

## Algorithm (`mpw-core`)

| Original | Rewrite |
| --- | --- |
| v0 results depend on the platform's `char` signedness and byte order, so builds for some platforms computed different v0 passwords. | The behaviour the official vectors expect is hard-coded. |
| Key IDs are compared with a non-constant-time string compare. | Constant-time comparison. |
| Secrets are left in shared static buffers (`mpw_str`, `mpw_hex`, a static IV) and in freed heap memory. | Keys, passwords and decrypted buffers live in types that are wiped on drop. No `unsafe`. |
| A stored state that is not a whole number of AES blocks decrypts to garbage; the base64 error check compares an unsigned size with `< 0` and can never fire. | Both cases return an error. |
| Base64 encoding reads out of bounds for inputs shorter than 2 bytes. | Uses a maintained base64 implementation. |
| `calloc`/`malloc` results are used unchecked in several paths. | No unchecked paths; no input can cause a panic. |

## Command line (`mpw`)

| Original | Rewrite |
| --- | --- |
| `-M` takes the master password as an argument, visible in `ps` and shell history. | Refused. The password is prompted with echo off, or read from stdin or an fd (`-m`). |
| `MPW_ASKPASS` runs whatever program the environment names. | Not supported. |
| The `-m` fd reader never advances its offset, so each 4 KB read overwrites the last, and the buffer is never terminated. | Reads exactly the bytes given, into a wiped buffer, with a size cap. |
| `-c abc` silently means counter 0 (a time-based password); a bad `-a` silently means v0; a bad `-m` means stdin. | Invalid numbers are errors. |
| The line reader always drops the last character, eating a real one at end of input. | Strips only the line ending. |
| An empty answer re-prompts forever. | Five attempts. |
| `-v` tracing prints personal passwords, generated passwords and an unsalted SHA-256 of the master password. | Nothing secret is logged at any verbosity. |
| A personal password can only be given with `-P` on the command line. | Prompted for with echo off (twice). `-P` still works, with a warning. |
| User files are written with `fopen("w")`: not atomic, default permissions. | Atomic, mode 0600, in a 0700 `~/.mpw.d`. |
| The file name is the full name with `/` replaced; a file whose embedded name differs is used anyway. | Names cannot escape `~/.mpw.d` or create hidden files; a mismatching file, a symlinked file or a symlinked `~/.mpw.d` is refused. |
| A file that was revealed (plaintext) stays revealed on every save. | Plaintext is written only on an explicit `-R 0`, with a warning. |
| `-U` (change master password) leaves stored passwords encrypted under the old key. | Stored values are re-encrypted, all or nothing. |
| A non-numeric derived-key size silently means 512 bits. | An error. |

## Model, file formats and storage (`mpw-model`)

| Original | Rewrite |
| --- | --- |
| User files are written non-atomically with default permissions (world-readable). | Written to a temporary file (mode 0600), synced, then renamed over the target. Directories are 0700. A crash or failed write never leaves a truncated file. |
| "Replace" on import deletes the existing user file before writing the new one. | One atomic replace. |
| The file name is the full name with only `/` replaced. A user named `..` escapes the directory; a name starting with `.` becomes a hidden file and the user vanishes from the list. | A reversible, collision-free encoding. The name inside the file is authoritative. Symlinks are never followed. |
| Merging an import copies encrypted stored passwords as-is. If the two users have different master passwords, the copies cannot be decrypted. | Each value is decrypted with the import's key and re-encrypted for the destination. A value that cannot be decrypted is skipped and reported. |
| Merging a newer import overwrites the existing user's key ID and algorithm, locking them out or silently changing every password. | A merge never changes the key ID. Settings are taken only when both users share the same key. |
| A failed re-authentication logs the user out. | A failed authentication changes nothing. |
| Users compare equal by name but order by last-used time, which breaks sorted and set containers. | Equality compares all fields; two named total orders are provided. |
| A security question always uses the "phrase" template, ignoring its own type. | Uses the question's type. |
| A site's stored login is decrypted with the site's algorithm key; it was encrypted with the user's. | Uses the user's key. |
| A revealed export includes device-private passwords in plaintext. | Device-private values are never exported, in any mode. |
| A redacted export decides whether to write a question's answer from the site's type. | Uses the question's type. |
| The flat-file reader gives every site login type 17 (a password template), drops the last line of a file without a trailing newline, and does not handle a BOM or CRLF. | All handled. |
| Dates are parsed through local time with a daylight-saving guess; `-1` on failure is tested as `0`, so bad dates are accepted and the epoch is rejected. | Strict UTC parsing and formatting. |
| Numbers are written with `%g`: counter 4294967295 becomes `4.29497e+09` and the file can no longer be read. | Exact integers. |
| A parse error message copies field values (which can be a plaintext login) and passes `NULL` to `%s`. | Errors carry line and field names only, never values. |
| No limits on file size, site count or nesting; per-key lookups scan linearly. | 8 MiB file limit, 50,000 sites, bounded nesting, no panics on hostile input (covered by mutation tests). |

## macOS app (`masterpwd-app`)

| Original | Rewrite |
| --- | --- |
| A copied password stays on the clipboard indefinitely and is visible to clipboard managers. | Marked concealed and transient; cleared after a timeout (default 60 s), on lock and on quit, if the clipboard still holds it. |
| Locks only from the menu or hotkey. | Also locks on sleep, display sleep, screen lock, screensaver, fast user switch and after an idle timeout. |
| The sites window can be captured by screenshots and screen sharing. | Excluded from screen capture (defence in depth; newer capture APIs may ignore it). |
| Key derivation has no cancellation: a result arriving after a lock still signs the user in. | A late result is discarded and wiped. Derivation never blocks the main thread. |
| Paid features are unlocked by any `NSUserDefaults` entry named after the product, so `defaults write` grants them. | In-app purchases are removed; everything is available. |
| Ships Sentry, Countly, Crashlytics and Freshchat hooks. Sentry starts *before* the user answers the diagnostics prompt, and log lines and settings are attached to reports. Telemetry events include an entropy estimate of the copied password. | No analytics, crash reporting or chat SDKs. No network code and no network entitlement. |
| A "password copied" notification puts site and login names into Notification Center history. | No notification. |
| Open at Login uses a separate helper app bundle and deprecated launch APIs. | `SMAppService`; no helper bundle. |
| Registering the second global hotkey overwrites the first's handle, so neither can be unregistered. | Both are unregistered on exit. |
| `deleteUser:` uses the active user without a nil check. | No unchecked path; the user is named in the confirmation. |
| Replacing a user on import needs only the import file's password. | Also requires the existing user's master password. |
| A plaintext export is guarded only by a warning line in the save panel. | A warning dialog, then the master password again. Export files are created 0600. |
| `importSites:` reads local files through `NSURLSession`. | Plain file reads, size-limited. |

The app also keeps only the derived keys after unlock; the typed master
password is wiped as soon as the keys exist.
| Entitlements include outgoing network access and an app group. | App Sandbox with user-selected file access only; hardened runtime. |
| Bundles Font Awesome Pro fonts. | Not carried over (paid licence); system fonts and SF Symbols are used. |
| Intel-only binary. | Native arm64 (universal when an x86_64 Rust target is installed). |

## New: smart card second factor

The original has no second factor. The rewrite adds an opt-in one, enforced
by the key derivation rather than by an app-level check (see the README for
how it works). Design decisions:

- **Not OIDC.** An OIDC login proves identity to a server; this app has none.
  A token could only gate the app, which anyone with the master password
  could bypass with another implementation. Making it real would need a
  key-escrow service and network access. The card is used directly instead.
- **Encrypt to the card, never derive from it.** The secret is random and is
  wrapped to the card's key-management certificate with RSA-OAEP-SHA256 or
  ECIES. Signature keys are never used to derive secrets, and PKCS#1 v1.5
  encryption is never used. A reissued card only needs re-enrolment.
- **PIN safety.** The PIN is entered in the macOS prompt and never reaches
  the app. One user action causes at most one decryption attempt; nothing is
  retried automatically, because a CAC locks after three wrong PINs.
- **Privacy.** A CAC certificate names its holder and carries their ID
  number, so only a fingerprint and a generic label are stored.
- **No lock-in.** Recovery is the master password, a space and the recovery
  code, typed into any Master Password implementation.

## Known limitations of the rewrite

- **The smart card path is untested with a real card.** Encryption and
  decryption are tested against software keys through the same code. Reading
  a real card's certificates, the PIN prompt and on-card decryption are
  unverified, including whether a sandboxed, ad-hoc signed build can read a
  card's keychain items at all. `--smart-cards` reports what the app sees.
- Passkeys are not supported: Apple's API needs a Developer ID signature and
  an associated domain. The slot format leaves room for other authenticators.

- Memory wiping is best effort: copies inside the scrypt, HMAC and JSON
  libraries, and stack copies made when a key is moved, are outside our
  control.
- With ad-hoc signing, saved keys go to the login keychain, which does not
  offer the "when unlocked, this device only" protection class. A Developer
  ID signature is needed for the data-protection keychain.
- The app and the CLI keep separate user files (the app in its sandbox
  container, the CLI in `~/.mpw.d` like the reference). Use import and export
  to move a user between them.
- There is no locking between concurrent writers of the same user file. The
  last writer wins; a file is never left truncated.
