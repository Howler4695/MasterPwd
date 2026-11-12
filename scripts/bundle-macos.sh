#!/usr/bin/env bash
# Build "dist/Master Password.app": release build (universal if an x86_64
# Rust target is installed, else arm64), Info.plist, icon, avatars,
# entitlements, ad-hoc signature with the hardened runtime.
#
#   scripts/bundle-macos.sh              # sandboxed (default)
#   MASTERPWD_SANDBOX=0 scripts/bundle-macos.sh   # without the App Sandbox
#
# Idempotent: the bundle is rebuilt from scratch every run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

APP_NAME="Master Password"
BUNDLE_ID="com.github.howler4695.masterpwd"
EXE="MasterPwd"
PACKAGE="masterpwd-app"
MIN_MACOS="11.0"
SANDBOX="${MASTERPWD_SANDBOX:-1}"
SIGN_IDENTITY="${MASTERPWD_SIGN_IDENTITY:--}"   # "-" = ad hoc
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target-app}"
export MACOSX_DEPLOYMENT_TARGET="$MIN_MACOS"

DIST="$ROOT/dist"
APP="$DIST/$APP_NAME.app"
CONTENTS="$APP/Contents"

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

for tool in cargo rustc iconutil codesign plutil lipo; do
    command -v "$tool" >/dev/null || die "$tool not found"
done

# Version from Cargo (workspace version, e.g. "0.1.0").
PKGID="$(cargo pkgid -p "$PACKAGE")"
VERSION="${PKGID##*@}"
VERSION="${VERSION##*#}"
[[ "$VERSION" =~ ^[0-9]+(\.[0-9]+)*$ ]] || die "could not read the version from '$PKGID'"
log "version $VERSION"

# ---------------------------------------------------------------- build
target_installed() {
    [[ -d "$(rustc --print sysroot)/lib/rustlib/$1/lib" ]]
}

TARGETS=(aarch64-apple-darwin)
if target_installed x86_64-apple-darwin; then
    TARGETS+=(x86_64-apple-darwin)
else
    log "x86_64-apple-darwin target not installed: building arm64 only"
fi

BINARIES=()
for target in "${TARGETS[@]}"; do
    log "cargo build --release --target $target"
    cargo build --release -p "$PACKAGE" --bin "$EXE" --target "$target"
    BINARIES+=("$CARGO_TARGET_DIR/$target/release/$EXE")
done

# ---------------------------------------------------------------- bundle
log "assembling $APP"
rm -rf "$APP"
mkdir -p "$CONTENTS/MacOS" "$CONTENTS/Resources/avatars"

if (( ${#BINARIES[@]} > 1 )); then
    lipo -create -output "$CONTENTS/MacOS/$EXE" "${BINARIES[@]}"
else
    cp "${BINARIES[0]}" "$CONTENTS/MacOS/$EXE"
fi
chmod 755 "$CONTENTS/MacOS/$EXE"

ICONSET_TMP="$(mktemp -d)"
trap 'rm -rf "$ICONSET_TMP"' EXIT
cp -R "$ROOT/assets/icon.iconset" "$ICONSET_TMP/AppIcon.iconset"
iconutil -c icns "$ICONSET_TMP/AppIcon.iconset" -o "$CONTENTS/Resources/AppIcon.icns"
cp "$ROOT"/assets/avatars/*.png "$CONTENTS/Resources/avatars/"
cp "$ROOT/LICENSE" "$CONTENTS/Resources/LICENSE"
printf 'APPL????' > "$CONTENTS/PkgInfo"

cat > "$CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleDisplayName</key>
	<string>$APP_NAME</string>
	<key>CFBundleName</key>
	<string>$APP_NAME</string>
	<key>CFBundleExecutable</key>
	<string>$EXE</string>
	<key>CFBundleIdentifier</key>
	<string>$BUNDLE_ID</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleSignature</key>
	<string>????</string>
	<key>CFBundleShortVersionString</key>
	<string>$VERSION</string>
	<key>CFBundleVersion</key>
	<string>$VERSION</string>
	<key>CFBundleIconFile</key>
	<string>AppIcon</string>
	<key>LSApplicationCategoryType</key>
	<string>public.app-category.productivity</string>
	<key>LSMinimumSystemVersion</key>
	<string>$MIN_MACOS</string>
	<key>LSUIElement</key>
	<true/>
	<key>NSPrincipalClass</key>
	<string>NSApplication</string>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>NSSupportsAutomaticTermination</key>
	<false/>
	<key>NSSupportsSuddenTermination</key>
	<false/>
	<key>NSHumanReadableCopyright</key>
	<string>Master Password © 2011–2020 Maarten Billemont (Lyndir). This Rust port is free software under the GNU General Public License v3 or later; it comes with NO WARRANTY.</string>
	<key>CFBundleDocumentTypes</key>
	<array>
		<dict>
			<key>CFBundleTypeName</key>
			<string>Master Password sites</string>
			<key>CFBundleTypeRole</key>
			<string>Viewer</string>
			<key>LSHandlerRank</key>
			<string>Alternate</string>
			<key>LSTypeIsPackage</key>
			<false/>
			<key>LSItemContentTypes</key>
			<array>
				<string>com.lyndir.masterpassword.sites</string>
			</array>
		</dict>
		<dict>
			<key>CFBundleTypeName</key>
			<string>Master Password JSON export</string>
			<key>CFBundleTypeRole</key>
			<string>Viewer</string>
			<key>LSHandlerRank</key>
			<string>Alternate</string>
			<key>LSTypeIsPackage</key>
			<false/>
			<key>LSItemContentTypes</key>
			<array>
				<string>com.lyndir.masterpassword.json</string>
			</array>
		</dict>
	</array>
	<key>UTImportedTypeDeclarations</key>
	<array>
		<dict>
			<key>UTTypeIdentifier</key>
			<string>com.lyndir.masterpassword.sites</string>
			<key>UTTypeDescription</key>
			<string>Master Password sites</string>
			<key>UTTypeConformsTo</key>
			<array>
				<string>public.utf8-plain-text</string>
			</array>
			<key>UTTypeTagSpecification</key>
			<dict>
				<key>public.filename-extension</key>
				<array>
					<string>mpsites</string>
				</array>
				<key>public.mime-type</key>
				<string>text/plain</string>
			</dict>
		</dict>
		<dict>
			<key>UTTypeIdentifier</key>
			<string>com.lyndir.masterpassword.json</string>
			<key>UTTypeDescription</key>
			<string>Master Password JSON export</string>
			<key>UTTypeConformsTo</key>
			<array>
				<string>public.json</string>
			</array>
			<key>UTTypeTagSpecification</key>
			<dict>
				<key>public.filename-extension</key>
				<array>
					<string>mpjson</string>
				</array>
				<key>public.mime-type</key>
				<string>application/json</string>
			</dict>
		</dict>
	</array>
</dict>
</plist>
PLIST
plutil -lint "$CONTENTS/Info.plist" >/dev/null

# ---------------------------------------------------------------- sign
if [[ "$SANDBOX" == "1" ]]; then
    ENTITLEMENTS="$ROOT/scripts/MasterPwd-sandbox.entitlements"
else
    ENTITLEMENTS="$ROOT/scripts/MasterPwd.entitlements"
fi
plutil -lint "$ENTITLEMENTS" >/dev/null
log "signing (identity '$SIGN_IDENTITY', hardened runtime, $(basename "$ENTITLEMENTS"))"
codesign --force --sign "$SIGN_IDENTITY" --options runtime --timestamp=none \
    --identifier "$BUNDLE_ID" --entitlements "$ENTITLEMENTS" "$APP"
codesign --verify --strict --verbose=2 "$APP" 2>&1 | sed 's/^/    /' >&2

log "built $APP ($(lipo -archs "$CONTENTS/MacOS/$EXE"))"
