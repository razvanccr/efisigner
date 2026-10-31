#!/bin/zsh
# Builds the app and the CLI and zips them into dist/. Usage: scripts/package.sh [version]
set -eu
cd "${0:A:h}/.."
VERSION="${1:-dev}"
./scripts/build-app.sh
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "build/EFI Signer.app/Contents/Info.plist" 2>/dev/null || true
codesign --force --sign - "build/EFI Signer.app" >/dev/null
swift build -c release --product efisign >/dev/null
rm -rf dist && mkdir -p dist
ditto -c -k --keepParent "build/EFI Signer.app" "dist/EFI-Signer-$VERSION.zip"
cp .build/release/efisign "dist/efisign-$VERSION"
ls -l dist
