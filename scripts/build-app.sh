#!/bin/zsh
# Builds EFISigner with SwiftPM and wraps it into build/EFI Signer.app
set -eu
cd "${0:A:h}/.."
swift build -c release --product EFISigner
APP="build/EFI Signer.app"
# never replace the bundle under a running instance
if pgrep -x EFISigner >/dev/null; then
  osascript -e 'tell application "EFI Signer" to quit' >/dev/null 2>&1 || true
  for i in {1..20}; do pgrep -x EFISigner >/dev/null || break; sleep 0.5; done
  pgrep -x EFISigner >/dev/null && killall EFISigner && sleep 1
fi
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp .build/release/EFISigner "$APP/Contents/MacOS/EFISigner"
cp scripts/Info.plist "$APP/Contents/Info.plist"
[[ -f scripts/AppIcon.icns ]] && cp scripts/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns" && /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string AppIcon" "$APP/Contents/Info.plist"
codesign --force --sign - "$APP" >/dev/null
echo "built $PWD/$APP"
