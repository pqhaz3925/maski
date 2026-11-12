#!/bin/bash
# Build the app + extension for a device and install it (UDID in $1 or $MASKI_DEVICE).
# Needs ../target/aarch64-apple-ios/apple/libmaski.a (../tools/build-apple.sh) and Config/server.json.
set -euo pipefail
cd "$(dirname "$0")"
xcodegen -q
xcodebuild -project Maski.xcodeproj -scheme MaskiApp -configuration Release -destination 'generic/platform=iOS' \
  -derivedDataPath build -allowProvisioningUpdates build -quiet
DEV=${1:-${MASKI_DEVICE:-}}
[ -n "$DEV" ] && xcrun devicectl device install app --device "$DEV" build/Build/Products/Release-iphoneos/MaskiApp.app | tail -1
