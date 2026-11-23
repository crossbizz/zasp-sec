#!/bin/bash
set -euo pipefail

# Build on a macOS signing host with the Apple SDK and notarytool profile.
: "${ZASP_APP_SIGNING_ID:?Developer ID Application identity required}"
: "${ZASP_INSTALLER_SIGNING_ID:?Developer ID Installer identity required}"
: "${ZASP_NOTARY_PROFILE:?Keychain notarytool profile required}"
: "${ZASP_PACKAGE_VERSION:?Package version required}"
out=${1:?Provide a new .pkg output path}
[[ "$(uname -s)" = Darwin && "$out" = /* && ! -e "$out" ]]
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
bin="$work/payload/usr/local/libexec"
daemons="$work/payload/Library/LaunchDaemons"
mkdir -p "$bin" "$daemons"
for arch in arm64 amd64; do
  CGO_ENABLED=1 GOARCH="$arch" go -C "$repo/services/endpoint-agent" build -trimpath -o "$work/endpoint-$arch" .
done
lipo -create "$work/endpoint-arm64" "$work/endpoint-amd64" -output "$bin/zasp-endpoint"
codesign --options runtime --timestamp --sign "$ZASP_APP_SIGNING_ID" "$bin/zasp-endpoint"
codesign --verify --strict "$bin/zasp-endpoint"
install -m 0644 "$repo/deploy/endpoint/ai.zasp.endpoint.plist" "$daemons/ai.zasp.endpoint.plist"
pkgbuild --root "$work/payload" --identifier ai.zasp.endpoint --version "$ZASP_PACKAGE_VERSION" --ownership recommended --sign "$ZASP_INSTALLER_SIGNING_ID" "$work/zasp-endpoint.pkg"
xcrun notarytool submit "$work/zasp-endpoint.pkg" --keychain-profile "$ZASP_NOTARY_PROFILE" --wait
xcrun stapler staple "$work/zasp-endpoint.pkg"
spctl --assess --type install "$work/zasp-endpoint.pkg"
cp -n "$work/zasp-endpoint.pkg" "$out"
