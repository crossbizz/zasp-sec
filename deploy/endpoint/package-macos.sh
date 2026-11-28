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
agents="$work/payload/Library/LaunchAgents"
mkdir -p "$bin" "$daemons" "$agents"
for arch in arm64 amd64; do
  CGO_ENABLED=1 GOARCH="$arch" go -C "$repo/services/endpoint-agent" build -trimpath -o "$work/endpoint-$arch" .
  CGO_ENABLED=0 GOARCH="$arch" go -C "$repo/cmd/zaspctl" build -trimpath -o "$work/cli-$arch" .
done
lipo -create "$work/cli-arm64" "$work/cli-amd64" -output "$bin/zaspctl"
codesign --options runtime --timestamp --sign "$ZASP_APP_SIGNING_ID" "$bin/zaspctl"
codesign --verify --strict "$bin/zaspctl"
lipo -create "$work/endpoint-arm64" "$work/endpoint-amd64" -output "$bin/zasp-endpoint"
codesign --options runtime --timestamp --sign "$ZASP_APP_SIGNING_ID" "$bin/zasp-endpoint"
codesign --verify --strict "$bin/zasp-endpoint"
install -m 0644 "$repo/deploy/endpoint/ai.zasp.endpoint.plist" "$daemons/ai.zasp.endpoint.plist"
install -m 0644 "$repo/deploy/endpoint/ai.zasp.skill-inventory.plist" "$agents/ai.zasp.skill-inventory.plist"
mkdir "$work/scripts"
install -m 0755 "$repo/deploy/endpoint/macos-postinstall.sh" "$work/scripts/postinstall"
pkgbuild --scripts "$work/scripts" --root "$work/payload" --identifier ai.zasp.endpoint --version "$ZASP_PACKAGE_VERSION" --ownership recommended --sign "$ZASP_INSTALLER_SIGNING_ID" "$work/zasp-endpoint.pkg"
xcrun notarytool submit "$work/zasp-endpoint.pkg" --keychain-profile "$ZASP_NOTARY_PROFILE" --wait
xcrun stapler staple "$work/zasp-endpoint.pkg"
spctl --assess --type install "$work/zasp-endpoint.pkg"
cp -n "$work/zasp-endpoint.pkg" "$out"
