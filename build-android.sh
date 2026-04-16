#!/usr/bin/env bash
# Build usque-rs for Android (arm64 + arm32) and optionally copy to rethink-app.
#
# Usage:
#   ./build-android.sh                  # build only
#   ./build-android.sh --copy-assets    # build + copy to ../rethink-app assets
#
# Requires: cross (cargo install cross), Docker

set -euo pipefail

COPY_ASSETS=false
for arg in "$@"; do
    [[ "$arg" == "--copy-assets" ]] && COPY_ASSETS=true
done

TARGETS=(
    "aarch64-linux-android"
    "armv7-linux-androideabi"
)

for target in "${TARGETS[@]}"; do
    echo "==> Building $target"
    cross build --target "$target" --release
done

# Strip symbols
echo "==> Stripping binaries"
aarch64-linux-android-strip  target/aarch64-linux-android/release/usque-rs
armv7-linux-androideabi-strip target/armv7-linux-androideabi/release/usque-rs

if [[ "$COPY_ASSETS" == true ]]; then
    ASSETS_DIR="../usque-rs/app/src/main/assets"
    echo "==> Copying to $ASSETS_DIR"
    cp target/aarch64-linux-android/release/usque-rs  "$ASSETS_DIR/usque-rs-arm64"
    cp target/armv7-linux-androideabi/release/usque-rs "$ASSETS_DIR/usque-rs-arm32"
    echo "==> Done"
else
    echo "==> Done (pass --copy-assets to copy binaries to rethink-app)"
fi
