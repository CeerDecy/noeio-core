#!/usr/bin/env bash
set -euo pipefail

# Copy the read-only source into the container; never reuse the host's target/.
mkdir -p /work/source /cache/cargo
tar -C /src --exclude=./target --exclude=./build/out --exclude=./.git \
    --exclude=./.idea --exclude=./.vscode -cf - . | tar -C /work/source -xf -
cd /work/source

# This repository ignores Cargo.lock. Resolve once per invocation when absent,
# then use the same lockfile for every target without writing it on the host.
if [[ ! -f Cargo.lock ]]; then cargo generate-lockfile; fi
cp Cargo.lock /out/Cargo.lock

for platform in "$@"; do
    suffix=
    case "$platform" in
        linux-amd64) target=x86_64-unknown-linux-musl ;;
        linux-arm64) target=aarch64-unknown-linux-musl ;;
        macos-amd64) target=x86_64-apple-darwin ;;
        macos-aarch64) target=aarch64-apple-darwin ;;
        windows-amd64) target=x86_64-pc-windows-gnu; suffix=.exe ;;
        *) echo "Unknown platform: $platform" >&2; exit 2 ;;
    esac
    echo "==> Building $platform ($target)"
    if [[ "$platform" == windows-* ]]; then
        cargo build --release --locked -p noeio --bin noeio --target "$target"
    else
        cargo zigbuild --release --locked -p noeio --bin noeio --target "$target"
    fi
    artifact="noeio-$platform$suffix"
    cp "$CARGO_TARGET_DIR/$target/release/noeio$suffix" "/out/$artifact"
    (cd /out && sha256sum "$artifact" > "$artifact.sha256")
done
