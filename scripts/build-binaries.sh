#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./scripts/build-binaries.sh [platform ...]

Build noeio in Docker. With no arguments, build all:
  linux-amd64 linux-arm64 macos-amd64 macos-aarch64 windows-amd64

Environment:
  RUST_IMAGE     Base image (default: rust:1.94-bookworm; may use a mirror)
  BUILD_IMAGE    Builder image name (default: noeio-cross:rust-1.94)
  BUILD_CACHE    Docker cache volume (default: noeio-cross-cache-v1)

Output: build/out/noeio-<platform>[.exe] and matching .sha256 files.
Requires Docker with Linux containers; no host Rust tools are used.
macOS targets require an SDK located by xcrun --sdk macosx --show-sdk-path.
EOF
}

if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then usage; exit 0; fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ $# -eq 0 ]]; then
    set -- linux-amd64 linux-arm64 macos-amd64 macos-aarch64 windows-amd64
fi
needs_sdk=false
for platform in "$@"; do
    case "$platform" in
        linux-amd64|linux-arm64|windows-amd64) ;;
        macos-amd64|macos-aarch64) needs_sdk=true ;;
        *) echo "Unknown platform: $platform (see --help)" >&2; exit 2 ;;
    esac
done

sdk_args=()
if [[ "$needs_sdk" == true ]]; then
    if ! command -v xcrun >/dev/null 2>&1 || \
        ! sdk="$(xcrun --sdk macosx --show-sdk-path)"; then
        echo 'macOS builds require xcrun and an SDK from Xcode or Command Line Tools.' >&2
        echo 'Install/select those tools, or select only Linux/Windows targets; see --help.' >&2
        exit 2
    fi
    if [[ -z "$sdk" || ! -d "$sdk/usr/include" || ! -d "$sdk/System/Library/Frameworks" ]]; then
        echo 'xcrun returned an invalid macOS SDK. Check your Xcode or Command Line Tools installation.' >&2
        echo 'Or select only Linux/Windows targets; see --help.' >&2
        exit 2
    fi
    sdk="$(cd "$sdk" && pwd -P)"
    sdk_args=(--mount "type=bind,source=$sdk,target=/opt/macos-sdk,readonly" --env SDKROOT=/opt/macos-sdk)
fi

command -v docker >/dev/null 2>&1 || { echo 'Docker is required.' >&2; exit 1; }
docker info >/dev/null
image="${BUILD_IMAGE:-noeio-cross:rust-1.94}"
cache="${BUILD_CACHE:-noeio-cross-cache-v1}"
docker build --build-arg "RUST_IMAGE=${RUST_IMAGE:-rust:1.94-bookworm}" \
    -f "$root/build/cross/Dockerfile" -t "$image" "$root"
mkdir -p "$root/build/out"

# Initialize ownership before running as the host user (also on Linux).
docker run --rm --user 0 --entrypoint sh \
    --mount "type=volume,source=$cache,target=/cache" "$image" \
    -c 'chown -R "$1:$2" /cache' sh "$(id -u)" "$(id -g)"
docker run --rm --user "$(id -u):$(id -g)" --env HOME=/tmp \
    --mount "type=bind,source=$root,target=/src,readonly" \
    --mount "type=bind,source=$root/build/out,target=/out" \
    --mount "type=volume,source=$cache,target=/cache" \
    --tmpfs /work:mode=1777 \
    ${sdk_args[@]+"${sdk_args[@]}"} "$image" "$@"
echo "Binaries written to $root/build/out"
