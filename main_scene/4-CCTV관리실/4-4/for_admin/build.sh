#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$ROOT/bin"
OUTPUT="$OUTPUT_DIR/archive-sweeper"
BUILDER_IMAGE="archive-sweeper-builder:ubuntu24.04"
BUILD_CONTEXT="$(mktemp -d)"
BUILD_CONTAINER=""

cleanup() {
    if [[ -n "$BUILD_CONTAINER" ]]; then
        docker rm -f "$BUILD_CONTAINER" >/dev/null 2>&1 || true
    fi
    rm -rf "$BUILD_CONTEXT"
}
trap cleanup EXIT

cp "$ROOT/src/chall.c" "$BUILD_CONTEXT/chall.c"

echo "[1/4] Preparing Ubuntu 24.04 builder"
docker build --quiet --platform linux/amd64 \
    -t "$BUILDER_IMAGE" -f - "$BUILD_CONTEXT" >/dev/null <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc binutils libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY chall.c /src/chall.c
RUN mkdir /out \
    && gcc -O0 -fno-omit-frame-pointer -fstack-protector-all -fPIE -pthread -Wall -Wextra \
        /src/chall.c -o /out/archive-sweeper \
        -pie -pthread -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
    && strip --strip-all /out/archive-sweeper
DOCKERFILE

echo "[2/4] Preparing output directory"
mkdir -p "$OUTPUT_DIR"

echo "[3/4] Building archive-sweeper"
BUILD_CONTAINER="$(docker create --platform linux/amd64 "$BUILDER_IMAGE")"
docker cp "$BUILD_CONTAINER:/out/archive-sweeper" "$OUTPUT"
docker rm "$BUILD_CONTAINER" >/dev/null
BUILD_CONTAINER=""

echo "[4/4] Verifying binary"
file "$OUTPUT"
sha256sum "$OUTPUT"
