#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
host_uid="$(id -u)"
host_gid="$(id -g)"

mkdir -p "$project_dir/bin"

printf '[1/3] Ubuntu 24.04 amd64 빌드 환경 준비\n'
docker run --rm --platform linux/amd64 \
    -e DEBIAN_FRONTEND=noninteractive \
    -e HOST_UID="$host_uid" \
    -e HOST_GID="$host_gid" \
    -v "$project_dir:/work" \
    -w /work \
    ubuntu:24.04 \
    bash -euc '
        apt-get update >/dev/null
        apt-get install -y --no-install-recommends gcc binutils libc6-dev >/dev/null
        gcc -O0 -fno-omit-frame-pointer -fstack-protector-all -fPIE -Wall -Wextra \
            src/chall.c -o bin/framevault \
            -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
        strip --strip-all bin/framevault
        chown "$HOST_UID:$HOST_GID" bin/framevault
    '

printf '[2/3] 바이너리 형식 확인\n'
file "$project_dir/bin/framevault"

printf '[3/3] 빌드 완료\n'
sha256sum "$project_dir/bin/framevault"
