#!/bin/sh
set -eu
mkdir -p ../for_user
cc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror \
  -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie \
  -Wl,-z,relro,-z,now -o ../for_user/donor-probe player.c -lcrypto -lz
strip --strip-all ../for_user/donor-probe
