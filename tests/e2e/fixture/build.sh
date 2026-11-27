#!/usr/bin/env bash
# Rebuild the fixture binary the end-to-end tests import (x86-64 ELF).
# The binary is committed so the tests need no compiler and see the same
# code everywhere; rerun this only after editing fixture.c.
set -euo pipefail
cd "$(dirname "$0")"
gcc -O1 -fno-pie -no-pie -Wl,--build-id=none -o fixture fixture.c
strip --strip-debug fixture
echo "built $(pwd)/fixture ($(stat -c %s fixture) bytes)"
