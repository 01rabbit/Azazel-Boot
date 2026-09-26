#!/bin/sh
set -eu

# apt's generated binary cache was the only differing rootfs file in the
# previous A/B measurement. It is not needed by the immutable live runtime.
ROOT=${1:-/}
case "$ROOT" in
    /*) ;;
    *)
    echo "normalization root must be an absolute path" >&2
    exit 2
    ;;
esac

rm -f -- "$ROOT/var/cache/apt/pkgcache.bin"
