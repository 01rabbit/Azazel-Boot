#!/bin/sh
# Install the evaluation-only Nexus .deb from the offline live-image medium.
# The package has no maintainer scripts; setup remains an explicit call to
# Nexus's existing installer, which masks operational units and starts none.
set -eu

PACKAGE=${1:-/usr/share/azazel-nexus/azazel-nexus-prototype.deb}
CHECKSUM=${2:-/usr/share/azazel-nexus/azazel-nexus-prototype.deb.sha256}

if [ "$(id -u)" -ne 0 ]; then
    echo "Nexus prototype package installation needs root" >&2
    exit 4
fi
[ -r "$PACKAGE" ] && [ -r "$CHECKSUM" ] || {
    echo "offline Nexus .deb or checksum file is missing" >&2
    exit 1
}

package_name=$(basename -- "$PACKAGE")
awk 'NR != 1 || NF != 2 { exit 1 } END { if (NR != 1) exit 1 }' "$CHECKSUM" || {
    echo "Nexus package checksum sidecar must contain exactly one digest and filename" >&2
    exit 1
}
expected_digest=$(awk 'NR == 1 {print $1}' "$CHECKSUM")
checksum_name=$(awk 'NR == 1 {print $2}' "$CHECKSUM")
[ "$checksum_name" = "$package_name" ] || {
    echo "Nexus package checksum names an unexpected file" >&2
    exit 1
}
case "$expected_digest" in
    ''|*[!0-9a-f]*) echo "Nexus package checksum is not lowercase SHA-256" >&2; exit 1 ;;
esac
digest_length=$(printf '%s' "$expected_digest" | wc -c | tr -d ' ')
[ "$digest_length" -eq 64 ] || {
    echo "Nexus package checksum is not lowercase SHA-256" >&2
    exit 1
}
actual_digest=$(sha256sum "$PACKAGE" | awk '{print $1}')
[ "$actual_digest" = "$expected_digest" ] || {
    echo "Nexus package digest differs from its checksum sidecar" >&2
    exit 1
}

[ "$(dpkg-deb -f "$PACKAGE" Package)" = "azazel-nexus-prototype" ] || {
    echo "unexpected Nexus package name" >&2
    exit 1
}
[ "$(dpkg-deb -f "$PACKAGE" Architecture)" = "all" ] || {
    echo "unexpected Nexus package architecture" >&2
    exit 1
}
[ "$(dpkg-deb -f "$PACKAGE" Version)" = "0.0.1~prototype1" ] || {
    echo "unexpected Nexus prototype package version" >&2
    exit 1
}

dpkg -i "$PACKAGE"
/usr/lib/azazel-nexus/packaging/install.sh
printf 'NEXUS_DEB_INSTALLED package=%s version=%s architecture=all\n' \
    "$(dpkg-query -W -f='${Package}' azazel-nexus-prototype)" \
    "$(dpkg-query -W -f='${Version}' azazel-nexus-prototype)"
