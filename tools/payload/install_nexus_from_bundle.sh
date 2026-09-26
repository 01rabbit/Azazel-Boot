#!/bin/sh
# Prototype-only offline staging helper. It installs the frozen CORE/runtime
# Python sources and the existing Nexus installer; it introduces no policy,
# admission, activation, fetch, or storage-writing decision.
set -eu

BUNDLE=${1:-/usr/share/azazel-nexus/azazel-nexus-source.tar}
BUNDLE_MANIFEST=${2:-/usr/share/azazel-nexus/azazel-nexus-bundle-manifest.json}
DESTDIR=${DESTDIR:-}
PYTHON=${PYTHON:-python3}

if [ "$(id -u)" -ne 0 ]; then
    echo "Nexus prototype installation needs root" >&2
    exit 4
fi
if [ ! -d /run/systemd/system ]; then
    echo "Nexus prototype integration requires a running systemd guest" >&2
    exit 3
fi
"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {
    echo "Nexus requires Python 3.11 or newer" >&2
    exit 1
}
[ -r "$BUNDLE" ] && [ -r "$BUNDLE_MANIFEST" ] || {
    echo "Nexus offline source bundle or manifest is missing" >&2
    exit 1
}

work=$(mktemp -d /run/azazel-nexus-bundle.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
python3 - "$BUNDLE" "$BUNDLE_MANIFEST" "$work/extracted" <<'PY'
import hashlib
import json
import pathlib
import stat
import sys
import tarfile

bundle = pathlib.Path(sys.argv[1])
manifest = json.loads(pathlib.Path(sys.argv[2]).read_text())
destination = pathlib.Path(sys.argv[3])
actual_bundle_digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
if actual_bundle_digest != manifest.get("bundle_sha256"):
    raise SystemExit("Nexus offline bundle digest differs from its manifest")
expected = {item["path"]: item for item in manifest.get("files", [])}
if len(expected) != len(manifest.get("files", [])) or not expected:
    raise SystemExit("Nexus offline bundle manifest has duplicate or no files")
destination.mkdir(mode=0o700, parents=True)
seen = set()
with tarfile.open(bundle, "r:gz") as archive:
    for member in archive.getmembers():
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not member.isfile():
            raise SystemExit(f"unsafe Nexus bundle member: {member.name}")
        record = expected.get(member.name)
        if record is None or member.name in seen:
            raise SystemExit(f"unmanifested or duplicate Nexus bundle member: {member.name}")
        source = archive.extractfile(member)
        if source is None:
            raise SystemExit(f"Nexus bundle member is unreadable: {member.name}")
        content = source.read()
        if (
            len(content) != record.get("size")
            or hashlib.sha256(content).hexdigest() != record.get("sha256")
            or f"{stat.S_IMODE(member.mode):04o}" != record.get("mode")
        ):
            raise SystemExit(f"Nexus bundle member differs from its manifest: {member.name}")
        target = destination.joinpath(*path.parts)
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(stat.S_IMODE(member.mode))
        seen.add(member.name)
if seen != set(expected):
    raise SystemExit("Nexus offline bundle is missing manifest-declared files")
PY
root=$work/extracted
[ -d "$root/src/azazel_nexus" ] && [ -d "$root/runtime/src/azazel_nexus_runtime" ] || {
    echo "Nexus bundle has an unexpected source layout" >&2
    exit 1
}

install -d -m 0755 "${DESTDIR}/usr/lib/python3/dist-packages" \
    "${DESTDIR}/usr/libexec/azazel"
cp -a "$root/src/azazel_nexus" "${DESTDIR}/usr/lib/python3/dist-packages/"
cp -a "$root/runtime/src/azazel_nexus_runtime" "${DESTDIR}/usr/lib/python3/dist-packages/"

write_entrypoint() {
    name=$1 module=$2
    target=${DESTDIR}/usr/libexec/azazel/$name
    printf '#!/bin/sh\nexec %s -c %s "$@"\n' \
        "$PYTHON" \
        "'from $module import main; raise SystemExit(main())'" > "$target"
    chmod 0755 "$target"
}

write_entrypoint az-activated azazel_nexus_runtime.activated
write_entrypoint az-commissiond azazel_nexus_runtime.commissiond
write_entrypoint az-auditd azazel_nexus_runtime.auditd
write_entrypoint az-watchdog azazel_nexus_runtime.watchdog
write_entrypoint az-edge-probed azazel_nexus_runtime.edge_probed
write_entrypoint az-model-fetchd azazel_nexus_runtime.model_fetchd
write_entrypoint az-mio-locald azazel_nexus_runtime.mio_locald
write_entrypoint az-mio-remoted azazel_nexus_runtime.mio_remoted
write_entrypoint azazel-nexus azazel_nexus.cli

cd "$root"
sh packaging/install.sh
