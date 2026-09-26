#!/usr/bin/env bash
set -euo pipefail

# Build only from the frozen PREPARE bundle. Caller transports the manifest
# digest separately, so replacing a manifest and its sidecar cannot redefine
# this build's inputs.
FROZEN_ROOT=$(realpath "${1:?frozen input bundle}")
OUTPUT_DIR=$(realpath -m "${2:?empty output directory}")
EXPECTED_MANIFEST_SHA256=${3:?manifest SHA-256 from PREPARE}
RUNNING_RECIPE=$(realpath "${BASH_SOURCE[0]}")
RUNNING_RECIPE_DIR=$(dirname "$RUNNING_RECIPE")
MANIFEST=$FROZEN_ROOT/build-input-manifest.json
INPUTS=$FROZEN_ROOT/frozen-inputs

if [[ -e "$OUTPUT_DIR" ]] && [[ -n "$(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "output directory must be empty: $OUTPUT_DIR" >&2
    exit 2
fi
mkdir -p "$OUTPUT_DIR"

cleanup_untrusted_result() {
    local status=$?
    if (( status != 0 )); then
        rm -f "$OUTPUT_DIR/build-result.json" \
            "$OUTPUT_DIR/evidence-file-digests.sha256" \
            "$OUTPUT_DIR/.build-result.json.tmp"
    fi
    return "$status"
}
trap cleanup_untrusted_result EXIT

sha256() { sha256sum "$1" | cut -d ' ' -f 1; }
verify_inputs() {
    python3 "$INPUTS/verify_frozen_inputs.py" \
        --manifest "$MANIFEST" --bundle-root "$FROZEN_ROOT" \
        --expected-sha256 "$EXPECTED_MANIFEST_SHA256" \
        --running-recipe "$RUNNING_RECIPE" --verify-builder-environment
}
input_tree_digest() {
    python3 - "$MANIFEST" "$FROZEN_ROOT" <<'PY'
import hashlib,json,pathlib,sys
doc=json.loads(pathlib.Path(sys.argv[1]).read_text()); root=pathlib.Path(sys.argv[2]); h=hashlib.sha256()
for name,item in sorted(doc["inputs"].items()):
    actual=hashlib.sha256((root/item["path"]).read_bytes()).hexdigest()
    if actual!=item["sha256"]: raise SystemExit(f"frozen input changed: {name}")
    h.update(name.encode()+b"\0"+actual.encode()+b"\n")
print(h.hexdigest())
PY
}

verify_inputs
START_MANIFEST_HASH=$(sha256 "$MANIFEST")
START_INPUTS_HASH=$(input_tree_digest)
BUILDER_INSTANCE_ID=$(python3 - <<'PY'
import hashlib,pathlib
machine_id=pathlib.Path("/etc/machine-id").read_bytes().strip()
if not machine_id: raise SystemExit("builder machine-id is empty")
print(hashlib.sha256(machine_id).hexdigest())
PY
)
BUILDER_KERNEL=$(uname -r)
cp "$MANIFEST" "$OUTPUT_DIR/build-input-manifest.json"
cp "$FROZEN_ROOT/build-input-manifest.sha256" "$OUTPUT_DIR/build-input-manifest.sha256"

manifest_input_path() {
    python3 - "$MANIFEST" "$1" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))["inputs"][sys.argv[2]]["path"])
PY
}

eval "$(python3 - "$MANIFEST" <<'PY'
import json,shlex,sys
m=json.load(open(sys.argv[1]))
print("MIRROR="+shlex.quote(m["target"]["repository"]["snapshot"]))
print("SOURCE_DATE_EPOCH="+shlex.quote(str(m["normalization"]["source_date_epoch"])))
PY
)"
export SOURCE_DATE_EPOCH TZ=UTC LC_ALL=C.UTF-8 LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1
umask 022

python3 - "$MANIFEST" <<'PY'
import json,subprocess,sys
m=json.load(open(sys.argv[1])); lock=m["target"]["toolchain_lock"]
if subprocess.check_output(["dpkg","--print-architecture"],text=True).strip()!=m["target"]["architecture"]:
    raise SystemExit("builder architecture differs from manifest")
for item in lock["packages"]:
    actual=subprocess.check_output(["dpkg-query","-W","-f=${Version}",item["name"]],text=True).strip()
    if actual!=item["version"]:
        raise SystemExit(f"toolchain version mismatch for {item['name']}: {actual} != {item['version']}")
PY

mkdir -p "$OUTPUT_DIR/work"
cd "$OUTPUT_DIR/work"
lb config \
    --distribution trixie --architectures amd64 --archive-areas main \
    --security false --updates false --binary-images iso-hybrid \
    --mirror-bootstrap "$MIRROR" --mirror-chroot "$MIRROR" --mirror-binary "$MIRROR"

mkdir -p config/includes.chroot/etc/initramfs-tools/scripts/init-top \
    config/includes.chroot/etc/initramfs-tools/scripts/init-bottom \
    config/includes.chroot/etc/initramfs-tools/hooks \
    config/includes.chroot/etc/initramfs-tools/conf.d \
    config/includes.chroot/etc/udev/rules.d \
    config/includes.chroot/etc/apt/apt.conf.d \
    config/includes.chroot/etc/systemd/system/multi-user.target.wants \
    config/includes.chroot/usr/libexec \
    config/includes.chroot/usr/lib/python3/dist-packages/azazel_boot \
    config/includes.chroot/usr/share/azazel-nexus \
    config/includes.chroot/usr/share/azazel-nexus/e2e \
    config/includes.chroot/etc/azazel config/includes.chroot/usr/libexec \
    config/package-lists config/hooks/normal
POLICY_INPUT=$(manifest_input_path quarantine_policy)
PACKAGE_INPUT=$(manifest_input_path package_requests)
NORMALIZER_INPUT=$(manifest_input_path rootfs_normalizer)
APT_CACHE_POLICY_INPUT=$(manifest_input_path apt_cache_policy)
PERSISTENCE_PROBE_INPUT=$(manifest_input_path c5_persistence_probe)
PERSISTENCE_SERVICE_INPUT=$(manifest_input_path c5_persistence_service)
C5_CONFIGURATOR_INPUT=$(manifest_input_path c5_initramfs_configurator)
QUARANTINE_HELPER_INPUT=$(manifest_input_path quarantine_block_helper)
QUARANTINE_RULE_INPUT=$(manifest_input_path quarantine_udev_rule)
HOTPLUG_PROBE_SERVICE_INPUT=$(manifest_input_path hotplug_probe_service)
INITRAMFS_QUARANTINE_HOOK_INPUT=$(manifest_input_path initramfs_quarantine_hook)
ROOTFS_EXTRACTION_INSPECTOR_INPUT=$(manifest_input_path rootfs_extraction_inspector)
NEXUS_DEB_PACKAGER_INPUT=$(manifest_input_path nexus_deb_packager)
NEXUS_INSTALLER_INPUT=$(manifest_input_path nexus_guest_installer)
NEXUS_E2E_INPUT=$(manifest_input_path nexus_guest_e2e)
NEXUS_SERVICE_INPUT=$(manifest_input_path nexus_guest_service)
BOOT_RUNTIME_SERVICE_INPUT=$(manifest_input_path boot_runtime_service)

python3 "$FROZEN_ROOT/$NEXUS_DEB_PACKAGER_INPUT" \
    --bundle "$FROZEN_ROOT/$(manifest_input_path nexus_source_bundle)" \
    --manifest "$FROZEN_ROOT/$(manifest_input_path nexus_bundle_manifest)" \
    --output-dir "$OUTPUT_DIR/nexus-package"
dpkg-deb --build --root-owner-group \
    "$OUTPUT_DIR/nexus-package/package-root" \
    "$OUTPUT_DIR/azazel-nexus-prototype.deb"
[[ "$(dpkg-deb -f "$OUTPUT_DIR/azazel-nexus-prototype.deb" Package)" == "azazel-nexus-prototype" ]]
[[ "$(dpkg-deb -f "$OUTPUT_DIR/azazel-nexus-prototype.deb" Architecture)" == "all" ]]
cp "$OUTPUT_DIR/nexus-package/package-summary.json" "$OUTPUT_DIR/nexus-package-summary.json"
(cd "$OUTPUT_DIR" && sha256sum azazel-nexus-prototype.deb > azazel-nexus-prototype.deb.sha256)
cp "$FROZEN_ROOT/$POLICY_INPUT" config/includes.chroot/etc/azazel/quarantine-policy.json
cp "$FROZEN_ROOT/$APT_CACHE_POLICY_INPUT" \
    config/includes.chroot/etc/apt/apt.conf.d/99azazel-disable-generated-cache.conf
cp "$FROZEN_ROOT/$PERSISTENCE_PROBE_INPUT" \
    config/includes.chroot/usr/libexec/azazel-c5-persistence-probe
chmod 0755 config/includes.chroot/usr/libexec/azazel-c5-persistence-probe
cp "$FROZEN_ROOT/$PERSISTENCE_SERVICE_INPUT" \
    config/includes.chroot/etc/systemd/system/azazel-c5-persistence-probe.service
ln -s ../azazel-c5-persistence-probe.service \
    config/includes.chroot/etc/systemd/system/multi-user.target.wants/azazel-c5-persistence-probe.service
cp "$OUTPUT_DIR/azazel-nexus-prototype.deb" \
    config/includes.chroot/usr/share/azazel-nexus/
cp "$OUTPUT_DIR/azazel-nexus-prototype.deb.sha256" \
    config/includes.chroot/usr/share/azazel-nexus/
cp "$FROZEN_ROOT/$NEXUS_INSTALLER_INPUT" \
    config/includes.chroot/usr/libexec/azazel-nexus-prototype-install
chmod 0755 config/includes.chroot/usr/libexec/azazel-nexus-prototype-install
cp "$FROZEN_ROOT/$NEXUS_E2E_INPUT" \
    config/includes.chroot/usr/share/azazel-nexus/e2e/run_nexus_guest_e2e.py
cp "$FROZEN_ROOT/$NEXUS_SERVICE_INPUT" \
    config/includes.chroot/etc/systemd/system/azazel-nexus-prototype-e2e.service
ln -s ../azazel-nexus-prototype-e2e.service \
    config/includes.chroot/etc/systemd/system/multi-user.target.wants/azazel-nexus-prototype-e2e.service
cp "$FROZEN_ROOT/$NEXUS_E2E_INPUT" \
    config/includes.chroot/usr/libexec/azazel-nexus-prototype-e2e
chmod 0755 config/includes.chroot/usr/libexec/azazel-nexus-prototype-e2e
cp "$FROZEN_ROOT/$NORMALIZER_INPUT" config/hooks/normal/9999-remove-apt-generated-cache.hook.chroot
chmod 0755 config/hooks/normal/9999-remove-apt-generated-cache.hook.chroot
cp "$FROZEN_ROOT/$QUARANTINE_HELPER_INPUT" \
    config/includes.chroot/usr/libexec/azazel-quarantine-block
chmod 0755 config/includes.chroot/usr/libexec/azazel-quarantine-block
cp "$FROZEN_ROOT/$QUARANTINE_RULE_INPUT" \
    config/includes.chroot/etc/udev/rules.d/00-azazel-quarantine.rules
cp "$FROZEN_ROOT/$HOTPLUG_PROBE_SERVICE_INPUT" \
    config/includes.chroot/etc/systemd/system/azazel-c5-hotplug-write-probe@.service
cp "$FROZEN_ROOT/$INITRAMFS_QUARANTINE_HOOK_INPUT" \
    config/includes.chroot/etc/initramfs-tools/hooks/azazel-quarantine
chmod 0755 config/includes.chroot/etc/initramfs-tools/hooks/azazel-quarantine
cp "$FROZEN_ROOT/$C5_CONFIGURATOR_INPUT" \
    config/hooks/normal/0010-configure-azazel-c5-initramfs.hook.chroot
chmod 0755 config/hooks/normal/0010-configure-azazel-c5-initramfs.hook.chroot
cp "$FROZEN_ROOT/$BOOT_RUNTIME_SERVICE_INPUT" \
    config/includes.chroot/etc/systemd/system/azazel-boot-runtime.service
ln -s ../azazel-boot-runtime.service \
    config/includes.chroot/etc/systemd/system/multi-user.target.wants/azazel-boot-runtime.service
cp "$FROZEN_ROOT/$(manifest_input_path boot_package_init)" \
    config/includes.chroot/usr/lib/python3/dist-packages/azazel_boot/__init__.py
for boot_module in version inventory commissioning session_mode quarantine refusals runtime; do
    if [[ "$boot_module" == quarantine ]]; then
        boot_input=boot_quarantine_module
    elif [[ "$boot_module" == refusals ]]; then
        boot_input=boot_quarantine_refusals
    else
        boot_input="boot_runtime_${boot_module}"
    fi
    cp "$FROZEN_ROOT/$(manifest_input_path "$boot_input")" \
        "config/includes.chroot/usr/lib/python3/dist-packages/azazel_boot/${boot_module}.py"
done
printf 'RESUME=none\n' > config/includes.chroot/etc/initramfs-tools/conf.d/azazel-resume
python3 - "$MANIFEST" "$FROZEN_ROOT" <<'PY'
import hashlib,json,pathlib,shutil,sys
m=json.loads(pathlib.Path(sys.argv[1]).read_text()); root=pathlib.Path(sys.argv[2])
dst=pathlib.Path("config/includes.chroot/etc/initramfs-tools/scripts/init-top")
bottom=pathlib.Path("config/includes.chroot/etc/initramfs-tools/scripts/init-bottom")
first=pathlib.Path("config/includes.chroot/usr/libexec/azazel-quarantine-first")
for hook in m["initramfs_hooks"]:
    src=root/hook["path"]
    if hashlib.sha256(src.read_bytes()).hexdigest()!=hook["sha256"]:
        raise SystemExit(f"pinned hook changed: {hook['name']}")
    if hook["name"] == "az-quarantine-block-devices":
        target=first
    elif hook["name"] == "az-handoff-udev":
        target=bottom/hook["filename"]
    else:
        target=dst/hook["filename"]
    shutil.copyfile(src,target); target.chmod(0o755)
PY
cp "$FROZEN_ROOT/$PACKAGE_INPUT" config/package-lists/azazel-prototype.list.chroot
cp -a config "$OUTPUT_DIR/config-used"
lb build 2>&1 | tee "$OUTPUT_DIR/live-build.log"

find_one() {
    local root=$1 pattern=$2
    mapfile -t found < <(find "$root" -type f -name "$pattern" -print | LC_ALL=C sort)
    if (( ${#found[@]} == 0 )); then
        echo "expected one content-unique $pattern under $root; found none" >&2
        exit 44
    fi
    local -A seen=()
    local path hash canonical=""
    local -a content_unique=()
    for path in "${found[@]}"; do
        hash=$(sha256 "$path")
        if [[ -z "${seen[$hash]+present}" ]]; then
            seen[$hash]=$path
            content_unique+=("$path")
        fi
        # Debian live-build exposes both generic and kernel-version aliases.
        # Prefer the generic filename after proving all aliases are byte-identical.
        if [[ "$(basename "$path")" == "${pattern%\*}" ]]; then
            canonical=$path
        fi
    done
    if (( ${#content_unique[@]} != 1 )); then
        echo "expected one content-unique $pattern under $root; found ${#content_unique[@]} distinct contents" >&2
        printf '  %s\n' "${content_unique[@]}" >&2
        exit 44
    fi
    printf '%s\n' "${canonical:-${content_unique[0]}}"
}
INITRD=$(find_one binary 'initrd.img*')
VMLINUX=$(find_one binary 'vmlinuz*')
ISO=$(find_one . '*.iso')
[[ -f binary/live/filesystem.packages ]] || {
    echo "resolved versioned package closure is missing" >&2
    exit 45
}
cp "$INITRD" "$OUTPUT_DIR/initrd.img"
cp "$VMLINUX" "$OUTPUT_DIR/vmlinuz"
cp "$ISO" "$OUTPUT_DIR/payload.iso"
cp binary/live/filesystem.packages "$OUTPUT_DIR/filesystem.packages"
SQUASHFS=binary/live/filesystem.squashfs
[[ -f "$SQUASHFS" ]] || { echo "live root filesystem image is missing" >&2; exit 46; }
mkdir -p "$OUTPUT_DIR/iso-extracted"
xorriso -osirrox on -indev "$OUTPUT_DIR/payload.iso" \
    -extract /live/filesystem.squashfs "$OUTPUT_DIR/iso-extracted/filesystem.squashfs" \
    > "$OUTPUT_DIR/iso-squashfs-extract.log" 2>&1
cmp "$SQUASHFS" "$OUTPUT_DIR/iso-extracted/filesystem.squashfs"
ROOTFS_DIR=$OUTPUT_DIR/rootfs-extracted
unsquashfs -no-progress -d "$ROOTFS_DIR" \
    "$OUTPUT_DIR/iso-extracted/filesystem.squashfs" > "$OUTPUT_DIR/iso-unsquashfs.log" 2>&1
ROOTFS_EXTRACTION_INSPECTOR=$FROZEN_ROOT/$ROOTFS_EXTRACTION_INSPECTOR_INPUT
[[ -f "$ROOTFS_EXTRACTION_INSPECTOR" ]] || {
    echo "rootfs extraction inspector is unavailable: $ROOTFS_EXTRACTION_INSPECTOR" >&2
    exit 48
}
ROOTFS_EXTRACTION_INSPECTOR_SHA256=$(python3 - "$MANIFEST" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))["inputs"]["rootfs_extraction_inspector"]["sha256"])
PY
)
[[ "$(sha256 "$ROOTFS_EXTRACTION_INSPECTOR")" == "$ROOTFS_EXTRACTION_INSPECTOR_SHA256" ]] || {
    echo "rootfs extraction inspector differs from its frozen manifest entry" >&2
    exit 48
}
python3 "$ROOTFS_EXTRACTION_INSPECTOR" \
    --root "$ROOTFS_DIR" --output "$OUTPUT_DIR/rootfs-extraction-diagnostics.json"
[[ "$(sha256 "$ROOTFS_EXTRACTION_INSPECTOR")" == "$ROOTFS_EXTRACTION_INSPECTOR_SHA256" ]] || {
    echo "rootfs extraction inspector changed during diagnostic collection" >&2
    exit 48
}
ISO_PACKAGE="$ROOTFS_DIR/usr/share/azazel-nexus/azazel-nexus-prototype.deb"
ISO_PACKAGE_CHECKSUM="$ROOTFS_DIR/usr/share/azazel-nexus/azazel-nexus-prototype.deb.sha256"
cmp "$OUTPUT_DIR/azazel-nexus-prototype.deb" "$ISO_PACKAGE"
cmp "$OUTPUT_DIR/azazel-nexus-prototype.deb.sha256" "$ISO_PACKAGE_CHECKSUM"
if [[ -e "$ROOTFS_DIR/var/cache/apt/pkgcache.bin" ]]; then
    echo "generated APT package cache was not removed from immutable rootfs" >&2
    exit 47
fi
(
    cd "$ROOTFS_DIR"
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) > "$OUTPUT_DIR/rootfs-file-content.sha256"
find "$ROOTFS_DIR" -printf '%P\t%y\t%m\t%U:%G\t%i\t%s\t%T@\t%l\n' | LC_ALL=C sort \
    > "$OUTPUT_DIR/rootfs-metadata.tsv"

INSPECT=$OUTPUT_DIR/initramfs-inspected
mkdir -p "$INSPECT"
unmkinitramfs "$INITRD" "$INSPECT"
lsinitramfs -l "$INITRD" > "$OUTPUT_DIR/initramfs-entry-listing.txt" 2>&1 || {
    echo "unable to enumerate initramfs cpio entries" >&2
    exit 43
}
file -b "$INITRD" > "$OUTPUT_DIR/initramfs-container-type.txt"
python3 "$INPUTS/inspect_initramfs.py" \
    --initramfs "$INITRD" --output "$OUTPUT_DIR/initramfs-inspection.json"
find "$INSPECT" -printf '%P\t%y\t%m\t%U:%G\t%i\t%s\t%T@\t%l\n' | LC_ALL=C sort \
    > "$OUTPUT_DIR/initramfs-extracted-metadata.tsv"
find binary -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum \
    > "$OUTPUT_DIR/binary-component-digests.sha256"
xorriso -indev "$ISO" -report_system_area plain -report_el_torito plain \
    > "$OUTPUT_DIR/iso-boot-metadata.txt" 2>&1
xorriso -indev "$ISO" -find / -type f -exec lsdl -- \
    > "$OUTPUT_DIR/iso-file-metadata.txt" 2>&1

python3 "$INPUTS/measure_initramfs_c5.py" \
    --frozen-inputs "$INPUTS" --initramfs-tree "$INSPECT" \
    --rootfs-tree "$ROOTFS_DIR" \
    --payload "$OUTPUT_DIR/payload.iso" --initramfs "$OUTPUT_DIR/initrd.img" \
    --output "$OUTPUT_DIR/c5-manifest.json"

# VERIFY after every measured artifact exists, but before publishing a result
# that downstream evidence could mistake for a successful pinned build.
verify_inputs
END_MANIFEST_HASH=$(sha256 "$MANIFEST")
END_INPUTS_HASH=$(input_tree_digest)
if [[ "$START_MANIFEST_HASH" != "$END_MANIFEST_HASH" || "$START_INPUTS_HASH" != "$END_INPUTS_HASH" ]]; then
    echo "FAIL CLOSED: manifest or frozen inputs changed during build" >&2
    exit 42
fi

python3 - "$OUTPUT_DIR" "$MANIFEST" "$EXPECTED_MANIFEST_SHA256" \
    "$START_MANIFEST_HASH" "$END_MANIFEST_HASH" "$START_INPUTS_HASH" "$END_INPUTS_HASH" \
    "$BUILDER_INSTANCE_ID" "$BUILDER_KERNEL" <<'PY'
import hashlib,json,pathlib,subprocess,sys
out=pathlib.Path(sys.argv[1]); mpath=pathlib.Path(sys.argv[2]); mdigest=sys.argv[3]
manifest_start,manifest_end,inputs_start,inputs_end,instance_id,kernel_release=sys.argv[4:]
digest=lambda p:"sha256:"+hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads(mpath.read_text())
report_names=(
 "binary-component-digests.sha256", "filesystem.packages",
 "initramfs-entry-listing.txt", "initramfs-container-type.txt",
 "initramfs-inspection.json", "initramfs-extracted-metadata.tsv",
 "rootfs-file-content.sha256", "rootfs-metadata.tsv",
 "rootfs-extraction-diagnostics.json",
 "iso-boot-metadata.txt", "iso-file-metadata.txt",
 "c5-manifest.json", "c5-result.json", "nexus-package-summary.json",
 "iso-squashfs-extract.log", "iso-unsquashfs.log"
)
package_lines=(out/"filesystem.packages").read_text().splitlines()
kernel_packages=[line.strip() for line in package_lines if line.split() and line.split()[0].startswith("linux-image-")]
if not kernel_packages:
    raise SystemExit("resolved versioned payload package list contains no Linux kernel package")
result={
 "schema":"azazel-payload/build-result@4",
 "build_input_manifest_digest":"sha256:"+mdigest,
 "builder":"live-build-evaluation-only",
 "builder_version":subprocess.check_output(["lb","--version"],text=True).strip(),
 "builder_environment":manifest["builder_environment"],
 "builder_tool_versions":manifest["builder"]["packages"],
 "source_date_epoch":manifest["normalization"]["source_date_epoch"],
 "input_manifest_start_sha256":"sha256:"+manifest_start,
 "input_manifest_end_sha256":"sha256:"+manifest_end,
 "frozen_inputs_start_sha256":"sha256:"+inputs_start,
 "frozen_inputs_end_sha256":"sha256:"+inputs_end,
 "builder_instance_id_sha256":"sha256:"+instance_id,
 "builder_kernel_release":kernel_release,
 "toolchain_lock_sha256":manifest["inputs"]["toolchain_lock"]["sha256"],
 "recipe_sha256":manifest["inputs"]["recipe"]["sha256"],
 "rootfs_normalizer_sha256":manifest["inputs"]["rootfs_normalizer"]["sha256"],
 "reproducibility_comparator_sha256":manifest["inputs"]["reproducibility_comparator"]["sha256"],
 "source_repositories":manifest["source"]["repositories"],
 "c5_inspector_sha256":manifest["inputs"]["c5_inspector"]["sha256"],
 "qemu_c5_runner_sha256":manifest["inputs"]["qemu_c5_runner"]["sha256"],
 "initramfs_inspector_sha256":manifest["inputs"]["initramfs_inspector"]["sha256"],
 "rootfs_extraction_inspector_sha256":manifest["inputs"]["rootfs_extraction_inspector"]["sha256"],
 "c5_evaluator_sha256":manifest["c5"]["evaluator_sha256"],
 "c5_policy_sha256":manifest["c5"]["policy_sha256"],
 "kernel_package_identity":kernel_packages,
 "architecture":"amd64",
 "kernel_digest":digest(out/"vmlinuz"),
 "initramfs_digest":digest(out/"initrd.img"),
 "squashfs_digest":digest(out/"work/binary/live/filesystem.squashfs"),
 "filesystem_packages_digest":digest(out/"filesystem.packages"),
 "payload_digest":digest(out/"payload.iso"),
 "component_digest_manifest":"binary-component-digests.sha256",
 "initramfs_entry_listing":"initramfs-entry-listing.txt",
 "initramfs_container_type":"initramfs-container-type.txt",
 "initramfs_inspection":"initramfs-inspection.json",
 "initramfs_extracted_metadata":"initramfs-extracted-metadata.tsv",
 "rootfs_file_content_manifest":"rootfs-file-content.sha256",
 "rootfs_metadata":"rootfs-metadata.tsv",
 "rootfs_extraction_diagnostics":"rootfs-extraction-diagnostics.json",
 "iso_boot_metadata":"iso-boot-metadata.txt",
 "iso_file_metadata":"iso-file-metadata.txt",
 "c5_manifest_digest":digest(out/"c5-manifest.json"),
 "c5_result_digest":digest(out/"c5-result.json"),
 "nexus_deb_packager_sha256":manifest["inputs"]["nexus_deb_packager"]["sha256"],
 "nexus_qemu_runner_sha256":manifest["inputs"]["nexus_qemu_runner"]["sha256"],
 "nexus_package_digest":digest(out/"azazel-nexus-prototype.deb"),
 "nexus_package_in_iso_rootfs_digest":digest(out/"rootfs-extracted/usr/share/azazel-nexus/azazel-nexus-prototype.deb"),
 "iso_embedded_squashfs_digest":digest(out/"iso-extracted/filesystem.squashfs"),
 "nexus_package_sha256_sidecar_digest":digest(out/"azazel-nexus-prototype.deb.sha256"),
 "nexus_package_summary_digest":digest(out/"nexus-package-summary.json"),
 "evidence_report_digests":{name:digest(out/name) for name in report_names},
 "release_disposition":"NON-RELEASABLE / EVALUATION ONLY",
 "hardware_verified":False,
 "builder_selected_for_production":False,
}
temporary=out/".build-result.json.tmp"
temporary.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
temporary.replace(out/"build-result.json")
PY
verify_inputs
FINAL_MANIFEST_HASH=$(sha256 "$MANIFEST")
FINAL_INPUTS_HASH=$(input_tree_digest)
if [[ "$START_MANIFEST_HASH" != "$FINAL_MANIFEST_HASH" || "$START_INPUTS_HASH" != "$FINAL_INPUTS_HASH" ]]; then
    echo "FAIL CLOSED: manifest or frozen inputs changed before evidence publication" >&2
    exit 42
fi
(cd "$OUTPUT_DIR" && \
    find . -maxdepth 1 -type f ! -name evidence-file-digests.sha256 -print0 \
        | LC_ALL=C sort -z | xargs -0 sha256sum \
        > evidence-file-digests.sha256)
trap - EXIT
printf 'payload build complete: %s\n' "$OUTPUT_DIR"
