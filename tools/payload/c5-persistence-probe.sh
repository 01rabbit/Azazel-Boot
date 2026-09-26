#!/bin/sh
set -u

marker=/run/azazel/host-storage-quarantined
evidence=/run/azazel/c5-persistence-evidence.json
trace=/run/azazel/c5-persistence.strace
target_trace=/run/azazel/c5-persistence-target.strace
kernel_log=/run/azazel/c5-persistence-kernel.log
device=/dev/vda
sys_device=/sys/class/block/vda
sysfs=$sys_device/ro
result=/run/azazel/c5-persistence-probe.exit

discovered=NOT_OBSERVED
mount_observation=NOT_OBSERVED
mount_guard=NOT_OBSERVED
marker_present=NOT_OBSERVED
marker_valid=NOT_OBSERVED
session_binding_valid=NOT_OBSERVED
handoff_valid=NOT_OBSERVED
sysfs_ro_before=NOT_OBSERVED
blockdev_ro_before=NOT_OBSERVED
sysfs_ro_after=NOT_OBSERVED
blockdev_ro_after=NOT_OBSERVED
boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf NOT_OBSERVED)
marker_session_id=NOT_OBSERVED
mount_state=NOT_OBSERVED
mount_point=NOT_OBSERVED
mount_type=NOT_OBSERVED
mount_flags=NOT_OBSERVED
mount_mode=NOT_OBSERVED
mount_source=NOT_OBSERVED
mount_state_after=NOT_OBSERVED
probe=NOT_OBSERVED
probe_exit=NOT_OBSERVED
probe_observation=NOT_OBSERVED
write_syscall_count=0
target_syscall_count=0
fixture_cmdline=FAIL
udev_devpath=NOT_OBSERVED
udev_action=NOT_OBSERVED
probe_uptime=NOT_OBSERVED

json_quote() {
  json_quoted_value=$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g')
  printf '"%s"' "$json_quoted_value"
}

json_lines() {
  json_first=1
  printf '['
  while IFS= read -r json_line || [ -n "$json_line" ]; do
    [ "$json_first" = 1 ] || printf ','
    json_quote "$json_line"
    json_first=0
  done < "$1"
  printf ']'
}

emit_phase() {
  phase_name=$1
  phase_status=$2
  phase_fields=$3
  phase_uptime=$(cut -d' ' -f1 /proc/uptime 2>/dev/null || printf NOT_OBSERVED)
  printf 'AZAZEL_C5_PHASE phase=%s status=%s stage=userspace target=%s path=%s %s guest_uptime_seconds=%s boot_id=%s\n' \
    "$phase_name" "$phase_status" "$device" "$device" \
    "$phase_fields" "$phase_uptime" "$boot_id" >/dev/console 2>/dev/null || true
}

read_mount_evidence() {
  mount_device=$1
  tab=$(printf '\t')
  mount_devno=$(cat "$sys_device/dev" 2>/dev/null || true)
  mount_match=$(awk -v wanted="$mount_devno" '
    $3 == wanted {
      separator = 0
      for (i = 7; i <= NF; i++) if ($i == "-") { separator = i; break }
      if (separator > 0) {
        printf "%s\t%s\t%s\t%s\n", $5, $6, $(separator + 1), $(separator + 2)
        found = 1
        exit
      }
    }
    END { if (!found) exit 1 }
  ' /proc/self/mountinfo 2>/dev/null) || mount_match=
  if [ -n "$mount_match" ]; then
    mount_state=mounted
    mount_point=${mount_match%%"$tab"*}
    mount_rest=${mount_match#*"$tab"}
    mount_flags=${mount_rest%%"$tab"*}
    mount_rest=${mount_rest#*"$tab"}
    mount_type=${mount_rest%%"$tab"*}
    mount_source=${mount_rest#*"$tab"}
    case ",$mount_flags," in
      *,ro,*) mount_mode=read_only ;;
      *,rw,*) mount_mode=read_write ;;
      *) mount_mode=unknown ;;
    esac
  else
    mount_state=not_mounted
    mount_point=N/A
    mount_type=N/A
    mount_flags=N/A
    mount_source=N/A
    mount_mode=NOT_APPLICABLE
  fi
}

mkdir -p /run/azazel || exit 1
rm -f "$evidence" "$trace" "$target_trace" "$kernel_log" "$result"
: > "$trace"
: > "$target_trace"
: > "$kernel_log"

if grep -Eq '(^| )azazel\.c5_fixture=QEMU-regular-file( |$)' /proc/cmdline 2>/dev/null; then
  fixture_cmdline=PASS
fi

if [ -b "$device" ] && [ -r "$sys_device/dev" ] && [ -r "$sysfs" ]; then
  discovered=PASS
else
  discovered=FAIL
fi
emit_phase discovered "$discovered" "udev_devpath=$udev_devpath udev_action=$udev_action"

if [ "$discovered" = PASS ]; then
  read_mount_evidence "$device"
  if [ "$mount_state" = mounted ] || [ "$mount_state" = not_mounted ]; then
    mount_observation=PASS
    if [ "$mount_state" = not_mounted ]; then mount_guard=PASS; else mount_guard=FAIL; fi
  else
    mount_observation=NOT_OBSERVED
    mount_guard=NOT_OBSERVED
  fi
fi
mount_state_before=$mount_state
mount_point_before=$mount_point
mount_type_before=$mount_type
mount_flags_before=$mount_flags
mount_source_before=$mount_source
emit_phase mount_observation "$mount_observation" \
  "mount_state=$mount_state_before mount_point=$mount_point_before mount_type=$mount_type_before mount_mode=$mount_mode mount_flags=$mount_flags_before mount_source=$mount_source_before"
emit_phase mount_guard "$mount_guard" "mount_state=$mount_state_before mount_mode=$mount_mode required_state=not_mounted"

if [ -e "$marker" ]; then marker_present=PASS; else marker_present=FAIL; fi
if [ "$marker_present" = PASS ]; then
  marker_contents=$(sed -n '1,8p' "$marker" 2>/dev/null | tr '\n' '|')
  schema_count=$(grep -c '^schema=' "$marker" 2>/dev/null || true)
  session_count=$(grep -c '^session_id=' "$marker" 2>/dev/null || true)
  phase_count=$(grep -c '^phase=' "$marker" 2>/dev/null || true)
  device_count=$(grep -c '^device=' "$marker" 2>/dev/null || true)
  schema=$(sed -n 's/^schema=//p' "$marker" | head -n 1)
  marker_session_id=$(sed -n 's/^session_id=//p' "$marker" | head -n 1)
  marker_phase=$(sed -n 's/^phase=//p' "$marker" | head -n 1)
  marker_device=$(sed -n 's/^device=//p' "$marker" | head -n 1)
  if ! printf '%s\n' "$marker_session_id" | grep -Eq '^[[:xdigit:]-]{36}$'; then
    marker_session_id=invalid
  fi
  if [ "$schema_count" = 1 ] && [ "$session_count" = 1 ] && \
     [ "$phase_count" = 1 ] && [ "$device_count" = 1 ] && \
     [ "$(wc -l < "$marker" | tr -d ' ')" = 4 ] && \
     [ "$schema" = azazel-c5-handoff-v1 ] && \
     [ "$marker_phase" = device_quarantined ] && [ "$marker_device" = "$device" ] && \
     [ "$marker_session_id" != invalid ]; then
    marker_valid=PASS
  else
    marker_valid=FAIL
  fi
  if [ "$marker_valid" = PASS ] && [ "$boot_id" != NOT_OBSERVED ]; then
    if [ "$marker_session_id" = "$boot_id" ]; then session_binding_valid=PASS; else session_binding_valid=FAIL; fi
  elif [ "$marker_valid" = PASS ]; then
    session_binding_valid=NOT_OBSERVED
  else
    session_binding_valid=FAIL
  fi
else
  marker_contents=NOT_OBSERVED
fi
emit_phase marker_present "$marker_present" "marker_path=$marker marker_contents=${marker_contents:-NOT_OBSERVED}"
emit_phase marker_valid "$marker_valid" "schema=azazel-c5-handoff-v1 marker_session_id=$marker_session_id"
emit_phase session_binding_valid "$session_binding_valid" "boot_id=$boot_id marker_session_id=$marker_session_id"

if [ "$discovered" = PASS ]; then
  sysfs_ro_before=$(cat "$sysfs" 2>/dev/null || printf NOT_OBSERVED)
  if [ -x /usr/sbin/blockdev ]; then
    blockdev_ro_before=$(/usr/sbin/blockdev --getro "$device" 2>/dev/null || printf NOT_OBSERVED)
  fi
fi

# Recheck every write guard immediately before probing. The fixture marker is
# explicit; no device write is attempted unless unmounted and both RO views are 1.
if [ "$discovered" = PASS ] && [ "$fixture_cmdline" = PASS ] && \
   [ -x /usr/bin/strace ] && [ "$sysfs_ro_before" = 1 ] && [ "$blockdev_ro_before" = 1 ]; then
  read_mount_evidence "$device"
  if [ "$mount_state" = not_mounted ]; then
    sysfs_ro_before=$(cat "$sysfs" 2>/dev/null || printf NOT_OBSERVED)
    blockdev_ro_before=$(/usr/sbin/blockdev --getro "$device" 2>/dev/null || printf NOT_OBSERVED)
    if [ "$sysfs_ro_before" = 1 ] && [ "$blockdev_ro_before" = 1 ]; then
      probe_uptime=$(cut -d' ' -f1 /proc/uptime 2>/dev/null || printf NOT_OBSERVED)
      dmesg > /run/azazel/c5-kernel-before.log 2>/dev/null || :
      if /usr/bin/strace -qq -yy -e trace=openat,open,dup2,dup3,close,write,pwrite64,writev,pwritev \
          -o "$trace" /bin/sh -c 'exec 3>"$1" && printf "\\000" >&3' \
          azazel-c5-write-probe "$device"; then
        probe_exit=0
      else
        probe_exit=$?
      fi
      awk -v target="$device" '
        /^(open|openat)\(/ && index($0, "\"" target "\"") { print; next }
        /^(write|pwrite64|writev|pwritev)\(/ && \
          (index($0, "<" target ">") || index($0, "<" target "<block ")) { print }
      ' "$trace" > "$target_trace"
      : > "$result"
      while IFS= read -r syscall_line || [ -n "$syscall_line" ]; do
        syscall_name=${syscall_line%%(*}
        syscall_tail=${syscall_line##* = }
        syscall_result=${syscall_tail%% *}
        syscall_errno=NOT_OBSERVED
        if [ "$syscall_result" = -1 ]; then
          syscall_errno=$(printf '%s\n' "$syscall_tail" | awk '{print $2}')
          [ -n "$syscall_errno" ] || syscall_errno=NOT_OBSERVED
        fi
        case "$syscall_name" in open|openat|write|pwrite64|writev|pwritev)
          target_syscall_count=$((target_syscall_count + 1))
          case "$syscall_name" in write|pwrite64|writev|pwritev) write_syscall_count=$((write_syscall_count + 1));; esac
          if [ "$syscall_name" != open ] && [ "$syscall_name" != openat ] && \
             [ "$syscall_result" != -1 ] && [ "$syscall_result" != "?" ]; then
            probe=FAIL
            probe_observation=target_write_returned
          elif [ "$syscall_result" = -1 ] && [ "$syscall_errno" != NOT_OBSERVED ] && \
               [ "$probe" != FAIL ]; then
            syscall_errno_name=$(printf '%s\n' "$syscall_tail" | awk '{print $2}')
            case "$syscall_name:$syscall_errno_name" in
              open:EROFS|openat:EROFS)
                probe=PASS; probe_observation=target_open_denied_by_read_only_policy ;;
              write:EROFS|write:EPERM|pwrite64:EROFS|pwrite64:EPERM|writev:EROFS|writev:EPERM|pwritev:EROFS|pwritev:EPERM)
                probe=PASS; probe_observation=target_write_denied_by_read_only_policy ;;
              open:*|openat:*) probe=FAIL; probe_observation=target_open_failed_causality_unproven ;;
              *) probe=FAIL; probe_observation=target_write_failed_causality_unproven ;;
            esac
          fi
        esac
        printf '%s\t%s\t%s\t%s\n' "$syscall_name" "$syscall_result" "$syscall_errno" "$syscall_line" >> "$result"
        printf 'AZAZEL_C5_WRITE_SYSCALL stage=userspace target=%s %s\n' \
          "$device" "$syscall_line" >/dev/console 2>/dev/null || true
      done < "$target_trace"
      if [ "$target_syscall_count" -eq 0 ]; then
        probe=NOT_OBSERVED
        probe_observation=no_target_annotated_syscall
      fi
      dmesg > /run/azazel/c5-kernel-after.log 2>/dev/null || :
      { grep -E 'vda|virtio|read.only|readonly|I/O error|block' /run/azazel/c5-kernel-before.log 2>/dev/null || :
        grep -E 'vda|virtio|read.only|readonly|I/O error|block' /run/azazel/c5-kernel-after.log 2>/dev/null || :; } | tail -n 40 > "$kernel_log"
      while IFS= read -r kernel_line || [ -n "$kernel_line" ]; do
        printf 'AZAZEL_C5_KERNEL_LOG stage=userspace target=%s guest_uptime_seconds=%s line=%s\n' \
          "$device" "$(cut -d' ' -f1 /proc/uptime 2>/dev/null || printf NOT_OBSERVED)" \
          "$kernel_line" >/dev/console 2>/dev/null || true
      done < "$kernel_log"
    else
      probe_observation=pre_probe_ro_recheck_failed
    fi
  else
    mount_guard=FAIL
    probe_observation=target_mounted_before_probe
  fi
fi

if [ "$discovered" = PASS ]; then
  sysfs_ro_after=$(cat "$sysfs" 2>/dev/null || printf NOT_OBSERVED)
  blockdev_ro_after=$(/usr/sbin/blockdev --getro "$device" 2>/dev/null || printf NOT_OBSERVED)
  read_mount_evidence "$device"
mount_state_after=$mount_state
mount_mode_after=$mount_mode
  if [ "$mount_state" = not_mounted ]; then mounted_after=PASS; else mounted_after=FAIL; fi
else
  mounted_after=NOT_OBSERVED
fi
emit_phase write_probe "$probe" \
  "observation=$probe_observation syscall_count=$write_syscall_count target_syscall_count=$target_syscall_count probe_exit=$probe_exit probe_uptime_seconds=$probe_uptime sysfs_ro_before=$sysfs_ro_before blockdev_ro_before=$blockdev_ro_before sysfs_ro_after=$sysfs_ro_after blockdev_ro_after=$blockdev_ro_after mount_state_after=$mount_state_after udev_devpath=$udev_devpath udev_action=$udev_action"
emit_phase post_write "$probe" \
  "sysfs_ro_before=$sysfs_ro_before blockdev_ro_before=$blockdev_ro_before sysfs_ro_after=$sysfs_ro_after blockdev_ro_after=$blockdev_ro_after mount_state_after=$mount_state_after observation=$probe_observation"

if [ "$discovered" = FAIL ] || [ "$mount_guard" = FAIL ] || [ "$mounted_after" = FAIL ] || \
   [ "$marker_present" = FAIL ] || [ "$marker_valid" = FAIL ] || \
   [ "$session_binding_valid" = FAIL ] || [ "$fixture_cmdline" = FAIL ] || \
   [ "$probe" = FAIL ] || [ "$sysfs_ro_after" = 0 ] || [ "$blockdev_ro_after" = 0 ]; then
  handoff_valid=FAIL
elif [ "$discovered" = NOT_OBSERVED ] || [ "$mount_observation" = NOT_OBSERVED ] || \
     [ "$mount_guard" = NOT_OBSERVED ] || \
     [ "$marker_present" = NOT_OBSERVED ] || [ "$marker_valid" = NOT_OBSERVED ] || \
     [ "$session_binding_valid" = NOT_OBSERVED ] || [ "$fixture_cmdline" = NOT_OBSERVED ] || \
     [ "$probe" = NOT_OBSERVED ] || [ "$sysfs_ro_after" = NOT_OBSERVED ] || \
     [ "$blockdev_ro_after" = NOT_OBSERVED ]; then
  handoff_valid=NOT_OBSERVED
else
  handoff_valid=PASS
fi

syscall_records=[]
if [ -s "$result" ]; then
  syscall_records=$(while IFS="$(printf '\t')" read -r rec_name rec_result rec_errno rec_raw; do
    [ -n "$rec_name" ] || continue
    printf '{"syscall":%s,"result":%s,"errno":%s,"raw":%s},' \
      "$(json_quote "$rec_name")" "$(json_quote "$rec_result")" \
      "$(json_quote "$rec_errno")" "$(json_quote "$rec_raw")"
  done < "$result" | sed 's/,$//')
  syscall_records=[$syscall_records]
fi
kernel_json=$(json_lines "$kernel_log")
marker_json=$(json_quote "${marker_contents:-NOT_OBSERVED}")
mount_point_json=$(json_quote "$mount_point_before")
mount_type_json=$(json_quote "$mount_type_before")
mount_flags_json=$(json_quote "$mount_flags_before")
mount_source_json=$(json_quote "$mount_source_before")
boot_runtime_status=FAIL
boot_runtime_json=null
if [ -s /run/azazel/boot-runtime.json ]; then
  if boot_runtime_json=$(python3 - /run/azazel/boot-runtime.json "$boot_id" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text())
required = {
    "schema": "azazel-boot/runtime-evidence@1",
    "boot_id_matches_initramfs": True,
    "boot_session_created_once_in_runtime": True,
    "owner_lifetime_scope": "post-initramfs-userspace-process",
    "initramfs_python_owner_survives_handoff": False,
    "boot_session_mode": "ephemeral",
    "safe_persistence_path_available": False,
    "acquisition_enabled": False,
    "quarantine_instance_count": 1,
}
if any(value.get(key) != expected for key, expected in required.items()):
    raise SystemExit(1)
if value.get("observed_device_count", 0) < 1:
    raise SystemExit(1)
for action in ("read", "writable_mount", "fsck", "journal_replay", "export_write"):
    if value.get("policy_blocked_decision_counts", {}).get(action, 0) < 1:
        raise SystemExit(1)
print(json.dumps(value, sort_keys=True, separators=(",", ":")))
PY
  ); then
    boot_runtime_status=PASS
  fi
fi
cat > "$evidence" <<EOF
{
  "schema":"azazel-c5-persistence-evidence-v2",
  "scope":"QEMU-regular-file-fixture",
  "target":{"device":"/dev/vda","path":"/dev/vda","fixture_cmdline":"$fixture_cmdline"},
  "boot_session":{"boot_id":"$boot_id","marker_session_id":"$marker_session_id"},
  "mount":{"observation_status":"$mount_observation","guard_status":"$mount_guard","state":"$mount_state_before","point":$mount_point_json,"type":$mount_type_json,"mode":"$mount_mode","flags":$mount_flags_json,"source":$mount_source_json,"state_after":"$mount_state_after","mode_after":"$mount_mode_after","after_status":"$mounted_after"},
  "ro_state":{"sysfs_before":"$sysfs_ro_before","blockdev_before":"$blockdev_ro_before","sysfs_after":"$sysfs_ro_after","blockdev_after":"$blockdev_ro_after"},
  "phases":{
    "discovered":{"status":"$discovered","target":"/dev/vda","path":"/dev/vda","udev_devpath":"$udev_devpath","udev_action":"$udev_action"},
    "mount_observation":{"status":"$mount_observation","mount_state":"$mount_state_before","filesystem_type":$mount_type_json,"mount_mode":"$mount_mode","mount_flags":$mount_flags_json},
    "mount_guard":{"status":"$mount_guard","mount_state":"$mount_state_before","required_state":"not_mounted"},
    "marker_present":{"status":"$marker_present","path":"$marker","contents":$marker_json},
    "marker_valid":{"status":"$marker_valid","schema":"azazel-c5-handoff-v1"},
    "session_binding_valid":{"status":"$session_binding_valid","boot_id":"$boot_id","marker_session_id":"$marker_session_id"},
    "write_probe":{"status":"$probe","observation":"$probe_observation","write_syscall_count":$write_syscall_count,"target_syscall_count":$target_syscall_count,"actual_syscalls":$syscall_records,"trace_path":"$trace","probe_uptime_seconds":"$probe_uptime"},
    "handoff_valid":{"status":"$handoff_valid","sysfs_ro_before":"$sysfs_ro_before","blockdev_ro_before":"$blockdev_ro_before","sysfs_ro_after":"$sysfs_ro_after","blockdev_ro_after":"$blockdev_ro_after"}
  },
  "write_probe":{"status":"$probe","exit_status":"$probe_exit","observation":"$probe_observation","actual_syscalls":$syscall_records,"raw_trace_path":"$trace","target_trace_path":"$target_trace","no_errno_value_assumed":true},
  "boot_runtime":{"status":"$boot_runtime_status","evidence":$boot_runtime_json},
  "kernel_log":{"range":"relevant lines before/after probe, bounded to final 40 matches","lines":$kernel_json}
}
EOF

cat "$evidence" >/dev/console 2>/dev/null || true
printf 'AZAZEL_BOOT_RUNTIME_EVIDENCE status=%s evidence=%s\n' \
  "$boot_runtime_status" "$boot_runtime_json" >/dev/console 2>/dev/null || true
emit_phase handoff_valid "$handoff_valid" \
  "sysfs_ro_after=$sysfs_ro_after blockdev_ro_after=$blockdev_ro_after probe=$probe mount_state_after=$mount_state_after mounted_after=$mounted_after"
if [ "$discovered" = PASS ] && [ "$mount_observation" = PASS ] && [ "$mount_guard" = PASS ] && [ "$mounted_after" = PASS ] && \
   [ "$marker_present" = PASS ] && [ "$marker_valid" = PASS ] && \
   [ "$session_binding_valid" = PASS ] && [ "$handoff_valid" = PASS ]; then
  exit 0
fi
exit 1
