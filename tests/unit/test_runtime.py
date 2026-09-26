from __future__ import annotations

import json

from azazel_boot import runtime


def test_runtime_composes_one_ephemeral_owner_after_matching_initramfs_handoff(
    tmp_path, monkeypatch
) -> None:
    boot_id = "12345678-1234-1234-1234-123456789abc"
    run = tmp_path / "run/azazel"
    run.mkdir(parents=True)
    (run / "host-storage-quarantined").write_text(
        "schema=azazel-c5-handoff-v1\n"
        f"session_id={boot_id}\n"
        "device_scope=currently-registered\n"
        "phase=initial_quarantine\n",
        encoding="utf-8",
    )
    sys_block = tmp_path / "sys/class/block"
    device = sys_block / "vda"
    (device / "device").mkdir(parents=True)
    (device / "dev").write_text("252:0\n", encoding="ascii")
    (device / "ro").write_text("1\n", encoding="ascii")
    (device / "device/serial").write_text("qemu-file-fixture\n", encoding="ascii")

    monkeypatch.setattr(runtime, "RUN", run)
    monkeypatch.setattr(runtime, "MARKER", run / "host-storage-quarantined")
    monkeypatch.setattr(runtime, "EVIDENCE", run / "boot-runtime.json")
    monkeypatch.setattr(runtime, "BOOT_ID_FILE", tmp_path / "boot-id")
    monkeypatch.setattr(runtime, "SYS_BLOCK", sys_block)
    runtime.BOOT_ID_FILE.write_text(boot_id, encoding="ascii")

    assert runtime.run(once=True) == 0
    evidence = json.loads(runtime.EVIDENCE.read_text(encoding="utf-8"))
    assert evidence["boot_id_matches_initramfs"] is True
    assert evidence["boot_session_created_once_in_runtime"] is True
    assert evidence["owner_lifetime_scope"] == "post-initramfs-userspace-process"
    assert evidence["initramfs_python_owner_survives_handoff"] is False
    assert evidence["boot_session_mode"] == "ephemeral"
    assert evidence["safe_persistence_path_available"] is False
    assert evidence["acquisition_enabled"] is False
    assert evidence["quarantine_instance_count"] == 1
    assert evidence["observed_device_count"] == 1
    assert evidence["policy_blocked_decision_counts"]["read"] == 1
    assert evidence["policy_blocked_decision_counts"]["writable_mount"] == 1


def test_runtime_refuses_a_missing_or_foreign_initramfs_handoff(tmp_path, monkeypatch) -> None:
    run = tmp_path / "run/azazel"
    run.mkdir(parents=True)
    marker = run / "host-storage-quarantined"
    marker.write_text(
        "schema=azazel-c5-handoff-v1\nsession_id=foreign\nphase=initial_quarantine\n",
        encoding="utf-8",
    )
    boot_id_file = tmp_path / "boot-id"
    boot_id_file.write_text("12345678-1234-1234-1234-123456789abc", encoding="ascii")
    monkeypatch.setattr(runtime, "RUN", run)
    monkeypatch.setattr(runtime, "MARKER", marker)
    monkeypatch.setattr(runtime, "EVIDENCE", run / "boot-runtime.json")
    monkeypatch.setattr(runtime, "BOOT_ID_FILE", boot_id_file)

    assert runtime.run(once=True) == 1
    assert not runtime.EVIDENCE.exists()


def test_runtime_requires_explicit_boot_bound_device_quarantine_handoff(tmp_path) -> None:
    boot_id = "12345678-1234-1234-1234-123456789abc"
    marker = tmp_path / "host-storage-quarantined"
    marker.write_text(
        "schema=azazel-c5-handoff-v1\n"
        f"session_id={boot_id}\n"
        "phase=device_quarantined\n"
        "device=/dev/vda\n",
        encoding="utf-8",
    )

    values = runtime._marker_values(marker, boot_id)

    assert values["phase"] == "device_quarantined"


def test_runtime_rejects_unsafe_device_only_handoff(tmp_path) -> None:
    boot_id = "12345678-1234-1234-1234-123456789abc"
    marker = tmp_path / "host-storage-quarantined"
    marker.write_text(
        "schema=azazel-c5-handoff-v1\n"
        f"session_id={boot_id}\n"
        "phase=device_quarantined\n"
        "device=/dev/../vda\n",
        encoding="utf-8",
    )

    try:
        runtime._marker_values(marker, boot_id)
    except ValueError as exc:
        assert "device" in str(exc)
    else:
        raise AssertionError("unsafe device-only handoff was accepted")


def test_runtime_handoff_requires_live_read_only_sysfs_state(tmp_path, monkeypatch) -> None:
    sys_block = tmp_path / "sys/class/block"
    device = sys_block / "vda"
    device.mkdir(parents=True)
    (device / "dev").write_text("252:0\n", encoding="ascii")
    (device / "ro").write_text("0\n", encoding="ascii")
    monkeypatch.setattr(runtime, "SYS_BLOCK", sys_block)

    assert runtime._handoff_device_is_read_only(
        {"phase": "device_quarantined", "device": "/dev/vda"}
    ) is False
    (device / "ro").write_text("1\n", encoding="ascii")
    assert runtime._handoff_device_is_read_only(
        {"phase": "device_quarantined", "device": "/dev/vda"}
    ) is True
