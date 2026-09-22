"""An evaluation build must stay something a release can never be mistaken for.

`ADR-0009` D8.1 permits these builds precisely because the alternative makes
`ADR-0002` D4 unreachable — the selection needs measurements that only a build
can produce. The permission is narrow, and every boundary of it is checked here:
the stamp, the field set that cannot carry a claim, and the output directory.

The output-directory rule is the one with a history. A synthetic measurement
once reached a draft branch in a sibling repository because an unrelated
`git add -A` swept up a file a tool had written into the checkout. No claim was
made from it, and it was still an integrity incident: a non-authoritative
artifact became reachable as if it were evidence. `enclosing_git_working_tree`
exists so that cannot happen here, and it refuses every working tree, not just
this one.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.builder.closure import Closure  # noqa: E402
from tools.builder.evaluation import (  # noqa: E402
    FORBIDDEN_RECORD_FIELDS,
    STAMP,
    BuiltPayload,
    EvaluationRefused,
    Refusal,
    dedicated_output_directory,
    enclosing_git_working_tree,
    run_evaluation_build,
)

HOST_A = "0123456789abcdef"
HOST_B = "fedcba9876543210"

CLOSURE = Closure(
    profile_id="responder-eval",
    quarantine_policy="quarantine.v1",
    inputs=(("debian-snapshot", "snapshot:20260101T000000Z"),),
)


class FakeBuilder:
    """A stand-in for a candidate builder. It makes bytes, not a Debian image."""

    name = "fake-builder"
    version = "0.0.0"

    def __init__(self, *, payload: bytes = b"payload", stamp: str | None = STAMP,
                 elsewhere: Path | None = None) -> None:
        self._payload = payload
        self._stamp = stamp
        self._elsewhere = elsewhere

    def build(self, closure: Closure, work_dir: Path) -> BuiltPayload:
        target = self._elsewhere if self._elsewhere is not None else work_dir / "payload.img"
        target.write_bytes(self._payload)
        metadata = work_dir / "metadata.json"
        document = {"profile_id": closure.profile_id}
        if self._stamp is not None:
            document["release_disposition"] = self._stamp
        metadata.write_text(json.dumps(document), encoding="utf-8")
        return BuiltPayload(payload_path=target, metadata_path=metadata)


def _run(tmp_path: Path, builder: FakeBuilder, **overrides):
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    arguments = {
        "git_revision": "0" * 40,
        "source_date_epoch": 1735689600,
        "build_host_id": HOST_A,
        "build_time": "2026-09-22T00:00:00Z",
        "output_directory": out,
    }
    arguments.update(overrides)
    return run_evaluation_build(CLOSURE, builder, **arguments)


def test_a_record_is_stamped_non_releasable(tmp_path: Path) -> None:
    record, _ = _run(tmp_path, FakeBuilder())
    assert record.release_disposition == STAMP
    assert record.record_type == "evaluation"


def test_the_record_cannot_carry_a_signature_or_a_compatibility_claim(tmp_path: Path) -> None:
    """A record with no field for a claim cannot be read as making one."""

    record, _ = _run(tmp_path, FakeBuilder())
    document = json.loads(record.to_json())
    for field in FORBIDDEN_RECORD_FIELDS:
        assert field not in document, (
            f"{field!r} appeared in an evaluation record; an evaluation build is "
            "never signed, never released and never claims compatibility"
        )


def test_the_record_carries_the_input_digest_and_the_measured_payload_digest(
    tmp_path: Path,
) -> None:
    record, payload = _run(tmp_path, FakeBuilder())
    assert record.build_input_digest == CLOSURE.digest()
    assert record.unsigned_payload_digest.startswith("sha256:")
    assert record.payload_bytes == payload.stat().st_size


def test_an_unstamped_payload_produces_no_record_at_all(tmp_path: Path) -> None:
    with pytest.raises(EvaluationRefused) as refused:
        _run(tmp_path, FakeBuilder(stamp=None))
    assert refused.value.refusal is Refusal.STAMP_MISSING


def test_a_payload_stamped_as_something_else_is_refused(tmp_path: Path) -> None:
    with pytest.raises(EvaluationRefused) as refused:
        _run(tmp_path, FakeBuilder(stamp="RELEASE"))
    assert refused.value.refusal is Refusal.STAMP_MISSING


@pytest.mark.parametrize("marker", ["directory", "file"])
def test_output_inside_a_git_working_tree_is_refused(tmp_path: Path, marker: str) -> None:
    """A worktree's `.git` is a file and a clone's is a directory; both count."""

    tree = tmp_path / "checkout"
    (tree / "build").mkdir(parents=True)
    if marker == "directory":
        (tree / ".git").mkdir()
    else:
        (tree / ".git").write_text("gitdir: /elsewhere\n", encoding="utf-8")

    with pytest.raises(EvaluationRefused) as refused:
        _run(tmp_path, FakeBuilder(), output_directory=tree / "build")
    assert refused.value.refusal is Refusal.OUTPUT_INSIDE_A_GIT_WORKING_TREE


def test_output_in_a_subdirectory_of_a_working_tree_is_refused(tmp_path: Path) -> None:
    """The guard walks ancestors, so burying the output deeper does not help."""

    tree = tmp_path / "checkout"
    (tree / ".git").mkdir(parents=True)
    deep = tree / "a" / "b" / "c"
    deep.mkdir(parents=True)
    with pytest.raises(EvaluationRefused) as refused:
        _run(tmp_path, FakeBuilder(), output_directory=deep)
    assert refused.value.refusal is Refusal.OUTPUT_INSIDE_A_GIT_WORKING_TREE


def test_this_repository_is_itself_refused_as_an_output_directory() -> None:
    assert enclosing_git_working_tree(ROOT) is not None


def test_the_default_output_directory_is_outside_every_working_tree() -> None:
    out = dedicated_output_directory()
    try:
        assert enclosing_git_working_tree(out) is None
        assert not any(out.iterdir())
    finally:
        out.rmdir()


def test_a_non_empty_output_directory_is_refused(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "leftover").write_text("x", encoding="utf-8")
    with pytest.raises(EvaluationRefused) as refused:
        _run(tmp_path, FakeBuilder(), output_directory=out)
    assert refused.value.refusal is Refusal.OUTPUT_NOT_EMPTY


def test_a_payload_written_outside_the_output_directory_is_refused(tmp_path: Path) -> None:
    escape = tmp_path / "escape.img"
    with pytest.raises(EvaluationRefused) as refused:
        _run(tmp_path, FakeBuilder(elsewhere=escape))
    assert refused.value.refusal is Refusal.PAYLOAD_OUTSIDE_OUTPUT


@pytest.mark.parametrize(
    "host_id",
    ["builder-01", "builder.example.org", "0123456789ABCDEF", "0123", "", "S1234567"],
)
def test_a_build_host_is_identified_anonymously_or_not_at_all(
    tmp_path: Path, host_id: str
) -> None:
    """A hostname, an FQDN or a serial in a record is an identifier leak."""

    with pytest.raises(EvaluationRefused) as refused:
        _run(tmp_path, FakeBuilder(), build_host_id=host_id)
    assert refused.value.refusal is Refusal.HOST_ID_NOT_ANONYMOUS


@pytest.mark.parametrize("epoch", [-1, "1735689600", 1.5, True])
def test_an_invalid_source_date_epoch_is_refused(tmp_path: Path, epoch) -> None:
    with pytest.raises(EvaluationRefused) as refused:
        _run(tmp_path, FakeBuilder(), source_date_epoch=epoch)
    assert refused.value.refusal is Refusal.SOURCE_DATE_EPOCH_INVALID


def test_the_measured_digest_does_not_depend_on_the_clock_or_the_host(tmp_path: Path) -> None:
    """Two hosts building the same closure at different moments must still agree."""

    first, _ = _run(tmp_path / "a", FakeBuilder(), build_host_id=HOST_A,
                    build_time="2026-01-01T00:00:00Z")
    second, _ = _run(tmp_path / "b", FakeBuilder(), build_host_id=HOST_B,
                     build_time="2026-09-22T12:34:56Z")
    assert first.unsigned_payload_digest == second.unsigned_payload_digest
    assert first.build_input_digest == second.build_input_digest
