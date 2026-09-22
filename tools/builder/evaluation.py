"""Run a candidate builder to measure it, and record the result as evidence.

`ADR-0009` D8.1 draws the line this module sits on. A build that produces a
product artifact without a selection ADR is refused by `ADR-0002` D4. A build
performed as **evaluation evidence** is what that selection requires, and the
difference has to be structural rather than a matter of intent, because intent
is not visible three months later in a directory of files.

So an evaluation build is separated from a release by what it *cannot express*:

- the record produced here has no signature field, no signed-artifact field and
  no compatibility-claim field. A record that cannot carry a claim cannot be
  read as making one;
- the stamp `NON-RELEASABLE / EVALUATION ONLY` is in the record and is required
  to be in the payload's own metadata. A build whose payload does not carry it
  produces no record at all;
- the output never lands in a Git working tree. That is not tidiness: a
  synthetic artifact committed by an unrelated `git add -A` is exactly how a
  non-authoritative measurement reaches a branch and is later cited as one.

Nothing here selects a builder. A reproduced digest pair satisfies the
measurement C1 asks for; C2-C9, the Fabric gate and the supply-chain record are
untouched by it (`reproduction.py` says so in the verdict it returns).

**No evaluation build has been run.** This module has never been given a real
builder adapter.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol

from .closure import Closure

#: Stamped into the evaluation record and required in the payload's metadata.
STAMP = "NON-RELEASABLE / EVALUATION ONLY"

#: An anonymous host ID: opaque, fixed width, and unable to carry a hostname, an
#: FQDN, a serial or an asset tag. Independence of two builders is asserted by
#: comparing these, so they must be stable per host and meaningless off it.
ANONYMOUS_HOST_ID = re.compile(r"^[0-9a-f]{16}$")

RECORD_VERSION = 1

#: Field names an evaluation record must never grow. Listed so that adding one
#: is a deliberate act that fails a test, rather than a convenience.
FORBIDDEN_RECORD_FIELDS = (
    "signature",
    "signed_artifact_digest",
    "compatibility_claim",
    "published_at",
    "release_channel",
)


class Refusal(Enum):
    OUTPUT_INSIDE_A_GIT_WORKING_TREE = "output_inside_a_git_working_tree"
    OUTPUT_NOT_EMPTY = "output_not_empty"
    OUTPUT_MISSING = "output_missing"
    PAYLOAD_OUTSIDE_OUTPUT = "payload_outside_output"
    PAYLOAD_MISSING = "payload_missing"
    METADATA_UNREADABLE = "metadata_unreadable"
    STAMP_MISSING = "stamp_missing"
    HOST_ID_NOT_ANONYMOUS = "host_id_not_anonymous"
    SOURCE_DATE_EPOCH_INVALID = "source_date_epoch_invalid"


class EvaluationRefused(Exception):
    """The build did not produce a record, and no partial record exists."""

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


@dataclass(frozen=True)
class BuiltPayload:
    """What an adapter returns: the payload, and the metadata carried inside it."""

    payload_path: Path
    metadata_path: Path


class BuilderAdapter(Protocol):
    """A candidate builder, wrapped thinly enough to be swapped for another."""

    name: str
    version: str

    def build(self, closure: Closure, work_dir: Path) -> BuiltPayload: ...


@dataclass(frozen=True)
class EvaluationRecord:
    """Evidence about one build. Not a release record, and not convertible into one."""

    record_type: str
    record_version: int
    release_disposition: str
    profile_id: str
    quarantine_policy: str
    git_revision: str
    builder_name: str
    builder_version: str
    build_input_digest: str
    source_date_epoch: int
    unsigned_payload_digest: str
    payload_bytes: int
    build_host_id: str
    build_time: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def enclosing_git_working_tree(path: Path) -> Path | None:
    """Return the first ancestor (or `path`) holding a `.git`, or None.

    `.git` is read as a name, never executed: a worktree's `.git` is a file and
    a clone's is a directory, and both mean the same thing here.
    """

    for candidate in (path, *path.parents):
        marker = candidate / ".git"
        if marker.is_dir() or marker.is_file():
            return candidate
    return None


def dedicated_output_directory() -> Path:
    """A fresh directory outside any checkout, which is where output belongs."""

    return Path(tempfile.mkdtemp(prefix="az-boot-eval-"))


def run_evaluation_build(
    closure: Closure,
    adapter: BuilderAdapter,
    *,
    git_revision: str,
    source_date_epoch: int,
    build_host_id: str,
    build_time: str,
    output_directory: Path | None = None,
) -> tuple[EvaluationRecord, Path]:
    """Build once, verify the stamp, and return the record and where the payload is.

    `build_time` is recorded and is deliberately **not** an input to any digest:
    two hosts building the same closure at different moments must still agree.
    """

    if not ANONYMOUS_HOST_ID.match(build_host_id):
        raise EvaluationRefused(
            Refusal.HOST_ID_NOT_ANONYMOUS,
            "a build host is identified by an opaque ID, never by a hostname, "
            "serial or asset tag",
        )
    if not isinstance(source_date_epoch, int) or isinstance(source_date_epoch, bool):
        raise EvaluationRefused(Refusal.SOURCE_DATE_EPOCH_INVALID, repr(source_date_epoch))
    if source_date_epoch < 0:
        raise EvaluationRefused(Refusal.SOURCE_DATE_EPOCH_INVALID, str(source_date_epoch))

    out = output_directory if output_directory is not None else dedicated_output_directory()
    if not out.is_dir():
        raise EvaluationRefused(Refusal.OUTPUT_MISSING, str(out))
    tree = enclosing_git_working_tree(out.resolve())
    if tree is not None:
        raise EvaluationRefused(
            Refusal.OUTPUT_INSIDE_A_GIT_WORKING_TREE,
            f"{out} is inside the working tree at {tree}; an evaluation artifact "
            "must not be reachable by a commit",
        )
    if any(out.iterdir()):
        raise EvaluationRefused(Refusal.OUTPUT_NOT_EMPTY, str(out))

    work_dir = out / "work"
    work_dir.mkdir()
    built = adapter.build(closure, work_dir)

    payload = built.payload_path.resolve()
    if out.resolve() not in payload.parents:
        raise EvaluationRefused(Refusal.PAYLOAD_OUTSIDE_OUTPUT, str(payload))
    if not payload.is_file():
        raise EvaluationRefused(Refusal.PAYLOAD_MISSING, str(payload))

    _require_stamp(built.metadata_path)

    digest, size = _digest_file(payload)
    record = EvaluationRecord(
        record_type="evaluation",
        record_version=RECORD_VERSION,
        release_disposition=STAMP,
        profile_id=closure.profile_id,
        quarantine_policy=closure.quarantine_policy,
        git_revision=git_revision,
        builder_name=adapter.name,
        builder_version=adapter.version,
        build_input_digest=closure.digest(),
        source_date_epoch=source_date_epoch,
        unsigned_payload_digest=digest,
        payload_bytes=size,
        build_host_id=build_host_id,
        build_time=build_time,
    )
    return record, payload


def _require_stamp(metadata_path: Path) -> None:
    """The payload must say what it is, in its own metadata, or there is no record."""

    try:
        document = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvaluationRefused(
            Refusal.METADATA_UNREADABLE, f"{metadata_path}: {error}"
        ) from None
    if not isinstance(document, dict) or document.get("release_disposition") != STAMP:
        raise EvaluationRefused(
            Refusal.STAMP_MISSING,
            f"{metadata_path} does not carry {STAMP!r}; an unstamped payload is "
            "indistinguishable from a release artifact once it leaves this directory",
        )


def _digest_file(path: Path) -> tuple[str, int]:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 16), b""):
            hasher.update(block)
            size += len(block)
    return "sha256:" + hasher.hexdigest(), size
