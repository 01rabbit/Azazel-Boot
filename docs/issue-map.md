# Issue map and evidence policy

This map records the live inventory checked on 2026-09-26 (**24 open issues**),
with the measured prototype update below. It is not a closure record: reconcile
the live issue, review, merged commit, and default-branch CI before closing or
relabelling any row.

## Prototype measurement summary

The retained [R11 evidence](prototype-evidence-boot-runtime-r11.md) records an
unsigned prototype and bounded QEMU fixture results. Its ISO and bulky build
outputs were removed from the local workspace; recorded hashes and machine
results are historical evidence, not a currently available artifact. No
prototype result closes hardware-only or production-builder gates.

| Issue | Local classification | What exists | What still prevents closure |
| --- | --- | --- | --- |
| #1 | complete (bootstrap scope; close candidate) | The issue's latest comment says all bootstrap acceptance criteria were met after PR #3; governance, package scaffold, CI, and follow-up links are present. This is not product/HIL completion. | Its checkboxes remain unchecked and current Docs jobs have runner-allocation failures; reconcile the issue record and current CI evidence before any closure. |
| #4 | design decision required | ADR-0002/0009 and a refusal-first evaluation harness define the criteria; `build` does not select a tool. R11 is an unsigned QEMU-tested prototype; no production builder was selected. | Remaining C1–C9 evaluation, two independent builder hosts/digest pair, and Linux/macOS record parity; do not select a production builder from this prototype. |
| #6 | active implementation | R11 static hook ordering/content inspection and bounded regular-file QEMU probes are recorded; the initial scan observed zero devices, so pre-registration quarantine remains unobserved. | Actual persistence-media discovery/mount and session lifecycle, per-target approval, comprehensive zero-host-write observation through shutdown, and laptop HIL. |
| #7 | active implementation | Persistence, session-mode, dirty-write, and recovery decision logic; child issues #40–42 carry the narrower software boundaries. | Real USB/LUKS/key acquisition and recovery/HIL; #47 is also an unresolved software budget boundary. |
| #8 | blocked by external hardware | The selector logic follows the program's revised tier table. | Core reserve measurement on removable media and application of the measured reserve require an x86_64 laptop and USB SSD. |
| #9 | active implementation | Inventory and commissioning parsing/refusal logic; unit tests cover composite identity and fail-closed cases. | Real NIC identity read, operator role confirmation, host/session binding and target reboot evidence on a compatible laptop. |
| #10 | active implementation | Edge package boundary is specified. | An approved x86_64 Edge artifact and evidence it does not inherit the network installer; depends on Edge publishing a pin-able package. |
| #11 | design decision required | Local model carriage and advisory-only authority boundaries are documented. | Decide what model ships, its claims, sizing and policy; no model artifact or runtime evidence is present. |
| #12 | blocked by external hardware | Isolation boundary is documented. | Borrowed-hardware Deception isolation with approved Edge package/runtime and actual host/storage/network gates. |
| #16 | active implementation | Knowledge Lite admission decision logic and default-deny cache boundary. | Real verifier, artifact/cache implementation, offline bundle import and serving evidence. |
| #17 | active implementation | Service-objective definitions and software-side status scaffolding. | SO-01/SO-09/SO-10 require field measurements; SO-06 consumer and independent measurement evidence remain. Keep hardware status unverified. |
| #26 | active implementation | Host doctor, preparation plan, closure/evaluation decision logic, and a CLI that honestly refuses to build without selected inputs/builder. R11 was a remaster after clean live-build stalled; generated build outputs are no longer retained locally. | Integrate approved builder contract, maintain C5 measurement before other criteria, two independent builder hosts/digest pair, and Linux/macOS record-equality evidence. |
| #27 | active implementation | Artifact record/verification logic and writer authority state machine, tested with synthetic ports. | Host media enumeration, a session-bound user flow, real verifier, isolated privileged write service, read-back/inspect command, and real USB SSD write/boot HIL. |
| #28 | active implementation | R11 static C5 ordering/content inspection passed; manifest-bound QEMU evidence reconciles the static `quarantine_not_persistent` finding with same-boot userspace handoff. Cold-boot-attached regular-file vda and hotplug vdb were read-only before tested writes, which returned `EPERM`, and fixture digests stayed unchanged. The initial scan still saw zero devices; pre-registration quarantine is NOT_OBSERVED. | Observe pre-registration devices; persistence-media handoff/mount, stable physical identity, full lifecycle no-host-write HIL and approval workflow. |
| #40 | software-complete / hardware-unverified | Session-mode and passphrase attempt decision boundary. | Real key acquisition, LUKS and encrypted-volume/operator exercise. |
| #41 | software-complete / hardware-unverified | Volume-wide dirty-write quarantine decision boundary. | Real torn-write/removal and recovery media exercise. |
| #42 | software-complete / hardware-unverified | Snapshot preflight and recovery-candidate decision boundary. | Real snapshot/unlock/restore/operator exercise; #47's recovery key-attempt gap must not be mistaken as solved by this classification. |
| #47 | active implementation (prototype owner composed; unit suite verified) | Recovery delegates actual passphrase attempts to the supplied BootSession; tests cover shared commissioning/recovery budget, workflow recreation, post-exhaustion prompt denial, fixed mode, successful fifth attempt, parallel callers, and provider-error accounting. The prototype runtime creates one BootSession once per post-initramfs systemd process and fixes it ephemeral. | Real commissioning/recovery workflows do not yet invoke acquisition through this runtime owner; no acquisition is enabled in the prototype. Keep fail-closed until that call path and reboot/session boundary are exercised. Real key acquisition remains unverified. |
| #48 | active implementation (prototype Quarantine composed; unit suite verified) | `quarantine.v2` and ADR-0010 D4 state that same-instance volume quarantine blocks every action on every device; tests cover boot medium, host disk and unobserved devices. The prototype userspace runtime creates one Quarantine and evaluates newly observed devices after the initramfs handoff. | The Python Quarantine object is not shared across the initramfs/userspace process boundary and does not itself enforce kernel I/O. Physical torn-write/no-host-write evidence remains open; independent review and shared CI remain outstanding. |
| #49 | active implementation / design decision required | Issue evidence reports suite-green host write, process and network paths through modules the repo-wide static guard misses. | Select a repo-wide runtime audit or module-specific boundary approach, implement across the affected modules, and reproduce the probes; local changes do not yet establish this. |
| #50 | **closed / completed (2026-09-25)** | GitHub issue is closed with reason `completed`; current main documents the closed policy fields and corrected ADR-0002 tooling context. | No remaining acceptance gate recorded; this closure does not imply image/HIL verification. |
| #51 | software implementation present on work branch; issue remains open | Exact `str` constructor validation and base/subclass equality-bypass regressions cover `Quarantine` authority boundaries. The prototype runtime constructs the validated Quarantine through its ordinary public constructor; no arbitrary in-process mutation-resistance claim is made. | Independent review, merge and default-branch CI; in-process introspection remains outside the stated boundary. |
| #52 | active implementation (local fix, not main) | Local pickle/copy refusal and Python 3.11 `object.__getstate__` bypass test/documentation. | Independent review and default-branch CI; do not overclaim closure against arbitrary in-process introspection. |
| #53 | historical snapshot; **not closeable yet** | PR #46 is now merged and its review loop stopped at round 44, so the round-40 snapshot is stale. It still records unique/unmapped concerns: Docs runner allocation failures, an incomplete round-44 test-suite check, Unicode review stop criteria, D7/D8 equivalence, and specific HIL items. | Migrate or explicitly disposition those unique items before closing; keep current implementation status in #42/#47–#52 and the live issue map. |
| #55 | historical handoff; **not closeable yet** | PRs #45/#46 are merged; PR #54 is closed unmerged. Several points overlap #40–#42/#47–#52, but #50 is now closed and the handoff retains unique/unmapped CI, review-stop, ADR-equivalence, and implementation-scope decisions. | Resolve/migrate unique items and update cross-links before closure; do not treat this snapshot as current status. |

## B5 HIL condition

No row above becomes `complete` from a unit test, static scan, merge, or
documentation update. B5 needs an owner-approved removable USB SSD, compatible
laptop, trained operator, and recorded failure exercises. Evidence must show
the relevant acceptance criterion without publishing raw MAC addresses, serials,
TPM values, asset IDs, passphrases, or key material. Until then, a real-device
claim remains `hardware-unverified` and the issue stays open.

## Builder / writer command boundary

`tools/builder/cli.py` currently exposes only `doctor`, `prepare-host`,
`build`, and `verify`. `build` refuses after resolving its configured closure;
the checked-in profile/pin set does not produce an executable build. The
decision logic in `src/azazel_boot/media.py` can classify candidates and issue
per-enumeration codes, and `src/azazel_boot/writer.py` contains a write
authority state machine, but neither is connected to a host media enumerator,
privileged write service, read-back/inspect command, or console session.
Therefore `list-media`, `write`, and `inspect` are not available product
commands, and a target code cannot yet flow from one user-facing command to a
later write in the documented same session. Do not interpret the safety models
or their unit tests as a functional USB builder/writer. Integrating those
surfaces requires the missing session and OS-port contracts, followed by an
independent storage review; no device enumeration or write was attempted here.

## Stop condition

Without the required hardware, operator approval, signing/key material, or
GitHub evidence, this repository must refuse rather than simulate success. No
candidate artifact, closure result, or test fixture is compatibility, security,
or HIL evidence.
