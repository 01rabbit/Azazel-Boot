# Azazel-Boot removable SSD PoC: physical HIL record

Status: procedure draft for #63. Physical SSD boot is the primary PoC validation path. QEMU is supplemental and may run in parallel; passing QEMU is not a precondition for the first physical boot. Running this document is not evidence; record actual results under #57.

## Preconditions

Use a disposable removable SSD and a test laptop whose internal storage can be independently monitored. Preserve an external backup of any data on the SSD: provisioning destroys it. Record the laptop/firmware/USB bridge model in a restricted local evidence record; publish only a redacted identifier. Record the exact build digest, writer version, ADR profile, manifest digest, and firmware Secure Boot state. An unsigned prototype must be called unsigned even if UEFI boot succeeds.

Before a destructive operation, verify the detached local PoC attestation through #65 against the exact prototype artifact and independently pinned public key. Then inspect the candidate through #27 `list-media` and record its short-lived target code in the operator session only. Re-check capacity, removability, mounted partitions, root-disk relation and stable identity immediately before writing. Give a separate confirmation for artifact write and P3 creation. Never substitute a `/dev/...` argument or a shell script that guesses the USB disk. Stop when the writer refuses any check. Do not place a secret, serial, WWN, raw device path, or header backup in shared logs or issues. Do not write a physical SSD until #58's custom P2 root/overlay boot path is verified against the artifact and the reviewed #27 target-code writer is available.

## Evidence sequence

| Step | Observation to record | Pass condition |
| --- | --- | --- |
| 1. Artifact | Digest, signature status, Debian 13 amd64 root, initramfs hook inspection | Exact intended artifact; quarantine first; no unpinned early hook |
| 2. Write and inspect | Writer's sanitized result and read-back partition roles | GPT has exactly ESP, immutable boot root, LUKS2 P3 in order; no fourth partition |
| 3. Boot | Firmware state and boot transcript | External medium selected; quarantine precedes media classification and prompt |
| 4. Unlock | Classification only, no prompt transcript | Bound P3 opens as LUKS2/ext4; budget and mode fixed by one BootSession |
| 5. Retention | Harmless marker under an allowlisted state path; independent marker outside it | After reboot only allowlisted marker remains |
| 6. Refusal | Boot with unavailable or rejected local credential | Ephemeral CORE; P3 unopened; no host-storage fallback |
| 7. Removal | Controlled write to disposable state, then remove medium once | Services stop/fence, no silent success, no fallback write; reboot/recovery required |
| 8. Host observation | Independent block-write measurement method and before/after counters | Report measurement scope and limitations; full no-host-write claim only at Stage B |

Use a sterile disposable data item for step 7. Plan a power-safe lab setup, capture the terminal and storage counters externally, and expect the root payload to become unreadable after removal. Do not claim that continuing from cached pages is a valid ephemeral mode. Reconnect only after the stop/fence evidence has been preserved. Recovery is a separate explicit workflow and is not inferred from a subsequent successful boot.

## Result template

For each step record `PASS`, `FAIL`, or `NOT RUN`, the sanitized evidence artifact digest, time, firmware state, tool/build versions, and a short observation. A missing measurement is `NOT RUN`, never `PASS`. Mark the entire run `hardware-unverified` until step 3 executes on the actual laptop; mark Secure Boot, measured no-host-write and full recovery separately. Do not merge QEMU observations into physical evidence.
