# Boot tool proposal template

Copy this template for one concrete user-assistance or tool-installation need.
An incomplete proposal is not an implementation authorization.

## User problem

- User and situation:
- Task the user cannot safely/easily complete today:
- Why this belongs in Boot and is distinct from Nexus:

## Host and inputs

- Supported OS/version/architecture:
- Offline/online behavior:
- Exact package/tool inputs and immutable version/digest:
- Who authenticates those inputs and where trust is provisioned:

## Effects and authority

- Files, packages, services, users, permissions, and settings changed:
- Required privileges and why:
- User review and approval steps:
- Network activity (default must be none unless explicitly approved):
- Explicitly forbidden actions (including disk/image/firmware writes):
- What the tool cannot decide, admit, activate, or enforce:

## Failure, rollback, and evidence

- Fail-closed conditions:
- Rollback/uninstall limits:
- User-visible completion/refusal result:
- Synthetic tests and integration environment:
- Independent review needed:
- Remaining unsupported conditions:
