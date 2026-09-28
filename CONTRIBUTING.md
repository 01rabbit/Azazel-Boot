# Contributing to Azazel-Boot

Read [ADR-0012](docs/adr/0012-existing-environment-tooling.md), the
[architecture](docs/architecture.md), and the cross-repository
[program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
before proposing product behavior.

## Current scope

Boot is a non-operational user-assistance/tooling scaffold for an environment
already supplied and started by the user. It does not build or remaster an OS,
write boot media, partition/format devices, implement Boot-owned persistence,
or duplicate the Nexus base installer. The concrete helper toolset and host
contract are undecided.

Before implementation, write a proposal using
[`docs/tool-proposal-template.md`](docs/tool-proposal-template.md). A proposal
must explain why the work belongs in Boot rather than Nexus, declare host
effects and privileges, and state the test and rollback limits. No operational
installer, provider admission, network fetch, model acquisition, or Edge
activation is authorized by a proposal alone; the relevant owner must approve
that boundary separately.

Azazel-Edge remains the sole decision and enforcement authority. User approval
to install a package is not permission for Boot to change Edge policy or
activate services.

## Development checks

Use the locked development dependencies and run:

```bash
python3 tools/check_docs_links.py
pip install -c constraints-dev.txt -e ".[dev]"
ruff check src tests tools
python -m pytest tests -q
```

Tests must use synthetic data or disposable software environments. Do not
access or write physical media, block/loop devices, firmware, or host boot
configuration. Report exactly what ran; a local test is not a CI or hardware
result.

Link every new document from the README or the current ADR. Keep changes
focused, and state what the evidence does not establish.
