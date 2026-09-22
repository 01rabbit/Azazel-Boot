"""The adapter that reads the host, kept out of `tools.builder` on purpose.

`tests/unit/test_builder_tooling_boundary.py` refuses `subprocess`, `os`,
`socket` and `urllib` anywhere under `tools/builder/`, because
[ADR-0009](../../docs/adr/0009-builder-and-writer-contract.md) D4 says nothing
an operator types becomes a source and the build runs isolated. That guard is
not weakened to make room for a host probe: the probe lives here instead, and
`tools.builder` stays unable to reach the machine at all.

What crosses the boundary is a `HostFacts` value — plain data, produced by
read-only commands from a declared allowlist, consumed by `tools.builder.doctor`
as the only thing it knows about the world.
"""
