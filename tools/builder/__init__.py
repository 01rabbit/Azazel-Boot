"""The evaluation-side builder tooling.

This package exists to *measure* a candidate image builder, not to be one and
not to select one. `docs/adr/0002-image-builder.md` D2 leaves the tool open and
`docs/adr/0009-builder-and-writer-contract.md` D8 records what would settle it;
every module here produces one of the inputs that plan needs.

Nothing here has been run against a real builder. No image has been built, no
digest has been measured, and no candidate has been evaluated.
"""
