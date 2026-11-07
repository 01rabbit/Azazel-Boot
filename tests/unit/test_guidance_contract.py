from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_retired_media_workflow_is_not_part_of_current_checks():
    workflows = ROOT / ".github" / "workflows"
    assert not (workflows / "linux-media.yml").exists()
    assert not (workflows / "linux-media.yaml").exists()
    for workflow in workflows.iterdir():
        if workflow.suffix in {".yml", ".yaml"}:
            text = workflow.read_text(encoding="utf-8").lower()
            assert "linux media backend" not in text
            assert "tests/media" not in text


def test_guidance_matches_the_referenced_nexus_pin():
    # Immutable Nexus 3d9a2a68: pyproject.toml [mio] and
    # tools/build_wheelhouse.py describe this source/version pair.
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "user-prepared-live.md").read_text(encoding="utf-8")
    for text in (readme, guide):
        assert "3d9a2a68" in text
        assert "989dd959" in text
        assert "0.1.0.dev20261107+gited860f2" in text
