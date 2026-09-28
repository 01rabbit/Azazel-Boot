from __future__ import annotations

import json

import pytest

from azazel_boot.cli import main
from azazel_boot.status import BootStatus, current_status


def test_status_is_read_only_and_makes_no_capability_claim():
    status = current_status()
    assert status == BootStatus()
    assert status.operational is False
    assert status.installer == "not implemented"
    assert status.supported_host_environments == ()
    assert status.authority == ()


def test_status_json_reports_the_unimplemented_installer(capsys):
    assert main(["status", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["operational"] is False
    assert result["installer"] == "not implemented"
    assert result["supported_host_environments"] == []
    assert result["authority"] == []


def test_cli_exposes_no_image_builder_or_media_writer(capsys):
    with pytest.raises(SystemExit) as error:
        main(["--help"])
    assert error.value.code == 0
    output = capsys.readouterr().out
    assert "status" in output
    assert "build" not in output
    assert "write" not in output
