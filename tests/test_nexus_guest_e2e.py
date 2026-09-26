"""Keep the disposable Nexus E2E runner ordered behind its real installer."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import unittest
from pathlib import Path

from tools.payload.run_nexus_guest_e2e import (
    REPORT_CHUNK_BYTES,
    REPORT_PREFIX,
    format_report_frame,
)


SCRIPT = Path(__file__).parents[1] / "tools/payload/run_nexus_guest_e2e.py"


class NexusGuestE2EImportOrderTests(unittest.TestCase):
    def test_report_frame_is_compact_byte_counted_digest_bound_and_chunked(self) -> None:
        report = {"message": "nexus fixture — " + ("x" * 1900), "verdict": "pass"}
        lines = format_report_frame(report)
        payload = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(payload).hexdigest()
        chunk_lines = lines[1:-1]
        self.assertTrue(lines[0].startswith(f"{REPORT_PREFIX}_BEGIN length={len(payload)} sha256={digest} chunks="))
        self.assertEqual(
            lines[-1],
            f"{REPORT_PREFIX}_END length={len(payload)} sha256={digest} chunks={len(chunk_lines)}",
        )
        chunks = []
        for sequence, line in enumerate(chunk_lines):
            prefix = f"{REPORT_PREFIX}_CHUNK seq={sequence} data="
            self.assertTrue(line.startswith(prefix))
            encoded = line.removeprefix(prefix)
            decoded = base64.b64decode(encoded, validate=True)
            self.assertLessEqual(len(decoded), REPORT_CHUNK_BYTES)
            if sequence < len(chunk_lines) - 1:
                self.assertEqual(len(decoded), REPORT_CHUNK_BYTES)
            chunks.append(decoded)
        self.assertEqual(b"".join(chunks), payload)

    def test_report_frame_is_deterministic(self) -> None:
        report = {"verdict": "pass", "message": "stable"}
        self.assertEqual(format_report_frame(report), format_report_frame(report))

    def test_nexus_modules_are_not_imported_at_process_start(self) -> None:
        tree = ast.parse(SCRIPT.read_text())
        imports = [
            node
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        self.assertFalse(
            [node for node in imports if "azazel_nexus" in ast.unparse(node)]
        )

    def test_installer_call_precedes_lazy_nexus_imports(self) -> None:
        tree = ast.parse(SCRIPT.read_text())
        run_function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        install_lines = [
            node.lineno
            for node in ast.walk(run_function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr == "run"
            and node.args
            and isinstance(node.args[0], ast.List)
            and node.args[0].elts
            and isinstance(node.args[0].elts[0], ast.Constant)
            and node.args[0].elts[0].value == "/usr/libexec/azazel-nexus-prototype-install"
        ]
        import_lines = [
            node.lineno
            for node in ast.walk(run_function)
            if isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.startswith("azazel_nexus")
        ]
        self.assertEqual(len(install_lines), 1)
        self.assertTrue(import_lines)
        self.assertGreater(min(import_lines), install_lines[0])

    def test_fixture_store_uses_live_overlay_not_small_run_tmpfs(self) -> None:
        tree = ast.parse(SCRIPT.read_text())
        root_assignment = next(
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "ROOT" for target in node.targets)
        )
        self.assertEqual(
            ast.literal_eval(root_assignment.value.args[0]),
            "/var/tmp/azazel-nexus-prototype-e2e",
        )


if __name__ == "__main__":
    unittest.main()
