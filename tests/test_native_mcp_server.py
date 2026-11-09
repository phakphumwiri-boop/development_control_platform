"""End-to-end stdio protocol tests for the DCP read-only MCP adapter."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _tool_json(result):
    text = "\n".join(
        item.text for item in result.content if hasattr(item, "text")
    )
    if not text:
        raise AssertionError("MCP tool returned no text content.")
    return json.loads(text)


class NativeMCPServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_server_exposes_only_read_only_tools(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "one.txt").write_bytes(b"alpha\nbeta\n")
            (root / "two.txt").write_text("alpha\ngamma\n", encoding="utf-8")
            outside = root.parent / f"dcp-mcp-outside-{root.name}.txt"
            outside.write_text("outside", encoding="utf-8")
            (root / ".env").write_text("LOCAL_SECRET=do-not-read", encoding="utf-8")
            (root / "id_ed25519").write_text(
                "-----BEGIN OPENSSH PRIVATE KEY-----\\nprivate-material\\n",
                encoding="utf-8",
            )
            (root / "large.txt").write_text("x" * 8_001, encoding="utf-8")
            (root / "large-left.txt").write_text("a\n" * 5_000, encoding="utf-8")
            (root / "large-right.txt").write_text("b\n" * 5_000, encoding="utf-8")
            try:
                env = os.environ.copy()
                env["DCP_MCP_ROOT"] = str(root)
                existing_pythonpath = env.get("PYTHONPATH", "")
                env["PYTHONPATH"] = str(REPOSITORY_ROOT) + (
                    os.pathsep + existing_pythonpath if existing_pythonpath else ""
                )
                params = StdioServerParameters(
                    command=sys.executable,
                    args=["-m", "tools.mcp_engine.server"],
                    env=env,
                    cwd=str(REPOSITORY_ROOT),
                )

                async with stdio_client(params) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        listed = await session.list_tools()
                        names = {tool.name for tool in listed.tools}
                        self.assertEqual(
                            names,
                            {"read_text_file", "inspect_file", "diff_files", "copy_preview"},
                        )
                        self.assertNotIn("copy_apply", names)

                        read_result = await session.call_tool(
                            "read_text_file", {"path": "one.txt"}
                        )
                        self.assertFalse(read_result.isError)
                        read_data = _tool_json(read_result)
                        self.assertEqual(read_data["content"], "alpha\nbeta\n")
                        self.assertEqual(read_data["operation"], "READ_ONLY")
                        self.assertEqual(len(read_data["sha256"]), 64)

                        oversized_text = await session.call_tool(
                            "read_text_file", {"path": "large.txt"}
                        )
                        self.assertTrue(oversized_text.isError)

                        blocked_secret = await session.call_tool(
                            "read_text_file", {"path": ".env"}
                        )
                        self.assertTrue(blocked_secret.isError)

                        blocked_private_key = await session.call_tool(
                            "read_text_file", {"path": "id_ed25519"}
                        )
                        self.assertTrue(blocked_private_key.isError)

                        inspect_result = await session.call_tool(
                            "inspect_file", {"path": "one.txt"}
                        )
                        self.assertFalse(inspect_result.isError)
                        self.assertEqual(_tool_json(inspect_result)["operation"], "READ_ONLY")

                        diff_result = await session.call_tool(
                            "diff_files",
                            {"left_path": "one.txt", "right_path": "two.txt"},
                        )
                        self.assertFalse(diff_result.isError)
                        diff_data = _tool_json(diff_result)
                        self.assertFalse(diff_data["equal"])
                        self.assertIn("+gamma", diff_data["diff"])

                        bounded_diff = await session.call_tool(
                            "diff_files",
                            {"left_path": "large-left.txt", "right_path": "large-right.txt"},
                        )
                        self.assertFalse(bounded_diff.isError)
                        bounded_data = _tool_json(bounded_diff)
                        self.assertTrue(bounded_data["diff_truncated"])
                        self.assertLessEqual(len(bounded_data["diff"]), 8_000)

                        preview_result = await session.call_tool(
                            "copy_preview",
                            {"source_path": "one.txt", "destination_path": "preview.txt"},
                        )
                        self.assertFalse(preview_result.isError)
                        preview_data = _tool_json(preview_result)
                        self.assertFalse(preview_data["writes_performed"])
                        self.assertFalse((root / "preview.txt").exists())

                        traversal = await session.call_tool(
                            "read_text_file", {"path": f"../{outside.name}"}
                        )
                        self.assertTrue(traversal.isError)
            finally:
                outside.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
