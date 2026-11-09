"""Local STDIO MCP adapter for DCP's read-only source inspection tools.

The workspace root is fixed at process startup via DCP_MCP_ROOT. This server
does not expose copy_apply, shell execution, network listeners, or Git writes.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
from typing import Any

from mcp.server.fastmcp import FastMCP

from .engine import (
    copy_preview as engine_copy_preview,
    EngineError,
    diff_files as engine_diff_files,
    inspect_file as engine_inspect_file,
    read_text_file as engine_read_text_file,
)

_ROOT_VALUE = os.environ.get("DCP_MCP_ROOT", "").strip()
if not _ROOT_VALUE:
    raise RuntimeError("DCP_MCP_ROOT must point to one explicitly approved local workspace.")

WORKSPACE_ROOT = Path(_ROOT_VALUE).expanduser().resolve(strict=True)
if not WORKSPACE_ROOT.is_dir():
    raise RuntimeError("DCP_MCP_ROOT must point to an existing directory.")

mcp = FastMCP("dcp-local-readonly")


_DENIED_DIRECTORY_NAMES = {
    ".git", ".ssh", ".aws", ".azure", ".gnupg", ".codex",
    "secrets", "credentials",
}
_DENIED_FILE_NAMES = {
    ".npmrc", ".pypirc", "credentials.json", "token.json",
    "service-account.json", "service_account.json", "google-credentials.json",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    "ssh_host_rsa_key", "ssh_host_ed25519_key", "private_key", "privatekey",
}
_DENIED_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".kdbx"}


def _checked_path(value: str) -> str:
    """Reject common credential stores before any file operation."""
    if not isinstance(value, str) or not value.strip():
        raise EngineError("A non-empty relative path is required.")
    normalized = value.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    lowered = [part.casefold() for part in parts]
    filename = lowered[-1] if lowered else ""
    suffix = Path(filename).suffix
    if any(part in _DENIED_DIRECTORY_NAMES for part in lowered):
        raise EngineError("Sensitive credential directories are not available through DCP MCP.")
    if (
        filename.startswith(".env")
        or filename in _DENIED_FILE_NAMES
        or suffix in _DENIED_SUFFIXES
    ):
        raise EngineError("Sensitive credential files are not available through DCP MCP.")
    return value


@mcp.tool()
def read_text_file(path: str) -> dict[str, Any]:
    """Read a UTF-8 text file under the configured workspace (maximum 64 KiB and 8,000 Unicode characters)."""
    return engine_read_text_file(WORKSPACE_ROOT, _checked_path(path))


@mcp.tool()
def inspect_file(path: str) -> dict[str, Any]:
    """Return file size, encoding and SHA-256 evidence without changing the file."""
    return engine_inspect_file(WORKSPACE_ROOT, _checked_path(path))


@mcp.tool()
def diff_files(left_path: str, right_path: str) -> dict[str, Any]:
    """Compare files in the workspace; diff text is capped at 8,000 characters."""
    result = engine_diff_files(
        WORKSPACE_ROOT, _checked_path(left_path),
        WORKSPACE_ROOT, _checked_path(right_path),
    )
    diff = result.get("diff")
    if isinstance(diff, str) and len(diff) > 8_000:
        result["diff"] = diff[:8_000]
        result["diff_truncated"] = True
        result["diff_total_characters"] = len(diff)
    else:
        result["diff_truncated"] = False
    return result


@mcp.tool()
def copy_preview(source_path: str, destination_path: str) -> dict[str, Any]:
    """Preview copying to a new path inside the workspace; performs no write."""
    return engine_copy_preview(
        WORKSPACE_ROOT, _checked_path(source_path),
        WORKSPACE_ROOT, _checked_path(destination_path)
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
