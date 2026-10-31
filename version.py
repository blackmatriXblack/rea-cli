"""Single source of identity for the CLI and its evidence envelope."""

from __future__ import annotations

VERSION = "1.0.0"
ENGINE_NAME = "rea-cli-builtin"
ENGINE_KIND = "builtin-static"
#: This build never downloads tools, models or artifacts. Every reader is
#: implemented locally and external engines are only used when the host
#: already provides them.
DOWNLOAD_POLICY = "refused"

TOOL_LABEL = "REA CLI (offline)"
