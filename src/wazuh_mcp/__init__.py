"""MCP server for querying a remote Wazuh manager and indexer."""

from .context import WazuhContext
from .server import build_server

__version__ = "0.1.0"
__all__ = ["WazuhContext", "__version__", "build_server"]
