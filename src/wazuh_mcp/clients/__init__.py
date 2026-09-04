"""HTTP clients for the two Wazuh backends."""

from .indexer import IndexerClient, hits_of, total_of, validate_index
from .manager import ManagerClient

__all__ = ["IndexerClient", "ManagerClient", "hits_of", "total_of", "validate_index"]
