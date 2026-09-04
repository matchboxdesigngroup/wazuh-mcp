"""Tool modules, each exposing a `register(server, ctx)` entry point."""

from . import (
    agents,
    alerts,
    inventory,
    manager_ops,
    posture,
    reports,
    response,
    rules,
    vulnerabilities,
)

#: Registration order determines the order tools appear in `tools/list`.
MODULES = (
    manager_ops,
    agents,
    alerts,
    vulnerabilities,
    rules,
    posture,
    inventory,
    reports,
    response,
)

__all__ = ["MODULES"]
