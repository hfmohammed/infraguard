"""Content-free MCP call evidence and per-tool outcome counters."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from time import perf_counter
from typing import ParamSpec, TypeVar

from prometheus_client import CollectorRegistry, Counter

P = ParamSpec("P")
T = TypeVar("T")
REGISTRY = CollectorRegistry()
CALLS = Counter(
    "infraguard_mcp_tool_calls_total", "MCP calls by outcome", ["tool", "result"], registry=REGISTRY
)
_audit_path = Path("audit/mcp-calls.jsonl")


def configure_audit(root: Path) -> None:
    """Place audit records under the configured server root."""
    global _audit_path
    _audit_path = root / "audit" / "mcp-calls.jsonl"


def audited(function: Callable[P, T]) -> Callable[P, T]:
    """Record hashes and outcomes without persisting tool arguments or responses."""

    @wraps(function)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> T:
        started = perf_counter()
        outcome = "error"
        digest = hashlib.sha256(
            json.dumps([args, kwargs], sort_keys=True, default=str).encode()
        ).hexdigest()
        # Establish the audit destination before any API request is made.
        _audit_path.parent.mkdir(parents=True, exist_ok=True)
        with _audit_path.open("a", encoding="utf-8") as stream:
            try:
                result = function(*args, **kwargs)
                outcome = "success"
                return result
            finally:
                CALLS.labels(function.__name__, outcome).inc()
                stream.write(
                    json.dumps(
                        {
                            "ts": datetime.now(UTC).isoformat(),
                            "tool": function.__name__,
                            "args_sha256": digest,
                            "result": outcome,
                            "duration_ms": (perf_counter() - started) * 1000,
                        }
                    )
                    + "\n"
                )

    return wrapped
