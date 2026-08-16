from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Severity


@dataclass(slots=True)
class Policy:
    fail_on: Severity = Severity.HIGH
    ignore_rules: set[str] = field(default_factory=set)
    allowed_commands: set[str] = field(default_factory=set)
    allowed_hosts: set[str] = field(default_factory=set)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> Policy:
        return cls(
            fail_on=Severity.parse(str(data.get("fail_on", "high"))),
            ignore_rules={str(item).upper() for item in data.get("ignore_rules", [])},
            allowed_commands={str(item).lower() for item in data.get("allowed_commands", [])},
            allowed_hosts={str(item).lower() for item in data.get("allowed_hosts", [])},
        )


def load_policy(path: str | Path | None) -> Policy:
    if path is None:
        return Policy()
    policy_path = Path(path)
    with policy_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("policy must be a JSON object")
    return Policy.from_mapping(data)
