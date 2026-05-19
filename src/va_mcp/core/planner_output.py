from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PlannerOutput:
    owasp_candidates: list[str]
    tool_ids: list[str]
    need_more_context: bool = False
    missing: list[str] = field(default_factory=list)
