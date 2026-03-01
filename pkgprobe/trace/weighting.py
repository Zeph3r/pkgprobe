"""
Internal weighted inference model for switch suggestion.

DetectionEvidence and _WeightedSwitchCandidate are not part of the public API.
Used by switch_policy to build scored candidates; scores normalized and
returned as ordered list of switch strings.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

EvidenceSource = Literal["magic_bytes", "string_scan", "filename", "subtype"]


@dataclass
class DetectionEvidence:
    """Internal: single piece of evidence contributing to a switch score."""
    source: EvidenceSource
    value: str
    weight: float


@dataclass
class _WeightedSwitchCandidate:
    """Internal: switch with base weight and evidence list; score = base_weight + sum(evidence.weight)."""
    switch: str
    base_weight: float
    evidence: list[DetectionEvidence]

    def score(self) -> float:
        return self.base_weight + sum(e.weight for e in self.evidence)
