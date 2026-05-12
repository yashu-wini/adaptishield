# detection/fusion_engine.py
"""
Fusion Engine: Merges detections from Regex, Transformer, and spaCy.
Resolves conflicts, merges overlapping spans, and boosts confidence
when multiple detectors agree.
"""

from typing import List, Dict, Any


class FusionEngine:
    """
    Intelligently merges detections from multiple detectors:
    - Regex (high precision for structured PII)
    - Transformer (high recall for contextual PII)
    - spaCy (good for named entities)

    Confidence Boosting Rules:
    - Regex only:            confidence unchanged
    - Transformer only:      confidence unchanged
    - Regex + Transformer:   confidence * 1.15 (capped at 1.0)
    - All three agree:       confidence * 1.25 (capped at 1.0)
    """

    OVERLAP_THRESHOLD = 0.5  # IoU threshold to consider as same entity

    def fuse(
        self,
        regex_detections: list[dict],
        transformer_detections: list[dict],
        spacy_detections: list[dict]
    ) -> list[dict]:
        """
        Merge all detections into a unified, deduplicated list.
        """
        all_detections = (
            regex_detections +
            transformer_detections +
            spacy_detections
        )

        if not all_detections:
            return []

        # Sort by start position
        all_detections.sort(key=lambda x: x["start"])

        # Group overlapping detections
        groups = self._group_overlapping(all_detections)

        # For each group, produce final detection
        fused = []
        for group in groups:
            merged = self._merge_group(group)
            if merged:
                fused.append(merged)

        return fused

    def _group_overlapping(self, detections: list[dict]) -> list[list[dict]]:
        """Group detections that overlap in text span."""
        if not detections:
            return []

        groups = [[detections[0]]]
        for det in detections[1:]:
            merged = False
            for group in groups:
                if any(self._overlaps(det, g) for g in group):
                    group.append(det)
                    merged = True
                    break
            if not merged:
                groups.append([det])

        return groups

    def _overlaps(self, a: dict, b: dict) -> bool:
        """Check if two detections overlap."""
        overlap_start = max(a["start"], b["start"])
        overlap_end = min(a["end"], b["end"])
        overlap_len = max(0, overlap_end - overlap_start)
        if overlap_len == 0:
            return False
        len_a = a["end"] - a["start"]
        len_b = b["end"] - b["start"]
        union = len_a + len_b - overlap_len
        return (overlap_len / union) >= self.OVERLAP_THRESHOLD

    def _merge_group(self, group: list[dict]) -> dict | None:
        """Merge a group of overlapping detections into one."""
        if not group:
            return None

        # Prefer the most specific entity type
        # Priority: regex > transformer > spacy for type selection
        source_priority = {"regex": 0, "transformer": 1, "spacy": 2}
        group.sort(key=lambda x: source_priority.get(x["source"], 3))
        best = group[0]

        # Count unique sources
        sources = set(d["source"] for d in group)
        n_sources = len(sources)

        # Boost confidence based on agreement
        base_confidence = max(d["confidence"] for d in group)
        if n_sources == 3:
            boosted = min(1.0, base_confidence * 1.25)
        elif n_sources == 2:
            boosted = min(1.0, base_confidence * 1.15)
        else:
            boosted = base_confidence

        return {
            "entity_type": best["entity_type"],
            "value": best["value"],
            "start": min(d["start"] for d in group),
            "end": max(d["end"] for d in group),
            "confidence": round(boosted, 4),
            "source": "+".join(sorted(sources)),
            "detector_count": n_sources
        }
