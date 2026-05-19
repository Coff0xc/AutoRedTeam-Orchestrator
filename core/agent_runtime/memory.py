"""Serializable local memory primitives for agent runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat()


@dataclass
class MemoryRecord:
    """One memory item captured during a controlled run."""

    key: str
    value: str
    record_type: str = "note"
    source: str = "runtime"
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "record_type": self.record_type,
            "source": self.source,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }


@dataclass
class RunMemory:
    """In-memory record set for one run."""

    records: List[MemoryRecord] = field(default_factory=list)

    def add(
        self,
        key: str,
        value: str,
        record_type: str = "note",
        source: str = "runtime",
        confidence: float = 0.5,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MemoryRecord:
        record = MemoryRecord(
            key=key,
            value=value,
            record_type=record_type,
            source=source,
            confidence=confidence,
            metadata=metadata or {},
        )
        self.records.append(record)
        return record

    def query(self, key_prefix: Optional[str] = None, record_type: Optional[str] = None) -> List[MemoryRecord]:
        results = self.records
        if key_prefix:
            results = [record for record in results if record.key.startswith(key_prefix)]
        if record_type:
            results = [record for record in results if record.record_type == record_type]
        return results

    def to_dict(self) -> Dict[str, Any]:
        return {
            "records": [record.to_dict() for record in self.records],
            "count": len(self.records),
        }
