"""Evidence Ledger: Machine-readable, versioned evidence model for dynamicState investigations.

Provides a structured, immutable record of runtime facts, capture quality metrics,
typed object interpretations, observation comparisons, and static-code linkages,
strictly distinguishing direct observations from speculative inferences.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import uuid
from typing import Any, Dict, List, Optional, Set, Union


EVIDENCE_SCHEMA_VERSION = "1.0.0"

# Evidence Types
EVIDENCE_TYPE_RUNTIME_IDENTITY = "RUNTIME_IDENTITY"
EVIDENCE_TYPE_CAPTURE_QUALITY = "CAPTURE_QUALITY"
EVIDENCE_TYPE_OBJECT_STATE = "OBJECT_STATE"
EVIDENCE_TYPE_FIELD_OBSERVATION = "FIELD_OBSERVATION"
EVIDENCE_TYPE_COMPARISON = "COMPARISON"
EVIDENCE_TYPE_STATIC_LINK = "STATIC_LINK"
EVIDENCE_TYPE_HYPOTHESIS = "HYPOTHESIS"
EVIDENCE_TYPE_INFERENCE = "INFERENCE"
EVIDENCE_TYPE_DIAGNOSTIC = "DIAGNOSTIC"

VALID_EVIDENCE_TYPES = {
    EVIDENCE_TYPE_RUNTIME_IDENTITY,
    EVIDENCE_TYPE_CAPTURE_QUALITY,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_STATIC_LINK,
    EVIDENCE_TYPE_HYPOTHESIS,
    EVIDENCE_TYPE_INFERENCE,
    EVIDENCE_TYPE_DIAGNOSTIC,
}

# Nature classification: direct observation vs inference
NATURE_OBSERVATION = "observation"
NATURE_INFERENCE = "inference"
NATURE_HYPOTHESIS = "hypothesis"

VALID_NATURES = {NATURE_OBSERVATION, NATURE_INFERENCE, NATURE_HYPOTHESIS}


@dataclass
class EvidenceRecord:
    """Individual machine-readable evidence entry with full provenance."""
    evidence_id: str = ""
    evidence_type: str = EVIDENCE_TYPE_OBJECT_STATE
    nature: str = NATURE_OBSERVATION  # "observation", "inference", or "hypothesis"
    source: str = "runtime_collector"  # e.g., "raw_snapshot", "offline_analyzer", "dwarf", "static_provider", "state_diff"
    timestamp: str = ""
    session_id: Optional[str] = None
    finding_id: Optional[str] = None
    observation: str = ""
    parent_evidence_ids: List[str] = field(default_factory=list)

    # Provenance details
    provenance: Dict[str, Any] = field(default_factory=dict)

    # Specific evidence categories (all optional for schema flexibility and backward compatibility)
    target_identity: Optional[Dict[str, Any]] = None
    snapshot_ref: Optional[Dict[str, Any]] = None
    capture_quality: Optional[Dict[str, Any]] = None
    object_observation: Optional[Dict[str, Any]] = None
    field_observation: Optional[Dict[str, Any]] = None
    static_code_link: Optional[Dict[str, Any]] = None
    comparison_observation: Optional[Dict[str, Any]] = None
    uncertainty: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = EVIDENCE_SCHEMA_VERSION

    def __post_init__(self):
        if not self.evidence_id:
            self.evidence_id = f"ev_{uuid.uuid4().hex[:12]}"
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if self.nature not in VALID_NATURES:
            raise ValueError(f"Invalid evidence nature '{self.nature}'. Expected one of {sorted(VALID_NATURES)}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary without None values for optional fields."""
        data: Dict[str, Any] = {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "nature": self.nature,
            "source": self.source,
            "timestamp": self.timestamp,
            "observation": self.observation,
            "parent_evidence_ids": list(self.parent_evidence_ids),
            "schema_version": self.schema_version,
            "provenance": self.provenance,
            "details": self.details,
        }
        if self.session_id is not None:
            data["session_id"] = self.session_id
        if self.finding_id is not None:
            data["finding_id"] = self.finding_id
        if self.target_identity is not None:
            data["target_identity"] = self.target_identity
        if self.snapshot_ref is not None:
            data["snapshot_ref"] = self.snapshot_ref
        if self.capture_quality is not None:
            data["capture_quality"] = self.capture_quality
        if self.object_observation is not None:
            data["object_observation"] = self.object_observation
        if self.field_observation is not None:
            data["field_observation"] = self.field_observation
        if self.static_code_link is not None:
            data["static_code_link"] = self.static_code_link
        if self.comparison_observation is not None:
            data["comparison_observation"] = self.comparison_observation
        if self.uncertainty is not None:
            data["uncertainty"] = self.uncertainty
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceRecord":
        """Deserialize from dictionary, maintaining backward compatibility with missing fields."""
        parent_ids = data.get("parent_evidence_ids")
        if parent_ids is None:
            prov = data.get("provenance", {})
            if isinstance(prov, dict):
                parent_ids = prov.get("parent_evidence_ids", [])
            else:
                parent_ids = []

        return cls(
            evidence_id=data.get("evidence_id") or f"ev_{uuid.uuid4().hex[:12]}",
            evidence_type=data.get("evidence_type", EVIDENCE_TYPE_OBJECT_STATE),
            nature=data.get("nature", NATURE_OBSERVATION),
            source=data.get("source", "unknown"),
            timestamp=data.get("timestamp", ""),
            session_id=data.get("session_id"),
            finding_id=data.get("finding_id"),
            observation=data.get("observation", ""),
            parent_evidence_ids=list(parent_ids or []),
            provenance=data.get("provenance", {}),
            target_identity=data.get("target_identity"),
            snapshot_ref=data.get("snapshot_ref"),
            capture_quality=data.get("capture_quality"),
            object_observation=data.get("object_observation"),
            field_observation=data.get("field_observation"),
            static_code_link=data.get("static_code_link"),
            comparison_observation=data.get("comparison_observation"),
            uncertainty=data.get("uncertainty"),
            details=data.get("details", {}),
            schema_version=data.get("schema_version", EVIDENCE_SCHEMA_VERSION),
        )


class EvidenceLedger:
    """Versioned container and query index for evidence records within an investigation."""

    def __init__(self, session_id: Optional[str] = None, schema_version: str = EVIDENCE_SCHEMA_VERSION):
        self.session_id: str = session_id or f"inv_sess_{uuid.uuid4().hex[:8]}"
        self.schema_version: str = schema_version
        self.created_at: str = datetime.now(timezone.utc).isoformat()
        self._records: List[EvidenceRecord] = []
        self._by_id: Dict[str, EvidenceRecord] = {}
        self._by_type: Dict[str, List[EvidenceRecord]] = {}
        self._by_finding: Dict[str, List[EvidenceRecord]] = {}

    def add_record(self, record: Union[EvidenceRecord, Dict[str, Any]]) -> EvidenceRecord:
        """Add an evidence record to the ledger, rejecting duplicate IDs."""
        if isinstance(record, dict):
            record = EvidenceRecord.from_dict(record)
        if not record.session_id:
            record.session_id = self.session_id

        # Schema validation
        self.validate_record(record)

        if record.evidence_id in self._by_id:
            raise ValueError(f"Duplicate evidence_id '{record.evidence_id}': record with this ID already exists in ledger.")

        self._records.append(record)
        self._by_id[record.evidence_id] = record
        self._by_type.setdefault(record.evidence_type, []).append(record)
        if record.finding_id:
            self._by_finding.setdefault(record.finding_id, []).append(record)
        return record

    def validate_record(self, record: EvidenceRecord) -> None:
        """Validate record structure and consistency."""
        if not record.evidence_id:
            raise ValueError("EvidenceRecord must have a valid non-empty evidence_id")
        if not record.evidence_type:
            raise ValueError("EvidenceRecord must specify evidence_type")
        if record.nature not in VALID_NATURES:
            raise ValueError(f"Invalid nature '{record.nature}'. Expected one of {sorted(VALID_NATURES)}")

    def get_record(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """Look up record by unique ID."""
        return self._by_id.get(evidence_id)

    def query(
        self,
        evidence_type: Optional[str] = None,
        nature: Optional[str] = None,
        finding_id: Optional[str] = None,
        source: Optional[str] = None,
        object_id: Optional[str] = None,
    ) -> List[EvidenceRecord]:
        """Query evidence records matching given filters."""
        results = self._records
        if evidence_type:
            results = [r for r in results if r.evidence_type == evidence_type]
        if nature:
            results = [r for r in results if r.nature == nature]
        if finding_id:
            results = [r for r in results if r.finding_id == finding_id]
        if source:
            results = [r for r in results if r.source == source]
        if object_id:
            results = [
                r for r in results
                if (r.object_observation and r.object_observation.get("object_id") == object_id)
                or (r.field_observation and r.field_observation.get("object_id") == object_id)
            ]
        return results

    def trace_provenance_chain(self, evidence_id: str) -> List[Dict[str, Any]]:
        """Trace recursive provenance lineage for an evidence record with cycle detection and deterministic ordering."""
        chain: List[Dict[str, Any]] = []
        visited: Set[str] = set()

        def _dfs(eid: str, path: List[str]):
            if eid in path:
                # Cycle detected
                chain.append({
                    "evidence_id": eid,
                    "status": "CYCLE_DETECTED",
                    "cycle_path": path + [eid],
                    "reason": f"Cyclic provenance lineage detected involving '{eid}'.",
                })
                return

            if eid in visited:
                return
            visited.add(eid)

            rec = self.get_record(eid)
            if not rec:
                chain.append({
                    "evidence_id": eid,
                    "status": "UNRESOLVED_PARENT",
                    "reason": f"Parent evidence '{eid}' not found in ledger.",
                })
                return

            step = {
                "evidence_id": rec.evidence_id,
                "evidence_type": rec.evidence_type,
                "nature": rec.nature,
                "source": rec.source,
                "parent_evidence_ids": list(rec.parent_evidence_ids),
                "provenance": rec.provenance,
                "snapshot_ref": rec.snapshot_ref,
                "target_identity": rec.target_identity,
                "object_info": rec.object_observation or rec.field_observation,
                "static_link": rec.static_code_link,
                "status": "RESOLVED",
            }
            chain.append(step)

            # Traverse parents deterministically (sorted)
            sorted_parents = sorted(rec.parent_evidence_ids)
            for pid in sorted_parents:
                _dfs(pid, path + [eid])

        _dfs(evidence_id, [])
        return chain

    def get_provenance_chain(self, finding_id: Optional[str] = None, evidence_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Trace provenance link chain from finding/evidence down to artifact/snapshot."""
        if evidence_id:
            return self.trace_provenance_chain(evidence_id)

        if finding_id:
            records = self.query(finding_id=finding_id)
            combined_chain: List[Dict[str, Any]] = []
            seen_eids: Set[str] = set()
            for r in records:
                sub_chain = self.trace_provenance_chain(r.evidence_id)
                for item in sub_chain:
                    eid = item.get("evidence_id")
                    if eid and eid not in seen_eids:
                        seen_eids.add(eid)
                        combined_chain.append(item)
            return combined_chain

        return []

    def to_dict(self) -> Dict[str, Any]:
        """Serialize full ledger to dictionary."""
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "record_count": len(self._records),
            "records": [r.to_dict() for r in self._records],
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        """Serialize ledger to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceLedger":
        """Reconstruct EvidenceLedger from serialized dictionary."""
        ledger = cls(
            session_id=data.get("session_id"),
            schema_version=data.get("schema_version", EVIDENCE_SCHEMA_VERSION),
        )
        ledger.created_at = data.get("created_at", ledger.created_at)
        for rec_data in data.get("records", []):
            ledger.add_record(EvidenceRecord.from_dict(rec_data))
        return ledger

    @classmethod
    def from_json(cls, json_str: str) -> "EvidenceLedger":
        """Reconstruct EvidenceLedger from JSON string."""
        return cls.from_dict(json.loads(json_str))

