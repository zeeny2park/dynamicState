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
    evidence_id: Optional[str] = None
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
        if self.evidence_id is not None:
            if not isinstance(self.evidence_id, str) or not self.evidence_id.strip():
                raise ValueError("evidence_id must be a non-empty string")
        else:
            self.evidence_id = f"ev_{uuid.uuid4().hex[:12]}"

        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not isinstance(self.evidence_type, str) or not self.evidence_type.strip():
            raise ValueError("evidence_type must be a non-empty string")
        if self.evidence_type not in VALID_EVIDENCE_TYPES:
            raise ValueError(f"Invalid evidence_type '{self.evidence_type}'. Expected one of {sorted(VALID_EVIDENCE_TYPES)}")
        if self.nature not in VALID_NATURES:
            raise ValueError(f"Invalid evidence nature '{self.nature}'. Expected one of {sorted(VALID_NATURES)}")
        if self.session_id is not None and (not isinstance(self.session_id, str) or not self.session_id.strip()):
            raise ValueError("session_id must be a non-empty string when provided")
        if self.finding_id is not None and (not isinstance(self.finding_id, str) or not self.finding_id.strip()):
            raise ValueError("finding_id must be a non-empty string when provided")
        if not isinstance(self.parent_evidence_ids, (list, tuple)):
            raise TypeError("parent_evidence_ids must be a list of strings")
        for pid in self.parent_evidence_ids:
            if not isinstance(pid, str) or not pid.strip():
                raise ValueError(f"Invalid parent_evidence_id '{pid}' in parent_evidence_ids")
        if self.evidence_id in self.parent_evidence_ids:
            raise ValueError(f"Self-reference detected: record cannot have its own evidence_id '{self.evidence_id}' as a parent")

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
        eid = data.get("evidence_id")
        if "evidence_id" in data and eid is not None:
            if not isinstance(eid, str) or not eid.strip():
                raise ValueError("evidence_id in data must be a non-empty string")
        elif eid is None:
            eid = f"ev_{uuid.uuid4().hex[:12]}"

        # Normalize evidence_type for legacy compatibility
        etype = data.get("evidence_type", EVIDENCE_TYPE_OBJECT_STATE)
        if isinstance(etype, str) and etype.upper() in VALID_EVIDENCE_TYPES:
            etype = etype.upper()
        elif etype not in VALID_EVIDENCE_TYPES:
            raise ValueError(f"Invalid evidence_type '{etype}'. Expected one of {sorted(VALID_EVIDENCE_TYPES)}")

        # Normalize nature for legacy compatibility
        nat = data.get("nature", NATURE_OBSERVATION)
        if isinstance(nat, str) and nat.lower() in VALID_NATURES:
            nat = nat.lower()
        elif nat not in VALID_NATURES:
            raise ValueError(f"Invalid nature '{nat}'. Expected one of {sorted(VALID_NATURES)}")

        parent_ids = data.get("parent_evidence_ids")
        if parent_ids is None:
            prov = data.get("provenance", {})
            if isinstance(prov, dict):
                parent_ids = prov.get("parent_evidence_ids", [])
            else:
                parent_ids = []
        elif not isinstance(parent_ids, (list, tuple)):
            raise TypeError("parent_evidence_ids must be a list or tuple of strings")

        # Validate dictionary fields if provided
        for field_name in [
            "snapshot_ref", "target_identity", "capture_quality",
            "object_observation", "field_observation", "static_code_link",
            "comparison_observation", "provenance", "details"
        ]:
            if field_name in data and data[field_name] is not None and not isinstance(data[field_name], dict):
                raise TypeError(f"Field '{field_name}' must be a dictionary when provided, got {type(data[field_name]).__name__}")

        return cls(
            evidence_id=eid,
            evidence_type=etype,
            nature=nat,
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

    def __init__(
        self,
        session_id: Optional[str] = None,
        schema_version: str = EVIDENCE_SCHEMA_VERSION,
        session_secret: Optional[str] = None,
    ):
        self.session_id: str = session_id or f"inv_sess_{uuid.uuid4().hex[:8]}"
        self.schema_version: str = schema_version
        self.session_secret: str = session_secret or uuid.uuid4().hex
        self.created_at: str = datetime.now(timezone.utc).isoformat()
        self._records: List[EvidenceRecord] = []
        self._by_id: Dict[str, EvidenceRecord] = {}
        self._by_type: Dict[str, List[EvidenceRecord]] = {}
        self._by_finding: Dict[str, List[EvidenceRecord]] = {}

    def attest_causal_proof(
        self,
        evidence_id: str,
        target_function: Optional[str] = None,
        field_path: Optional[str] = None,
        verification_type: str = "deterministic_reproduction",
    ) -> bool:
        """Attest an authentic proof record in this ledger with the session secret."""
        rec = self.get_record(evidence_id)
        if not rec:
            raise ValueError(f"Evidence record '{evidence_id}' does not exist in ledger")

        p_details = rec.details or {}
        p_prov = rec.provenance or {}
        if (
            p_details.get("caller_submitted") is True
            or p_details.get("unverified_caller_claim") is True
            or rec.source == "unverified_caller"
            or p_prov.get("submission_channel") == "external_caller"
        ):
            raise ValueError(f"Cannot attest causal proof: record '{evidence_id}' originated from unverified external caller")

        cq = rec.capture_quality
        if not cq or not isinstance(cq, dict):
            raise ValueError(f"Cannot attest causal proof: record '{evidence_id}' lacks capture quality metadata")
        comp = cq.get("completeness") or cq.get("status")
        if comp != "COMPLETE":
            raise ValueError(f"Cannot attest causal proof: record '{evidence_id}' has non-complete capture quality '{comp}'")
        cons = cq.get("consistency_level") or cq.get("consistency_classification") or p_details.get("consistency_classification")
        if cons not in ("STOPPED", "ATOMIC", "CONSISTENT") or p_details.get("is_non_atomic") is True:
            raise ValueError(f"Cannot attest causal proof: record '{evidence_id}' lacks atomic/stopped consistency '{cons}'")

        if rec.session_id and rec.session_id != self.session_id:
            raise ValueError(f"Cannot attest causal proof: record '{evidence_id}' belongs to session '{rec.session_id}', not '{self.session_id}'")

        # Stamp authentic internal attestation
        rec.provenance["verifier_attestation"] = {
            "token": self.session_secret,
            "investigation_id": self.session_id,
            "target_function": target_function,
            "field_path": field_path,
            "verification_type": verification_type,
            "attested_at": datetime.now(timezone.utc).isoformat(),
        }
        rec.details["verified_transition"] = True
        rec.details["causal_proof"] = True
        if target_function and "target_function" not in rec.details:
            rec.details["target_function"] = target_function
        if field_path and "field_path" not in rec.details:
            rec.details["field_path"] = field_path
        return True

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
        """Validate record structure, types, and consistency."""
        if not record.evidence_id or not isinstance(record.evidence_id, str) or not record.evidence_id.strip():
            raise ValueError("EvidenceRecord must have a valid non-empty string evidence_id")
        if not record.evidence_type or not isinstance(record.evidence_type, str) or record.evidence_type not in VALID_EVIDENCE_TYPES:
            raise ValueError(f"Invalid evidence_type '{record.evidence_type}'. Expected one of {sorted(VALID_EVIDENCE_TYPES)}")
        if not record.nature or record.nature not in VALID_NATURES:
            raise ValueError(f"Invalid nature '{record.nature}'. Expected one of {sorted(VALID_NATURES)}")
        if record.session_id is not None and (not isinstance(record.session_id, str) or not record.session_id.strip()):
            raise ValueError("session_id must be a non-empty string when provided")
        if record.finding_id is not None and (not isinstance(record.finding_id, str) or not record.finding_id.strip()):
            raise ValueError("finding_id must be a non-empty string when provided")
        if not isinstance(record.parent_evidence_ids, (list, tuple)):
            raise TypeError("parent_evidence_ids must be a list or tuple of strings")
        for pid in record.parent_evidence_ids:
            if not isinstance(pid, str) or not pid.strip():
                raise ValueError(f"Invalid parent_evidence_id '{pid}' in parent_evidence_ids: must be a non-empty string")
        if record.evidence_id in record.parent_evidence_ids:
            raise ValueError(f"Self-reference detected: record cannot have its own evidence_id '{record.evidence_id}' as a parent")
        for field_name, val in [
            ("snapshot_ref", record.snapshot_ref),
            ("target_identity", record.target_identity),
            ("capture_quality", record.capture_quality),
            ("object_observation", record.object_observation),
            ("field_observation", record.field_observation),
            ("static_code_link", record.static_code_link),
            ("comparison_observation", record.comparison_observation),
            ("provenance", record.provenance),
            ("details", record.details),
        ]:
            if val is not None and not isinstance(val, dict):
                raise TypeError(f"Field '{field_name}' must be a dictionary when provided, got {type(val).__name__}")

        # Invalidate unauthenticated or caller-forged verifier attestations
        if record.provenance and "verifier_attestation" in record.provenance:
            att = record.provenance.get("verifier_attestation")
            if not isinstance(att, dict) or att.get("token") != self.session_secret or att.get("investigation_id") != self.session_id:
                record.provenance["verifier_attestation"] = None
                record.provenance["attestation_rejected"] = "Invalid, unverified, or cross-session attestation token"

        # Disarm attestation if record is marked caller_submitted
        p_details = record.details or {}
        p_prov = record.provenance or {}
        if (
            p_details.get("caller_submitted") is True
            or p_details.get("unverified_caller_claim") is True
            or record.source == "unverified_caller"
            or p_prov.get("submission_channel") == "external_caller"
        ):
            if record.provenance:
                record.provenance["verifier_attestation"] = None

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

            if eid in rec.parent_evidence_ids:
                chain.append({
                    "evidence_id": eid,
                    "status": "SELF_REFERENCE",
                    "reason": f"Self-referencing parent found on evidence '{eid}'.",
                })
                return

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

