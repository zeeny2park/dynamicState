"""Backend-neutral mutation result and validation errors."""

from dataclasses import asdict, dataclass, field as dc_field
from typing import Any, Dict, Optional


@dataclass
class MutationResult:
    success: bool
    object_id: Optional[str] = None
    field: Optional[str] = None
    type: Optional[str] = None
    before: Any = None
    after: Any = None
    address: Optional[str] = None
    error: Optional[Dict[str, Any]] = None
    performance: Dict[str, float] = dc_field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def mutation_error(code: str, message: str, **details: Any) -> MutationResult:
    error = {"code": code, "message": message}
    error.update(details)
    return MutationResult(success=False, error=error)
