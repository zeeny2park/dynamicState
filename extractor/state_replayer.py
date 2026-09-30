"""State Replayer: Live validation and execution replay of snapshot mutations.

Strictly separates:
- Replay capability (whether live process replay can be attempted)
- Replay attempted (whether replay was initiated)
- Replay completed (whether memory modification succeeded)
- Replay verified (whether read-back confirmation verified the exact state)
"""

from typing import Any, Dict, Optional


class StateReplayer:
    """Manages replay of offline snapshot mutations onto real target processes."""

    @staticmethod
    def replay(
        controller: Optional[Any],
        target_object_id: str,
        field_name: str,
        value: Any,
        timeout_ms: int = 2000
    ) -> Dict[str, Any]:
        """Attempt replay of a snapshot mutation onto a live process."""
        target_str = f"{target_object_id}.{field_name}" if field_name else target_object_id

        # 1. Capability check
        can_replay = False
        if controller is not None:
            if hasattr(controller, "is_attached") and controller.is_attached:
                can_replay = True
            elif hasattr(controller, "mutate"):
                can_replay = True

        if not can_replay:
            return {
                "capability": "UNAVAILABLE",
                "attempted": False,
                "completed": False,
                "verified": False,
                "verification_source": None,
                "target": target_str,
                "value": value,
                "error": "No active live execution controller attached to target process"
            }

        # 2. Attempt replay
        attempted = True
        completed = False
        verified = False
        verification_source = None
        error_msg = None

        try:
            # Perform mutation via controller
            res = controller.mutate(object_id=target_object_id, field_path=field_name, value=value)
            # Controller can return MutationResult or dict
            is_success = False
            if hasattr(res, "success"):
                is_success = res.success
                if not is_success and hasattr(res, "error"):
                    error_msg = str(res.error)
            elif isinstance(res, dict):
                is_success = res.get("success", False)
                if not is_success:
                    error_msg = res.get("error")

            if is_success:
                completed = True
                # 3. Readback Verification
                # Re-inspect field to ensure memory actually holds the proposed value
                try:
                    readback_field = controller.get_field(target_object_id, field_name) if hasattr(controller, "get_field") else None
                    if readback_field is not None:
                        current_val = getattr(readback_field, "value", None) or (readback_field.get("value") if isinstance(readback_field, dict) else None)
                        if str(current_val) == str(value):
                            verified = True
                            verification_source = "LIVE_MEMORY_READBACK_VERIFIED"
                except Exception:
                    pass

        except Exception as exc:
            error_msg = str(exc)

        return {
            "capability": "SUPPORTED",
            "attempted": attempted,
            "completed": completed,
            "verified": verified,
            "verification_source": verification_source,
            "target": target_str,
            "value": value,
            "error": error_msg
        }
