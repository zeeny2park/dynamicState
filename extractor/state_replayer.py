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
    def get_mutation_capabilities(controller: Optional[Any] = None) -> Dict[str, bool]:
        """Distinguish semantic mutation from live process write and verification capabilities."""
        can_write_live = False
        can_verify_live = False
        if controller is not None:
            if hasattr(controller, "mutate"):
                can_write_live = True
            if hasattr(controller, "get_field"):
                can_verify_live = True

        return {
            "CAN_MUTATE_SEMANTIC_STATE": True,
            "CAN_WRITE_LIVE_PROCESS": can_write_live,
            "CAN_VERIFY_LIVE_WRITE": can_verify_live,
        }

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
        caps = StateReplayer.get_mutation_capabilities(controller)

        # 1. Capability check
        can_replay = caps["CAN_WRITE_LIVE_PROCESS"]

        if not can_replay:
            return {
                "capability": "UNAVAILABLE",
                "capabilities": caps,
                "mutation_type": "LIVE_PROCESS_MUTATION",
                "mutation_status": "NOT_ATTEMPTED",
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

        if not completed:
            mutation_status = "FAILED"
        elif verified:
            mutation_status = "APPLIED_VERIFIED"
        else:
            mutation_status = "APPLIED_UNVERIFIED"

        return {
            "capability": "SUPPORTED",
            "capabilities": caps,
            "mutation_type": "LIVE_PROCESS_MUTATION",
            "mutation_status": mutation_status,
            "attempted": attempted,
            "completed": completed,
            "verified": verified,
            "verification_source": verification_source,
            "target": target_str,
            "value": value,
            "error": error_msg
        }
