"""Backend-neutral semantic object graph construction.

The supplied backend is the only component allowed to handle runtime values.
It provides GDB-specific reading, address, dereference and field operations.
"""

from .runtime_state import FieldState, ObjectState, RootState, VariableState


class ObjectGraphBuilder:
    MAX_OBJECT_DEPTH = 8
    MAX_POINTER_DEREFERENCE = 1

    def __init__(self, backend, type_resolver, max_object_depth=None, memory_maps=None):
        self.backend = backend
        self.types = type_resolver
        self.max_object_depth = max_object_depth or self.MAX_OBJECT_DEPTH
        self._objects = []
        self._by_identity = {}
        self.memory_maps = memory_maps
        self.roots = []
        self.max_depth_reached = 0
        self.cycles_detected = 0
        self.unreadable_objects = 0
        self._active_identities = set()

    @property
    def objects(self):
        return self._objects

    def variable(self, name, value, storage="unknown", context=None):
        """Convert a runtime value to a VariableState and connect objects."""
        info = self._value_info(value, storage, 0, context)
        return VariableState(name=name, **info)

    def add_root(self, name, source, variable, **metadata):
        """Register semantic roots without retaining a backend value."""
        if not variable.object_ref:
            return
        root = RootState(root_id="root_{:04d}".format(len(self.roots) + 1), name=name,
                         source=source, type=variable.type, address=variable.address,
                         object_ref=variable.object_ref, **metadata)
        self.roots.append(root)

    def _value_info(self, value, storage, depth, context=None):
        try:
            value_type = self.backend.value_type(value)
            kind = self.types.kind(value_type)
            result = {
                "type": self.types.display_name(value_type),
                "value": self.backend.primitive_value(value, kind),
                "address": self.backend.value_address(value),
            }
            if kind in ("pointer", "reference"):
                result["value"] = self.backend.pointer_text(value)
                # For pointers the useful address is the pointed-to address,
                # not the stack slot which stores the pointer itself.
                result["address"] = result["value"]
                target, error = self.backend.dereference(value)
                if error:
                    result["object_ref"] = None
                    result["error"] = error
                elif target is None:
                    result["object_ref"] = None
                else:
                    # Each pointer is dereferenced once. Object expansion is
                    # independently bounded by MAX_OBJECT_DEPTH.
                    if depth + 1 > self.max_object_depth:
                        result["object_ref"] = None
                        result["traversal"] = {"status": "depth_limit"}
                    elif self.types.kind(self.backend.value_type(target)) != "aggregate":
                        # Phase 2 does not infer raw array lengths or scan raw
                        # memory. A char*/int* remains an observed typed edge
                        # but is not promoted to a fabricated object node.
                        result["object_ref"] = None
                        result["traversal"] = {"status": "unsupported",
                                               "reason": "non_aggregate_target"}
                    else:
                        result["object_ref"] = self._object_for(target, storage, depth + 1, context)
            elif kind == "aggregate":
                result["object_ref"] = self._object_for(value, storage, depth, context)
            return self._drop_none(result)
        except Exception as exc:
            return {"type": "<unknown>", "value": None,
                    "availability": self.backend.availability(exc), "error": str(exc)}

    def _object_for(self, value, storage, depth, context=None):
        if depth > self.max_object_depth:
            return None
        value_type = self.backend.value_type(value)
        canonical = self.types.canonical_name(value_type)
        address = self.backend.object_address(value)
        if address is None:
            # An addressless temporary cannot safely participate in identity.
            return None
        identity = (address, canonical)
        existing = self._by_identity.get(identity)
        if existing:
            if identity in self._active_identities:
                self.cycles_detected += 1
            return existing.object_id
        self.max_depth_reached = max(self.max_depth_reached, depth)
        object_id = "obj_{:04d}".format(len(self._objects) + 1)
        classified = self.memory_maps.classify(address) if self.memory_maps else "unknown"
        obj = ObjectState(object_id=object_id, type=canonical, address=address,
                          storage=classified if classified != "unknown" else storage,
                          thread_id=(context or {}).get("thread_id"),
                          frame_level=(context or {}).get("frame_level"))
        # Register before fields: this is the cycle guard.
        self._by_identity[identity] = obj
        self._objects.append(obj)
        self._active_identities.add(identity)
        try:
            for field in self.backend.fields(value):
                if field.get("is_base_class"):
                    continue
                name = field["name"]
                try:
                    child = field["value"]
                    info = self._value_info(child, "unknown", depth, context)
                    obj.fields.append(FieldState(name=name, offset=field.get("offset"), **info))
                except Exception as exc:
                    obj.fields.append(FieldState(name=name, type=field.get("type", "<unknown>"),
                                                 availability=self.backend.availability(exc), error=str(exc)))
        except Exception as exc:
            obj.error = str(exc)
            self.unreadable_objects += 1
        finally:
            self._active_identities.discard(identity)
        return object_id

    @staticmethod
    def _drop_none(data):
        # ``null`` is meaningful for a null/unexpanded pointer target.
        return {key: value for key, value in data.items()
                if value is not None or key == "object_ref"}
