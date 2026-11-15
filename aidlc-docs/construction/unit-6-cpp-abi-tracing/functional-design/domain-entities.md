# Domain Entities: C++ STL Decoders & Cross-ABI Tracing (Unit 6)

> **Unit ID**: `unit-6-cpp-abi-tracing`  

---

## 1. Domain Entities & DTOs

### 1.1 `CppContainerLayout`
```python
@dataclass
class CppContainerLayout:
    container_type: str  # std::vector, std::map, etc.
    size: int
    capacity: int
    element_type: str
    is_corrupted: bool
    elements: List[Any]
```

### 1.2 `TracingLifecycleState`
- `ATTACHING` -> `ATTACHED` -> `DETACHING` -> `DETACHED`
