# Domain Entities: Diagnosis Accuracy & Hypothesis Budgeting (Unit 5)

> **Unit ID**: `unit-5-diagnosis-accuracy-budget`  

---

## 1. Domain Entities & DTOs

### 1.1 `StaticLocationCandidate`
```python
@dataclass
class StaticLocationCandidate:
    source_file: str
    line_number: int
    function_name: str
    reason: str
    basis: str = "static"
    observed: bool = False
```

### 1.2 `DiagnosticBudget`
```python
@dataclass
class DiagnosticBudget:
    total_budget_s: float
    elapsed_s: float
    remaining_s: float
    is_exhausted: bool
```
