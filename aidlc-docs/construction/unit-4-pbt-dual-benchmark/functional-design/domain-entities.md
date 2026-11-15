# Domain Entities: PBT Invariants & Clean Benchmark Verification (Unit 4)

> **Unit ID**: `unit-4-pbt-dual-benchmark`  

---

## 1. Domain Entities & Value Objects

### 1.1 `BenchmarkMetadata`
- `commit_sha`: str (40자 git SHA)
- `git_dirty`: bool (반드시 False)
- `architecture`: str (`aarch64` 또는 `x86_64`)
- `timestamp`: str (ISO 8601 UTC)
- `target_count`: int
- `verdict_agreement_rate`: float

### 1.2 `PBTInvariantReport`
- `seed`: int (42)
- `examples_run`: int (>= 100)
- `invariants_checked`: List[str]
- `status`: str (`PASS` / `FAIL`)
