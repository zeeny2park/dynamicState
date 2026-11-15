# Domain Entities: Report Equivalence, MCP Contracts & Clean Benchmark (Unit 7)

> **Unit ID**: `unit-7-report-mcp-benchmark`  

---

## 1. Domain Entities & DTOs

### 1.1 `ReportStory`
- `verdict`: str
- `confidence`: float
- `summary_narrative`: str
- `timeline_steps`: List[Dict[str, Any]]
- `evidence_links`: Dict[str, str]

### 1.2 `BenchmarkResult`
- `commit`: str
- `arch`: str
- `detected_ratio`: str
- `false_positives`: int
- `diagnose_time_mean_s`: float
