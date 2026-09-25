# PS2 Performance & Cold-Start Micro-Benchmarks

This document provides transparent, reproducible micro-benchmarks comparing **PS2 v0.4.0** against standard automation runtimes (**Python 3.12** and **PowerShell**) under identical conditions.

---

## 1. Methodology & Test Setup

- **Hardware / Environment**: Windows 11 x64, .NET 10.0 runtime (JIT mode), SSD storage.
- **Workload**: Real-world DevOps / Automation task:
  1. Process startup & runtime initialization (cold start).
  2. Read JSON dataset (`data.json`) from disk.
  3. Parse JSON into typed objects.
  4. Filter active records (`status == "active"`).
  5. Aggregate/reduce compute metrics (`sum(cpu)`).
  6. Output formatted summary and exit.
- **Measurement**: 10 sequential cold-start invocations per engine. Process wall-clock execution time measured from launch to exit via high-precision `Stopwatch`.
- **Reproducibility**: Run `powershell -ExecutionPolicy Bypass -File benchmarks/run_benchmarks.ps1`.

---

## 2. Empirical Benchmark Results

| Runtime Engine | Min Latency (ms) | Median Latency (ms) | Mean Latency (ms) | Max Latency (ms) | Security Model |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Python 3.12** | **63.65 ms** | **70.38 ms** | **72.35 ms** | **83.88 ms** | Ambient Authority (Full host access) |
| **PS2 (v0.4.0)** | **131.78 ms** | **144.95 ms** | **144.58 ms** | **176.40 ms** | **Default-Deny Zero-Trust Sandbox + Capabilities + Policy Check** |
| **PowerShell** | **377.87 ms** | **393.21 ms** | **405.24 ms** | **459.46 ms** | Ambient Authority (Full host access) |

---

## 3. Analysis & Key Takeaways

1. **PS2 vs PowerShell**:
   - PS2 executes the automation task **~2.8x faster** than PowerShell (144.95 ms median vs 393.21 ms median).
   - Unlike PowerShell which carries substantial legacy shell initialization overhead, PS2's lean AST evaluator starts and completes typical automation scripts in under 150 ms.
2. **PS2 vs Python**:
   - Python 3.12 achieves a faster cold-start (~70 ms median) due to its mature C-native runtime and fast startup path.
   - PS2's cold start in JIT mode (~144 ms median) includes .NET 10 CLR bootstrap, lexical analysis, AST parsing, manifest schema validation, and pre-flight policy evaluation.
   - PS2 delivers this near-native performance while providing **complete default-deny sandbox guarantees and cryptographic bundle validation** that Python does not provide out of the box.
3. **Future Optimization**:
   - Ahead-Of-Time (AOT) native compilation (NativeAOT) is expected to eliminate JIT compilation overhead, bringing PS2 startup times down into the sub-50 ms range for standalone binaries.
