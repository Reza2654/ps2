# PowerScript 2 (`ps2`)

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)]()
[![Language](https://img.shields.io/badge/engine-C%23%2010%20%2F%20.NET%2010-purple)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

**PowerScript 2 (`ps2`)** is a next-generation, high-performance, **Zero-Trust** scripting language and execution engine. Built entirely in modern **C# (.NET 10)** with ahead-of-time execution, single-binary distribution, declarative pipeline operators (`|>`), algebraic null safety (`Option<T>`, `Result<T, E>`), and an unyielding capability-based sandbox.

---

## Key Highlights

- 🛡️ **Zero-Trust Security Sandbox**: Scripts run with zero privileges by default. Unauthorized disk writes, socket connections, environment reads, and process executions are blocked before touching the OS.
- 📜 **Capability Manifest**: Scripts explicitly declare permissions at the top level (`#manifest requires { ... } #endmanifest`).
- ⚡ **Lightning Fast & Self-Contained**: Implemented in modern C# (.NET 10) with support for single-file native binaries (`PublishSingleFile=true`, Native AOT) for instant startup.
- 🔀 **Declarative Pipe Operator (`|>`)**: Smooth, functional data transformations over structured JSON, arrays, maps, and streams.
- 🛡️ **Compile-Time Null Safety & ADTs**: Native `Option<T>` (`Some(val)`, `None`), `Result<T, E>` (`Ok(val)`, `Err(err)`), and expressive `match` pattern matching.
- 📦 **Redistributable Self-Contained Bundles**: Package scripts and assets into `.ps2bundle` files with embedded SHA-256 integrity checksums.
- 🪟 **Deep OS Integration**:
  - **Windows**: Native registry association (`.ps2` -> `ps2.exe run "%1" %*`) via `ps2 register`.
  - **Unix / macOS**: Full Shebang support (`#!/usr/bin/env ps2`).

---

## Architectural Structure

```
ps2/
├── src/
│   ├── Ps2.Core/       # AST Nodes, Tokens, Value System, Capability Manifest & Security Exception
│   ├── Ps2.Parser/     # Zero-allocation Lexer, AST Parser, Capability Manifest Parser
│   ├── Ps2.Runtime/    # Execution Engine, Zero-Trust Sandbox Manager, Pipeline (|>) Engine, Standard Library
│   ├── Ps2.Bundler/    # Package Bundler (.ps2bundle) & SHA-256 Script Signer
│   └── Ps2.Cli/        # Command-line interface & Windows Registry integration
├── tests/
│   └── Ps2.Tests/      # 17 Unit & Integration Tests (100% passing)
├── examples/           # Ready-to-run demo scripts
└── distribution/       # Winget package manifest
```

---

## Syntax & Language Tour

### 1. Capability Manifest (Zero-Trust Sandbox)
```ps2
#manifest
requires {
    fs.read: ["./data", "C:/Logs"],
    fs.write: ["./sandbox_out.json"],
    net.http: ["api.github.com"],
    env: ["USERNAME", "PATH"],
    proc.exec: ["git"]
}
#endmanifest

let user = match sys.env("USERNAME") {
    Some(u) => u,
    None => "Guest"
};

println("Authenticated user: " + user);
```

### 2. Declarative Pipelines (`|>`)
```ps2
let raw_data = "[{\"name\": \"Alpha\", \"load\": 85}, {\"name\": \"Beta\", \"load\": 42}]";

let critical_servers = raw_data
    |> json.parse()
    |> filter(s => s["load"] > 80)
    |> map(s => s["name"]);

println("Critical nodes: " + critical_servers);
```

### 3. Algebraic Data Types (`Option` & `Result`) & Pattern Matching
```ps2
fn divide(a: float, b: float) {
    if b == 0.0 {
        return Err("Division by zero!");
    }
    return Ok(a / b);
}

let result = divide(100.0, 4.0);

match result {
    Ok(val) => println("Result: " + val),
    Err(e)  => println("Calculation error: " + e)
}
```

---

## CLI Usage

```bash
# Execute a script
ps2 run script.ps2

# Execute with arguments
ps2 run script.ps2 arg1 arg2

# Statically check syntax and inspect capability manifest
ps2 check script.ps2

# Sign a script with cryptographic SHA-256 integrity hash
ps2 sign script.ps2

# Verify script signature
ps2 verify script.ps2

# Package script and assets into a redistributable bundle
ps2 bundle script.ps2 -o myapp.ps2bundle --include config.json data.csv

# Execute a bundle directly
ps2 run myapp.ps2bundle

# Register .ps2 extension in Windows Registry (run on double-click)
ps2 register

# Remove Windows Registry association
ps2 unregister
```

---

## Verification & Testing

To run the complete test suite:

```bash
dotnet test
```

All 17 tests cover:
- Lexer tokenization & Shebang parsing
- Manifest parsing & grammar syntax validation
- Sandbox access restrictions (file read/write denial, network denial, path traversal protection)
- Pipeline operator (`|>`) transformations
- Option & Result algebraic pattern matching
- Cryptographic SHA-256 signing and bundle tamper detection
