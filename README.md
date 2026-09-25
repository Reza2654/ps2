# PowerScript 2 (`ps2`)

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)]()
[![Language](https://img.shields.io/badge/engine-C%23%2010%20%2F%20.NET%2010-purple)]()
[![Tests](https://img.shields.io/badge/tests-37%20passing-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

**PowerScript 2 (`ps2`)** is a next-generation, high-performance, **Zero-Trust** scripting language and execution engine. Built entirely in modern **C# (.NET 10)** with single-binary distribution, declarative pipeline operators (`|>`), algebraic null safety (`Option<T>`, `Result<T, E>`), and an unyielding capability-based security sandbox.

---

## Why PS2? Zero-Trust vs. Traditional Scripting

In traditional scripting environments (**Python**, **PowerShell**, **Bash**, **Node.js**), any imported script or downloaded utility executes with the **full privileges of the current user**. A simple `pip` dependency or administrative helper script can silently:
- Read confidential credentials (`~/.ssh/id_rsa`, `~/.aws/credentials`, `%USERPROFILE%\.azure`).
- Open arbitrary outbound sockets to exfiltrate company data (C2 telemetry).
- Spawn unauthorized background subprocesses or crypto miners.

**PS2 fundamentally solves this supply-chain and automation vulnerability.** Every PS2 script starts with **zero privileges** (`Default Deny`). A script cannot touch a single file, resolve a network host, read an environment variable, or execute an external binary unless explicitly declared in its `#manifest` header.

```
                      ┌──────────────────────────────────────────────┐
                      │             ps2 Execution Engine             │
                      │                                              │
                      │   ┌──────────────────────────────────────┐   │
                      │   │       Capability Manifest            │   │
                      │   │  requires { fs.read: ["./data"] }    │   │
                      │   └──────────────────┬───────────────────┘   │
                      │                      │                       │
                      │           Checked at Runtime                 │
                      │                      ▼                       │
                      │   ┌──────────────────────────────────────┐   │
                      │   │        Zero-Trust Sandbox Gate       │   │
                      │   └──────┬────────────────────────┬──────┘   │
                      └──────────┼────────────────────────┼──────────┘
                                 │                        │
                       [Allowed Target]         [Unauthorized Access]
                                 │                        │
                                 ▼                        ▼
                        Operating System        🛡️ Ps2SecurityException
                       (File / Net / Proc)      with Rich Rust-Style Diagnostics
```

---

## Key Highlights

- 🛡️ **Zero-Trust Security Sandbox**: Scripts run with zero privileges by default. Unauthorized disk writes, socket connections, environment reads, and process executions are blocked before touching the OS.
- 📜 **Declarative Capability Manifest**: Permissions are transparently auditable at the top of the file:
  `#manifest requires { fs.read: [...], net.http: [...] } #endmanifest`.
- ⚡ **Lightning Fast & Self-Contained**: Powered by modern C# (.NET 10) with single-file native binaries (`ps2.exe`) for instant startup.
- 💻 **Interactive REPL**: Rich interactive shell with line history, ANSI color output, and multi-turn evaluation.
- 🔀 **Declarative Pipe Operator (`|>`)**: Smooth, functional data transformations over structured JSON, arrays, maps, and streams.
- 🧱 **Algebraic Data Types & Pattern Matching**: Native `Option<T>` (`Some(val)`, `None`), `Result<T, E>` (`Ok(val)`, `Err(err)`), and expressive `match` expressions.
- 🛠️ **First-Class Developer Tooling**:
  - `ps2 init <name>`: Scaffold new PS2 projects instantly.
  - `ps2 fmt <file> [--check]`: Canonical code formatter.
  - `ps2 lint <file>`: Static analysis for undeclared capabilities, unused variables, and unreachable code.
  - `ps2 check <file>`: Full diagnostic report on signature, syntax, capabilities, and linting.
  - `ps2 bundle <file> -o <bundle>`: Self-contained, tamper-evident deployment packages.
  - `ps2 sign` & `ps2 verify`: Cryptographic SHA-256 integrity validation.
- 🪟 **Deep OS Integration**:
  - **Windows**: Native registry association (`.ps2` -> `ps2.exe run "%1" %*`) via `ps2 register`.
  - **Unix / macOS**: Full Shebang support (`#!/usr/bin/env ps2`).

---

## Architectural Structure

```
ps2/
├── src/
│   ├── Ps2.Core/       # AST Nodes, Tokens, Value System, Manifest, Formatter, Linter & Diagnostics
│   ├── Ps2.Parser/     # Zero-allocation Lexer, AST Parser, Capability Manifest Parser
│   ├── Ps2.Runtime/    # Execution Evaluator, Zero-Trust Sandbox Gate, Pipeline Engine, StdLib, REPL
│   ├── Ps2.Bundler/    # Package Bundler (.ps2bundle) & SHA-256 Script Signer
│   └── Ps2.Cli/        # Command-line interface & Windows Registry integration
├── tests/
│   └── Ps2.Tests/      # 37 Unit, Integration, Adversarial & Tooling Tests (100% passing)
├── extensions/
│   └── vscode/         # Official VS Code Extension (syntax grammar, snippets, tooling)
├── examples/           # Ready-to-run demo scripts
└── distribution/       # Packaging manifests
```

---

## Language Tour

### 1. Capability Manifest (Zero-Trust Sandbox)
```ps2
#manifest
requires {
    fs.read: ["./data"],
    fs.write: ["./out.json"],
    net.http: ["api.github.com"],
    env: ["USERNAME", "TOKEN"],
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

println("Critical nodes: " + json.stringify(critical_servers));
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

## High-Clarity Rust-Style Diagnostics

When an error or security violation occurs, PS2 produces high-clarity diagnostics pinpointing the exact line and column with source previews and actionable suggestions:

```
error[PS2_SECURITY]: [Zero-Trust Sandbox] Read access denied to '/etc/shadow'.
  --> scripts/backup.ps2:5:14
   |
 4 | let target = "/etc/shadow";
 5 | let data = fs.read_file(target);
   |            ^
   = help: Declare permission in '#manifest requires { fs.read: ["/etc/shadow"] }' or run with --allow-all.
```

---

## CLI Guide

| Command | Description | Example |
| :--- | :--- | :--- |
| `ps2` | Start interactive REPL shell | `ps2` |
| `ps2 run <file>` | Run script or bundle in sandbox | `ps2 run main.ps2 --allow-all` |
| `ps2 init [name]` | Initialize starter PS2 project template | `ps2 init my_automation` |
| `ps2 fmt <file>` | Format source according to official style | `ps2 fmt main.ps2 --check` |
| `ps2 lint <file>` | Static analysis for undeclared permissions | `ps2 lint main.ps2` |
| `ps2 check <file>` | Verify signature, syntax, capabilities | `ps2 check main.ps2` |
| `ps2 bundle <file>`| Package script and assets into bundle | `ps2 bundle main.ps2 -o app.ps2bundle` |
| `ps2 sign <file>` | Embed SHA-256 integrity hash header | `ps2 sign main.ps2` |
| `ps2 verify <file>`| Verify embedded cryptographic signature | `ps2 verify main.ps2` |
| `ps2 register` | Register `.ps2` Windows file association | `ps2 register` |
| `ps2 unregister` | Unregister `.ps2` Windows file association | `ps2 unregister` |

---

## Security Hardening Details

1. **Path Canonicalization & Directory Boundary Defense**:
   All filesystem access is resolved via `ResolveCanonicalPath`, stripping Windows Alternate Data Streams (`::$DATA`) and traversing symbolic escapes (`../`). Directory permissions require trailing slash or directory existence to prevent partial name collisions (e.g. `/allowed` vs `/allowed_unauthorized`).
2. **Process Argument Injection Defense**:
   Subprocess execution in `sys.exec` uses `psi.ArgumentList` rather than concatenated shell strings, eliminating argument injection and shell metacharacter vulnerabilities.
3. **SSRF & HTTP Redirect Validation**:
   `net.http_get` and `net.http_post` disable automatic redirects (`AllowAutoRedirect = false`). Each redirect hop is explicitly checked against the capability whitelist before following. Non-HTTP/HTTPS protocols (`file://`, `gopher://`) are strictly rejected.

---

## Verification & Testing

Run the full test suite with:

```bash
dotnet test
```

**37 Unit & Adversarial Tests** (100% passing):
- Lexer tokenization & shebang parsing
- Manifest parsing & grammar syntax validation
- Sandbox access restrictions (file read/write denial, network denial, path traversal protection)
- Adversarial attack tests (Windows ADS `::$DATA`, prefix collision, argument injection, SSRF redirect)
- Pipeline operator (`|>`) transformations
- Option & Result algebraic pattern matching
- Cryptographic SHA-256 signing and bundle tamper detection
- Diagnostic rendering with pointer carets
- Formatter canonicalization and Linter capability/unused variable detection
- CLI end-to-end integration (`init`, `fmt`, `lint`)
