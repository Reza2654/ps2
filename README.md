# PowerScript 2 (`ps2`)

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)]()
[![Language](https://img.shields.io/badge/engine-C%23%2010%20%2F%20.NET%2010-purple)]()
[![Tests](https://img.shields.io/badge/tests-52%20passing-brightgreen)]()
[![Release](https://img.shields.io/badge/release-v0.3.0--beta-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

**PowerScript 2 (`ps2`)** is an enterprise-grade **Secure Automation Runtime** engineered from the ground up for zero-trust infrastructure automation, CI/CD pipelines, and secure cloud operations. Built in modern **C# (.NET 10)**, PS2 combines single-binary deployment with an unyielding **Default-Deny** capability sandbox, organizational policy governance, structured audit logging, and automated secret hygiene.

> 📖 Read the full architecture and security boundary documentation in [**docs/ARCHITECTURE.md**](docs/ARCHITECTURE.md).

---

## Why PS2? Secure Automation vs. Traditional Scripting

In conventional scripting environments (**Python**, **PowerShell**, **Bash**, **Node.js**), scripts execute with the full privileges of the host process. A compromised package dependency, stolen pipeline script, or prompt-injected AI agent script can silently:
- Dump critical credentials (`~/.ssh/id_rsa`, `~/.aws/credentials`, `%USERPROFILE%\.azure`).
- Exfiltrate infrastructure secrets over outbound HTTP sockets.
- Spawn unauthorized child processes (`powershell -c ...`, `curl -d ...`, crypto miners).
- Leak plaintext passwords and API keys into CI/CD build logs and console output.

**PS2 solves this fundamental supply-chain and automation vulnerability.** Every PS2 script starts with **zero privileges** (`Default Deny`). A script cannot touch a single file, resolve a network host, read an environment variable, or execute an external binary unless explicitly declared in its `#manifest` header and approved by organizational policy.

```
                      ┌──────────────────────────────────────────────┐
                      │        ps2 Secure Automation Runtime         │
                      │                                              │
                      │   ┌──────────────────────────────────────┐   │
                      │   │    Organizational Policy Engine      │   │
                      │   │  (default | strict | production)     │   │
                      │   └──────────────────┬───────────────────┘   │
                      │                      │ Pre-Flight Gate       │
                      │                      ▼                       │
                      │   ┌──────────────────────────────────────┐   │
                      │   │      Capability Manifest v1.0        │   │
                      │   │  requires { fs.read, net.http, ... } │   │
                      │   └──────────────────┬───────────────────┘   │
                      │                      │ Checked on Every Call │
                      │                      ▼                       │
                      │   ┌──────────────────────────────────────┐   │
                      │   │       Zero-Trust Sandbox Gate        │   │
                      │   └──────┬────────────────────────┬──────┘   │
                      └──────────┼────────────────────────┼──────────┘
                                 │                        │
                       [Allowed Operation]      [Unauthorized Access]
                                 │                        │
                                 ▼                        ▼
                        Safe System Call        🛡️ Ps2SecurityException
                        (File / Net / Env)       + Structured Audit Event (DENY)
                                 │
                                 ▼
                     Structured Audit Log (ALLOW)
```

---

## Key Features & Enterprise Capabilities

- 🛡️ **Default-Deny Sandbox**: Filesystem, network, environment variables, and process execution are disabled by default.
- 🏢 **Organizational Policy Engine**: Enforce cluster-wide security policies (`production`, `strict`, or custom JSON) with pre-flight AST validation before any statement runs.
- 📜 **Versioned Capability Manifest (`version: "1.0"`)**: Transparent, auditable permission declarations validated prior to runtime evaluation.
- 🔍 **Structured JSON Audit Logging**: High-throughput audit trail recording every ALLOW and DENY authorization decision with timestamps, operations, resources, and script identities (SOC2/ISO27001 ready).
- 🔒 **Native Secret Hygiene**: Dedicated `Ps2Secret` type masking values as `[REDACTED]` in console logs, string conversions, and JSON serialization. Automatic scrubbing of secret values from runtime exception messages and stack traces.
- 🔀 **Declarative Pipelines (`|>`)**: Expressive, functional data transformations over structured JSON, arrays, maps, and streams.
- 🧱 **Algebraic Data Types & Safety**: Native `Option<T>` (`Some(val)`, `None`), `Result<T, E>` (`Ok(val)`, `Err(err)`), and exhaustive `match` expressions.
- 📦 **Tamper-Evident Bundling**: Package scripts and assets into self-contained `.ps2bundle` files with cryptographic SHA-256 integrity validation.
- 🛠️ **Full CLI Tooling**: `run`, `check`, `init`, `fmt`, `lint`, `bundle`, `sign`, `verify`, and native Windows file association registration (`register`).

---

## Language Tour

### 1. Versioned Capability Manifest
```ps2
#manifest
requires {
    version: "1.0",
    fs.read: ["./config", "./data"],
    fs.write: ["./reports"],
    net.http: ["api.internal.company.com"],
    env: ["DEPLOY_ENV", "API_SECRET_TOKEN"],
    proc.exec: ["git"]
}
#endmanifest

// Accessing environment variable safely
let env = unwrap_or(sys.env("DEPLOY_ENV"), "production");
println("Deploying to: " + env);

// Reading a secret (never printed in plaintext!)
let secretToken = unwrap(sys.secret("API_SECRET_TOKEN"));
println("Token loaded: " + secretToken); // Output: Token loaded: [REDACTED]
```

### 2. Functional Pipelines (`|>`) and JSON
```ps2
let rawMetrics = "[{\"service\": \"api\", \"latency_ms\": 45}, {\"service\": \"worker\", \"latency_ms\": 120}]";

let slowServices = rawMetrics
    |> json.parse()
    |> filter(s => s["latency_ms"] > 50)
    |> map(s => s["service"]);

println("Slow services: " + json.stringify(slowServices));
```

### 3. Algebraic Data Types (`Option` & `Result`)
```ps2
fn fetch_record(id: int) {
    if id <= 0 {
        return Err("Invalid record ID");
    }
    return Ok({ "id": id, "status": "active" });
}

match fetch_record(42) {
    Ok(rec) => println("Loaded record for: " + rec["id"]),
    Err(e)  => println("Query failed: " + e)
}
```

---

## Enterprise Policy Enforcement

Enforce organizational boundaries on scripts without modifying code:

```bash
# Run with Production policy (blocks process execution, external network, critical system directories)
ps2 run deploy.ps2 --policy production

# Run with custom JSON corporate policy
ps2 run deploy.ps2 --policy ./corporate-policy.json

# Pre-flight compliance audit without executing
ps2 check deploy.ps2 --policy production
```

### Sample Policy Output on Unauthorized Script
```
[SECURITY POLICY VIOLATION] Policy 'production' blocked proc.exec:
  Resource: powershell.exe
  Reason:   Policy 'production' prohibits process execution, but manifest requests execution of: [powershell.exe].
```

---

## Structured Audit Logging

Generate machine-readable JSON Lines audit trails for SIEM ingestion (Splunk, Datadog, Elastic):

```bash
ps2 run deploy.ps2 --audit-log /var/log/ps2/audit.jsonl
```

Sample audit log output:
```json
{"timestamp":"2026-09-25T16:55:00.123Z","script_identity":"deploy.ps2","operation":"fs.read","resource":"C:/app/config.json","decision":"ALLOW","reason":"Capability granted by manifest"}
{"timestamp":"2026-09-25T16:55:00.125Z","script_identity":"deploy.ps2","operation":"proc.exec","resource":"cmd.exe","decision":"DENY","reason":"Missing capability declaration in manifest"}
```

---

## CLI Reference

| Command | Description | Example |
| :--- | :--- | :--- |
| `ps2` | Start interactive REPL shell | `ps2` |
| `ps2 run <file>` | Run script with Zero-Trust sandbox | `ps2 run main.ps2 --policy production` |
| `ps2 check <file>` | Verify signature, syntax, capabilities & policy | `ps2 check main.ps2 --policy strict` |
| `ps2 init [name]` | Initialize starter PS2 project template | `ps2 init my_automation` |
| `ps2 fmt <file>` | Format source according to official style | `ps2 fmt main.ps2 --check` |
| `ps2 lint <file>` | Static analysis for undeclared permissions | `ps2 lint main.ps2` |
| `ps2 bundle <file>`| Package script and assets into `.ps2bundle` | `ps2 bundle main.ps2 -o app.ps2bundle` |
| `ps2 sign <file>` | Embed SHA-256 integrity hash header | `ps2 sign main.ps2` |
| `ps2 verify <file>`| Verify embedded cryptographic signature | `ps2 verify main.ps2` |
| `ps2 register` | Register `.ps2` Windows file association | `ps2 register` |
| `ps2 unregister` | Unregister `.ps2` Windows file association | `ps2 unregister` |

---

## Testing & Verification

Run the full automated test suite:

```bash
dotnet test
```

**52 Passing Automated Tests** (100% passing):
- Default-Deny capability enforcement across all operations (`fs.read`, `fs.write`, `net.http`, `env`, `proc.exec`)
- Pre-flight organizational policy enforcement (`default`, `strict`, `production`, and custom JSON)
- Structured audit event logging (ALLOW and DENY trails with metadata)
- Secret masking, redaction in JSON serialization, and exception message scrubbing
- Windows ADS (`::$DATA`) stripping, directory subtree escapes, and SSRF redirect hops
- Bundling, cryptographic signing, formatting, and linting
