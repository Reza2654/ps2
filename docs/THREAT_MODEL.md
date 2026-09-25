# PS2 Formal Threat Model & Security Assurance

This document outlines the formal threat model, security boundaries, attack vectors, mitigations, and automated verification tests for **PS2 (PowerScript 2) v0.4.0**.

---

## 1. Zero-Trust Philosophy & Security Invariant

### Core Invariant
> **The PS2 Security Invariant**: *No OS-sensitive operation (filesystem I/O, network egress, process execution, or environment variable access) may reach the host operating system unless it has passed the capability validation and active organizational policy enforcement layer.*

PS2 assumes all user scripts, third-party libraries, and automation manifests are potentially untrusted or compromised. Every script begins in a **Default-Deny** state:
- No file reading or writing without explicit paths or directories in `#manifest`.
- No outbound network connections without explicit hostnames in `#manifest`.
- No process executions without explicit binary allowlisting in `#manifest`.
- No environment access without explicit variable declarations in `#manifest`.
- No bypass of organizational policy in production (`--allow-all` is strictly prohibited in `production` and `strict` policies).

---

## 2. Security Enforcement Architecture

```
                          PS2 Multi-Layer Security Architecture
 ┌──────────────────────┐
 │ PS2 Source / Bundle  │
 └──────────┬───────────┘
            │  1. Parse & Verify Integrity
            ▼
 ┌──────────────────────┐      Fail
 │ Script Signer /      │ ───────────────> Reject Execution (Invalid Signature / Corrupted Bundle)
 │ Bundle Verifier      │
 └──────────┬───────────┘
            │  Pass
            ▼
 ┌──────────────────────┐      Fail
 │ PolicyEngine         │ ───────────────> Terminate Execution (Exit Code 126, Zero Statements Run)
 │ Pre-Flight Gate      │
 └──────────┬───────────┘
            │  Pass
            ▼
 ┌──────────────────────┐
 │ Runtime Evaluator    │
 │ (Secret-Scrubbed)    │
 └──────────┬───────────┘
            │
    Calls OS Operation
            ▼
 ┌──────────────────────┐      Fail        ┌──────────────────────────────────────┐
 │ CapabilityManifest   │ ───────────────> │ AuditLogger: DENY Event (UUID, v1.0) │ ──> Throw Ps2SecurityException
 │ Enforcement Gate     │                  └──────────────────────────────────────┘
 └──────────┬───────────┘
            │  Pass
            ▼
 ┌──────────────────────────────────────┐
 │ AuditLogger: ALLOW Event             │
 └──────────┬───────────────────────────┘
            ▼
 ┌──────────────────────────────────────┐
 │ Safe OS API Execution                │
 └──────────────────────────────────────┘
```

---

## 3. Formal Threat Matrix

| Threat ID | Threat & Attack Surface | Security Boundary | Runtime Mitigation | Automated Regression Test |
| :--- | :--- | :--- | :--- | :--- |
| **T-01** | **Path Traversal (`../`)**<br>Attacker attempts to escape allowed directory via relative traversal components. | Filesystem | Path is canonicalized via `ResolveCanonicalPath` to full normalized path before capability prefix verification. | `Defense_PathTraversal_ShouldBeDenied`<br>`Invariant_FsReadFile_BlockedWithoutCapability` |
| **T-02** | **UNC / SMB NTLM Leakage**<br>Attacker references `\\attacker-host\share` or `//host/share` to steal Windows NetNTLM hashes or access unauthorized network shares. | Filesystem | `ResolveCanonicalPath` rejects any path starting with `\\`, `//`, `\/`, or `/\`. | `Defense_UNC_Paths_ShouldBeRejected` |
| **T-03** | **DOS Device Hang / Crash**<br>Attacker passes `CON`, `NUL`, `AUX`, `PRN`, `COM1..9`, `LPT1..9` to hang Windows process. | Filesystem | Segment inspection detects and blocks all legacy DOS device names (with or without extension). | `Defense_DosDeviceNames_ShouldBeRejected` |
| **T-04** | **Alternate Data Streams (ADS)**<br>Attacker uses `file.txt:hidden_stream` or `::$DATA` to hide payloads or bypass exact filename matches. | Filesystem | Colons are rejected except for valid Windows drive letters (`C:\`); `::$DATA` suffix is stripped before path validation. | `Defense_AlternateDataStreams_CustomStream_ShouldBeRejected`<br>`Defense_WindowsADS_ShouldNotBypassSandbox` |
| **T-05** | **Symlink / Junction Escape**<br>Attacker creates a symlink inside an allowed folder pointing to an unauthorized directory (`/etc` or `C:\Windows`). | Filesystem | `IsPathMatching` resolves the underlying link target via `FileSystemInfo.ResolveLinkTarget` and verifies that BOTH the reference and the target satisfy allowed patterns. | `Defense_Symlink_Escape_ShouldBeBlocked` |
| **T-06** | **OS Case-Sensitivity Evasion**<br>Attacker relies on Linux case sensitivity to bypass prefix match or Windows case insensitivity. | Filesystem | OS-aware comparison: `Ordinal` on Linux, `OrdinalIgnoreCase` on Windows/macOS. | `Defense_DirectoryPrefixCollisions_ShouldBeDenied` |
| **T-07** | **SSRF & Cloud Metadata Theft**<br>Attacker attempts to query AWS/GCP/Azure instance metadata (`169.254.169.254`, `[fd00:ec2::254]`, `metadata.google.internal`). | Network | `IsCloudMetadataEndpoint` detects link-local IPv4, IPv6, and cloud DNS aliases, blocking requests unconditionally. | `Defense_Cloud_Metadata_SSRF_ShouldBeBlocked` |
| **T-08** | **HTTP Open Redirect Bypass**<br>Attacker queries an authorized server that redirects (301/302/307) to an unauthorized server. | Network | `SendHttpRequestWithValidatedRedirects` disables auto-redirect in `HttpClient` and re-evaluates `EnsureNetHttpAllowed` at every redirect hop. | `SendHttpRequestWithValidatedRedirects`<br>`StandardLibrary.cs` |
| **T-09** | **Command / Shell Injection**<br>Attacker passes spaces, semicolons, pipes (`\|`), or ampersands (`&`) in process arguments. | Process Execution | Processes are started directly with discrete `ProcessStartInfo.ArgumentList` array; no shell (`cmd.exe /c` or `sh -c`) is spawned. | `Defense_ProcExec_ArgumentListSafelyPassesSpacesWithoutInjection` |
| **T-10** | **Credential & Env Theft**<br>Attacker attempts to read environment variables (`AWS_SECRET_ACCESS_KEY`, `PATH`). | Environment | `EnsureEnvAllowed` enforces manifest declaration. In `production`, critical cloud credentials are hard-blocked by policy. | `Defense_ProcessExecutionWithoutPermission_ShouldThrowSecurityException`<br>`Invariant_SysEnv_BlockedWithoutCapability` |
| **T-11** | **Secret Leakage in Output / Logs**<br>Attacker tries to print secrets via string concatenation (`"key: " + secret`), collections (`[secret]`, `{"k": secret}`), JSON stringification, or stack traces. | Secret Model | `Ps2Secret` overrides `ToString()` to return `[REDACTED]`; `EvaluatorSecretScrubber` scrubs registered secrets from unhandled exception messages, console output, and audit logs. | `Defense_SecretModel_NeverLeaksInConcatenationOrCollections`<br>`Defense_AuditLog_ContainsUuidAndSchemaVersionAndZeroSecrets` |
| **T-12** | **Production Policy Override**<br>Operator or attacker passes `--allow-all` to bypass security controls in a production environment. | Policy Engine | `PolicyEngine` enforces `DisallowAllowAll`. If set, `--allow-all` is aborted before execution with exit code 126. | `Defense_AllowAll_InProductionPolicy_ShouldBeRejected`<br>`Defense_AllowAll_InStrictPolicy_ShouldBeRejected` |
| **T-13** | **Bundle Tampering & Bit-Flipping**<br>Attacker modifies payload bytes or ZIP archive inside a `.ps2bundle`. | Bundler & Crypto | Header SHA-256 is verified against payload hash before decompression; payload mismatch throws cryptographic exception. | `Defense_BundleTampering_PayloadMismatch_ThrowsCryptographicException` |
| **T-14** | **Script Signature Forgery**<br>Attacker tampers with script code while retaining an older `#signature:`. | Script Signer | SHA-256 digest is recomputed across normalized script body and compared with embedded signature. | `Defense_BundleTampering_CorruptedHeader_ThrowsInvalidDataException`<br>`BundlingAndCryptoTests.cs` |
| **T-15** | **Manifest Ambiguity / Confusion**<br>Attacker inserts duplicate manifests or non-string elements (`requires { fs.read: [123] }`) to trick parser. | Manifest Parser | Strict parser grammar enforces non-empty string literals and rejects duplicate manifest declarations with a security error. | `Defense_Manifest_DuplicateHeader_ShouldBeRejected`<br>`Defense_Manifest_NonStringElement_ShouldBeRejected` |

---

## 4. Operational Boundaries & Honest Limitations

To maintain architectural transparency, PS2 explicitly documents what is within its threat model and what is outside its scope:

### In Scope (Guaranteed by PS2)
1. **Deterministic Sandboxing**: No script operation reaches the operating system without capability and policy approval.
2. **Zero Ambient Authority**: Scripts do not inherit arbitrary process credentials or disk access.
3. **Secret Redaction**: Standard library, logging, and error reporters never print raw secret tokens.
4. **Audit Immutability**: All decisions (ALLOW and DENY) are recorded with unique UUIDs and ISO timestamps.

### Out of Scope (Environmental Responsibilities)
1. **OS Kernel Compromise**: If the underlying host OS kernel, .NET runtime JIT compiler, or hypervisor is compromised, PS2 cannot protect memory against out-of-band kernel exploits.
2. **Denial of Service via Infinite Loops**: PS2 v0.4 does not currently implement statement instruction count quotas or CPU time slice limits (planned for a future enterprise release).
3. **Hardware-Level Side Channels**: Speculative execution side channels (e.g. Spectre/Meltdown) must be mitigated at the CPU and OS patch level.
