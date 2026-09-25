using System;
using System.Collections.Generic;
using System.IO;

namespace Ps2.Core;

public sealed class CapabilityManifest
{
    public string SchemaVersion { get; set; } = "1.0";
    public string ScriptIdentity { get; set; } = "anonymous";
    public SecurityPolicy ActivePolicy { get; set; } = SecurityPolicy.Default;
    public IAuditLogger AuditLogger { get; set; } = NullAuditLogger.Instance;

    public HashSet<string> FsRead { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> FsWrite { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> NetHttp { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> Env { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> ProcExec { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool AllowAll { get; set; } = false;

    public void AddFsRead(string path) => FsRead.Add(NormalizePathPattern(path));
    public void AddFsWrite(string path) => FsWrite.Add(NormalizePathPattern(path));
    public void AddNetHttp(string host) => NetHttp.Add(host.Trim());
    public void AddEnv(string envVar) => Env.Add(envVar.Trim());
    public void AddProcExec(string binary) => ProcExec.Add(binary.Trim());

    public void Validate()
    {
        if (!string.Equals(SchemaVersion, "1.0", StringComparison.OrdinalIgnoreCase))
        {
            throw new Ps2SecurityException(
                "manifest",
                SchemaVersion,
                $"[Zero-Trust Sandbox] Unsupported manifest schema version '{SchemaVersion}'. Supported versions: '1.0'."
            );
        }
    }

    private static string NormalizePathPattern(string path)
    {
        var cleaned = path.Trim().Replace('\\', '/');
        // Preserve trailing slash if explicitly specified as directory marker
        bool isExplicitDir = cleaned.EndsWith('/') && cleaned.Length > 1;
        if (isExplicitDir)
        {
            cleaned = cleaned.TrimEnd('/') + "/";
        }
        return cleaned;
    }

    public string EnsureFsReadAllowed(string targetPath, string? baseDirectory = null)
    {
        string canonicalPath;
        try
        {
            canonicalPath = ResolveCanonicalPath(targetPath, baseDirectory);
        }
        catch (Exception ex)
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "fs.read",
                targetPath,
                AuditDecision.DENY,
                $"Path resolution failed: {ex.Message}"
            ));
            throw new Ps2SecurityException("fs.read", targetPath, $"[Zero-Trust Sandbox] Invalid path '{targetPath}': {ex.Message}");
        }

        // Policy check first
        if (!PolicyEngine.IsPathAllowedByPolicy(canonicalPath, isWrite: false, ActivePolicy, out var policyReason))
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "fs.read",
                canonicalPath,
                AuditDecision.DENY,
                policyReason
            ));
            throw new Ps2PolicyViolationException(ActivePolicy.Name, "fs.read", canonicalPath, policyReason);
        }

        if (AllowAll)
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "fs.read",
                canonicalPath,
                AuditDecision.ALLOW,
                "Allowed via --allow-all override"
            ));
            return canonicalPath;
        }

        if (IsPathMatching(targetPath, FsRead, baseDirectory, out _))
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "fs.read",
                canonicalPath,
                AuditDecision.ALLOW,
                "Capability granted by manifest"
            ));
            return canonicalPath;
        }

        AuditLogger.Log(new AuditEvent(
            DateTimeOffset.UtcNow.ToString("o"),
            ScriptIdentity,
            "fs.read",
            canonicalPath,
            AuditDecision.DENY,
            "Missing capability declaration in manifest"
        ));

        throw new Ps2SecurityException(
            "fs.read",
            targetPath,
            $"[Zero-Trust Sandbox] Read access denied to '{targetPath}'. Declare permission in '#manifest requires {{ fs.read: [\"{targetPath}\"] }}' or run with --allow-all."
        );
    }

    public string EnsureFsWriteAllowed(string targetPath, string? baseDirectory = null)
    {
        string canonicalPath;
        try
        {
            canonicalPath = ResolveCanonicalPath(targetPath, baseDirectory);
        }
        catch (Exception ex)
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "fs.write",
                targetPath,
                AuditDecision.DENY,
                $"Path resolution failed: {ex.Message}"
            ));
            throw new Ps2SecurityException("fs.write", targetPath, $"[Zero-Trust Sandbox] Invalid path '{targetPath}': {ex.Message}");
        }

        // Policy check first
        if (!PolicyEngine.IsPathAllowedByPolicy(canonicalPath, isWrite: true, ActivePolicy, out var policyReason))
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "fs.write",
                canonicalPath,
                AuditDecision.DENY,
                policyReason
            ));
            throw new Ps2PolicyViolationException(ActivePolicy.Name, "fs.write", canonicalPath, policyReason);
        }

        if (AllowAll)
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "fs.write",
                canonicalPath,
                AuditDecision.ALLOW,
                "Allowed via --allow-all override"
            ));
            return canonicalPath;
        }

        if (IsPathMatching(targetPath, FsWrite, baseDirectory, out _))
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "fs.write",
                canonicalPath,
                AuditDecision.ALLOW,
                "Capability granted by manifest"
            ));
            return canonicalPath;
        }

        AuditLogger.Log(new AuditEvent(
            DateTimeOffset.UtcNow.ToString("o"),
            ScriptIdentity,
            "fs.write",
            canonicalPath,
            AuditDecision.DENY,
            "Missing capability declaration in manifest"
        ));

        throw new Ps2SecurityException(
            "fs.write",
            targetPath,
            $"[Zero-Trust Sandbox] Write access denied to '{targetPath}'. Declare permission in '#manifest requires {{ fs.write: [\"{targetPath}\"] }}' or run with --allow-all."
        );
    }

    public void EnsureNetHttpAllowed(string urlOrHost)
    {
        Uri uri;
        if (Uri.TryCreate(urlOrHost, UriKind.Absolute, out var parsedUri))
        {
            uri = parsedUri;
        }
        else if (Uri.TryCreate("https://" + urlOrHost, UriKind.Absolute, out var fallbackUri))
        {
            uri = fallbackUri;
        }
        else
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "net.http",
                urlOrHost,
                AuditDecision.DENY,
                "Malformed URL or host"
            ));
            throw new Ps2SecurityException(
                "net.http",
                urlOrHost,
                $"[Zero-Trust Sandbox] Malformed URL or host: '{urlOrHost}'."
            );
        }

        // Protocol Whitelist
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "net.http",
                urlOrHost,
                AuditDecision.DENY,
                $"Prohibited network protocol: {uri.Scheme}"
            ));
            throw new Ps2SecurityException(
                "net.http",
                urlOrHost,
                $"[Zero-Trust Sandbox] Prohibited network protocol '{uri.Scheme}'. Only HTTP and HTTPS are permitted."
            );
        }

        string host = uri.Host;

        // Policy check first
        if (!PolicyEngine.IsDomainAllowedByPolicy(host, ActivePolicy, out var policyReason))
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "net.http",
                host,
                AuditDecision.DENY,
                policyReason
            ));
            throw new Ps2PolicyViolationException(ActivePolicy.Name, "net.http", host, policyReason);
        }

        if (AllowAll)
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "net.http",
                host,
                AuditDecision.ALLOW,
                "Allowed via --allow-all override"
            ));
            return;
        }

        foreach (var rule in NetHttp)
        {
            if (rule == "*" || string.Equals(rule, host, StringComparison.OrdinalIgnoreCase))
            {
                AuditLogger.Log(new AuditEvent(
                    DateTimeOffset.UtcNow.ToString("o"),
                    ScriptIdentity,
                    "net.http",
                    host,
                    AuditDecision.ALLOW,
                    "Capability granted by manifest"
                ));
                return;
            }

            if (rule.StartsWith("*.") && host.EndsWith(rule.Substring(1), StringComparison.OrdinalIgnoreCase))
            {
                AuditLogger.Log(new AuditEvent(
                    DateTimeOffset.UtcNow.ToString("o"),
                    ScriptIdentity,
                    "net.http",
                    host,
                    AuditDecision.ALLOW,
                    "Capability granted by manifest wildcard"
                ));
                return;
            }
        }

        AuditLogger.Log(new AuditEvent(
            DateTimeOffset.UtcNow.ToString("o"),
            ScriptIdentity,
            "net.http",
            host,
            AuditDecision.DENY,
            "Missing capability declaration in manifest"
        ));

        throw new Ps2SecurityException(
            "net.http",
            urlOrHost,
            $"[Zero-Trust Sandbox] Network access denied to host '{host}'. Declare permission in '#manifest requires {{ net.http: [\"{host}\"] }}' or run with --allow-all."
        );
    }

    public void EnsureEnvAllowed(string variableName)
    {
        // Policy check first
        if (!PolicyEngine.IsEnvAllowedByPolicy(variableName, ActivePolicy, out var policyReason))
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "env",
                variableName,
                AuditDecision.DENY,
                policyReason
            ));
            throw new Ps2PolicyViolationException(ActivePolicy.Name, "env", variableName, policyReason);
        }

        if (AllowAll)
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "env",
                variableName,
                AuditDecision.ALLOW,
                "Allowed via --allow-all override"
            ));
            return;
        }

        foreach (var rule in Env)
        {
            if (rule == "*" || string.Equals(rule, variableName, StringComparison.OrdinalIgnoreCase))
            {
                AuditLogger.Log(new AuditEvent(
                    DateTimeOffset.UtcNow.ToString("o"),
                    ScriptIdentity,
                    "env",
                    variableName,
                    AuditDecision.ALLOW,
                    "Capability granted by manifest"
                ));
                return;
            }
        }

        AuditLogger.Log(new AuditEvent(
            DateTimeOffset.UtcNow.ToString("o"),
            ScriptIdentity,
            "env",
            variableName,
            AuditDecision.DENY,
            "Missing capability declaration in manifest"
        ));

        throw new Ps2SecurityException(
            "env",
            variableName,
            $"[Zero-Trust Sandbox] Access to environment variable '{variableName}' denied. Declare permission in '#manifest requires {{ env: [\"{variableName}\"] }}' or run with --allow-all."
        );
    }

    public void EnsureProcExecAllowed(string binaryName)
    {
        var nameOnly = Path.GetFileName(binaryName);

        // Policy check first
        if (!PolicyEngine.IsBinaryAllowedByPolicy(binaryName, ActivePolicy, out var policyReason))
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "proc.exec",
                binaryName,
                AuditDecision.DENY,
                policyReason
            ));
            throw new Ps2PolicyViolationException(ActivePolicy.Name, "proc.exec", binaryName, policyReason);
        }

        if (AllowAll)
        {
            AuditLogger.Log(new AuditEvent(
                DateTimeOffset.UtcNow.ToString("o"),
                ScriptIdentity,
                "proc.exec",
                binaryName,
                AuditDecision.ALLOW,
                "Allowed via --allow-all override"
            ));
            return;
        }

        foreach (var rule in ProcExec)
        {
            if (rule == "*" || string.Equals(rule, binaryName, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(rule, nameOnly, StringComparison.OrdinalIgnoreCase))
            {
                AuditLogger.Log(new AuditEvent(
                    DateTimeOffset.UtcNow.ToString("o"),
                    ScriptIdentity,
                    "proc.exec",
                    binaryName,
                    AuditDecision.ALLOW,
                    "Capability granted by manifest"
                ));
                return;
            }
        }

        AuditLogger.Log(new AuditEvent(
            DateTimeOffset.UtcNow.ToString("o"),
            ScriptIdentity,
            "proc.exec",
            binaryName,
            AuditDecision.DENY,
            "Missing capability declaration in manifest"
        ));

        throw new Ps2SecurityException(
            "proc.exec",
            binaryName,
            $"[Zero-Trust Sandbox] Execution of external binary '{binaryName}' denied. Declare permission in '#manifest requires {{ proc.exec: [\"{nameOnly}\"] }}' or run with --allow-all."
        );
    }

    private static string ResolveCanonicalPath(string targetPath, string? baseDirectory)
    {
        var cleaned = targetPath.Trim();
        // Strip Windows Alternate Data Streams suffix if present
        int adsIdx = cleaned.IndexOf("::$DATA", StringComparison.OrdinalIgnoreCase);
        if (adsIdx >= 0)
        {
            cleaned = cleaned.Substring(0, adsIdx);
        }

        if (Path.IsPathRooted(cleaned))
        {
            return Path.GetFullPath(cleaned).Replace('\\', '/');
        }

        var baseDir = baseDirectory != null ? Path.GetFullPath(baseDirectory) : Directory.GetCurrentDirectory();
        return Path.GetFullPath(Path.Combine(baseDir, cleaned)).Replace('\\', '/');
    }

    private static bool IsPathMatching(string targetPath, IEnumerable<string> allowedPatterns, string? baseDirectory, out string fullTarget)
    {
        try
        {
            fullTarget = ResolveCanonicalPath(targetPath, baseDirectory);
        }
        catch
        {
            fullTarget = targetPath;
            return false;
        }

        foreach (var rawPattern in allowedPatterns)
        {
            if (rawPattern == "*") return true;

            string fullPattern;
            try
            {
                fullPattern = ResolveCanonicalPath(rawPattern, baseDirectory);
            }
            catch
            {
                continue;
            }

            var normTarget = fullTarget.TrimEnd('/');
            var normPattern = fullPattern.TrimEnd('/');

            // Exact match (files or exact directory match)
            if (string.Equals(normTarget, normPattern, StringComparison.OrdinalIgnoreCase))
                return true;

            // Directory subtree match:
            // Only allow prefix containment if pattern was specified as directory or is an existing directory
            bool isExplicitDir = rawPattern.EndsWith('/') || rawPattern.EndsWith('\\');
            bool isExistingDir = Directory.Exists(fullPattern);

            if (isExplicitDir || isExistingDir)
            {
                if (normTarget.StartsWith(normPattern + "/", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }
}
