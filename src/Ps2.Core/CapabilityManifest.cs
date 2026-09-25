using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

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
        bool isExplicitDir = cleaned.EndsWith('/') && cleaned.Length > 1;
        if (isExplicitDir)
        {
            cleaned = cleaned.TrimEnd('/') + "/";
        }
        return cleaned;
    }

    private bool TryHandleAllowAll(string operation, string resource)
    {
        if (!AllowAll) return false;

        if (ActivePolicy.DisallowAllowAll)
        {
            var reason = $"Policy '{ActivePolicy.Name}' strictly forbids the use of '--allow-all' override.";
            AuditLogger.Log(AuditEvent.Create(
                ScriptIdentity,
                operation,
                resource,
                AuditDecision.DENY,
                reason
            ));
            throw new Ps2PolicyViolationException(ActivePolicy.Name, "allow-all", resource, reason);
        }

        AuditLogger.Log(AuditEvent.Create(
            ScriptIdentity,
            operation,
            resource,
            AuditDecision.ALLOW,
            "Allowed via --allow-all override"
        ));
        return true;
    }

    public string EnsureFsReadAllowed(string targetPath, string? baseDirectory = null)
    {
        string canonicalPath;
        try
        {
            canonicalPath = ResolveCanonicalPath(targetPath, baseDirectory, "fs.read");
        }
        catch (Ps2SecurityException)
        {
            throw;
        }
        catch (Exception ex)
        {
            AuditLogger.Log(AuditEvent.Create(
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
            AuditLogger.Log(AuditEvent.Create(
                ScriptIdentity,
                "fs.read",
                canonicalPath,
                AuditDecision.DENY,
                policyReason
            ));
            throw new Ps2PolicyViolationException(ActivePolicy.Name, "fs.read", canonicalPath, policyReason);
        }

        if (TryHandleAllowAll("fs.read", canonicalPath))
        {
            return canonicalPath;
        }

        if (IsPathMatching(targetPath, FsRead, baseDirectory, out _))
        {
            AuditLogger.Log(AuditEvent.Create(
                ScriptIdentity,
                "fs.read",
                canonicalPath,
                AuditDecision.ALLOW,
                "Capability granted by manifest"
            ));
            return canonicalPath;
        }

        AuditLogger.Log(AuditEvent.Create(
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
            canonicalPath = ResolveCanonicalPath(targetPath, baseDirectory, "fs.write");
        }
        catch (Ps2SecurityException)
        {
            throw;
        }
        catch (Exception ex)
        {
            AuditLogger.Log(AuditEvent.Create(
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
            AuditLogger.Log(AuditEvent.Create(
                ScriptIdentity,
                "fs.write",
                canonicalPath,
                AuditDecision.DENY,
                policyReason
            ));
            throw new Ps2PolicyViolationException(ActivePolicy.Name, "fs.write", canonicalPath, policyReason);
        }

        if (TryHandleAllowAll("fs.write", canonicalPath))
        {
            return canonicalPath;
        }

        if (IsPathMatching(targetPath, FsWrite, baseDirectory, out _))
        {
            AuditLogger.Log(AuditEvent.Create(
                ScriptIdentity,
                "fs.write",
                canonicalPath,
                AuditDecision.ALLOW,
                "Capability granted by manifest"
            ));
            return canonicalPath;
        }

        AuditLogger.Log(AuditEvent.Create(
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
            AuditLogger.Log(AuditEvent.Create(
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
            AuditLogger.Log(AuditEvent.Create(
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

        // Cloud Metadata Protection
        if (IsCloudMetadataEndpoint(host))
        {
            var reason = $"Access blocked: Target host '{host}' is a protected cloud instance metadata endpoint.";
            AuditLogger.Log(AuditEvent.Create(
                ScriptIdentity,
                "net.http",
                host,
                AuditDecision.DENY,
                reason
            ));
            throw new Ps2SecurityException("net.http", host, $"[Zero-Trust Sandbox] Access to cloud instance metadata endpoint '{host}' is strictly prohibited.");
        }

        // Policy check first
        if (!PolicyEngine.IsDomainAllowedByPolicy(host, ActivePolicy, out var policyReason))
        {
            AuditLogger.Log(AuditEvent.Create(
                ScriptIdentity,
                "net.http",
                host,
                AuditDecision.DENY,
                policyReason
            ));
            throw new Ps2PolicyViolationException(ActivePolicy.Name, "net.http", host, policyReason);
        }

        if (TryHandleAllowAll("net.http", host))
        {
            return;
        }

        foreach (var rule in NetHttp)
        {
            if (rule == "*" || string.Equals(rule, host, StringComparison.OrdinalIgnoreCase))
            {
                AuditLogger.Log(AuditEvent.Create(
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
                AuditLogger.Log(AuditEvent.Create(
                    ScriptIdentity,
                    "net.http",
                    host,
                    AuditDecision.ALLOW,
                    "Capability granted by manifest wildcard"
                ));
                return;
            }
        }

        AuditLogger.Log(AuditEvent.Create(
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

    public static bool IsCloudMetadataEndpoint(string host)
    {
        var h = host.Trim().Trim('[', ']');
        if (string.Equals(h, "169.254.169.254", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(h, "169.254.169.253", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(h, "metadata.google.internal", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(h, "metadata", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(h, "fd00:ec2::254", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (System.Net.IPAddress.TryParse(h, out var ip))
        {
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var bytes = ip.GetAddressBytes();
                if (bytes[0] == 169 && bytes[1] == 254)
                {
                    return true;
                }
            }
            else if (ip.IsIPv6LinkLocal)
            {
                return true;
            }
        }

        return false;
    }

    public void EnsureEnvAllowed(string variableName)
    {
        // Policy check first
        if (!PolicyEngine.IsEnvAllowedByPolicy(variableName, ActivePolicy, out var policyReason))
        {
            AuditLogger.Log(AuditEvent.Create(
                ScriptIdentity,
                "env",
                variableName,
                AuditDecision.DENY,
                policyReason
            ));
            throw new Ps2PolicyViolationException(ActivePolicy.Name, "env", variableName, policyReason);
        }

        if (TryHandleAllowAll("env", variableName))
        {
            return;
        }

        var comp = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

        foreach (var rule in Env)
        {
            if (rule == "*" || string.Equals(rule, variableName, comp))
            {
                AuditLogger.Log(AuditEvent.Create(
                    ScriptIdentity,
                    "env",
                    variableName,
                    AuditDecision.ALLOW,
                    "Capability granted by manifest"
                ));
                return;
            }
        }

        AuditLogger.Log(AuditEvent.Create(
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
            AuditLogger.Log(AuditEvent.Create(
                ScriptIdentity,
                "proc.exec",
                binaryName,
                AuditDecision.DENY,
                policyReason
            ));
            throw new Ps2PolicyViolationException(ActivePolicy.Name, "proc.exec", binaryName, policyReason);
        }

        if (TryHandleAllowAll("proc.exec", binaryName))
        {
            return;
        }

        foreach (var rule in ProcExec)
        {
            if (rule == "*" || string.Equals(rule, binaryName, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(rule, nameOnly, StringComparison.OrdinalIgnoreCase))
            {
                AuditLogger.Log(AuditEvent.Create(
                    ScriptIdentity,
                    "proc.exec",
                    binaryName,
                    AuditDecision.ALLOW,
                    "Capability granted by manifest"
                ));
                return;
            }
        }

        AuditLogger.Log(AuditEvent.Create(
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

    private static readonly HashSet<string> DosDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    private static string ResolveCanonicalPath(string targetPath, string? baseDirectory, string capability = "fs")
    {
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            throw new Ps2SecurityException(capability, targetPath, "[Zero-Trust Sandbox] Path cannot be empty or whitespace.");
        }

        var cleaned = targetPath.Trim();

        // 1. Detect UNC and remote network share paths (e.g. \\server\share or //server/share)
        if (cleaned.StartsWith(@"\\") || cleaned.StartsWith("//") || cleaned.StartsWith(@"\/") || cleaned.StartsWith(@"/\"))
        {
            throw new Ps2SecurityException(capability, targetPath, "[Zero-Trust Sandbox] UNC and remote network paths ('\\\\...') are strictly prohibited.");
        }

        // 2. Detect DOS device names (e.g. CON, NUL, AUX, PRN, COM1..9, LPT1..9)
        var segments = cleaned.Split(new[] { '/', '\\' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var seg in segments)
        {
            var nameWithoutExt = Path.GetFileNameWithoutExtension(seg);
            if (DosDeviceNames.Contains(seg) || DosDeviceNames.Contains(nameWithoutExt))
            {
                throw new Ps2SecurityException(capability, targetPath, $"[Zero-Trust Sandbox] Access to DOS device name '{seg}' is prohibited.");
            }
        }

        // Strip Windows Alternate Data Streams suffix if present (e.g. ::$DATA) before stream check
        int adsIdx = cleaned.IndexOf("::$DATA", StringComparison.OrdinalIgnoreCase);
        if (adsIdx >= 0)
        {
            cleaned = cleaned.Substring(0, adsIdx);
        }

        // 3. Detect invalid colons (Alternate Data Streams like file.txt:evil or dir:stream)
        for (int i = 0; i < cleaned.Length; i++)
        {
            if (cleaned[i] == ':')
            {
                // Only allow colon as drive specifier at index 1 (e.g. C:)
                if (i != 1 || !char.IsLetter(cleaned[0]))
                {
                    throw new Ps2SecurityException(capability, targetPath, $"[Zero-Trust Sandbox] Path contains invalid stream specifier or colon: '{targetPath}'.");
                }
            }
        }

        string full;
        if (Path.IsPathRooted(cleaned))
        {
            full = Path.GetFullPath(cleaned).Replace('\\', '/');
        }
        else
        {
            var baseDir = baseDirectory != null ? Path.GetFullPath(baseDirectory) : Directory.GetCurrentDirectory();
            full = Path.GetFullPath(Path.Combine(baseDir, cleaned)).Replace('\\', '/');
        }

        // Double check UNC after GetFullPath
        if (full.StartsWith("//") || full.StartsWith(@"\\"))
        {
            throw new Ps2SecurityException(capability, targetPath, "[Zero-Trust Sandbox] Resolved path is a UNC network path, which is prohibited.");
        }

        return full;
    }

    private static string ResolveSymlinkTargetIfPresent(string fullPath)
    {
        try
        {
            if (File.Exists(fullPath))
            {
                var fi = new FileInfo(fullPath);
                var target = fi.ResolveLinkTarget(returnFinalTarget: true);
                if (target != null)
                {
                    return target.FullName.Replace('\\', '/');
                }
            }
            else if (Directory.Exists(fullPath))
            {
                var di = new DirectoryInfo(fullPath);
                var target = di.ResolveLinkTarget(returnFinalTarget: true);
                if (target != null)
                {
                    return target.FullName.Replace('\\', '/');
                }
            }
            else
            {
                var parentDir = Path.GetDirectoryName(fullPath);
                if (!string.IsNullOrEmpty(parentDir) && Directory.Exists(parentDir))
                {
                    var di = new DirectoryInfo(parentDir);
                    var target = di.ResolveLinkTarget(returnFinalTarget: true);
                    if (target != null)
                    {
                        var fileName = Path.GetFileName(fullPath);
                        return Path.Combine(target.FullName, fileName).Replace('\\', '/');
                    }
                }
            }
        }
        catch
        {
            // Fallback to original path if symlink resolution throws
        }
        return fullPath;
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

        string symlinkResolvedTarget = ResolveSymlinkTargetIfPresent(fullTarget);

        var comparison = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        // Both the direct canonical path AND the underlying link target must match allowed patterns
        return CheckPathMatchesPatterns(fullTarget, allowedPatterns, baseDirectory, comparison) &&
               CheckPathMatchesPatterns(symlinkResolvedTarget, allowedPatterns, baseDirectory, comparison);
    }

    private static bool CheckPathMatchesPatterns(string pathToCheck, IEnumerable<string> allowedPatterns, string? baseDirectory, StringComparison comparison)
    {
        var normTarget = pathToCheck.TrimEnd('/');

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

            var normPattern = fullPattern.TrimEnd('/');

            // Exact match (files or exact directory match)
            if (string.Equals(normTarget, normPattern, comparison))
                return true;

            // Directory subtree match:
            bool isExplicitDir = rawPattern.EndsWith('/') || rawPattern.EndsWith('\\');
            bool isExistingDir = Directory.Exists(fullPattern);

            if (isExplicitDir || isExistingDir)
            {
                if (normTarget.StartsWith(normPattern + "/", comparison))
                    return true;
            }
        }

        return false;
    }
}
