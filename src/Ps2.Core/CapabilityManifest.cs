using System;
using System.Collections.Generic;
using System.IO;

namespace Ps2.Core;

public sealed class CapabilityManifest
{
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

    private static string NormalizePathPattern(string path)
    {
        var cleaned = path.Trim().Replace('\\', '/');
        if (cleaned.EndsWith('/') && cleaned.Length > 1)
        {
            cleaned = cleaned.TrimEnd('/');
        }
        return cleaned;
    }

    public void EnsureFsReadAllowed(string targetPath, string? baseDirectory = null)
    {
        if (AllowAll) return;

        if (IsPathMatching(targetPath, FsRead, baseDirectory))
            return;

        throw new Ps2SecurityException(
            "fs.read",
            targetPath,
            $"[Zero-Trust Sandbox] Read access denied to '{targetPath}'. Declare permission in '#manifest requires {{ fs.read: [\"{targetPath}\"] }}' or run with --allow-all."
        );
    }

    public void EnsureFsWriteAllowed(string targetPath, string? baseDirectory = null)
    {
        if (AllowAll) return;

        if (IsPathMatching(targetPath, FsWrite, baseDirectory))
            return;

        throw new Ps2SecurityException(
            "fs.write",
            targetPath,
            $"[Zero-Trust Sandbox] Write access denied to '{targetPath}'. Declare permission in '#manifest requires {{ fs.write: [\"{targetPath}\"] }}' or run with --allow-all."
        );
    }

    public void EnsureNetHttpAllowed(string urlOrHost)
    {
        if (AllowAll) return;

        string host = urlOrHost;
        if (Uri.TryCreate(urlOrHost, UriKind.Absolute, out var uri))
        {
            host = uri.Host;
        }

        foreach (var rule in NetHttp)
        {
            if (rule == "*" || string.Equals(rule, host, StringComparison.OrdinalIgnoreCase))
                return;

            if (rule.StartsWith("*.") && host.EndsWith(rule.Substring(1), StringComparison.OrdinalIgnoreCase))
                return;
        }

        throw new Ps2SecurityException(
            "net.http",
            urlOrHost,
            $"[Zero-Trust Sandbox] Network access denied to host '{host}'. Declare permission in '#manifest requires {{ net.http: [\"{host}\"] }}' or run with --allow-all."
        );
    }

    public void EnsureEnvAllowed(string variableName)
    {
        if (AllowAll) return;

        foreach (var rule in Env)
        {
            if (rule == "*" || string.Equals(rule, variableName, StringComparison.OrdinalIgnoreCase))
                return;
        }

        throw new Ps2SecurityException(
            "env",
            variableName,
            $"[Zero-Trust Sandbox] Access to environment variable '{variableName}' denied. Declare permission in '#manifest requires {{ env: [\"{variableName}\"] }}' or run with --allow-all."
        );
    }

    public void EnsureProcExecAllowed(string binaryName)
    {
        if (AllowAll) return;

        var nameOnly = Path.GetFileName(binaryName);
        foreach (var rule in ProcExec)
        {
            if (rule == "*" || string.Equals(rule, binaryName, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(rule, nameOnly, StringComparison.OrdinalIgnoreCase))
                return;
        }

        throw new Ps2SecurityException(
            "proc.exec",
            binaryName,
            $"[Zero-Trust Sandbox] Execution of external binary '{binaryName}' denied. Declare permission in '#manifest requires {{ proc.exec: [\"{nameOnly}\"] }}' or run with --allow-all."
        );
    }

    private static bool IsPathMatching(string targetPath, IEnumerable<string> allowedPatterns, string? baseDirectory)
    {
        string fullTarget;
        try
        {
            if (Path.IsPathRooted(targetPath))
            {
                fullTarget = Path.GetFullPath(targetPath).Replace('\\', '/');
            }
            else
            {
                var baseDir = baseDirectory ?? Directory.GetCurrentDirectory();
                fullTarget = Path.GetFullPath(Path.Combine(baseDir, targetPath)).Replace('\\', '/');
            }
        }
        catch
        {
            return false;
        }

        foreach (var rawPattern in allowedPatterns)
        {
            if (rawPattern == "*") return true;

            string fullPattern;
            if (Path.IsPathRooted(rawPattern))
            {
                fullPattern = Path.GetFullPath(rawPattern).Replace('\\', '/');
            }
            else
            {
                var baseDir = baseDirectory ?? Directory.GetCurrentDirectory();
                fullPattern = Path.GetFullPath(Path.Combine(baseDir, rawPattern)).Replace('\\', '/');
            }

            if (string.Equals(fullTarget, fullPattern, StringComparison.OrdinalIgnoreCase))
                return true;

            // Check if fullTarget is inside fullPattern directory
            if (!fullPattern.EndsWith('/')) fullPattern += "/";
            if (fullTarget.StartsWith(fullPattern, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
