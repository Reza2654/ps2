using System;
using System.Collections.Generic;
using System.IO;

namespace Ps2.Core;

public sealed class Ps2PolicyViolationException : Exception
{
    public string PolicyName { get; }
    public string ViolationType { get; }
    public string TargetResource { get; }

    public Ps2PolicyViolationException(string policyName, string violationType, string targetResource, string message)
        : base(message)
    {
        PolicyName = policyName;
        ViolationType = violationType;
        TargetResource = targetResource;
    }
}

public static class PolicyEngine
{
    public static void ValidateManifestAgainstPolicy(CapabilityManifest manifest, SecurityPolicy policy)
    {
        if (!ValidateManifestAgainstPolicy(manifest, policy, out var violations))
        {
            throw new Ps2PolicyViolationException(policy.Name, "manifest", "manifest", string.Join(" ", violations));
        }
    }

    public static bool ValidateManifestAgainstPolicy(CapabilityManifest manifest, SecurityPolicy policy, out List<string> violations)
    {
        violations = new List<string>();

        // 0. Global allow-all override check
        if (manifest.AllowAll && policy.DisallowAllowAll)
        {
            violations.Add($"Policy '{policy.Name}' strictly forbids the use of '--allow-all' override.");
        }

        // 1. Process execution check
        if (policy.DisallowProcessExecution && manifest.ProcExec.Count > 0)
        {
            violations.Add($"Policy '{policy.Name}' prohibits process execution, but manifest requests execution of: [{string.Join(", ", manifest.ProcExec)}].");
        }
        else
        {
            foreach (var bin in manifest.ProcExec)
            {
                if (policy.BlockedBinaries.Contains(bin) || policy.BlockedBinaries.Contains(Path.GetFileName(bin)))
                {
                    violations.Add($"Policy '{policy.Name}' explicitly blocks execution of binary '{bin}'.");
                }

                if (policy.AllowedBinaries.Count > 0 && !policy.AllowedBinaries.Contains(bin) && !policy.AllowedBinaries.Contains(Path.GetFileName(bin)))
                {
                    violations.Add($"Binary '{bin}' is not in policy '{policy.Name}' allowlist.");
                }
            }
        }

        // 2. Network check
        if (policy.DisallowExternalNetwork)
        {
            foreach (var domain in manifest.NetHttp)
            {
                if (domain == "*" || !IsDomainWhitelisted(domain, policy.AllowedDomains))
                {
                    violations.Add($"Policy '{policy.Name}' disallows external network access to domain '{domain}'.");
                }
            }
        }

        foreach (var domain in manifest.NetHttp)
        {
            if (policy.BlockedDomains.Contains(domain))
            {
                violations.Add($"Policy '{policy.Name}' explicitly blocks network requests to domain '{domain}'.");
            }
        }

        // 3. Filesystem write checks against read-only or blocked paths
        foreach (var writePath in manifest.FsWrite)
        {
            if (IsSubpathOrMatch(writePath, policy.BlockedPaths))
            {
                violations.Add($"Policy '{policy.Name}' blocks write access to path '{writePath}'.");
            }

            if (IsSubpathOrMatch(writePath, policy.ReadOnlyPaths))
            {
                violations.Add($"Policy '{policy.Name}' enforces path '{writePath}' as read-only. Write access is forbidden.");
            }
        }

        // 4. Filesystem read checks against blocked paths
        foreach (var readPath in manifest.FsRead)
        {
            if (IsSubpathOrMatch(readPath, policy.BlockedPaths))
            {
                violations.Add($"Policy '{policy.Name}' blocks read access to path '{readPath}'.");
            }
        }

        // 5. Environment variable checks
        if (policy.DisallowAllEnv && manifest.Env.Count > 0)
        {
            violations.Add($"Policy '{policy.Name}' disallows all environment variable access.");
        }

        foreach (var envVar in manifest.Env)
        {
            if (policy.BlockedEnvVars.Contains(envVar))
            {
                violations.Add($"Policy '{policy.Name}' blocks access to sensitive environment variable '{envVar}'.");
            }

            if (policy.AllowedEnvVars != null && !policy.AllowedEnvVars.Contains(envVar))
            {
                violations.Add($"Environment variable '{envVar}' is not in policy '{policy.Name}' allowlist.");
            }
        }

        return violations.Count == 0;
    }

    public static bool IsPathAllowedByPolicy(string canonicalPath, bool isWrite, SecurityPolicy policy, out string reason)
    {
        if (IsSubpathOrMatch(canonicalPath, policy.BlockedPaths))
        {
            reason = $"Access blocked: Path '{canonicalPath}' is prohibited by policy '{policy.Name}'.";
            return false;
        }

        if (isWrite && IsSubpathOrMatch(canonicalPath, policy.ReadOnlyPaths))
        {
            reason = $"Write blocked: Path '{canonicalPath}' is marked read-only by policy '{policy.Name}'.";
            return false;
        }

        reason = "Path allowed by policy";
        return true;
    }

    public static bool IsDomainAllowedByPolicy(string domain, SecurityPolicy policy, out string reason)
    {
        if (policy.BlockedDomains.Contains(domain))
        {
            reason = $"Network blocked: Domain '{domain}' is explicitly blocked by policy '{policy.Name}'.";
            return false;
        }

        if (policy.DisallowExternalNetwork && !IsDomainWhitelisted(domain, policy.AllowedDomains))
        {
            reason = $"Network blocked: Domain '{domain}' is not whitelisted by policy '{policy.Name}'.";
            return false;
        }

        reason = "Domain allowed by policy";
        return true;
    }

    public static bool IsBinaryAllowedByPolicy(string binaryName, SecurityPolicy policy, out string reason)
    {
        if (policy.DisallowProcessExecution)
        {
            reason = $"Execution blocked: Process execution is forbidden by policy '{policy.Name}'.";
            return false;
        }

        var nameOnly = Path.GetFileName(binaryName);
        if (policy.BlockedBinaries.Contains(binaryName) || policy.BlockedBinaries.Contains(nameOnly))
        {
            reason = $"Execution blocked: Binary '{nameOnly}' is explicitly prohibited by policy '{policy.Name}'.";
            return false;
        }

        if (policy.AllowedBinaries.Count > 0 && !policy.AllowedBinaries.Contains(binaryName) && !policy.AllowedBinaries.Contains(nameOnly))
        {
            reason = $"Execution blocked: Binary '{nameOnly}' is not in allowed list for policy '{policy.Name}'.";
            return false;
        }

        reason = "Binary execution allowed by policy";
        return true;
    }

    public static bool IsEnvAllowedByPolicy(string varName, SecurityPolicy policy, out string reason)
    {
        if (policy.DisallowAllEnv)
        {
            reason = $"Env access blocked: Environment access is forbidden by policy '{policy.Name}'.";
            return false;
        }

        if (policy.BlockedEnvVars.Contains(varName))
        {
            reason = $"Env access blocked: Variable '{varName}' is blocked by policy '{policy.Name}'.";
            return false;
        }

        if (policy.AllowedEnvVars != null && !policy.AllowedEnvVars.Contains(varName))
        {
            reason = $"Env access blocked: Variable '{varName}' is not in allowlist for policy '{policy.Name}'.";
            return false;
        }

        reason = "Environment access allowed by policy";
        return true;
    }

    public static List<CapabilityComplianceItem> EvaluateDetailedCompliance(CapabilityManifest manifest, SecurityPolicy policy)
    {
        var items = new List<CapabilityComplianceItem>();

        if (manifest.AllowAll)
        {
            if (policy.DisallowAllowAll)
            {
                items.Add(new CapabilityComplianceItem("override", "--allow-all", false, "DisallowAllowAll", $"Policy '{policy.Name}' strictly forbids --allow-all override."));
            }
            else
            {
                items.Add(new CapabilityComplianceItem("override", "--allow-all", true, null, "Global sandbox override permitted by policy."));
            }
        }

        foreach (var r in manifest.FsRead)
        {
            bool ok = IsPathAllowedByPolicy(r, isWrite: false, policy, out var reason);
            items.Add(new CapabilityComplianceItem("fs.read", r, ok, ok ? null : "BlockedPaths", reason));
        }

        foreach (var w in manifest.FsWrite)
        {
            bool ok = IsPathAllowedByPolicy(w, isWrite: true, policy, out var reason);
            items.Add(new CapabilityComplianceItem("fs.write", w, ok, ok ? null : (reason.Contains("read-only") ? "ReadOnlyPaths" : "BlockedPaths"), reason));
        }

        foreach (var net in manifest.NetHttp)
        {
            bool ok = IsDomainAllowedByPolicy(net, policy, out var reason);
            items.Add(new CapabilityComplianceItem("net.http", net, ok, ok ? null : (policy.DisallowExternalNetwork ? "DisallowExternalNetwork" : "BlockedDomains"), reason));
        }

        foreach (var env in manifest.Env)
        {
            bool ok = IsEnvAllowedByPolicy(env, policy, out var reason);
            items.Add(new CapabilityComplianceItem("env", env, ok, ok ? null : (policy.DisallowAllEnv ? "DisallowAllEnv" : "BlockedEnvVars"), reason));
        }

        foreach (var proc in manifest.ProcExec)
        {
            bool ok = IsBinaryAllowedByPolicy(proc, policy, out var reason);
            items.Add(new CapabilityComplianceItem("proc.exec", proc, ok, ok ? null : (policy.DisallowProcessExecution ? "DisallowProcessExecution" : "BlockedBinaries"), reason));
        }

        return items;
    }

    private static bool IsDomainWhitelisted(string targetDomain, HashSet<string> allowedDomains)
    {
        foreach (var allowed in allowedDomains)
        {
            if (string.Equals(allowed, targetDomain, StringComparison.OrdinalIgnoreCase)) return true;
            if (allowed.StartsWith("*.") && targetDomain.EndsWith(allowed.Substring(1), StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static bool IsSubpathOrMatch(string path, IEnumerable<string> restrictedPatterns)
    {
        var norm = path.Replace('\\', '/').TrimEnd('/');
        var comp = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        foreach (var raw in restrictedPatterns)
        {
            var pattern = raw.Replace('\\', '/').TrimEnd('/');
            if (string.Equals(norm, pattern, comp)) return true;
            if (norm.StartsWith(pattern + "/", comp)) return true;
        }
        return false;
    }
}

public sealed record CapabilityComplianceItem(
    string Capability,
    string Resource,
    bool IsAllowed,
    string? RuleTriggered,
    string Reason
);
