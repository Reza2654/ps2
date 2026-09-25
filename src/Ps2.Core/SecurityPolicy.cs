using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Ps2.Core;

public sealed class SecurityPolicy
{
    public string Name { get; set; } = "default";
    public string Description { get; set; } = string.Empty;

    // Network policies
    public bool DisallowExternalNetwork { get; set; } = false;
    public HashSet<string> AllowedDomains { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> BlockedDomains { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    // Process execution policies
    public bool DisallowProcessExecution { get; set; } = false;
    public HashSet<string> AllowedBinaries { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> BlockedBinaries { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    // Filesystem policies
    public List<string> BlockedPaths { get; set; } = new();
    public List<string> ReadOnlyPaths { get; set; } = new();

    // Environment variable policies
    public bool DisallowAllEnv { get; set; } = false;
    public HashSet<string> BlockedEnvVars { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string>? AllowedEnvVars { get; set; } = null; // null means no restriction beyond manifest

    public static SecurityPolicy Default => new()
    {
        Name = "default",
        Description = "Standard Zero-Trust policy relying on script manifest capabilities."
    };

    public static SecurityPolicy Strict => new()
    {
        Name = "strict",
        Description = "Strict enterprise policy requiring signed scripts and explicitly restricted paths.",
        BlockedPaths = new List<string>
        {
            "/etc/shadow",
            "/etc/sudoers",
            "C:/Windows/System32/config",
            "C:/Windows/System32/SAM"
        }
    };

    public static SecurityPolicy Production => new()
    {
        Name = "production",
        Description = "Hardened production policy: process execution forbidden, external network restricted to internal domains, critical system paths blocked.",
        DisallowProcessExecution = true,
        DisallowExternalNetwork = true,
        BlockedPaths = new List<string>
        {
            "/etc",
            "/var/run",
            "/root",
            "C:/Windows",
            "C:/Program Files",
            "C:/ProgramData"
        },
        ReadOnlyPaths = new List<string>
        {
            "/etc/ssl",
            "C:/Windows/System32/drivers/etc/hosts"
        },
        BlockedEnvVars = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "AWS_SECRET_ACCESS_KEY",
            "AZURE_CLIENT_SECRET",
            "KUBERNETES_SERVICE_HOST"
        }
    };

    public static SecurityPolicy FromProfile(string profileName)
    {
        return profileName.ToLowerInvariant() switch
        {
            "default" => Default,
            "strict" => Strict,
            "production" or "prod" => Production,
            _ => throw new ArgumentException($"Unknown security policy profile: '{profileName}'. Built-in profiles: default, strict, production.")
        };
    }

    public static SecurityPolicy FromJsonFile(string path) => LoadFromFile(path);

    public static SecurityPolicy LoadFromFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Security policy file not found: '{path}'");
        }

        var json = File.ReadAllText(path);
        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        var policy = JsonSerializer.Deserialize<SecurityPolicy>(json, options);
        if (policy == null)
        {
            throw new InvalidOperationException($"Failed to deserialize security policy from '{path}'");
        }
        return policy;
    }
}
