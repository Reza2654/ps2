using System;
using System.Collections.Generic;
using System.Threading;

namespace Ps2.Core;

public static class EvaluatorSecretScrubber
{
    private static readonly AsyncLocal<HashSet<string>> ActiveSecrets = new();

    public static void InitializeSession()
    {
        ActiveSecrets.Value = new HashSet<string>(StringComparer.Ordinal);
    }

    public static void RegisterSecret(string secret)
    {
        if (string.IsNullOrEmpty(secret) || secret.Length < 3) return;
        ActiveSecrets.Value ??= new HashSet<string>(StringComparer.Ordinal);
        ActiveSecrets.Value.Add(secret);
    }

    public static string Scrub(string? text)
    {
        if (string.IsNullOrEmpty(text)) return text ?? string.Empty;
        var secrets = ActiveSecrets.Value;
        if (secrets == null || secrets.Count == 0) return text;

        var result = text;
        foreach (var sec in secrets)
        {
            if (!string.IsNullOrEmpty(sec))
            {
                result = result.Replace(sec, "[REDACTED]");
            }
        }
        return result;
    }
}
