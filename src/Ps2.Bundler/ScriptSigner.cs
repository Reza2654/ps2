using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Ps2.Bundler;

public static class ScriptSigner
{
    private static readonly Regex SignatureRegex = new(@"^\s*#signature:\s*(?<sig>[^\r\n]+)", RegexOptions.Multiline);

    public static string ComputeScriptHash(string scriptContent)
    {
        // Strip out existing #signature line so hashing is stable
        var stripped = SignatureRegex.Replace(scriptContent, string.Empty).Trim();
        var bytes = Encoding.UTF8.GetBytes(stripped);
        var hashBytes = SHA256.HashData(bytes);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    public static string SignScript(string scriptContent)
    {
        var hash = ComputeScriptHash(scriptContent);
        var stripped = SignatureRegex.Replace(scriptContent, string.Empty).TrimStart();
        return $"#signature: sha256:{hash}\n{stripped}";
    }

    public static bool VerifyScript(string scriptContent, out string message)
    {
        var match = SignatureRegex.Match(scriptContent);
        if (!match.Success)
        {
            message = "No #signature header found in script.";
            return false;
        }

        var sig = match.Groups["sig"].Value.Trim();
        string expectedPrefix = "sha256:";
        if (!sig.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase))
        {
            message = $"Unsupported signature algorithm in '{sig}'. Expected sha256:...";
            return false;
        }

        var embeddedHash = sig.Substring(expectedPrefix.Length).Trim();
        var actualHash = ComputeScriptHash(scriptContent);

        if (string.Equals(embeddedHash, actualHash, StringComparison.OrdinalIgnoreCase))
        {
            message = $"Signature valid (SHA256: {actualHash})";
            return true;
        }

        message = $"Signature verification FAILED! Integrity compromised. Embedded: {embeddedHash}, Computed: {actualHash}";
        return false;
    }
}
