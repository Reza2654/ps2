using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Ps2.Core;

public readonly record struct SourceLocation(string FilePath, int Line, int Column)
{
    public static readonly SourceLocation Unknown = new("<unknown>", 1, 1);

    public override string ToString() => $"{FilePath}:{Line}:{Column}";
}

public enum DiagnosticSeverity
{
    Info,
    Warning,
    Error
}

public sealed record Diagnostic(DiagnosticSeverity Severity, string Code, string Message, SourceLocation Location)
{
    public override string ToString() => $"[{Severity.ToString().ToUpperInvariant()}] {Code} at {Location}: {Message}";
}

public sealed class Ps2ParserException : Exception
{
    public IReadOnlyList<Diagnostic> Diagnostics { get; }

    public Ps2ParserException(IReadOnlyList<Diagnostic> diagnostics)
        : base(diagnostics.Count > 0 ? diagnostics[0].Message : "Syntax parser error")
    {
        Diagnostics = diagnostics;
    }
}

public static class DiagnosticRenderer
{
    public static string Render(Diagnostic diag, string? sourceText = null, bool useColor = false)
    {
        return Render(diag.Severity.ToString().ToLowerInvariant(), diag.Code, diag.Message, diag.Location, sourceText, useColor);
    }

    public static string Render(string severity, string code, string message, SourceLocation loc, string? sourceText = null, bool useColor = false)
    {
        var sb = new StringBuilder();

        string reset = useColor ? "\u001b[0m" : "";
        string bold = useColor ? "\u001b[1m" : "";
        string sevColor = severity.ToLowerInvariant() switch
        {
            "error" => useColor ? "\u001b[1;31m" : "",
            "warning" => useColor ? "\u001b[1;33m" : "",
            "info" => useColor ? "\u001b[1;36m" : "",
            _ => useColor ? "\u001b[1m" : ""
        };
        string cyan = useColor ? "\u001b[1;36m" : "";
        string dim = useColor ? "\u001b[2m" : "";

        // Separate help/note from message if present
        string mainMsg = message;
        string? helpNote = null;
        int helpIdx = message.IndexOf("Declare permission", StringComparison.OrdinalIgnoreCase);
        if (helpIdx >= 0)
        {
            mainMsg = message.Substring(0, helpIdx).Trim();
            helpNote = message.Substring(helpIdx).Trim();
        }

        sb.AppendLine($"{sevColor}{severity.ToLowerInvariant()}[{code}]{reset}{bold}: {mainMsg}{reset}");
        sb.AppendLine($"  {cyan}-->{reset} {loc.FilePath}:{loc.Line}:{loc.Column}");

        if (sourceText == null && File.Exists(loc.FilePath))
        {
            try
            {
                sourceText = File.ReadAllText(loc.FilePath);
            }
            catch
            {
                // ignore
            }
        }

        if (!string.IsNullOrEmpty(sourceText) && loc.Line > 0)
        {
            var lines = sourceText.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            int targetIdx = loc.Line - 1;

            if (targetIdx >= 0 && targetIdx < lines.Length)
            {
                int maxLineNo = Math.Min(lines.Length, loc.Line + 1);
                int gutterWidth = Math.Max(2, maxLineNo.ToString().Length);

                sb.AppendLine($"  {cyan}{new string(' ', gutterWidth)} |{reset}");

                // Previous line if available
                if (targetIdx > 0)
                {
                    int prevLineNo = loc.Line - 1;
                    sb.AppendLine($"  {cyan}{prevLineNo.ToString().PadLeft(gutterWidth)} |{reset} {dim}{lines[targetIdx - 1]}{reset}");
                }

                // Target line
                string targetLine = lines[targetIdx];
                sb.AppendLine($"  {cyan}{loc.Line.ToString().PadLeft(gutterWidth)} |{reset} {targetLine}");

                // Underline caret
                int col = Math.Max(1, loc.Column);
                int padding = Math.Max(0, col - 1);
                sb.AppendLine($"  {cyan}{new string(' ', gutterWidth)} |{reset} {new string(' ', padding)}{sevColor}^{reset}");

                // Next line if available
                if (targetIdx + 1 < lines.Length)
                {
                    int nextLineNo = loc.Line + 1;
                    sb.AppendLine($"  {cyan}{nextLineNo.ToString().PadLeft(gutterWidth)} |{reset} {dim}{lines[targetIdx + 1]}{reset}");
                }
            }
        }

        if (!string.IsNullOrEmpty(helpNote))
        {
            sb.AppendLine($"  {cyan}={reset} {bold}help:{reset} {helpNote}");
        }

        return sb.ToString().TrimEnd();
    }
}
