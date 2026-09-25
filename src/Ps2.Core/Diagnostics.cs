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
