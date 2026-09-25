using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ps2.Core;

[JsonConverter(typeof(JsonStringEnumConverter<AuditDecision>))]
public enum AuditDecision
{
    ALLOW,
    DENY
}

public sealed record AuditEvent(
    [property: JsonPropertyName("event_id")] string EventId,
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("timestamp")] string Timestamp,
    [property: JsonPropertyName("script_identity")] string ScriptIdentity,
    [property: JsonPropertyName("operation")] string Operation,
    [property: JsonPropertyName("resource")] string Resource,
    [property: JsonPropertyName("decision")] AuditDecision Decision,
    [property: JsonPropertyName("reason")] string Reason
)
{
    public AuditEvent(
        string timestamp,
        string scriptIdentity,
        string operation,
        string resource,
        AuditDecision decision,
        string reason)
        : this(Guid.NewGuid().ToString(), "1.0", timestamp, scriptIdentity, operation, EvaluatorSecretScrubber.Scrub(resource), decision, EvaluatorSecretScrubber.Scrub(reason))
    {
    }

    public static AuditEvent Create(
        string scriptIdentity,
        string operation,
        string resource,
        AuditDecision decision,
        string reason)
    {
        return new AuditEvent(
            Guid.NewGuid().ToString(),
            "1.0",
            DateTimeOffset.UtcNow.ToString("o"),
            scriptIdentity,
            operation,
            EvaluatorSecretScrubber.Scrub(resource),
            decision,
            EvaluatorSecretScrubber.Scrub(reason)
        );
    }

    public string ToJson() => JsonSerializer.Serialize(this, AuditJsonContext.Default.AuditEvent);
}

[JsonSerializable(typeof(AuditEvent))]
[JsonSerializable(typeof(List<AuditEvent>))]
internal partial class AuditJsonContext : JsonSerializerContext
{
}

public interface IAuditLogger
{
    void Log(AuditEvent evt);
}

public sealed class NullAuditLogger : IAuditLogger
{
    public static readonly NullAuditLogger Instance = new();
    public void Log(AuditEvent evt) { }
}

public sealed class InMemoryAuditLogger : IAuditLogger
{
    private readonly List<AuditEvent> _events = new();
    private readonly object _lock = new();

    public IReadOnlyList<AuditEvent> Events
    {
        get
        {
            lock (_lock) return _events.ToArray();
        }
    }

    public void Log(AuditEvent evt)
    {
        lock (_lock)
        {
            _events.Add(evt);
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _events.Clear();
        }
    }
}

public sealed class FileAuditLogger : IAuditLogger
{
    private readonly string _filePath;
    private readonly object _fileLock = new();

    public FileAuditLogger(string filePath)
    {
        _filePath = filePath;
        var dir = Path.GetDirectoryName(Path.GetFullPath(filePath));
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }
    }

    public void Log(AuditEvent evt)
    {
        var line = evt.ToJson() + Environment.NewLine;
        lock (_fileLock)
        {
            File.AppendAllText(_filePath, line);
        }
    }
}

public sealed class CompositeAuditLogger : IAuditLogger
{
    private readonly List<IAuditLogger> _loggers;

    public CompositeAuditLogger(params IAuditLogger[] loggers)
    {
        _loggers = new List<IAuditLogger>(loggers);
    }

    public void Log(AuditEvent evt)
    {
        foreach (var logger in _loggers)
        {
            try
            {
                logger.Log(evt);
            }
            catch
            {
                // Never let audit logging failure crash application execution
            }
        }
    }
}
