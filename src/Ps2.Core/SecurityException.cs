using System;

namespace Ps2.Core;

public sealed class Ps2SecurityException : Exception
{
    public string Capability { get; }
    public string TargetResource { get; }
    public SourceLocation Location { get; set; }

    public Ps2SecurityException(string capability, string targetResource, string message, SourceLocation location = default)
        : base(message)
    {
        Capability = capability;
        TargetResource = targetResource;
        Location = location == default ? SourceLocation.Unknown : location;
    }
}

