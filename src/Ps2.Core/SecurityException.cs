using System;

namespace Ps2.Core;

public sealed class Ps2SecurityException : Exception
{
    public string Capability { get; }
    public string TargetResource { get; }

    public Ps2SecurityException(string capability, string targetResource, string message)
        : base(message)
    {
        Capability = capability;
        TargetResource = targetResource;
    }
}
