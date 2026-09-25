using System;

namespace Ps2.Core;

public sealed class Ps2RuntimeException : Exception
{
    public SourceLocation Location { get; }

    public Ps2RuntimeException(string message, SourceLocation location, Exception? innerException = null)
        : base(message, innerException)
    {
        Location = location;
    }
}
