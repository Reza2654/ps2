using System;
using Ps2.Core;

namespace Ps2.Runtime;

public sealed class ReturnException : Exception
{
    public Ps2Value Value { get; }

    public ReturnException(Ps2Value value)
    {
        Value = value;
    }
}
