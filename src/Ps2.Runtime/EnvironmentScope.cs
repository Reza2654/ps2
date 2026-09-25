using System;
using System.Collections.Generic;
using Ps2.Core;

namespace Ps2.Runtime;

public sealed class EnvironmentScope
{
    private readonly EnvironmentScope? _parent;
    private readonly Dictionary<string, (Ps2Value Value, bool IsMutable)> _variables = new(StringComparer.Ordinal);

    public EnvironmentScope(EnvironmentScope? parent = null)
    {
        _parent = parent;
    }

    public EnvironmentScope CreateChild() => new(this);

    public void Define(string name, Ps2Value value, bool isMutable = true)
    {
        _variables[name] = (value, isMutable);
    }

    public void Assign(string name, Ps2Value value)
    {
        if (_variables.TryGetValue(name, out var entry))
        {
            if (!entry.IsMutable)
            {
                throw new InvalidOperationException($"Cannot reassign to immutable variable '{name}'. Use 'let mut' to declare mutable variables.");
            }
            _variables[name] = (value, true);
            return;
        }

        if (_parent != null)
        {
            _parent.Assign(name, value);
            return;
        }

        throw new KeyNotFoundException($"Variable '{name}' is not defined in the current scope.");
    }

    public bool TryLookup(string name, out Ps2Value value)
    {
        if (_variables.TryGetValue(name, out var entry))
        {
            value = entry.Value;
            return true;
        }

        if (_parent != null)
        {
            return _parent.TryLookup(name, out value);
        }

        value = Ps2Value.Null;
        return false;
    }

    public Ps2Value Get(string name)
    {
        if (TryLookup(name, out var value))
        {
            return value;
        }
        throw new KeyNotFoundException($"Undefined variable or symbol '{name}'.");
    }
}
