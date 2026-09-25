using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace Ps2.Core;

public enum Ps2ValueType
{
    Null,
    Bool,
    Int,
    Float,
    String,
    List,
    Map,
    Option,
    Result,
    Function,
    NativeFunction,
    Secret
}

public sealed class Ps2Value : IEquatable<Ps2Value>
{
    public Ps2ValueType Type { get; }
    public object? RawValue { get; }

    public static readonly Ps2Value Null = new(Ps2ValueType.Null, null);
    public static readonly Ps2Value True = new(Ps2ValueType.Bool, true);
    public static readonly Ps2Value False = new(Ps2ValueType.Bool, false);

    private Ps2Value(Ps2ValueType type, object? rawValue)
    {
        Type = type;
        RawValue = rawValue;
    }

    public static Ps2Value From(bool value) => value ? True : False;
    public static Ps2Value From(long value) => new(Ps2ValueType.Int, value);
    public static Ps2Value From(int value) => new(Ps2ValueType.Int, (long)value);
    public static Ps2Value From(double value) => new(Ps2ValueType.Float, value);
    public static Ps2Value From(string value) => new(Ps2ValueType.String, value);
    public static Ps2Value From(List<Ps2Value> value) => new(Ps2ValueType.List, value);
    public static Ps2Value From(Dictionary<string, Ps2Value> value) => new(Ps2ValueType.Map, value);

    public static Ps2Value Some(Ps2Value inner) => new(Ps2ValueType.Option, new Ps2Option(true, inner));
    public static Ps2Value None() => new(Ps2ValueType.Option, new Ps2Option(false, null));

    public static Ps2Value Ok(Ps2Value inner) => new(Ps2ValueType.Result, new Ps2Result(true, inner));
    public static Ps2Value Err(Ps2Value inner) => new(Ps2ValueType.Result, new Ps2Result(false, inner));
    public static Ps2Value Secret(string value) => new(Ps2ValueType.Secret, new Ps2Secret(value));

    public static Ps2Value CreateFunction(FunctionDeclStatement decl, object closureScope)
        => new(Ps2ValueType.Function, new Ps2Function(decl, closureScope));

    public static Ps2Value CreateNativeFunction(string name, Func<IReadOnlyList<Ps2Value>, Ps2Value> callback)
        => new(Ps2ValueType.NativeFunction, new Ps2NativeFunction(name, callback));

    public bool IsNull => Type == Ps2ValueType.Null;
    public bool IsTruthy => Type switch
    {
        Ps2ValueType.Null => false,
        Ps2ValueType.Bool => (bool)RawValue!,
        Ps2ValueType.Int => (long)RawValue! != 0,
        Ps2ValueType.Float => (double)RawValue! != 0.0,
        Ps2ValueType.String => !string.IsNullOrEmpty((string)RawValue!),
        Ps2ValueType.List => ((List<Ps2Value>)RawValue!).Count > 0,
        Ps2ValueType.Map => ((Dictionary<string, Ps2Value>)RawValue!).Count > 0,
        Ps2ValueType.Option => ((Ps2Option)RawValue!).HasValue,
        Ps2ValueType.Result => ((Ps2Result)RawValue!).IsOk,
        Ps2ValueType.Secret => !string.IsNullOrEmpty(((Ps2Secret)RawValue!).Unmask()),
        _ => true
    };

    public bool AsBool() => RawValue is bool b ? b : IsTruthy;

    public long AsInt() => RawValue switch
    {
        long l => l,
        int i => i,
        double d => (long)d,
        string s when long.TryParse(s, out var parsed) => parsed,
        _ => throw new InvalidCastException($"Cannot convert {Type} to integer.")
    };

    public double AsFloat() => RawValue switch
    {
        double d => d,
        float f => f,
        long l => l,
        int i => i,
        string s when double.TryParse(s, out var parsed) => parsed,
        _ => throw new InvalidCastException($"Cannot convert {Type} to float.")
    };

    public string AsString() => RawValue switch
    {
        null => "null",
        Ps2Secret s => s.ToString(),
        string s => s,
        _ => ToString()
    };

    public List<Ps2Value> AsList() =>
        RawValue as List<Ps2Value> ?? throw new InvalidCastException($"Expected List, found {Type}.");

    public Dictionary<string, Ps2Value> AsMap() =>
        RawValue as Dictionary<string, Ps2Value> ?? throw new InvalidCastException($"Expected Map, found {Type}.");

    public Ps2Option AsOption() =>
        RawValue as Ps2Option ?? throw new InvalidCastException($"Expected Option, found {Type}.");

    public Ps2Result AsResult() =>
        RawValue as Ps2Result ?? throw new InvalidCastException($"Expected Result, found {Type}.");

    public Ps2Secret AsSecret() =>
        RawValue as Ps2Secret ?? throw new InvalidCastException($"Expected Secret, found {Type}.");

    public override string ToString()
    {
        return Type switch
        {
            Ps2ValueType.Null => "null",
            Ps2ValueType.Bool => (bool)RawValue! ? "true" : "false",
            Ps2ValueType.Int => ((long)RawValue!).ToString(),
            Ps2ValueType.Float => ((double)RawValue!).ToString("G"),
            Ps2ValueType.String => (string)RawValue!,
            Ps2ValueType.List => "[" + string.Join(", ", ((List<Ps2Value>)RawValue!).Select(x => x.ToString())) + "]",
            Ps2ValueType.Map => "{" + string.Join(", ", ((Dictionary<string, Ps2Value>)RawValue!).Select(kv => $"\"{kv.Key}\": {kv.Value}")) + "}",
            Ps2ValueType.Option => ((Ps2Option)RawValue!).ToString(),
            Ps2ValueType.Result => ((Ps2Result)RawValue!).ToString(),
            Ps2ValueType.Secret => "[REDACTED]",
            Ps2ValueType.Function => $"<fn {((Ps2Function)RawValue!).Decl.Name}>",
            Ps2ValueType.NativeFunction => $"<native fn {((Ps2NativeFunction)RawValue!).Name}>",
            _ => "<unknown>"
        };
    }

    public bool Equals(Ps2Value? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        if (Type != other.Type) return false;

        return Type switch
        {
            Ps2ValueType.Null => true,
            Ps2ValueType.Bool => (bool)RawValue! == (bool)other.RawValue!,
            Ps2ValueType.Int => (long)RawValue! == (long)other.RawValue!,
            Ps2ValueType.Float => Math.Abs((double)RawValue! - (double)other.RawValue!) < 1e-9,
            Ps2ValueType.String => string.Equals((string)RawValue!, (string)other.RawValue!, StringComparison.Ordinal),
            Ps2ValueType.Option => ((Ps2Option)RawValue!).Equals(other.RawValue),
            Ps2ValueType.Result => ((Ps2Result)RawValue!).Equals(other.RawValue),
            Ps2ValueType.Secret => ((Ps2Secret)RawValue!).Equals(other.RawValue),
            _ => Equals(RawValue, other.RawValue)
        };
    }

    public override bool Equals(object? obj) => obj is Ps2Value val && Equals(val);

    public override int GetHashCode() => HashCode.Combine(Type, RawValue);
}

public sealed class Ps2Secret : IEquatable<Ps2Secret>
{
    private readonly string _secretValue;

    public Ps2Secret(string secretValue)
    {
        _secretValue = secretValue ?? string.Empty;
    }

    public string Unmask() => _secretValue;

    public override string ToString() => "[REDACTED]";

    public bool Equals(Ps2Secret? other)
    {
        if (other is null) return false;
        return string.Equals(_secretValue, other._secretValue, StringComparison.Ordinal);
    }

    public override bool Equals(object? obj) => obj is Ps2Secret s && Equals(s);
    public override int GetHashCode() => _secretValue.GetHashCode();
}

public sealed record Ps2Option(bool HasValue, Ps2Value? Value)
{
    public override string ToString() => HasValue ? $"Some({Value})" : "None";
}

public sealed record Ps2Result(bool IsOk, Ps2Value Value)
{
    public override string ToString() => IsOk ? $"Ok({Value})" : $"Err({Value})";
}

public sealed class Ps2Function
{
    public FunctionDeclStatement Decl { get; }
    public object ClosureScope { get; }

    public Ps2Function(FunctionDeclStatement decl, object closureScope)
    {
        Decl = decl;
        ClosureScope = closureScope;
    }
}

public sealed record Ps2NativeFunction(string Name, Func<IReadOnlyList<Ps2Value>, Ps2Value> Callback);
