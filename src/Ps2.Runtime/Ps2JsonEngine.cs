using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using Ps2.Core;

namespace Ps2.Runtime;

public static class Ps2JsonEngine
{
    public static string Stringify(Ps2Value value, bool indented = true)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = indented }))
        {
            WriteValue(writer, value);
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteValue(Utf8JsonWriter writer, Ps2Value value)
    {
        switch (value.Type)
        {
            case Ps2ValueType.Null:
                writer.WriteNullValue();
                break;
            case Ps2ValueType.Bool:
                writer.WriteBooleanValue((bool)value.RawValue!);
                break;
            case Ps2ValueType.Int:
                writer.WriteNumberValue((long)value.RawValue!);
                break;
            case Ps2ValueType.Float:
                writer.WriteNumberValue((double)value.RawValue!);
                break;
            case Ps2ValueType.String:
                writer.WriteStringValue((string)value.RawValue!);
                break;
            case Ps2ValueType.List:
                writer.WriteStartArray();
                foreach (var item in value.AsList())
                {
                    WriteValue(writer, item);
                }
                writer.WriteEndArray();
                break;
            case Ps2ValueType.Map:
                writer.WriteStartObject();
                foreach (var kv in value.AsMap())
                {
                    writer.WritePropertyName(kv.Key);
                    WriteValue(writer, kv.Value);
                }
                writer.WriteEndObject();
                break;
            case Ps2ValueType.Option:
                var opt = value.AsOption();
                if (opt.HasValue && opt.Value != null)
                {
                    WriteValue(writer, opt.Value);
                }
                else
                {
                    writer.WriteNullValue();
                }
                break;
            case Ps2ValueType.Result:
                var res = value.AsResult();
                writer.WriteStartObject();
                writer.WriteBoolean("is_ok", res.IsOk);
                writer.WritePropertyName("value");
                WriteValue(writer, res.Value);
                writer.WriteEndObject();
                break;
            default:
                writer.WriteStringValue(value.ToString());
                break;
        }
    }

    public static Ps2Value Parse(string jsonString)
    {
        if (string.IsNullOrWhiteSpace(jsonString)) return Ps2Value.Null;

        using var doc = JsonDocument.Parse(jsonString);
        return ConvertJsonElement(doc.RootElement);
    }

    private static Ps2Value ConvertJsonElement(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.Null or JsonValueKind.Undefined => Ps2Value.Null,
            JsonValueKind.True => Ps2Value.True,
            JsonValueKind.False => Ps2Value.False,
            JsonValueKind.Number => element.TryGetInt64(out var i) ? Ps2Value.From(i) : Ps2Value.From(element.GetDouble()),
            JsonValueKind.String => Ps2Value.From(element.GetString() ?? string.Empty),
            JsonValueKind.Array => Ps2Value.From(new List<Ps2Value>(element.EnumerateArray().Select(ConvertJsonElement))),
            JsonValueKind.Object => Ps2Value.From(new Dictionary<string, Ps2Value>(element.EnumerateObject().ToDictionary(p => p.Name, p => ConvertJsonElement(p.Value)))),
            _ => Ps2Value.Null
        };
    }
}
