using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Ps2.Core;

namespace Ps2.Runtime;

public static class TableFormatter
{
    public static void Print(Ps2Value data)
    {
        if (data.Type != Ps2ValueType.List)
        {
            Console.WriteLine(data.ToString());
            return;
        }

        var list = data.AsList();
        if (list.Count == 0)
        {
            Console.WriteLine("(empty list)");
            return;
        }

        // If list of Maps
        if (list.All(item => item.Type == Ps2ValueType.Map))
        {
            var maps = list.Select(item => item.AsMap()).ToList();
            var headers = maps.SelectMany(m => m.Keys).Distinct().ToList();

            if (headers.Count == 0)
            {
                Console.WriteLine("[]");
                return;
            }

            var colWidths = new Dictionary<string, int>();
            foreach (var h in headers)
            {
                int maxLen = h.Length;
                foreach (var m in maps)
                {
                    if (m.TryGetValue(h, out var val))
                    {
                        var s = val.AsString();
                        if (s.Length > maxLen) maxLen = s.Length;
                    }
                }
                colWidths[h] = Math.Min(maxLen + 2, 50); // padding & cap
            }

            // Top Border
            Console.WriteLine("┌" + string.Join("┬", headers.Select(h => new string('─', colWidths[h]))) + "┐");

            // Header Row
            var headerRow = "│" + string.Join("│", headers.Select(h => (" " + h).PadRight(colWidths[h]))) + "│";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(headerRow);
            Console.ResetColor();

            // Middle Separator
            Console.WriteLine("├" + string.Join("┼", headers.Select(h => new string('─', colWidths[h]))) + "┤");

            // Data Rows
            foreach (var m in maps)
            {
                var row = "│" + string.Join("│", headers.Select(h =>
                {
                    var text = m.TryGetValue(h, out var v) ? (" " + v.AsString()) : " -";
                    if (text.Length > colWidths[h]) text = text[..(colWidths[h] - 3)] + "...";
                    return text.PadRight(colWidths[h]);
                })) + "│";
                Console.WriteLine(row);
            }

            // Bottom Border
            Console.WriteLine("└" + string.Join("┴", headers.Select(h => new string('─', colWidths[h]))) + "┘");
            return;
        }

        // Otherwise list of primitives
        int indexWidth = Math.Max(list.Count.ToString().Length, 5) + 2;
        int valueWidth = Math.Min(list.Max(x => x.ToString().Length) + 2, 60);

        Console.WriteLine("┌" + new string('─', indexWidth) + "┬" + new string('─', valueWidth) + "┐");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("│" + " Index".PadRight(indexWidth) + "│" + " Value".PadRight(valueWidth) + "│");
        Console.ResetColor();
        Console.WriteLine("├" + new string('─', indexWidth) + "┼" + new string('─', valueWidth) + "┤");

        for (int i = 0; i < list.Count; i++)
        {
            var idxStr = (" " + i).PadRight(indexWidth);
            var valStr = (" " + list[i].AsString());
            if (valStr.Length > valueWidth) valStr = valStr[..(valueWidth - 3)] + "...";
            valStr = valStr.PadRight(valueWidth);
            Console.WriteLine($"│{idxStr}│{valStr}│");
        }

        Console.WriteLine("└" + new string('─', indexWidth) + "┴" + new string('─', valueWidth) + "┘");
    }
}
