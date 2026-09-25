using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace Ps2.Core;

public static class Ps2Formatter
{
    public static string Format(string source)
    {
        if (string.IsNullOrWhiteSpace(source))
            return string.Empty;

        var lines = source.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
        var formattedLines = new List<string>();

        int indentLevel = 0;
        const int IndentSize = 4;

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();

            if (string.IsNullOrEmpty(line))
            {
                formattedLines.Add(string.Empty);
                continue;
            }

            // Directives check
            if (line.StartsWith("#manifest", StringComparison.OrdinalIgnoreCase))
            {
                formattedLines.Add("#manifest");
                indentLevel = 0;
                continue;
            }
            if (line.StartsWith("#endmanifest", StringComparison.OrdinalIgnoreCase))
            {
                formattedLines.Add("#endmanifest");
                indentLevel = 0;
                continue;
            }

            // Adjust indentation for closing braces/brackets on current line
            int closingCount = CountChar(line, '}') + CountChar(line, ']');
            int openingCount = CountChar(line, '{') + CountChar(line, '[');

            // If line starts with closing brace, indent down first
            if (line.StartsWith("}") || line.StartsWith("]"))
            {
                indentLevel = Math.Max(0, indentLevel - 1);
            }

            var indent = new string(' ', indentLevel * IndentSize);
            var normalizedLine = NormalizeLineContent(line);
            formattedLines.Add(indent + normalizedLine);

            // If line starts with closing brace, we already decremented
            int netChange = openingCount - closingCount;
            if (line.StartsWith("}") || line.StartsWith("]"))
            {
                netChange += 1;
            }

            indentLevel = Math.Max(0, indentLevel + netChange);
        }

        // Remove trailing empty lines and add single newline at end
        while (formattedLines.Count > 0 && string.IsNullOrWhiteSpace(formattedLines[^1]))
        {
            formattedLines.RemoveAt(formattedLines.Count - 1);
        }

        return string.Join(Environment.NewLine, formattedLines) + Environment.NewLine;
    }

    private static string NormalizeLineContent(string line)
    {
        // Don't format inside full comment line
        if (line.StartsWith("//") || line.StartsWith("/*"))
        {
            return line;
        }

        // Standardize spacing around binary operators outside string literals
        // For simplicity and safety, normalize spaces around |, |>, =>, =, +, -, *, /
        var sb = new StringBuilder();
        bool inString = false;
        char stringDelimiter = '\0';

        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];

            if ((c == '"' || c == '\'') && (i == 0 || line[i - 1] != '\\'))
            {
                if (!inString)
                {
                    inString = true;
                    stringDelimiter = c;
                }
                else if (stringDelimiter == c)
                {
                    inString = false;
                }
                sb.Append(c);
                continue;
            }

            if (inString)
            {
                sb.Append(c);
                continue;
            }

            // Outside string literals: ensure single space around '|>' and '=>'
            if (c == '|' && i + 1 < line.Length && line[i + 1] == '>')
            {
                EnsureTrailingSpace(sb);
                sb.Append("|> ");
                i++;
                SkipSpaces(line, ref i);
                continue;
            }

            if (c == '=' && i + 1 < line.Length && line[i + 1] == '>')
            {
                EnsureTrailingSpace(sb);
                sb.Append("=> ");
                i++;
                SkipSpaces(line, ref i);
                continue;
            }

            if (c == '=' && i + 1 < line.Length && line[i + 1] == '=')
            {
                EnsureTrailingSpace(sb);
                sb.Append("== ");
                i++;
                SkipSpaces(line, ref i);
                continue;
            }

            if (c == '!' && i + 1 < line.Length && line[i + 1] == '=')
            {
                EnsureTrailingSpace(sb);
                sb.Append("!= ");
                i++;
                SkipSpaces(line, ref i);
                continue;
            }

            if (c == '=')
            {
                EnsureTrailingSpace(sb);
                sb.Append("= ");
                SkipSpaces(line, ref i);
                continue;
            }

            if (c == '*' && (i == 0 || line[i - 1] != '/') && (i + 1 >= line.Length || line[i + 1] != '/'))
            {
                EnsureTrailingSpace(sb);
                sb.Append("* ");
                SkipSpaces(line, ref i);
                continue;
            }

            // Commas: ensure single trailing space
            if (c == ',')
            {
                sb.Append(", ");
                SkipSpaces(line, ref i);
                continue;
            }

            sb.Append(c);
        }

        return sb.ToString().TrimEnd();
    }

    private static void EnsureTrailingSpace(StringBuilder sb)
    {
        if (sb.Length > 0 && sb[^1] != ' ')
        {
            sb.Append(' ');
        }
    }

    private static void SkipSpaces(string line, ref int i)
    {
        while (i + 1 < line.Length && line[i + 1] == ' ')
        {
            i++;
        }
    }

    private static int CountChar(string line, char ch)
    {
        int count = 0;
        bool inString = false;
        char quote = '\0';

        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if ((c == '"' || c == '\'') && (i == 0 || line[i - 1] != '\\'))
            {
                if (!inString)
                {
                    inString = true;
                    quote = c;
                }
                else if (quote == c)
                {
                    inString = false;
                }
                continue;
            }

            if (!inString && c == ch)
            {
                count++;
            }
        }
        return count;
    }
}
