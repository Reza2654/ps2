using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Ps2.Core;
using Ps2.Parser;

namespace Ps2.Runtime.Repl;

public sealed class Ps2Repl
{
    private readonly CapabilityManifest _manifest;
    private readonly string _workingDirectory;
    private readonly List<string> _history = new();
    private Evaluator _evaluator;

    public Ps2Repl(CapabilityManifest? manifest = null, string? workingDirectory = null)
    {
        _manifest = manifest ?? new CapabilityManifest { AllowAll = true };
        _workingDirectory = workingDirectory ?? Directory.GetCurrentDirectory();
        _evaluator = new Evaluator(_manifest, _workingDirectory, Array.Empty<string>(), allowAll: _manifest.AllowAll);
    }

    public void Run()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("""
        =========================================================
          PowerScript 2 (ps2) Interactive Shell (REPL) v0.1.0-alpha
          Type expressions to evaluate, :help for commands, exit to quit.
        =========================================================
        """);
        Console.ResetColor();

        var multiLineBuffer = new StringBuilder();

        while (true)
        {
            string prompt = multiLineBuffer.Length == 0 ? "ps2> " : "...  ";
            Console.ForegroundColor = multiLineBuffer.Length == 0 ? ConsoleColor.Green : ConsoleColor.DarkGray;
            Console.Write(prompt);
            Console.ResetColor();

            string? line = ReadLineWithHistory();
            if (line == null) break; // EOF (Ctrl+Z / Ctrl+D)

            var trimmed = line.Trim();

            // REPL commands (when not in multi-line)
            if (multiLineBuffer.Length == 0)
            {
                if (trimmed.Equals("exit", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Equals("quit", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Exiting ps2 shell. Goodbye!");
                    break;
                }

                if (trimmed.Equals(":clear", StringComparison.OrdinalIgnoreCase))
                {
                    Console.Clear();
                    continue;
                }

                if (trimmed.Equals(":help", StringComparison.OrdinalIgnoreCase))
                {
                    PrintReplHelp();
                    continue;
                }

                if (trimmed.Equals(":reset", StringComparison.OrdinalIgnoreCase))
                {
                    _evaluator = new Evaluator(_manifest, _workingDirectory, Array.Empty<string>(), allowAll: _manifest.AllowAll);
                    Console.WriteLine("[INFO] Environment scope reset.");
                    continue;
                }

                if (string.IsNullOrWhiteSpace(trimmed))
                {
                    continue;
                }
            }

            multiLineBuffer.AppendLine(line);

            // Check if brackets are balanced: { }, [ ], ( )
            var fullInput = multiLineBuffer.ToString();
            if (IsBracketBalanced(fullInput))
            {
                var inputToExecute = fullInput.Trim();
                multiLineBuffer.Clear();

                if (!string.IsNullOrEmpty(inputToExecute))
                {
                    _history.Add(inputToExecute);
                    ExecuteReplInput(inputToExecute);
                }
            }
        }
    }

    private void ExecuteReplInput(string input)
    {
        try
        {
            // 1. Try tokenizing
            var lexer = new Ps2Lexer(input, "<repl>");
            var tokens = lexer.Tokenize();

            // 2. Parse as Program
            var parser = new Ps2Parser(tokens);
            var program = parser.Parse();

            if (program.Statements.Count == 0) return;

            // 3. Execute statements in persistent scope
            foreach (var stmt in program.Statements)
            {
                if (stmt is ExpressionStatement exprStmt)
                {
                    // Evaluate and auto-print expression result
                    var result = _evaluator.EvaluateExpression(exprStmt.Expression, _evaluator.GlobalScope);
                    if (result != Ps2Value.Null)
                    {
                        PrintResult(result);
                    }
                }
                else
                {
                    _evaluator.Execute(new ProgramNode(program.Manifest, program.Signature, new List<StatementNode> { stmt }, stmt.Location));
                }
            }
        }
        catch (Ps2SecurityException secEx)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[SECURITY ERROR] {secEx.Message}");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[ERROR] {ex.Message}");
            Console.ResetColor();
        }
    }

    private static void PrintResult(Ps2Value val)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        if (val.Type == Ps2ValueType.String)
        {
            Console.WriteLine($"\"{val.AsString()}\"");
        }
        else
        {
            Console.WriteLine(val.ToString());
        }
        Console.ResetColor();
    }

    private static bool IsBracketBalanced(string input)
    {
        int braces = 0;   // { }
        int brackets = 0; // [ ]
        int parens = 0;   // ( )
        bool inString = false;

        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];

            if (c == '"' && (i == 0 || input[i - 1] != '\\'))
            {
                inString = !inString;
                continue;
            }

            if (inString) continue;

            switch (c)
            {
                case '{': braces++; break;
                case '}': braces--; break;
                case '[': brackets++; break;
                case ']': brackets--; break;
                case '(': parens++; break;
                case ')': parens--; break;
            }
        }

        return braces <= 0 && brackets <= 0 && parens <= 0;
    }

    private string? ReadLineWithHistory()
    {
        // If console is redirected, fallback to standard ReadLine
        if (Console.IsInputRedirected)
        {
            return Console.ReadLine();
        }

        int historyIndex = _history.Count;
        var currentInput = new StringBuilder();

        while (true)
        {
            var keyInfo = Console.ReadKey(intercept: true);

            if (keyInfo.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return currentInput.ToString();
            }

            if (keyInfo.Key == ConsoleKey.UpArrow)
            {
                if (historyIndex > 0)
                {
                    historyIndex--;
                    ClearCurrentLine(currentInput.Length);
                    currentInput.Clear();
                    currentInput.Append(_history[historyIndex]);
                    Console.Write(currentInput.ToString());
                }
            }
            else if (keyInfo.Key == ConsoleKey.DownArrow)
            {
                if (historyIndex < _history.Count - 1)
                {
                    historyIndex++;
                    ClearCurrentLine(currentInput.Length);
                    currentInput.Clear();
                    currentInput.Append(_history[historyIndex]);
                    Console.Write(currentInput.ToString());
                }
                else if (historyIndex == _history.Count - 1)
                {
                    historyIndex = _history.Count;
                    ClearCurrentLine(currentInput.Length);
                    currentInput.Clear();
                }
            }
            else if (keyInfo.Key == ConsoleKey.Backspace)
            {
                if (currentInput.Length > 0)
                {
                    currentInput.Remove(currentInput.Length - 1, 1);
                    Console.Write("\b \b");
                }
            }
            else if (keyInfo.Key == ConsoleKey.Escape)
            {
                ClearCurrentLine(currentInput.Length);
                currentInput.Clear();
            }
            else if (!char.IsControl(keyInfo.KeyChar))
            {
                currentInput.Append(keyInfo.KeyChar);
                Console.Write(keyInfo.KeyChar);
            }
        }
    }

    private static void ClearCurrentLine(int length)
    {
        for (int i = 0; i < length; i++)
        {
            Console.Write("\b \b");
        }
    }

    private static void PrintReplHelp()
    {
        Console.WriteLine("""
        Available commands:
          exit, quit    Exit the REPL session
          :help         Show this help information
          :clear        Clear the screen
          :reset        Reset variable scopes
          Up/Down       Navigate previous command history
        
        Example expressions:
          let x = [1, 2, 3, 4]
          x |> map(n => n * 10)
          let server = {"name": "node-1", "active": true}
          server["name"]
        """);
    }
}
