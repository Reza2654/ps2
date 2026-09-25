using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Ps2.Bundler;
using Ps2.Core;
using Ps2.Parser;
using Ps2.Runtime;

using Ps2.Runtime.Repl;

namespace Ps2.Cli;

public static class Program
{
    private const string Version = "0.1.0-alpha (Native .NET 10 Engine)";

    public static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            new Ps2Repl().Run();
            return 0;
        }

        if (args[0] is "-h" or "--help" or "help")
        {
            PrintHelp();
            return 0;
        }

        if (args[0] is "-v" or "--version" or "version")
        {
            Console.WriteLine($"ps2 version {Version}");
            return 0;
        }

        var command = args[0].ToLowerInvariant();

        try
        {
            return command switch
            {
                "repl" => HandleRepl(),
                "run" => HandleRun(args.Skip(1).ToArray()),
                "check" => HandleCheck(args.Skip(1).ToArray()),
                "init" => HandleInit(args.Skip(1).ToArray()),
                "fmt" => HandleFmt(args.Skip(1).ToArray()),
                "lint" => HandleLint(args.Skip(1).ToArray()),
                "bundle" => HandleBundle(args.Skip(1).ToArray()),
                "sign" => HandleSign(args.Skip(1).ToArray()),
                "verify" => HandleVerify(args.Skip(1).ToArray()),
                "register" => HandleRegister(),
                "unregister" => HandleUnregister(),
                _ when File.Exists(args[0]) || args[0].EndsWith(".ps2", StringComparison.OrdinalIgnoreCase) || args[0].EndsWith(".ps2bundle", StringComparison.OrdinalIgnoreCase)
                    => HandleRun(args),
                _ => UnknownCommand(command)
            };
        }
        catch (Ps2ParserException parseEx)
        {
            foreach (var diag in parseEx.Diagnostics)
            {
                Console.Error.WriteLine(DiagnosticRenderer.Render(diag, null, useColor: true));
            }
            return 1;
        }
        catch (Ps2SecurityException secEx)
        {
            Console.Error.WriteLine(DiagnosticRenderer.Render("error", "PS2_SECURITY", secEx.Message, secEx.Location, null, useColor: true));
            return 126;
        }
        catch (Ps2RuntimeException runEx)
        {
            Console.Error.WriteLine(DiagnosticRenderer.Render("error", "PS2_RUNTIME", runEx.Message, runEx.Location, null, useColor: true));
            return 1;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Error.WriteLine($"\n[PS2 ERROR] {ex.Message}");
            Console.ResetColor();
            return 1;
        }
    }

    private static int HandleRepl()
    {
        new Ps2Repl().Run();
        return 0;
    }

    private static int HandleRun(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Error: Missing script file path. Usage: ps2 run <file.ps2> [args...]");
            return 1;
        }

        string targetFile = string.Empty;
        bool allowAll = false;
        bool strict = false;
        bool noVerify = false;
        var scriptArgs = new List<string>();

        int i = 0;
        while (i < args.Length)
        {
            var arg = args[i];
            if (arg == "--allow-all")
            {
                allowAll = true;
            }
            else if (arg == "--strict")
            {
                strict = true;
            }
            else if (arg == "--no-verify")
            {
                noVerify = true;
            }
            else if (string.IsNullOrEmpty(targetFile))
            {
                targetFile = arg;
            }
            else
            {
                scriptArgs.Add(arg);
            }
            i++;
        }

        if (string.IsNullOrEmpty(targetFile))
        {
            Console.WriteLine("Error: No script specified.");
            return 1;
        }

        string scriptContent;
        string scriptDir;

        if (targetFile.EndsWith(".ps2bundle", StringComparison.OrdinalIgnoreCase))
        {
            var (entryContent, metadata, files) = BundlePackage.ReadBundle(targetFile);
            scriptContent = entryContent;
            scriptDir = Path.GetDirectoryName(Path.GetFullPath(targetFile)) ?? Directory.GetCurrentDirectory();
            Console.WriteLine($"[INFO] Executing bundle: {metadata.EntryScript} (SHA256: {metadata.Sha256[..8]}...)");
        }
        else
        {
            if (!File.Exists(targetFile))
            {
                Console.WriteLine($"Error: File '{targetFile}' not found.");
                return 1;
            }
            scriptContent = File.ReadAllText(targetFile);
            scriptDir = Path.GetDirectoryName(Path.GetFullPath(targetFile)) ?? Directory.GetCurrentDirectory();

            if (!noVerify && scriptContent.Contains("#signature:"))
            {
                if (!ScriptSigner.VerifyScript(scriptContent, out var msg))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[SECURITY ERROR] {msg}");
                    Console.ResetColor();
                    if (strict) return 126;
                }
            }
            else if (strict && !scriptContent.Contains("#signature:"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[SECURITY ERROR] --strict mode requires a signed script (#signature:).");
                Console.ResetColor();
                return 126;
            }
        }

        // Tokenize
        var lexer = new Ps2Lexer(scriptContent, targetFile);
        var tokens = lexer.Tokenize();

        // Parse
        var parser = new Ps2Parser(tokens);
        var program = parser.Parse();

        // Evaluate
        var evaluator = new Evaluator(program.Manifest, scriptDir, scriptArgs, allowAll);
        var result = evaluator.Execute(program);

        return 0;
    }

    private static int HandleCheck(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Error: Missing script file path. Usage: ps2 check <file.ps2>");
            return 1;
        }

        var path = args[0];
        if (!File.Exists(path))
        {
            Console.WriteLine($"Error: File '{path}' not found.");
            return 1;
        }

        var content = File.ReadAllText(path);
        Console.WriteLine($"=== Checking: {path} ===");

        // Signature check
        if (content.Contains("#signature:"))
        {
            if (ScriptSigner.VerifyScript(content, out var msg))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[SIGNATURE] Valid: {msg}");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[SIGNATURE] INVALID: {msg}");
                Console.ResetColor();
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine("[SIGNATURE] Unsigned script (no #signature header found)");
            Console.ResetColor();
        }

        // Lex & Parse
        var lexer = new Ps2Lexer(content, path);
        var tokens = lexer.Tokenize();
        var parser = new Ps2Parser(tokens);
        var program = parser.Parse();

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[SYNTAX] OK ({program.Statements.Count} top-level statements parsed)");
        Console.ResetColor();

        // Manifest report
        Console.WriteLine("\n[CAPABILITY MANIFEST - ZERO-TRUST SANDBOX]");
        PrintCapabilityList("fs.read", program.Manifest.FsRead);
        PrintCapabilityList("fs.write", program.Manifest.FsWrite);
        PrintCapabilityList("net.http", program.Manifest.NetHttp);
        PrintCapabilityList("env", program.Manifest.Env);
        PrintCapabilityList("proc.exec", program.Manifest.ProcExec);

        return 0;
    }

    private static void PrintCapabilityList(string name, HashSet<string> items)
    {
        if (items.Count == 0)
        {
            Console.WriteLine($"  {name,-10}: (none declared - access blocked)");
        }
        else
        {
            Console.WriteLine($"  {name,-10}: [ {string.Join(", ", items.Select(i => $"\"{i}\""))} ]");
        }
    }

    private static int HandleBundle(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Usage: ps2 bundle <entry.ps2> -o <output.ps2bundle> [--include <file1> <file2>]");
            return 1;
        }

        string entryScript = args[0];
        string outputBundle = Path.ChangeExtension(entryScript, ".ps2bundle");
        var extraFiles = new List<string>();

        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "-o" && i + 1 < args.Length)
            {
                outputBundle = args[++i];
            }
            else if (args[i] == "--include")
            {
                while (i + 1 < args.Length && !args[i + 1].StartsWith('-'))
                {
                    extraFiles.Add(args[++i]);
                }
            }
        }

        Console.WriteLine($"Bundling '{entryScript}' -> '{outputBundle}'...");
        BundlePackage.CreateBundle(entryScript, outputBundle, extraFiles);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[SUCCESS] Bundle generated: {outputBundle}");
        Console.ResetColor();
        return 0;
    }

    private static int HandleSign(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Usage: ps2 sign <file.ps2>");
            return 1;
        }

        var path = args[0];
        if (!File.Exists(path))
        {
            Console.WriteLine($"File '{path}' not found.");
            return 1;
        }

        var content = File.ReadAllText(path);
        var signed = ScriptSigner.SignScript(content);
        File.WriteAllText(path, signed);

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[SUCCESS] Script '{path}' signed with SHA-256 integrity hash.");
        Console.ResetColor();
        return 0;
    }

    private static int HandleVerify(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Usage: ps2 verify <file.ps2>");
            return 1;
        }

        var path = args[0];
        if (!File.Exists(path))
        {
            Console.WriteLine($"File '{path}' not found.");
            return 1;
        }

        var content = File.ReadAllText(path);
        if (ScriptSigner.VerifyScript(content, out var msg))
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[VERIFIED] {msg}");
            Console.ResetColor();
            return 0;
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[VERIFICATION FAILED] {msg}");
            Console.ResetColor();
            return 1;
        }
    }

    private static int HandleRegister()
    {
        return WindowsRegistryIntegration.RegisterFileAssociation() ? 0 : 1;
    }

    private static int HandleUnregister()
    {
        return WindowsRegistryIntegration.UnregisterFileAssociation() ? 0 : 1;
    }

    private static int HandleInit(string[] args)
    {
        string projectName = args.Length > 0 ? args[0] : "ps2_app";
        string targetDir = Path.GetFullPath(projectName);

        if (Directory.Exists(targetDir) && Directory.GetFileSystemEntries(targetDir).Length > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Directory '{projectName}' already exists and is not empty.");
            Console.ResetColor();
        }
        else
        {
            Directory.CreateDirectory(targetDir);
        }

        string mainPs2Path = Path.Combine(targetDir, "main.ps2");
        if (!File.Exists(mainPs2Path))
        {
            var rawTemplate = """
            #manifest
            requires {
                fs.read: ["./data"],
                fs.write: ["./out"]
            }
            #endmanifest

            println("Welcome to PS2 (PowerScript 2)!");

            let numbers = [1, 2, 3, 4, 5];
            let squared = numbers |> map(n => n * n);

            println("Squared list: " + json.stringify(squared));
            """;
            File.WriteAllText(mainPs2Path, Ps2Formatter.Format(rawTemplate));
        }

        string readmePath = Path.Combine(targetDir, "README.md");
        if (!File.Exists(readmePath))
        {
            File.WriteAllText(readmePath, $"""
            # {projectName}

            A modern automation and scripting project powered by **PS2 (PowerScript 2)**.

            ## Getting Started
            - Run script: `ps2 run main.ps2`
            - Lint checks: `ps2 lint main.ps2`
            - Format code: `ps2 fmt main.ps2`
            - Sign script: `ps2 sign main.ps2`
            - Bundle app: `ps2 bundle main.ps2 -o {projectName}.ps2bundle`
            """);
        }

        string gitignorePath = Path.Combine(targetDir, ".gitignore");
        if (!File.Exists(gitignorePath))
        {
            File.WriteAllText(gitignorePath, """
            *.ps2bundle
            out/
            *.tmp
            """);
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[INIT] Created PS2 project in '{targetDir}'.");
        Console.WriteLine("  main.ps2    - Starter script with manifest and pipeline");
        Console.WriteLine("  README.md   - Project documentation and CLI guide");
        Console.WriteLine("  .gitignore  - Default ignore rules");
        Console.ResetColor();
        return 0;
    }

    private static int HandleFmt(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Error: Missing file path. Usage: ps2 fmt <file.ps2> [--check]");
            return 1;
        }

        string path = args[0];
        bool checkOnly = args.Contains("--check");

        if (!File.Exists(path))
        {
            Console.WriteLine($"Error: File '{path}' not found.");
            return 1;
        }

        string content = File.ReadAllText(path);
        string formatted = Ps2Formatter.Format(content);

        if (checkOnly)
        {
            if (content == formatted)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[FORMAT OK] '{path}' is canonically formatted.");
                Console.ResetColor();
                return 0;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[FORMAT NEEDED] '{path}' is not canonically formatted.");
                Console.ResetColor();
                return 1;
            }
        }

        if (content != formatted)
        {
            File.WriteAllText(path, formatted);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[FORMATTED] '{path}' updated successfully.");
            Console.ResetColor();
        }
        else
        {
            Console.WriteLine($"[FORMATTED] '{path}' was already formatted.");
        }

        return 0;
    }

    private static int HandleLint(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Error: Missing file path. Usage: ps2 lint <file.ps2>");
            return 1;
        }

        string path = args[0];
        if (!File.Exists(path))
        {
            Console.WriteLine($"Error: File '{path}' not found.");
            return 1;
        }

        string content = File.ReadAllText(path);
        var lexer = new Ps2Lexer(content, path);
        var tokens = lexer.Tokenize();
        var parser = new Ps2Parser(tokens);
        ProgramNode program;
        try
        {
            program = parser.Parse();
        }
        catch (Ps2ParserException pEx)
        {
            foreach (var diag in pEx.Diagnostics)
            {
                Console.Error.WriteLine(DiagnosticRenderer.Render(diag, content, useColor: true));
            }
            return 1;
        }

        var diagnostics = Ps2Linter.Lint(program);

        if (diagnostics.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[LINT OK] No issues found in '{path}'.");
            Console.ResetColor();
            return 0;
        }

        bool hasError = false;
        foreach (var diag in diagnostics)
        {
            if (diag.Severity == DiagnosticSeverity.Error) hasError = true;
            Console.Error.WriteLine(DiagnosticRenderer.Render(diag, content, useColor: true));
        }

        return hasError ? 1 : 0;
    }

    private static int UnknownCommand(string command)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Unknown command or invalid script: '{command}'.");
        Console.ResetColor();
        PrintHelp();
        return 1;
    }

    private static void PrintHelp()
    {
        Console.WriteLine($"""
        ps2 - PowerScript 2 Execution Engine & Language Runtime ({Version})

        USAGE:
            ps2 run <file.ps2 | bundle.ps2bundle> [flags] [args...]
            ps2 check <file.ps2>
            ps2 init [project_name]
            ps2 fmt <file.ps2> [--check]
            ps2 lint <file.ps2>
            ps2 bundle <entry.ps2> -o <bundle.ps2bundle> [--include <files...>]
            ps2 sign <file.ps2>
            ps2 verify <file.ps2>
            ps2 register
            ps2 unregister

        COMMANDS:
            run         Execute a .ps2 script or .ps2bundle with Zero-Trust sandbox
            check       Statically check syntax, manifest capabilities, and signature
            init        Initialize a new PS2 project template with starter code
            fmt         Format PS2 source file according to official style guidelines
            lint        Perform static analysis for undeclared permissions and unused vars
            bundle      Package scripts and assets into a single redistributable bundle
            sign        Embed cryptographic SHA-256 integrity hash into script header
            verify      Validate embedded cryptographic signature of a script
            register    Register .ps2 file association in Windows Registry (HKCU\Classes)
            unregister  Remove .ps2 file association from Windows Registry
            version     Display version information

        FLAGS:
            --allow-all Bypass sandbox restrictions (allow all disk, network, proc calls)
            --strict    Enforce strict signature verification and sandbox requirements
            --no-verify Skip cryptographic signature check during execution
            -h, --help  Show this help screen
        """);
    }
}
