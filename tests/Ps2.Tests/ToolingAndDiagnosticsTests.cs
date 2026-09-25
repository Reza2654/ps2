using System;
using System.IO;
using System.Linq;
using Ps2.Core;
using Ps2.Parser;
using Xunit;

namespace Ps2.Tests;

public class ToolingAndDiagnosticsTests : IDisposable
{
    private readonly string _testDir;

    public ToolingAndDiagnosticsTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "ps2_tooling_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_testDir))
        {
            Directory.Delete(_testDir, recursive: true);
        }
    }

    [Fact]
    public void DiagnosticRenderer_ShouldRender_CodeSnippetsAndPointer()
    {
        var script = """
        let x = 10;
        let data = fs.read_file("/unauthorized");
        println(data);
        """;

        var loc = new SourceLocation("test_script.ps2", 2, 12);
        var diag = new Diagnostic(DiagnosticSeverity.Error, "PS2_SECURITY", "[Zero-Trust Sandbox] Read access denied to '/unauthorized'. Declare permission in '#manifest requires { fs.read: [\"/unauthorized\"] }' or run with --allow-all.", loc);

        var rendered = DiagnosticRenderer.Render(diag, script, useColor: false);

        Assert.Contains("error[PS2_SECURITY]", rendered);
        Assert.Contains("test_script.ps2:2:12", rendered);
        Assert.Contains("let data = fs.read_file(\"/unauthorized\");", rendered);
        Assert.Contains("^", rendered);
        Assert.Contains("help:", rendered);
    }

    [Fact]
    public void Formatter_ShouldCanonicalize_IndentationAndSpacing()
    {
        var messy = """
        #manifest
        requires {
        fs.read: ["/tmp"]
        }
        #endmanifest

        let x=10;
        let list=[1,2,3];
        let squared=list|>map(n=>n*2);
        """;

        var formatted = Ps2Formatter.Format(messy);

        Assert.Contains("    fs.read: [\"/tmp\"]", formatted);
        Assert.Contains("let list = [1, 2, 3];", formatted);
        Assert.Contains("|> map(n => n * 2);", formatted);
    }

    [Fact]
    public void Linter_ShouldDetect_UndeclaredCapabilities()
    {
        var script = """
        let content = fs.read_file("data.txt");
        println(content);
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();

        var diags = Ps2Linter.Lint(program);

        Assert.Contains(diags, d => d.Code == "LINT_CAP_FS_READ");
    }

    [Fact]
    public void Linter_ShouldDetect_UnusedVariables()
    {
        var script = """
        let unusedVar = 42;
        let usedVar = 100;
        println(usedVar);
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();

        var diags = Ps2Linter.Lint(program);

        Assert.Contains(diags, d => d.Code == "LINT_UNUSED_VAR" && d.Message.Contains("'unusedVar'"));
        Assert.DoesNotContain(diags, d => d.Code == "LINT_UNUSED_VAR" && d.Message.Contains("'usedVar'"));
    }

    [Fact]
    public void Linter_ShouldDetect_UnreachableCode()
    {
        var script = """
        fn calculate() {
            return 42;
            let unreachable = 10;
            println(unreachable);
        }
        calculate();
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();

        var diags = Ps2Linter.Lint(program);

        Assert.Contains(diags, d => d.Code == "LINT_UNREACHABLE_CODE");
    }

    [Fact]
    public void Cli_Init_ShouldCreateStarterProject()
    {
        var projDir = Path.Combine(_testDir, "sample_app");
        int exitCode = Ps2.Cli.Program.Main(new[] { "init", projDir });

        Assert.Equal(0, exitCode);
        Assert.True(File.Exists(Path.Combine(projDir, "main.ps2")));
        Assert.True(File.Exists(Path.Combine(projDir, "README.md")));
        Assert.True(File.Exists(Path.Combine(projDir, ".gitignore")));
    }

    [Fact]
    public void Cli_FmtAndLint_ShouldSucceedOnStarterProject()
    {
        var projDir = Path.Combine(_testDir, "sample_lint");
        Ps2.Cli.Program.Main(new[] { "init", projDir });
        var scriptPath = Path.Combine(projDir, "main.ps2");

        int fmtCode = Ps2.Cli.Program.Main(new[] { "fmt", scriptPath, "--check" });
        Assert.Equal(0, fmtCode);

        int lintCode = Ps2.Cli.Program.Main(new[] { "lint", scriptPath });
        Assert.Equal(0, lintCode);
    }
}

