using System;
using System.IO;
using Ps2.Core;
using Ps2.Parser;
using Ps2.Runtime;
using Xunit;

namespace Ps2.Tests;

public class SandboxSecurityTests : IDisposable
{
    private readonly string _testDir;

    public SandboxSecurityTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "ps2_security_tests_" + Guid.NewGuid().ToString("N"));
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
    public void Sandbox_ShouldDeny_UndeclaredFileRead()
    {
        var secretFile = Path.Combine(_testDir, "secret.txt");
        File.WriteAllText(secretFile, "confidential data");

        var secretPath = secretFile.Replace('\\', '/');
        // Script declares NO permissions
        var script = $$"""
        let data = fs.read_file("{{secretPath}}");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Equal("fs.read", ex.Capability);
    }

    [Fact]
    public void Sandbox_ShouldAllow_DeclaredFileRead()
    {
        var allowedFile = Path.Combine(_testDir, "allowed.txt");
        File.WriteAllText(allowedFile, "safe data");

        var normalizedPath = allowedFile.Replace('\\', '/');
        var script = $$"""
        #manifest
        requires {
            fs.read: ["{{normalizedPath}}"]
        }
        #endmanifest

        let data = fs.read_file("{{normalizedPath}}");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var result = evaluator.Execute(program);
        Assert.Equal("safe data", result.AsString());
    }

    [Fact]
    public void Sandbox_ShouldDeny_UndeclaredFileWrite()
    {
        var targetFile = Path.Combine(_testDir, "output.txt").Replace('\\', '/');

        var script = $$"""
        fs.write_file("{{targetFile}}", "hello");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Equal("fs.write", ex.Capability);
        Assert.False(File.Exists(targetFile));
    }

    [Fact]
    public void Sandbox_ShouldDeny_UndeclaredNetworkRequest()
    {
        var script = """
        let res = net.http_get("https://unauthorized-domain.com/data");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Equal("net.http", ex.Capability);
    }

    [Fact]
    public void Sandbox_ShouldPrevent_PathTraversalEscape()
    {
        var safeFolder = Path.Combine(_testDir, "safe_folder");
        Directory.CreateDirectory(safeFolder);
        var secretFile = Path.Combine(_testDir, "outside_secret.txt");
        File.WriteAllText(secretFile, "hidden");

        var safePath = safeFolder.Replace('\\', '/');
        var script = $$"""
        #manifest
        requires {
            fs.read: ["{{safePath}}"]
        }
        #endmanifest

        let data = fs.read_file("{{safePath}}/../outside_secret.txt");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Equal("fs.read", ex.Capability);
    }
}
