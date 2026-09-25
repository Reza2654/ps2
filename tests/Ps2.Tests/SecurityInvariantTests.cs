using System;
using System.IO;
using Ps2.Core;
using Ps2.Parser;
using Ps2.Runtime;
using Xunit;

namespace Ps2.Tests;

public class SecurityInvariantTests : IDisposable
{
    private readonly string _testDir;

    public SecurityInvariantTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "ps2_invariants_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_testDir))
        {
            Directory.Delete(_testDir, recursive: true);
        }
    }

    private Evaluator CreateZeroCapabilityEvaluator(string script)
    {
        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        return new Evaluator(program.Manifest, _testDir);
    }

    [Fact]
    public void Invariant_FsReadFile_BlockedWithoutCapability()
    {
        var targetFile = Path.Combine(_testDir, "test.txt");
        File.WriteAllText(targetFile, "content");

        var evaluator = CreateZeroCapabilityEvaluator($$"""
        let x = fs.read_file("{{targetFile.Replace('\\', '/')}}");
        """);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(new Ps2Parser(new Ps2Lexer($$"""
        let x = fs.read_file("{{targetFile.Replace('\\', '/')}}");
        """).Tokenize()).Parse()));

        Assert.Equal("fs.read", ex.Capability);
    }

    [Fact]
    public void Invariant_FsWriteFile_BlockedWithoutCapability()
    {
        var targetFile = Path.Combine(_testDir, "out.txt");
        var script = $$"""
        fs.write_file("{{targetFile.Replace('\\', '/')}}", "data");
        """;

        var evaluator = CreateZeroCapabilityEvaluator(script);
        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(new Ps2Parser(new Ps2Lexer(script).Tokenize()).Parse()));
        Assert.Equal("fs.write", ex.Capability);
        Assert.False(File.Exists(targetFile));
    }

    [Fact]
    public void Invariant_FsListDir_BlockedWithoutCapability()
    {
        var script = """
        fs.list_dir(".");
        """;

        var evaluator = CreateZeroCapabilityEvaluator(script);
        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(new Ps2Parser(new Ps2Lexer(script).Tokenize()).Parse()));
        Assert.Equal("fs.read", ex.Capability);
    }

    [Fact]
    public void Invariant_FsCreateDir_BlockedWithoutCapability()
    {
        var targetSubdir = Path.Combine(_testDir, "new_sub_dir");
        var script = $$"""
        fs.create_dir("{{targetSubdir.Replace('\\', '/')}}");
        """;

        var evaluator = CreateZeroCapabilityEvaluator(script);
        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(new Ps2Parser(new Ps2Lexer(script).Tokenize()).Parse()));
        Assert.Equal("fs.write", ex.Capability);
        Assert.False(Directory.Exists(targetSubdir));
    }

    [Fact]
    public void Invariant_FsDeleteFile_BlockedWithoutCapability()
    {
        var targetFile = Path.Combine(_testDir, "target_to_delete.txt");
        File.WriteAllText(targetFile, "preserve");

        var script = $$"""
        fs.delete_file("{{targetFile.Replace('\\', '/')}}");
        """;

        var evaluator = CreateZeroCapabilityEvaluator(script);
        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(new Ps2Parser(new Ps2Lexer(script).Tokenize()).Parse()));
        Assert.Equal("fs.write", ex.Capability);
        Assert.True(File.Exists(targetFile)); // Invariant: file was NOT deleted!
    }

    [Fact]
    public void Invariant_FsExists_BlockedWithoutCapability()
    {
        var targetFile = Path.Combine(_testDir, "probe.txt");
        File.WriteAllText(targetFile, "probe");

        var script = $$"""
        fs.exists("{{targetFile.Replace('\\', '/')}}");
        """;

        var evaluator = CreateZeroCapabilityEvaluator(script);
        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(new Ps2Parser(new Ps2Lexer(script).Tokenize()).Parse()));
        Assert.Equal("fs.read", ex.Capability);
    }

    [Fact]
    public void Invariant_NetHttpGet_BlockedWithoutCapability()
    {
        var script = """
        net.http_get("https://api.github.com/zen");
        """;

        var evaluator = CreateZeroCapabilityEvaluator(script);
        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(new Ps2Parser(new Ps2Lexer(script).Tokenize()).Parse()));
        Assert.Equal("net.http", ex.Capability);
    }

    [Fact]
    public void Invariant_NetHttpPost_BlockedWithoutCapability()
    {
        var script = """
        net.http_post("https://api.github.com/events", "{}");
        """;

        var evaluator = CreateZeroCapabilityEvaluator(script);
        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(new Ps2Parser(new Ps2Lexer(script).Tokenize()).Parse()));
        Assert.Equal("net.http", ex.Capability);
    }

    [Fact]
    public void Invariant_SysEnv_BlockedWithoutCapability()
    {
        var script = """
        sys.env("PATH");
        """;

        var evaluator = CreateZeroCapabilityEvaluator(script);
        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(new Ps2Parser(new Ps2Lexer(script).Tokenize()).Parse()));
        Assert.Equal("env", ex.Capability);
    }

    [Fact]
    public void Invariant_SysSecret_BlockedWithoutCapability()
    {
        var script = """
        sys.secret("API_KEY");
        """;

        var evaluator = CreateZeroCapabilityEvaluator(script);
        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(new Ps2Parser(new Ps2Lexer(script).Tokenize()).Parse()));
        Assert.Equal("env", ex.Capability);
    }

    [Fact]
    public void Invariant_SysExec_BlockedWithoutCapability()
    {
        var script = """
        sys.exec("git", ["status"]);
        """;

        var evaluator = CreateZeroCapabilityEvaluator(script);
        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(new Ps2Parser(new Ps2Lexer(script).Tokenize()).Parse()));
        Assert.Equal("proc.exec", ex.Capability);
    }

    [Fact]
    public void Invariant_EnvGet_BlockedWithoutCapability()
    {
        var script = """
        env.get("SECRET_KEY");
        """;

        var evaluator = CreateZeroCapabilityEvaluator(script);
        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(new Ps2Parser(new Ps2Lexer(script).Tokenize()).Parse()));
        Assert.Equal("env", ex.Capability);
    }

    [Fact]
    public void Invariant_EnvHas_BlockedWithoutCapability()
    {
        var script = """
        env.has("SECRET_KEY");
        """;

        var evaluator = CreateZeroCapabilityEvaluator(script);
        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(new Ps2Parser(new Ps2Lexer(script).Tokenize()).Parse()));
        Assert.Equal("env", ex.Capability);
    }

    [Fact]
    public void Invariant_EnvSet_BlockedWithoutCapability()
    {
        var script = """
        env.set("SECRET_KEY", "new_val");
        """;

        var evaluator = CreateZeroCapabilityEvaluator(script);
        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(new Ps2Parser(new Ps2Lexer(script).Tokenize()).Parse()));
        Assert.Equal("env", ex.Capability);
    }

    [Fact]
    public void Invariant_PolicyPreFlight_StopsExecutionBeforeAnyStatementRuns()
    {
        var sideEffectFile = Path.Combine(_testDir, "side_effect.txt");

        // Script requests proc.exec, but Production policy prohibits it.
        // It has a side-effect attempt before the exec call.
        var script = $$"""
        #manifest
        requires {
            fs.write: ["{{sideEffectFile.Replace('\\', '/')}}"],
            proc.exec: ["git"]
        }
        #endmanifest

        fs.write_file("{{sideEffectFile.Replace('\\', '/')}}", "malicious write");
        sys.exec("git", []);
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();

        var evaluator = new Evaluator(
            program.Manifest,
            _testDir,
            policy: SecurityPolicy.Production
        );

        // Pre-flight must throw Ps2PolicyViolationException BEFORE statement 1 executes
        var ex = Assert.Throws<Ps2PolicyViolationException>(() => evaluator.Execute(program));
        Assert.Equal("production", ex.PolicyName);

        // Invariant: The side effect file was NEVER written to disk!
        Assert.False(File.Exists(sideEffectFile));
    }
}
