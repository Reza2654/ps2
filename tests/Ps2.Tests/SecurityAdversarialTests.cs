using System;
using System.IO;
using Ps2.Core;
using Ps2.Parser;
using Ps2.Runtime;
using Xunit;

namespace Ps2.Tests;

public class SecurityAdversarialTests : IDisposable
{
    private readonly string _testDir;

    public SecurityAdversarialTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "ps2_adversarial_" + Guid.NewGuid().ToString("N"));
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
    public void Defense_WindowsADS_ShouldNotBypassSandbox()
    {
        var secretFile = Path.Combine(_testDir, "secret_creds.txt");
        File.WriteAllText(secretFile, "super-secret-token");

        var allowedFile = Path.Combine(_testDir, "public.txt");
        File.WriteAllText(allowedFile, "public data");

        var allowedPath = allowedFile.Replace('\\', '/');
        var adsPath = (secretFile + "::$DATA").Replace('\\', '/');

        var script = $$"""
        #manifest
        requires {
            fs.read: ["{{allowedPath}}"]
        }
        #endmanifest

        let stolen = fs.read_file("{{adsPath}}");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Equal("fs.read", ex.Capability);
    }

    [Fact]
    public void Defense_DirectoryPrefixCollisions_ShouldBeDenied()
    {
        // Directory A is allowed: /path/allowed/
        // Directory B is NOT allowed: /path/allowed_other/secret.txt
        // String prefix without slash would match /path/allowed_other, but canonical check must deny it!
        var allowedDir = Path.Combine(_testDir, "allowed");
        Directory.CreateDirectory(allowedDir);
        var otherDir = Path.Combine(_testDir, "allowed_other");
        Directory.CreateDirectory(otherDir);

        var secretFile = Path.Combine(otherDir, "passwords.txt");
        File.WriteAllText(secretFile, "secret");

        var allowedDirPath = (allowedDir + "/").Replace('\\', '/');
        var secretPath = secretFile.Replace('\\', '/');

        var script = $$"""
        #manifest
        requires {
            fs.read: ["{{allowedDirPath}}"]
        }
        #endmanifest

        let stolen = fs.read_file("{{secretPath}}");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Equal("fs.read", ex.Capability);
    }

    [Fact]
    public void Defense_FilePermission_CannotBeUsedAsDirectoryPrefix()
    {
        // Allowed is a specific file: foo.txt
        // Attacker attempts to read foo.txt/nested (or on Windows if foo.txt were a directory)
        var fileAllowed = Path.Combine(_testDir, "my_file.txt");
        File.WriteAllText(fileAllowed, "allowed content");

        var subFile = Path.Combine(_testDir, "my_file.txt", "sub.txt");

        var allowedPath = fileAllowed.Replace('\\', '/');
        var subPath = subFile.Replace('\\', '/');

        var script = $$"""
        #manifest
        requires {
            fs.read: ["{{allowedPath}}"]
        }
        #endmanifest

        let data = fs.read_file("{{subPath}}");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Equal("fs.read", ex.Capability);
    }

    [Fact]
    public void Defense_ProtocolWhitelisting_ShouldRejectNonHttpSchemes()
    {
        var script = """
        let res = net.http_get("file:///C:/Windows/win.ini");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Equal("net.http", ex.Capability);
        Assert.Contains("Prohibited network protocol", ex.Message);
    }

    [Fact]
    public void Defense_SysEnv_UndeclaredAccessIsDenied()
    {
        Environment.SetEnvironmentVariable("PS2_TEST_SECRET", "super_secret_value");

        var script = """
        let secret = sys.env("PS2_TEST_SECRET");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Equal("env", ex.Capability);
    }

    [Fact]
    public void Defense_SysEnv_DeclaredAccessIsAllowed()
    {
        Environment.SetEnvironmentVariable("PS2_TEST_ALLOWED", "permitted_value");

        var script = """
        #manifest
        requires {
            env: ["PS2_TEST_ALLOWED"]
        }
        #endmanifest

        let val = sys.env("PS2_TEST_ALLOWED");
        val |> unwrap
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var result = evaluator.Execute(program);
        Assert.Equal("permitted_value", result.AsString());
    }

    [Fact]
    public void Defense_ProcExec_UndeclaredProcessExecutionIsDenied()
    {
        var script = """
        let res = sys.exec("cmd.exe", ["/c", "echo hello"]);
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Equal("proc.exec", ex.Capability);
    }

    [Fact]
    public void Defense_ProcExec_ArgumentListSafelyPassesSpacesWithoutInjection()
    {
        var script = """
        #manifest
        requires {
            proc.exec: ["cmd.exe"]
        }
        #endmanifest

        let res = sys.exec("cmd.exe", ["/c", "echo", "arg with spaces & special < > | symbols"]);
        res["stdout"]
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var result = evaluator.Execute(program);
        // cmd.exe echo output should contain the string intact
        Assert.Contains("arg with spaces & special < > | symbols", result.AsString());
    }
}
