using System;
using System.IO;
using System.Security.Cryptography;
using Ps2.Bundler;
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
        bool isWindows = OperatingSystem.IsWindows();
        string binary = isWindows ? "cmd.exe" : "echo";
        string argList = isWindows 
            ? "[\"/c\", \"echo\", \"arg with spaces & special < > | symbols\"]" 
            : "[\"arg with spaces & special < > | symbols\"]";

        var script = $$"""
        #manifest
        requires {
            proc.exec: ["{{binary}}"]
        }
        #endmanifest

        let res = sys.exec("{{binary}}", {{argList}});
        res["stdout"]
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var result = evaluator.Execute(program);
        Assert.Contains("arg with spaces & special < > | symbols", result.AsString());
    }

    [Theory]
    [InlineData(@"\\evil-server\share\exploit.txt")]
    [InlineData("//evil-server/share/exploit.txt")]
    public void Defense_UNC_Paths_ShouldBeRejected(string uncPath)
    {
        var script = $$"""
        #manifest
        requires {
            fs.read: ["*"]
        }
        #endmanifest

        let res = fs.read_file("{{uncPath.Replace("\\", "\\\\")}}");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Contains("UNC and remote network paths", ex.Message);
    }

    [Theory]
    [InlineData("CON")]
    [InlineData("NUL.txt")]
    [InlineData("AUX")]
    [InlineData("PRN")]
    [InlineData("COM1")]
    [InlineData("LPT2.dat")]
    public void Defense_DosDeviceNames_ShouldBeRejected(string deviceName)
    {
        var script = $$"""
        #manifest
        requires {
            fs.read: ["*"]
        }
        #endmanifest

        let res = fs.read_file("{{deviceName}}");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Contains("DOS device name", ex.Message);
    }

    [Fact]
    public void Defense_AlternateDataStreams_CustomStream_ShouldBeRejected()
    {
        var script = """
        #manifest
        requires {
            fs.read: ["*"]
        }
        #endmanifest

        let res = fs.read_file("file.txt:hidden_payload");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Contains("invalid stream specifier or colon", ex.Message);
    }

    [Fact]
    public void Defense_Symlink_Escape_ShouldBeBlocked()
    {
        var allowedDir = Path.Combine(_testDir, "allowed_workspace");
        Directory.CreateDirectory(allowedDir);

        var forbiddenDir = Path.Combine(_testDir, "forbidden_secrets");
        Directory.CreateDirectory(forbiddenDir);
        var secretFile = Path.Combine(forbiddenDir, "root_password.txt");
        File.WriteAllText(secretFile, "super-secret");

        var linkPath = Path.Combine(allowedDir, "escape_link");

        try
        {
            File.CreateSymbolicLink(linkPath, secretFile);
        }
        catch
        {
            // Symlink creation may require elevated privileges on some environments
            return;
        }

        var script = $$"""
        #manifest
        requires {
            fs.read: ["{{allowedDir.Replace('\\', '/')}}/"]
        }
        #endmanifest

        let content = fs.read_file("{{linkPath.Replace('\\', '/')}}");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Equal("fs.read", ex.Capability);
    }

    [Theory]
    [InlineData("http://169.254.169.254/latest/meta-data")]
    [InlineData("http://169.254.169.253/")]
    [InlineData("http://metadata.google.internal/computeMetadata/v1")]
    [InlineData("http://metadata/")]
    [InlineData("http://[fd00:ec2::254]/")]
    public void Defense_Cloud_Metadata_SSRF_ShouldBeBlocked(string url)
    {
        var script = $$"""
        #manifest
        requires {
            net.http: ["*"]
        }
        #endmanifest

        let res = net.http_get("{{url}}");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Equal("net.http", ex.Capability);
        Assert.Contains("cloud instance metadata", ex.Message);
    }

    [Fact]
    public void Defense_Manifest_DuplicateHeader_ShouldBeRejected()
    {
        var script = """
        #manifest
        requires {
            fs.read: ["./file1.txt"]
        }
        #endmanifest

        #manifest
        requires {
            fs.read: ["./file2.txt"]
        }
        #endmanifest

        let x = 1;
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());

        var ex = Assert.Throws<Ps2SecurityException>(() => parser.Parse());
        Assert.Equal("manifest", ex.Capability);
        Assert.Contains("Duplicate #manifest declaration found", ex.Message);
    }

    [Fact]
    public void Defense_Manifest_NonStringElement_ShouldBeRejected()
    {
        var script = """
        #manifest
        requires {
            fs.read: [12345]
        }
        #endmanifest

        let x = 1;
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());

        var ex = Assert.Throws<Ps2SecurityException>(() => parser.Parse());
        Assert.Equal("manifest", ex.Capability);
        Assert.Contains("Expected string literal", ex.Message);
    }

    [Fact]
    public void Defense_Manifest_EmptyStringElement_ShouldBeRejected()
    {
        var script = """
        #manifest
        requires {
            fs.read: [""]
        }
        #endmanifest

        let x = 1;
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());

        var ex = Assert.Throws<Ps2SecurityException>(() => parser.Parse());
        Assert.Equal("manifest", ex.Capability);
        Assert.Contains("Empty string element", ex.Message);
    }

    [Fact]
    public void Defense_AllowAll_InProductionPolicy_ShouldBeRejected()
    {
        var script = """
        #manifest
        requires {
            fs.read: ["./config.json"]
        }
        #endmanifest

        let x = 1;
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();

        var evaluator = new Evaluator(
            program.Manifest,
            _testDir,
            allowAll: true,
            policy: SecurityPolicy.Production
        );

        var ex = Assert.Throws<Ps2PolicyViolationException>(() => evaluator.Execute(program));
        Assert.Contains("--allow-all", ex.Message);
    }

    [Fact]
    public void Defense_AllowAll_InStrictPolicy_ShouldBeRejected()
    {
        var script = """
        #manifest
        requires {
            fs.read: ["./config.json"]
        }
        #endmanifest

        let x = 1;
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();

        var evaluator = new Evaluator(
            program.Manifest,
            _testDir,
            allowAll: true,
            policy: SecurityPolicy.Strict
        );

        var ex = Assert.Throws<Ps2PolicyViolationException>(() => evaluator.Execute(program));
        Assert.Contains("--allow-all", ex.Message);
    }

    [Fact]
    public void Defense_SecretModel_NeverLeaksInConcatenationOrCollections()
    {
        string secretValue = "SUPER_SECRET_TOKEN_XYZ987";
        Environment.SetEnvironmentVariable("TEST_SENSITIVE_KEY", secretValue);

        var script = """
        #manifest
        requires {
            env: ["TEST_SENSITIVE_KEY"]
        }
        #endmanifest

        let opt = sys.secret("TEST_SENSITIVE_KEY");
        let s = unwrap(opt);

        let concat_str = "Prefix: " + s;
        let concat_both = s + s;
        let list = [s, "other"];
        let map = {"key": s};
        let json_dump = json.stringify(map);

        let final_result = {
            "concat_str": concat_str,
            "concat_both": concat_both,
            "list_str": "" + list,
            "json": json_dump
        };
        final_result
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var result = evaluator.Execute(program);
        var mapRes = result.AsMap();

        Assert.DoesNotContain(secretValue, mapRes["concat_str"].AsString());
        Assert.Contains("[REDACTED]", mapRes["concat_str"].AsString());

        Assert.DoesNotContain(secretValue, mapRes["concat_both"].AsString());
        Assert.Contains("[REDACTED][REDACTED]", mapRes["concat_both"].AsString());

        Assert.DoesNotContain(secretValue, mapRes["list_str"].AsString());
        Assert.Contains("[REDACTED]", mapRes["list_str"].AsString());

        Assert.DoesNotContain(secretValue, mapRes["json"].AsString());
        Assert.Contains("[REDACTED]", mapRes["json"].AsString());
    }

    [Fact]
    public void Defense_AuditLog_ContainsUuidAndSchemaVersionAndZeroSecrets()
    {
        string secretVal = "AUDIT_SECRET_CREDENTIAL_12345";
        Environment.SetEnvironmentVariable("SECRET_AUDIT_VAR", secretVal);

        var auditLogger = new InMemoryAuditLogger();

        var script = """
        #manifest
        requires {
            env: ["SECRET_AUDIT_VAR"]
        }
        #endmanifest

        let opt = sys.secret("SECRET_AUDIT_VAR");
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, _testDir, auditLogger: auditLogger);

        evaluator.Execute(program);

        Assert.NotEmpty(auditLogger.Events);
        foreach (var evt in auditLogger.Events)
        {
            Assert.True(Guid.TryParse(evt.EventId, out _));
            Assert.Equal("1.0", evt.SchemaVersion);

            Assert.DoesNotContain(secretVal, evt.Resource);
            Assert.DoesNotContain(secretVal, evt.Reason);
            Assert.DoesNotContain(secretVal, evt.ToJson());
        }
    }

    [Fact]
    public void Defense_BundleTampering_PayloadMismatch_ThrowsCryptographicException()
    {
        var scriptPath = Path.Combine(_testDir, "entry.ps2");
        File.WriteAllText(scriptPath, "let x = 42;");

        var bundlePath = Path.Combine(_testDir, "app.ps2bundle");
        BundlePackage.CreateBundle(scriptPath, bundlePath);

        // Tamper with bundle payload by modifying the last byte
        var bytes = File.ReadAllBytes(bundlePath);
        bytes[^1] ^= 0xFF;
        File.WriteAllBytes(bundlePath, bytes);

        Assert.Throws<CryptographicUnexpectedOperationException>(() => BundlePackage.ReadBundle(bundlePath));
    }

    [Fact]
    public void Defense_BundleTampering_CorruptedHeader_ThrowsInvalidDataException()
    {
        var scriptPath = Path.Combine(_testDir, "entry2.ps2");
        File.WriteAllText(scriptPath, "let x = 100;");

        var bundlePath = Path.Combine(_testDir, "app2.ps2bundle");
        BundlePackage.CreateBundle(scriptPath, bundlePath);

        // Corrupt magic header
        var bytes = File.ReadAllBytes(bundlePath);
        bytes[0] = (byte)'X';
        File.WriteAllBytes(bundlePath, bytes);

        Assert.Throws<InvalidDataException>(() => BundlePackage.ReadBundle(bundlePath));
    }
}
