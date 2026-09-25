using System;
using System.IO;
using System.Linq;
using Ps2.Core;
using Ps2.Parser;
using Ps2.Runtime;
using Xunit;

namespace Ps2.Tests;

public class PolicyAndAuditSecurityTests : IDisposable
{
    private readonly string _testDir;

    public PolicyAndAuditSecurityTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "ps2_audit_policy_tests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_testDir))
        {
            try { Directory.Delete(_testDir, recursive: true); } catch { }
        }
    }

    private static ProgramNode Parse(string script)
    {
        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        return parser.Parse();
    }

    [Fact]
    public void Manifest_Version10_ShouldPassValidation()
    {
        var script = """
        #manifest
        requires {
            version: "1.0",
            fs.read: ["./config.json"]
        }
        #endmanifest

        let x = 42;
        """;

        var program = Parse(script);
        Assert.Equal("1.0", program.Manifest.SchemaVersion);
        Assert.Single(program.Manifest.FsRead);
    }

    [Fact]
    public void Manifest_UnsupportedVersion_ShouldThrowPs2SecurityException()
    {
        var script = """
        #manifest
        requires {
            version: "2.0"
        }
        #endmanifest

        let x = 42;
        """;

        var ex = Assert.Throws<Ps2SecurityException>(() => Parse(script));
        Assert.Equal("manifest", ex.Capability);
        Assert.Contains("Unsupported manifest schema version '2.0'", ex.Message);
    }

    [Fact]
    public void Manifest_UnknownCapability_ShouldThrowPs2SecurityException()
    {
        var script = """
        #manifest
        requires {
            version: "1.0",
            kernel.access: ["unrestricted"]
        }
        #endmanifest

        let x = 1;
        """;

        var ex = Assert.Throws<Ps2SecurityException>(() => Parse(script));
        Assert.Equal("manifest", ex.Capability);
        Assert.Contains("Unknown capability 'kernel.access'", ex.Message);
    }

    [Fact]
    public void Policy_Production_BlocksProcessExecutionPreFlight()
    {
        var script = """
        #manifest
        requires {
            proc.exec: ["cmd.exe"]
        }
        #endmanifest

        let unreachable = 100;
        """;

        var program = Parse(script);
        var auditLogger = new InMemoryAuditLogger();
        var evaluator = new Evaluator(
            program.Manifest,
            _testDir,
            policy: SecurityPolicy.Production,
            auditLogger: auditLogger,
            scriptIdentity: "test_proc.ps2"
        );

        var ex = Assert.Throws<Ps2PolicyViolationException>(() => evaluator.Execute(program));
        Assert.Equal("production", ex.PolicyName);
        Assert.Contains("prohibits process execution", ex.Message);
    }

    [Fact]
    public void Policy_Production_BlocksExternalNetworkPreFlight()
    {
        var script = """
        #manifest
        requires {
            net.http: ["evil.attacker.com"]
        }
        #endmanifest

        let unreachable = 100;
        """;

        var program = Parse(script);
        var evaluator = new Evaluator(
            program.Manifest,
            _testDir,
            policy: SecurityPolicy.Production
        );

        var ex = Assert.Throws<Ps2PolicyViolationException>(() => evaluator.Execute(program));
        Assert.Contains("evil.attacker.com", ex.Message);
    }

    [Fact]
    public void Policy_Production_BlocksSystemDirectoryWritePreFlight()
    {
        var script = """
        #manifest
        requires {
            fs.write: ["C:/Windows/malicious.dll"]
        }
        #endmanifest

        let unreachable = 100;
        """;

        var program = Parse(script);
        var evaluator = new Evaluator(
            program.Manifest,
            _testDir,
            policy: SecurityPolicy.Production
        );

        var ex = Assert.Throws<Ps2PolicyViolationException>(() => evaluator.Execute(program));
        Assert.Contains("blocks write access to path", ex.Message);
    }

    [Fact]
    public void Policy_Production_BlocksSensitiveEnvVarPreFlight()
    {
        var script = """
        #manifest
        requires {
            env: ["AWS_SECRET_ACCESS_KEY"]
        }
        #endmanifest

        let unreachable = 100;
        """;

        var program = Parse(script);
        var evaluator = new Evaluator(
            program.Manifest,
            _testDir,
            policy: SecurityPolicy.Production
        );

        var ex = Assert.Throws<Ps2PolicyViolationException>(() => evaluator.Execute(program));
        Assert.Contains("AWS_SECRET_ACCESS_KEY", ex.Message);
    }

    [Fact]
    public void AuditLogger_RecordsAllowAndDenyEventsWithStructuredMetadata()
    {
        var allowedFile = Path.Combine(_testDir, "allowed.txt").Replace('\\', '/');
        var deniedFile = Path.Combine(_testDir, "denied.txt").Replace('\\', '/');
        File.WriteAllText(allowedFile, "safe");
        File.WriteAllText(deniedFile, "restricted");

        var script = $$"""
        #manifest
        requires {
            fs.read: ["{{allowedFile}}"]
        }
        #endmanifest

        let content = fs.read_file("{{allowedFile}}");
        let blocked = fs.read_file("{{deniedFile}}");
        """;

        var program = Parse(script);
        var auditLogger = new InMemoryAuditLogger();
        var evaluator = new Evaluator(
            program.Manifest,
            _testDir,
            auditLogger: auditLogger,
            scriptIdentity: "audit_script.ps2"
        );

        Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));

        var events = auditLogger.Events;
        Assert.NotEmpty(events);

        // First event should be ALLOW for allowedFile
        var allowEvt = events.FirstOrDefault(e => e.Decision == AuditDecision.ALLOW && e.Resource == allowedFile);
        Assert.NotNull(allowEvt);
        Assert.Equal("fs.read", allowEvt.Operation);
        Assert.Equal("audit_script.ps2", allowEvt.ScriptIdentity);
        Assert.False(string.IsNullOrEmpty(allowEvt.Timestamp));

        // Second event should be DENY for deniedFile
        var denyEvt = events.FirstOrDefault(e => e.Decision == AuditDecision.DENY && e.Resource == deniedFile);
        Assert.NotNull(denyEvt);
        Assert.Equal("fs.read", denyEvt.Operation);
        Assert.Equal("audit_script.ps2", denyEvt.ScriptIdentity);
        Assert.Contains("Missing capability", denyEvt.Reason);

        // Verify JSON serialization of audit event is valid and structured
        var json = allowEvt.ToJson();
        Assert.Contains("\"decision\":\"ALLOW\"", json);
        Assert.Contains("\"operation\":\"fs.read\"", json);
    }

    [Fact]
    public void Secret_SysSecret_MasksValueByDefault()
    {
        const string envName = "TEST_PS2_SUPER_SECRET_TOKEN";
        const string secretVal = "ghp_9948281728192847291823912";
        Environment.SetEnvironmentVariable(envName, secretVal);

        try
        {
            var script = $$"""
            #manifest
            requires {
                env: ["{{envName}}"]
            }
            #endmanifest

            let secOpt = sys.secret("{{envName}}");
            let sec = unwrap(secOpt);
            let asStr = sec;
            """;

            var program = Parse(script);
            var evaluator = new Evaluator(program.Manifest, _testDir);
            var result = evaluator.Execute(program);

            var scope = evaluator.GlobalScope;
            var secVal = scope.Get("sec");
            Assert.Equal(Ps2ValueType.Secret, secVal.Type);
            Assert.Equal("[REDACTED]", secVal.ToString());
            Assert.Equal("[REDACTED]", secVal.AsString());

            var secObj = secVal.AsSecret();
            Assert.Equal(secretVal, secObj.Unmask());
        }
        finally
        {
            Environment.SetEnvironmentVariable(envName, null);
        }
    }

    [Fact]
    public void Secret_MaskAndReveal_WorkAsExpected()
    {
        var script = """
        let raw = "super_classified_password_123";
        let masked = secret.mask(raw);
        let revealed = secret.reveal(masked);
        """;

        var program = Parse(script);
        var evaluator = new Evaluator(program.Manifest, _testDir);
        evaluator.Execute(program);

        var maskedVal = evaluator.GlobalScope.Get("masked");
        Assert.Equal(Ps2ValueType.Secret, maskedVal.Type);
        Assert.Equal("[REDACTED]", maskedVal.ToString());
        Assert.Equal("[REDACTED]", maskedVal.AsString());

        var revealedVal = evaluator.GlobalScope.Get("revealed");
        Assert.Equal("super_classified_password_123", revealedVal.AsString());
    }

    [Fact]
    public void Secret_NeverAppearsInJsonStringify()
    {
        var script = """
        let token = secret.mask("top_secret_bearer_key_abc");
        let payload = {
            "service": "billing",
            "token": token
        };
        let serialized = json.stringify(payload);
        """;

        var program = Parse(script);
        var evaluator = new Evaluator(program.Manifest, _testDir);
        evaluator.Execute(program);

        var jsonVal = evaluator.GlobalScope.Get("serialized").AsString();
        Assert.DoesNotContain("top_secret_bearer_key_abc", jsonVal);
        Assert.Contains("[REDACTED]", jsonVal);
    }

    [Fact]
    public void Secret_EvaluatorSecretScrubber_MasksInExceptions()
    {
        var script = """
        let password = secret.mask("my_secret_db_password_xyz");
        // Trigger a runtime error that might reference variables
        let n = 10 / 0;
        """;

        var program = Parse(script);
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2RuntimeException>(() => evaluator.Execute(program));
        Assert.DoesNotContain("my_secret_db_password_xyz", ex.Message);
    }

    [Fact]
    public void Policy_CustomJsonPolicy_LoadsAndEnforcesRules()
    {
        var policyJson = """
        {
            "name": "custom_financial_policy",
            "disallowprocessexecution": true,
            "disallowexternalnetwork": false,
            "blockeddomains": ["untrusted.com"],
            "blockedpaths": ["/data/pci_dss"]
        }
        """;

        var policyFile = Path.Combine(_testDir, "policy.json");
        File.WriteAllText(policyFile, policyJson);

        var loadedPolicy = SecurityPolicy.LoadFromFile(policyFile);
        Assert.Equal("custom_financial_policy", loadedPolicy.Name);
        Assert.True(loadedPolicy.DisallowProcessExecution);
        Assert.Contains("untrusted.com", loadedPolicy.BlockedDomains);

        var script = """
        #manifest
        requires {
            proc.exec: ["powershell.exe"]
        }
        #endmanifest

        let x = 1;
        """;

        var program = Parse(script);
        var evaluator = new Evaluator(program.Manifest, _testDir, policy: loadedPolicy);

        var ex = Assert.Throws<Ps2PolicyViolationException>(() => evaluator.Execute(program));
        Assert.Equal("custom_financial_policy", ex.PolicyName);
    }

    [Fact]
    public void DefaultDeny_EnvVar_BlockedWithoutManifest()
    {
        const string varName = "TEST_UNAUTHORIZED_ENV_VAR";
        Environment.SetEnvironmentVariable(varName, "some_value");

        try
        {
            var script = $$"""
            let val = sys.env("{{varName}}");
            """;

            var program = Parse(script);
            var evaluator = new Evaluator(program.Manifest, _testDir);

            var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
            Assert.Equal("env", ex.Capability);
            Assert.Contains(varName, ex.Message);
        }
        finally
        {
            Environment.SetEnvironmentVariable(varName, null);
        }
    }

    [Fact]
    public void DefaultDeny_ProcExec_BlockedWithoutManifest()
    {
        var script = """
        let res = sys.exec("whoami");
        """;

        var program = Parse(script);
        var evaluator = new Evaluator(program.Manifest, _testDir);

        var ex = Assert.Throws<Ps2SecurityException>(() => evaluator.Execute(program));
        Assert.Equal("proc.exec", ex.Capability);
        Assert.Contains("whoami", ex.Message);
    }
}
