using System;
using System.IO;
using Ps2.Bundler;
using Xunit;

namespace Ps2.Tests;

public class BundlingAndCryptoTests : IDisposable
{
    private readonly string _testDir;

    public BundlingAndCryptoTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "ps2_bundling_tests_" + Guid.NewGuid().ToString("N"));
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
    public void ScriptSigner_ShouldSignAndVerifyValidScript()
    {
        var rawScript = "let x = 100;\nlet y = 200;\nprintln(x + y);";
        var signed = ScriptSigner.SignScript(rawScript);

        Assert.StartsWith("#signature: sha256:", signed);
        var isValid = ScriptSigner.VerifyScript(signed, out var msg);
        Assert.True(isValid, msg);
    }

    [Fact]
    public void ScriptSigner_ShouldDetect_TamperedScript()
    {
        var rawScript = "let x = 100;\nlet y = 200;\nprintln(x + y);";
        var signed = ScriptSigner.SignScript(rawScript);

        // Tamper with the script body
        var tampered = signed.Replace("let x = 100;", "let x = 999;");
        var isValid = ScriptSigner.VerifyScript(tampered, out var msg);

        Assert.False(isValid);
        Assert.Contains("FAILED", msg);
    }

    [Fact]
    public void Bundler_ShouldPackageAndExtract_SelfContainedBundle()
    {
        var entryScript = Path.Combine(_testDir, "main.ps2");
        File.WriteAllText(entryScript, "println(\"Hello from inside bundle!\");");

        var extraFile = Path.Combine(_testDir, "config.json");
        File.WriteAllText(extraFile, "{\"mode\": \"production\"}");

        var bundleOutput = Path.Combine(_testDir, "app.ps2bundle");

        BundlePackage.CreateBundle(entryScript, bundleOutput, new[] { extraFile });

        Assert.True(File.Exists(bundleOutput));

        // Read and verify bundle
        var (content, meta, files) = BundlePackage.ReadBundle(bundleOutput);

        Assert.Equal("main.ps2", meta.EntryScript);
        Assert.Contains("main.ps2", files.Keys);
        Assert.Contains("config.json", files.Keys);
        Assert.Equal("println(\"Hello from inside bundle!\");", content);
    }
}
