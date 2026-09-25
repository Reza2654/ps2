using System;
using System.Collections.Generic;
using System.IO;
using Ps2.Core;
using Ps2.Parser;
using Ps2.Runtime;
using Xunit;

namespace Ps2.Tests;

public class ReplAndStdLibTests
{
    [Fact]
    public void PathModule_ShouldPerformPathOperations()
    {
        var script = """
        let joined = path.join("dir", "sub", "file.txt");
        let base = path.basename(joined);
        let ext = path.extname(joined);
        let dir = path.dirname(joined);
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, ".");
        evaluator.Execute(program);

        Assert.Equal("dir/sub/file.txt", evaluator.GlobalScope.Get("joined").AsString());
        Assert.Equal("file.txt", evaluator.GlobalScope.Get("base").AsString());
        Assert.Equal(".txt", evaluator.GlobalScope.Get("ext").AsString());
        Assert.Equal("dir/sub", evaluator.GlobalScope.Get("dir").AsString());
    }

    [Fact]
    public void TimeModule_ShouldMeasureBenchmark()
    {
        var script = """
        fn work() {
            let mut sum = 0;
            let mut i = 0;
            while i < 1000 {
                sum = sum + i;
                i = i + 1;
            }
            return sum;
        }

        let bench = time.benchmark(work);
        let result = bench["result"];
        let elapsed = bench["elapsed_ms"];
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, ".");
        evaluator.Execute(program);

        Assert.Equal(499500L, evaluator.GlobalScope.Get("result").AsInt());
        Assert.True(evaluator.GlobalScope.Get("elapsed").AsFloat() >= 0.0);
    }

    [Fact]
    public void EnvModule_ShouldRespectSandbox()
    {
        var script = """
        #manifest
        requires {
            env: ["TEST_VAR_123"]
        }
        #endmanifest

        env.set("TEST_VAR_123", "ps2_value");
        let exists = env.has("TEST_VAR_123");
        let val_opt = env.get("TEST_VAR_123");
        let val = unwrap(val_opt);
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, ".");
        evaluator.Execute(program);

        Assert.True(evaluator.GlobalScope.Get("exists").AsBool());
        Assert.Equal("ps2_value", evaluator.GlobalScope.Get("val").AsString());
    }

    [Fact]
    public void TableFormatter_ShouldFormatWithoutError()
    {
        var script = """
        let servers = [
            {"name": "srv1", "ip": "10.0.0.1", "status": "UP"},
            {"name": "srv2", "ip": "10.0.0.2", "status": "DOWN"}
        ];
        table.print(servers);
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, ".");
        
        // Ensure table.print runs cleanly
        evaluator.Execute(program);
    }

    [Fact]
    public void Ps2JsonEngine_ShouldSerializeAndParse_AotSafely()
    {
        var map = new Dictionary<string, Ps2Value>
        {
            ["id"] = Ps2Value.From(101L),
            ["active"] = Ps2Value.True,
            ["tags"] = Ps2Value.From(new List<Ps2Value> { Ps2Value.From("a"), Ps2Value.From("b") })
        };
        var val = Ps2Value.From(map);

        var jsonStr = Ps2JsonEngine.Stringify(val);
        Assert.Contains("\"id\": 101", jsonStr);
        Assert.Contains("\"active\": true", jsonStr);

        var parsed = Ps2JsonEngine.Parse(jsonStr);
        Assert.Equal(Ps2ValueType.Map, parsed.Type);
        Assert.Equal(101L, parsed.AsMap()["id"].AsInt());
        Assert.True(parsed.AsMap()["active"].AsBool());
    }
}
