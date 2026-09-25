using System.Linq;
using Ps2.Core;
using Ps2.Parser;
using Ps2.Runtime;
using Xunit;

namespace Ps2.Tests;

public class PipelineAndErgonomicsTests
{
    [Fact]
    public void Pipeline_ShouldFilterAndTransformList()
    {
        var script = """
        let numbers = [1, 2, 3, 4, 5, 6];
        let result = numbers 
            |> filter(x => x % 2 == 0)
            |> map(x => x * 10);
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, ".");

        var res = evaluator.Execute(program);
        var list = res.AsList();

        Assert.Equal(3, list.Count);
        Assert.Equal(20L, list[0].AsInt());
        Assert.Equal(40L, list[1].AsInt());
        Assert.Equal(60L, list[2].AsInt());
    }

    [Fact]
    public void Pipeline_ShouldSupport_JsonProcessing()
    {
        var script = """
        let raw = "[{\"name\": \"Alice\", \"age\": 30}, {\"name\": \"Bob\", \"age\": 20}]";
        let parsed = raw 
            |> json.parse()
            |> filter(u => u["age"] > 25)
            |> map(u => u["name"]);
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, ".");

        var res = evaluator.Execute(program);
        var names = res.AsList();

        Assert.Single(names);
        Assert.Equal("Alice", names[0].AsString());
    }

    [Fact]
    public void OptionAndResult_MatchPattern_ShouldWorkCorrectly()
    {
        var script = """
        fn find_user(id) {
            if id == 1 {
                return Ok("Admin");
            } else {
                return Err("UserNotFound");
            }
        }

        let user1 = find_user(1);
        let user2 = find_user(99);

        let msg1 = match user1 {
            Ok(name) => "Found: " + name,
            Err(e) => "Error: " + e
        };

        let msg2 = match user2 {
            Ok(name) => "Found: " + name,
            Err(e) => "Error: " + e
        };
        """;

        var lexer = new Ps2Lexer(script);
        var parser = new Ps2Parser(lexer.Tokenize());
        var program = parser.Parse();
        var evaluator = new Evaluator(program.Manifest, ".");

        evaluator.Execute(program);

        var msg1 = evaluator.GlobalScope.Get("msg1").AsString();
        var msg2 = evaluator.GlobalScope.Get("msg2").AsString();

        Assert.Equal("Found: Admin", msg1);
        Assert.Equal("Error: UserNotFound", msg2);
    }
}
