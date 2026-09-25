using System.Linq;
using Ps2.Core;
using Ps2.Parser;
using Xunit;

namespace Ps2.Tests;

public class ParserTests
{
    [Fact]
    public void Parser_ShouldParse_Manifest_Correctly()
    {
        var script = """
        #manifest
        requires {
            fs.read: ["./logs", "/tmp"],
            fs.write: ["./out.json"],
            net.http: ["api.github.com"],
            env: ["PATH", "USER"],
            proc.exec: ["git"]
        }
        #endmanifest

        let x = 10;
        """;

        var lexer = new Ps2Lexer(script);
        var tokens = lexer.Tokenize();
        var parser = new Ps2Parser(tokens);
        var program = parser.Parse();

        Assert.Contains("./logs", program.Manifest.FsRead);
        Assert.Contains("/tmp", program.Manifest.FsRead);
        Assert.Contains("./out.json", program.Manifest.FsWrite);
        Assert.Contains("api.github.com", program.Manifest.NetHttp);
        Assert.Contains("PATH", program.Manifest.Env);
        Assert.Contains("git", program.Manifest.ProcExec);
        Assert.Single(program.Statements);
    }

    [Fact]
    public void Parser_ShouldParse_PipelineExpression()
    {
        var script = "let res = [1, 2, 3] |> filter(x => x > 1) |> map(x => x * 10);";
        var lexer = new Ps2Lexer(script);
        var tokens = lexer.Tokenize();
        var parser = new Ps2Parser(tokens);
        var program = parser.Parse();

        Assert.Single(program.Statements);
        var varDecl = Assert.IsType<VarDeclStatement>(program.Statements[0]);
        var pipe1 = Assert.IsType<PipeExpression>(varDecl.Initializer);
        var pipe2 = Assert.IsType<PipeExpression>(pipe1.Left);

        Assert.IsType<ListLiteralExpression>(pipe2.Left);
        Assert.IsType<CallExpression>(pipe2.Right);
        Assert.IsType<CallExpression>(pipe1.Right);
    }

    [Fact]
    public void Parser_ShouldParse_MatchStatement()
    {
        var script = """
        match result {
            Ok(v) => println(v),
            Err(e) => println(e),
            _ => println("other")
        }
        """;

        var lexer = new Ps2Lexer(script);
        var tokens = lexer.Tokenize();
        var parser = new Ps2Parser(tokens);
        var program = parser.Parse();

        var matchStmt = Assert.IsType<MatchStatement>(program.Statements[0]);
        Assert.Equal(3, matchStmt.Cases.Count);
        Assert.IsType<ResultOkPatternNode>(matchStmt.Cases[0].Pattern);
        Assert.IsType<ResultErrPatternNode>(matchStmt.Cases[1].Pattern);
        Assert.IsType<WildcardPatternNode>(matchStmt.Cases[2].Pattern);
    }
}
