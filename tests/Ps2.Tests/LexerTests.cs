using System.Linq;
using Ps2.Core;
using Ps2.Parser;
using Xunit;

namespace Ps2.Tests;

public class LexerTests
{
    [Fact]
    public void Lexer_ShouldHandle_Shebang_Gracefully()
    {
        var script = "#!/usr/bin/env ps2\nlet x = 42;";
        var lexer = new Ps2Lexer(script);
        var tokens = lexer.Tokenize();

        Assert.Equal(TokenType.Let, tokens[0].Type);
        Assert.Equal(TokenType.Identifier, tokens[1].Type);
        Assert.Equal("x", tokens[1].Text);
        Assert.Equal(TokenType.Equal, tokens[2].Type);
        Assert.Equal(TokenType.IntLiteral, tokens[3].Type);
        Assert.Equal(42L, tokens[3].LiteralValue);
    }

    [Fact]
    public void Lexer_ShouldTokenize_PipeAndFatArrow()
    {
        var script = "data |> filter(x => x > 5)";
        var lexer = new Ps2Lexer(script);
        var tokens = lexer.Tokenize();

        var pipe = tokens.First(t => t.Type == TokenType.Pipe);
        var fatArrow = tokens.First(t => t.Type == TokenType.FatArrow);

        Assert.Equal("|>", pipe.Text);
        Assert.Equal("=>", fatArrow.Text);
    }

    [Fact]
    public void Lexer_ShouldTokenize_OptionAndResultKeywords()
    {
        var script = "let a = Some(10); let b = None; let c = Ok(20); let d = Err(\"fail\");";
        var lexer = new Ps2Lexer(script);
        var tokens = lexer.Tokenize();

        Assert.Contains(tokens, t => t.Type == TokenType.Some);
        Assert.Contains(tokens, t => t.Type == TokenType.None);
        Assert.Contains(tokens, t => t.Type == TokenType.Ok);
        Assert.Contains(tokens, t => t.Type == TokenType.Err);
    }
}
