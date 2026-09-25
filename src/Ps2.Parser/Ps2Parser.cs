using System;
using System.Collections.Generic;
using Ps2.Core;

namespace Ps2.Parser;

public sealed class Ps2Parser
{
    private readonly IReadOnlyList<Token> _tokens;
    private int _current = 0;
    private readonly List<Diagnostic> _diagnostics = new();

    public IReadOnlyList<Diagnostic> Diagnostics => _diagnostics;

    public Ps2Parser(IReadOnlyList<Token> tokens)
    {
        _tokens = tokens;
    }

    private Token Current => _current < _tokens.Count ? _tokens[_current] : _tokens[^1];
    private Token Peek(int offset = 1) => (_current + offset) < _tokens.Count ? _tokens[_current + offset] : _tokens[^1];
    private bool IsAtEnd => Current.Type == TokenType.Eof;

    private Token Advance()
    {
        var token = Current;
        if (!IsAtEnd) _current++;
        return token;
    }

    private bool Check(TokenType type) => Current.Type == type;

    private bool Match(params TokenType[] types)
    {
        foreach (var type in types)
        {
            if (Check(type))
            {
                Advance();
                return true;
            }
        }
        return false;
    }

    private Token Consume(TokenType type, string errorMessage)
    {
        if (Check(type)) return Advance();

        var diag = new Diagnostic(DiagnosticSeverity.Error, "PS2_SYNTAX", errorMessage, Current.Location);
        _diagnostics.Add(diag);
        throw new Exception(diag.ToString());
    }

    public ProgramNode Parse()
    {
        var (manifest, signature, startIndex) = ManifestParser.Parse(_tokens);
        _current = startIndex;

        var statements = new List<StatementNode>();
        var loc = Current.Location;

        while (!IsAtEnd)
        {
            try
            {
                var stmt = ParseStatement();
                if (stmt != null)
                {
                    statements.Add(stmt);
                }
            }
            catch (Exception)
            {
                Synchronize();
            }
        }

        return new ProgramNode(manifest, signature, statements, loc);
    }

    private void Synchronize()
    {
        Advance();
        while (!IsAtEnd)
        {
            if (_tokens[_current - 1].Type == TokenType.Semicolon) return;

            switch (Current.Type)
            {
                case TokenType.Let:
                case TokenType.Fn:
                case TokenType.Async:
                case TokenType.If:
                case TokenType.While:
                case TokenType.For:
                case TokenType.Match:
                case TokenType.Return:
                    return;
            }

            Advance();
        }
    }

    private StatementNode? ParseStatement()
    {
        if (Match(TokenType.Let))
        {
            return ParseVarDecl();
        }

        if (Check(TokenType.Fn) || (Check(TokenType.Async) && Peek().Type == TokenType.Fn))
        {
            return ParseFunctionDecl();
        }

        if (Match(TokenType.If))
        {
            return ParseIfStatement();
        }

        if (Match(TokenType.While))
        {
            return ParseWhileStatement();
        }

        if (Match(TokenType.For))
        {
            return ParseForStatement();
        }

        if (Match(TokenType.Match))
        {
            return ParseMatchStatement();
        }

        if (Match(TokenType.Return))
        {
            return ParseReturnStatement();
        }

        if (Check(TokenType.OpenBrace))
        {
            return ParseBlock();
        }

        return ParseExpressionOrAssignmentStatement();
    }

    private StatementNode ParseVarDecl()
    {
        var loc = Current.Location;
        bool isMut = false;
        if (Check(TokenType.Identifier) && Current.Text == "mut")
        {
            isMut = true;
            Advance();
        }

        var nameTok = Consume(TokenType.Identifier, "Expected variable name after 'let'.");
        string name = nameTok.Text;

        string? typeAnnotation = null;
        if (Match(TokenType.Colon))
        {
            typeAnnotation = Consume(TokenType.Identifier, "Expected type name after ':'.").Text;
        }

        Consume(TokenType.Equal, "Expected '=' in variable declaration.");
        var init = ParseExpression();
        Match(TokenType.Semicolon); // optional/standard semicolon

        return new VarDeclStatement(name, typeAnnotation, init, isMut, loc);
    }

    private StatementNode ParseFunctionDecl()
    {
        var loc = Current.Location;
        bool isAsync = false;
        if (Match(TokenType.Async))
        {
            isAsync = true;
        }

        Consume(TokenType.Fn, "Expected 'fn' keyword.");
        var nameTok = Consume(TokenType.Identifier, "Expected function name.");
        string name = nameTok.Text;

        Consume(TokenType.OpenParen, "Expected '(' after function name.");
        var parameters = new List<ParameterNode>();

        if (!Check(TokenType.CloseParen))
        {
            do
            {
                var paramLoc = Current.Location;
                var paramName = Consume(TokenType.Identifier, "Expected parameter name.").Text;
                string? pType = null;
                if (Match(TokenType.Colon))
                {
                    pType = Consume(TokenType.Identifier, "Expected parameter type.").Text;
                }
                parameters.Add(new ParameterNode(paramName, pType, paramLoc));
            } while (Match(TokenType.Comma));
        }

        Consume(TokenType.CloseParen, "Expected ')' after parameters.");

        string? returnType = null;
        if (Match(TokenType.Arrow))
        {
            returnType = Consume(TokenType.Identifier, "Expected return type after '->'.").Text;
        }

        var body = ParseBlock();
        return new FunctionDeclStatement(name, parameters, returnType, body, isAsync, loc);
    }

    private BlockStatement ParseBlock()
    {
        var loc = Current.Location;
        Consume(TokenType.OpenBrace, "Expected '{' to begin block.");
        var statements = new List<StatementNode>();

        while (!Check(TokenType.CloseBrace) && !IsAtEnd)
        {
            var stmt = ParseStatement();
            if (stmt != null)
            {
                statements.Add(stmt);
            }
        }

        Consume(TokenType.CloseBrace, "Expected '}' to end block.");
        return new BlockStatement(statements, loc);
    }

    private StatementNode ParseIfStatement()
    {
        var loc = Current.Location;
        var cond = ParseExpression();
        var thenBranch = ParseBlock();
        StatementNode? elseBranch = null;

        if (Match(TokenType.Else))
        {
            if (Match(TokenType.If))
            {
                elseBranch = ParseIfStatement();
            }
            else
            {
                elseBranch = ParseBlock();
            }
        }

        return new IfStatement(cond, thenBranch, elseBranch, loc);
    }

    private StatementNode ParseWhileStatement()
    {
        var loc = Current.Location;
        var cond = ParseExpression();
        var body = ParseBlock();
        return new WhileStatement(cond, body, loc);
    }

    private StatementNode ParseForStatement()
    {
        var loc = Current.Location;
        var varName = Consume(TokenType.Identifier, "Expected loop variable name.").Text;
        Consume(TokenType.In, "Expected 'in' after variable name in for loop.");
        var iterable = ParseExpression();
        var body = ParseBlock();
        return new ForInStatement(varName, iterable, body, loc);
    }

    private StatementNode ParseReturnStatement()
    {
        var loc = Current.Location;
        ExpressionNode? val = null;
        if (!Check(TokenType.Semicolon) && !Check(TokenType.CloseBrace))
        {
            val = ParseExpression();
        }
        Match(TokenType.Semicolon);
        return new ReturnStatement(val, loc);
    }

    private StatementNode ParseMatchStatement()
    {
        var loc = _tokens[_current - 1].Location;
        var matchExpr = ParseMatchExpression(loc);
        Match(TokenType.Semicolon);
        return new MatchStatement(matchExpr.Expression, matchExpr.Cases, loc);
    }

    private MatchExpression ParseMatchExpression(SourceLocation loc)
    {
        var expr = ParseExpression();
        Consume(TokenType.OpenBrace, "Expected '{' after match expression.");

        var cases = new List<MatchCaseNode>();
        while (!Check(TokenType.CloseBrace) && !IsAtEnd)
        {
            var caseLoc = Current.Location;
            var pattern = ParsePattern();
            Consume(TokenType.FatArrow, "Expected '=>' after match pattern.");

            AstNode body;
            if (Check(TokenType.OpenBrace))
            {
                body = ParseBlock();
            }
            else
            {
                body = ParseExpression();
                Match(TokenType.Comma);
            }

            cases.Add(new MatchCaseNode(pattern, body, caseLoc));
            Match(TokenType.Comma);
        }

        Consume(TokenType.CloseBrace, "Expected '}' after match block.");
        return new MatchExpression(expr, cases, loc);
    }

    private PatternNode ParsePattern()
    {
        var loc = Current.Location;

        if (Check(TokenType.Identifier) && Current.Text == "_")
        {
            Advance();
            return new WildcardPatternNode(loc);
        }

        if (Match(TokenType.Some))
        {
            Consume(TokenType.OpenParen, "Expected '(' after 'Some'.");
            var varName = Consume(TokenType.Identifier, "Expected variable name in Some(...) pattern.").Text;
            Consume(TokenType.CloseParen, "Expected ')' after pattern variable.");
            return new OptionSomePatternNode(varName, loc);
        }

        if (Match(TokenType.None))
        {
            if (Match(TokenType.OpenParen))
            {
                Consume(TokenType.CloseParen, "Expected ')' after None().");
            }
            return new OptionNonePatternNode(loc);
        }

        if (Match(TokenType.Ok))
        {
            Consume(TokenType.OpenParen, "Expected '(' after 'Ok'.");
            var varName = Consume(TokenType.Identifier, "Expected variable name in Ok(...) pattern.").Text;
            Consume(TokenType.CloseParen, "Expected ')' after pattern variable.");
            return new ResultOkPatternNode(varName, loc);
        }

        if (Match(TokenType.Err))
        {
            Consume(TokenType.OpenParen, "Expected '(' after 'Err'.");
            var varName = Consume(TokenType.Identifier, "Expected variable name in Err(...) pattern.").Text;
            Consume(TokenType.CloseParen, "Expected ')' after pattern variable.");
            return new ResultErrPatternNode(varName, loc);
        }

        if (Check(TokenType.IntLiteral) || Check(TokenType.FloatLiteral) || Check(TokenType.StringLiteral) || Check(TokenType.True) || Check(TokenType.False))
        {
            var tok = Advance();
            return new LiteralPatternNode(tok.LiteralValue, loc);
        }

        if (Check(TokenType.Identifier))
        {
            var tok = Advance();
            return new IdentifierPatternNode(tok.Text, loc);
        }

        throw new Exception($"Unexpected pattern token '{Current.Text}' at {loc}");
    }

    private StatementNode ParseExpressionOrAssignmentStatement()
    {
        var loc = Current.Location;
        var expr = ParseExpression();

        if (Match(TokenType.Equal))
        {
            var value = ParseExpression();
            Match(TokenType.Semicolon);
            return new AssignmentStatement(expr, value, loc);
        }

        Match(TokenType.Semicolon);
        return new ExpressionStatement(expr, loc);
    }

    // Expressions
    public ExpressionNode ParseExpression()
    {
        return ParsePipeline();
    }

    private ExpressionNode ParsePipeline()
    {
        var expr = ParseLogicalOr();

        while (Match(TokenType.Pipe))
        {
            var loc = Current.Location;
            var right = ParseLogicalOr();
            expr = new PipeExpression(expr, right, loc);
        }

        return expr;
    }

    private ExpressionNode ParseLogicalOr()
    {
        var expr = ParseLogicalAnd();

        while (Match(TokenType.OrOr))
        {
            var loc = Current.Location;
            var right = ParseLogicalAnd();
            expr = new BinaryExpression(expr, BinaryOp.Or, right, loc);
        }

        return expr;
    }

    private ExpressionNode ParseLogicalAnd()
    {
        var expr = ParseEquality();

        while (Match(TokenType.AndAnd))
        {
            var loc = Current.Location;
            var right = ParseEquality();
            expr = new BinaryExpression(expr, BinaryOp.And, right, loc);
        }

        return expr;
    }

    private ExpressionNode ParseEquality()
    {
        var expr = ParseComparison();

        while (Check(TokenType.EqualEqual) || Check(TokenType.BangEqual))
        {
            var opTok = Advance();
            var loc = Current.Location;
            var op = opTok.Type == TokenType.EqualEqual ? BinaryOp.Equal : BinaryOp.NotEqual;
            var right = ParseComparison();
            expr = new BinaryExpression(expr, op, right, loc);
        }

        return expr;
    }

    private ExpressionNode ParseComparison()
    {
        var expr = ParseAddition();

        while (Check(TokenType.Less) || Check(TokenType.LessEqual) || Check(TokenType.Greater) || Check(TokenType.GreaterEqual))
        {
            var opTok = Advance();
            var loc = Current.Location;
            var op = opTok.Type switch
            {
                TokenType.Less => BinaryOp.Less,
                TokenType.LessEqual => BinaryOp.LessEqual,
                TokenType.Greater => BinaryOp.Greater,
                _ => BinaryOp.GreaterEqual
            };
            var right = ParseAddition();
            expr = new BinaryExpression(expr, op, right, loc);
        }

        return expr;
    }

    private ExpressionNode ParseAddition()
    {
        var expr = ParseMultiplication();

        while (Check(TokenType.Plus) || Check(TokenType.Minus))
        {
            var opTok = Advance();
            var loc = Current.Location;
            var op = opTok.Type == TokenType.Plus ? BinaryOp.Add : BinaryOp.Subtract;
            var right = ParseMultiplication();
            expr = new BinaryExpression(expr, op, right, loc);
        }

        return expr;
    }

    private ExpressionNode ParseMultiplication()
    {
        var expr = ParseUnary();

        while (Check(TokenType.Star) || Check(TokenType.Slash) || Check(TokenType.Percent))
        {
            var opTok = Advance();
            var loc = Current.Location;
            var op = opTok.Type switch
            {
                TokenType.Star => BinaryOp.Multiply,
                TokenType.Slash => BinaryOp.Divide,
                _ => BinaryOp.Modulo
            };
            var right = ParseUnary();
            expr = new BinaryExpression(expr, op, right, loc);
        }

        return expr;
    }

    private ExpressionNode ParseUnary()
    {
        if (Check(TokenType.Bang) || Check(TokenType.Minus))
        {
            var opTok = Advance();
            var loc = Current.Location;
            var op = opTok.Type == TokenType.Bang ? UnaryOp.Not : UnaryOp.Negate;
            var right = ParseUnary();
            return new UnaryExpression(op, right, loc);
        }

        if (Match(TokenType.Await))
        {
            var loc = Current.Location;
            var right = ParseUnary();
            return new AwaitExpression(right, loc);
        }

        return ParseCallMemberOrIndexer();
    }

    private ExpressionNode ParseCallMemberOrIndexer()
    {
        var expr = ParsePrimary();

        while (true)
        {
            if (Match(TokenType.OpenParen))
            {
                var loc = Current.Location;
                var args = new List<ExpressionNode>();
                if (!Check(TokenType.CloseParen))
                {
                    do
                    {
                        args.Add(ParseExpression());
                    } while (Match(TokenType.Comma));
                }
                Consume(TokenType.CloseParen, "Expected ')' after argument list.");
                expr = new CallExpression(expr, args, loc);
            }
            else if (Match(TokenType.Dot))
            {
                var loc = Current.Location;
                var member = Consume(TokenType.Identifier, "Expected member name after '.').").Text;
                expr = new MemberAccessExpression(expr, member, loc);
            }
            else if (Match(TokenType.OpenBracket))
            {
                var loc = Current.Location;
                var index = ParseExpression();
                Consume(TokenType.CloseBracket, "Expected ']' after index.");
                expr = new IndexAccessExpression(expr, index, loc);
            }
            else
            {
                break;
            }
        }

        return expr;
    }

    private ExpressionNode ParsePrimary()
    {
        var loc = Current.Location;

        // Lambda: x => expr
        if (Check(TokenType.Identifier) && Peek().Type == TokenType.FatArrow)
        {
            var paramName = Advance().Text;
            Advance(); // skip =>
            if (Check(TokenType.OpenBrace))
            {
                var block = ParseBlock();
                return new LambdaExpression(new List<ParameterNode> { new(paramName, null, loc) }, null, block, loc);
            }
            var body = ParseExpression();
            return new LambdaExpression(new List<ParameterNode> { new(paramName, null, loc) }, body, null, loc);
        }

        // Literals
        if (Match(TokenType.IntLiteral))
        {
            return new LiteralExpression(_tokens[_current - 1].LiteralValue, Ps2LiteralType.Int, loc);
        }

        if (Match(TokenType.FloatLiteral))
        {
            return new LiteralExpression(_tokens[_current - 1].LiteralValue, Ps2LiteralType.Float, loc);
        }

        if (Match(TokenType.StringLiteral))
        {
            return new LiteralExpression(_tokens[_current - 1].LiteralValue, Ps2LiteralType.String, loc);
        }

        if (Match(TokenType.True))
        {
            return new LiteralExpression(true, Ps2LiteralType.Bool, loc);
        }

        if (Match(TokenType.False))
        {
            return new LiteralExpression(false, Ps2LiteralType.Bool, loc);
        }

        if (Match(TokenType.Null))
        {
            return new LiteralExpression(null, Ps2LiteralType.Null, loc);
        }

        // Algebraic constructors: Some, None, Ok, Err
        if (Match(TokenType.Some))
        {
            Consume(TokenType.OpenParen, "Expected '(' after 'Some'.");
            var inner = ParseExpression();
            Consume(TokenType.CloseParen, "Expected ')' after Some expression.");
            return new OptionExpression(true, inner, loc);
        }

        if (Match(TokenType.None))
        {
            if (Match(TokenType.OpenParen))
            {
                Consume(TokenType.CloseParen, "Expected ')' after None().");
            }
            return new OptionExpression(false, null, loc);
        }

        if (Match(TokenType.Ok))
        {
            Consume(TokenType.OpenParen, "Expected '(' after 'Ok'.");
            var inner = ParseExpression();
            Consume(TokenType.CloseParen, "Expected ')' after Ok expression.");
            return new ResultExpression(true, inner, loc);
        }

        if (Match(TokenType.Err))
        {
            Consume(TokenType.OpenParen, "Expected '(' after 'Err'.");
            var inner = ParseExpression();
            Consume(TokenType.CloseParen, "Expected ')' after Err expression.");
            return new ResultExpression(false, inner, loc);
        }

        if (Match(TokenType.Match))
        {
            return ParseMatchExpression(_tokens[_current - 1].Location);
        }

        // Identifier
        if (Match(TokenType.Identifier))
        {
            return new IdentifierExpression(_tokens[_current - 1].Text, loc);
        }

        // Grouping or multi-parameter lambda: (a, b) => expr
        if (Match(TokenType.OpenParen))
        {
            // Check if this is a lambda like `(a, b) => ...` or empty `() => ...`
            int lookahead = _current;
            bool isLambda = false;
            if (lookahead < _tokens.Count && _tokens[lookahead].Type == TokenType.CloseParen &&
                lookahead + 1 < _tokens.Count && _tokens[lookahead + 1].Type == TokenType.FatArrow)
            {
                isLambda = true;
            }
            else
            {
                // look forward for `) =>`
                int parenDepth = 1;
                for (int i = lookahead; i < _tokens.Count; i++)
                {
                    if (_tokens[i].Type == TokenType.OpenParen) parenDepth++;
                    else if (_tokens[i].Type == TokenType.CloseParen)
                    {
                        parenDepth--;
                        if (parenDepth == 0)
                        {
                            if (i + 1 < _tokens.Count && _tokens[i + 1].Type == TokenType.FatArrow)
                            {
                                isLambda = true;
                            }
                            break;
                        }
                    }
                }
            }

            if (isLambda)
            {
                var parameters = new List<ParameterNode>();
                if (!Check(TokenType.CloseParen))
                {
                    do
                    {
                        var pLoc = Current.Location;
                        var pName = Consume(TokenType.Identifier, "Expected lambda parameter name.").Text;
                        string? pType = null;
                        if (Match(TokenType.Colon))
                        {
                            pType = Consume(TokenType.Identifier, "Expected parameter type.").Text;
                        }
                        parameters.Add(new ParameterNode(pName, pType, pLoc));
                    } while (Match(TokenType.Comma));
                }
                Consume(TokenType.CloseParen, "Expected ')' after parameters.");
                Consume(TokenType.FatArrow, "Expected '=>' after lambda parameters.");

                if (Check(TokenType.OpenBrace))
                {
                    var block = ParseBlock();
                    return new LambdaExpression(parameters, null, block, loc);
                }
                else
                {
                    var bodyExpr = ParseExpression();
                    return new LambdaExpression(parameters, bodyExpr, null, loc);
                }
            }
            else
            {
                var expr = ParseExpression();
                Consume(TokenType.CloseParen, "Expected ')' after grouped expression.");
                return expr;
            }
        }

        // List literal: [1, 2, 3]
        if (Match(TokenType.OpenBracket))
        {
            var elements = new List<ExpressionNode>();
            if (!Check(TokenType.CloseBracket))
            {
                do
                {
                    elements.Add(ParseExpression());
                } while (Match(TokenType.Comma));
            }
            Consume(TokenType.CloseBracket, "Expected ']' after list elements.");
            return new ListLiteralExpression(elements, loc);
        }

        // Map literal: {"key": value}
        if (Match(TokenType.OpenBrace))
        {
            var keyValues = new List<KeyValuePair<string, ExpressionNode>>();
            if (!Check(TokenType.CloseBrace))
            {
                do
                {
                    string key;
                    if (Check(TokenType.StringLiteral))
                    {
                        key = (string)Advance().LiteralValue!;
                    }
                    else if (Check(TokenType.Identifier))
                    {
                        key = Advance().Text;
                    }
                    else
                    {
                        throw new Exception($"Expected map key at {Current.Location}");
                    }

                    Consume(TokenType.Colon, "Expected ':' after map key.");
                    var val = ParseExpression();
                    keyValues.Add(new KeyValuePair<string, ExpressionNode>(key, val));
                } while (Match(TokenType.Comma));
            }

            Consume(TokenType.CloseBrace, "Expected '}' after map entries.");
            return new MapLiteralExpression(keyValues, loc);
        }

        throw new Exception($"Unexpected token '{Current.Text}' ({Current.Type}) at {loc}");
    }
}
