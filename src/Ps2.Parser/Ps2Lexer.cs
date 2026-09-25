using System;
using System.Collections.Generic;
using System.Text;
using Ps2.Core;

namespace Ps2.Parser;

public sealed class Ps2Lexer
{
    private readonly string _source;
    private readonly string _filePath;
    private int _pos = 0;
    private int _line = 1;
    private int _column = 1;

    private static readonly Dictionary<string, TokenType> Keywords = new(StringComparer.Ordinal)
    {
        { "let", TokenType.Let },
        { "fn", TokenType.Fn },
        { "async", TokenType.Async },
        { "await", TokenType.Await },
        { "if", TokenType.If },
        { "else", TokenType.Else },
        { "while", TokenType.While },
        { "for", TokenType.For },
        { "in", TokenType.In },
        { "match", TokenType.Match },
        { "return", TokenType.Return },
        { "true", TokenType.True },
        { "false", TokenType.False },
        { "null", TokenType.Null },
        { "requires", TokenType.Requires },
        { "as", TokenType.As },
        { "Some", TokenType.Some },
        { "None", TokenType.None },
        { "Ok", TokenType.Ok },
        { "Err", TokenType.Err }
    };

    public Ps2Lexer(string source, string filePath = "<source>")
    {
        _source = source ?? string.Empty;
        _filePath = filePath;
    }

    private char Current => _pos < _source.Length ? _source[_pos] : '\0';
    private char Peek(int offset = 1) => (_pos + offset) < _source.Length ? _source[_pos + offset] : '\0';

    private void Advance()
    {
        if (_pos < _source.Length)
        {
            if (_source[_pos] == '\n')
            {
                _line++;
                _column = 1;
            }
            else
            {
                _column++;
            }
            _pos++;
        }
    }

    public List<Token> Tokenize()
    {
        var tokens = new List<Token>();

        // Skip Unix shebang if present on first line
        if (_pos == 0 && _source.StartsWith("#!"))
        {
            SkipUntilNewline();
        }

        while (_pos < _source.Length)
        {
            SkipWhitespaceAndComments();

            if (_pos >= _source.Length)
                break;

            var startLine = _line;
            var startCol = _column;
            var loc = new SourceLocation(_filePath, startLine, startCol);
            char c = Current;

            // Directives: #manifest, #endmanifest, #signature:
            if (c == '#')
            {
                var directiveToken = ReadDirective(loc);
                if (directiveToken != null)
                {
                    tokens.Add(directiveToken);
                    continue;
                }
            }

            // Identifiers / Keywords
            if (char.IsLetter(c) || c == '_')
            {
                tokens.Add(ReadIdentifierOrKeyword(loc));
                continue;
            }

            // Numbers
            if (char.IsDigit(c))
            {
                tokens.Add(ReadNumber(loc));
                continue;
            }

            // Strings
            if (c == '"')
            {
                tokens.Add(ReadString(loc));
                continue;
            }

            // Operators & Delimiters
            switch (c)
            {
                case '|':
                    if (Peek() == '>')
                    {
                        Advance(); Advance();
                        tokens.Add(new Token(TokenType.Pipe, "|>", null, loc));
                    }
                    else if (Peek() == '|')
                    {
                        Advance(); Advance();
                        tokens.Add(new Token(TokenType.OrOr, "||", null, loc));
                    }
                    else
                    {
                        Advance();
                        tokens.Add(new Token(TokenType.Invalid, "|", null, loc));
                    }
                    break;

                case '=':
                    if (Peek() == '=')
                    {
                        Advance(); Advance();
                        tokens.Add(new Token(TokenType.EqualEqual, "==", null, loc));
                    }
                    else if (Peek() == '>')
                    {
                        Advance(); Advance();
                        tokens.Add(new Token(TokenType.FatArrow, "=>", null, loc));
                    }
                    else
                    {
                        Advance();
                        tokens.Add(new Token(TokenType.Equal, "=", null, loc));
                    }
                    break;

                case '!':
                    if (Peek() == '=')
                    {
                        Advance(); Advance();
                        tokens.Add(new Token(TokenType.BangEqual, "!=", null, loc));
                    }
                    else
                    {
                        Advance();
                        tokens.Add(new Token(TokenType.Bang, "!", null, loc));
                    }
                    break;

                case '<':
                    if (Peek() == '=')
                    {
                        Advance(); Advance();
                        tokens.Add(new Token(TokenType.LessEqual, "<=", null, loc));
                    }
                    else
                    {
                        Advance();
                        tokens.Add(new Token(TokenType.Less, "<", null, loc));
                    }
                    break;

                case '>':
                    if (Peek() == '=')
                    {
                        Advance(); Advance();
                        tokens.Add(new Token(TokenType.GreaterEqual, ">=", null, loc));
                    }
                    else
                    {
                        Advance();
                        tokens.Add(new Token(TokenType.Greater, ">", null, loc));
                    }
                    break;

                case '&':
                    if (Peek() == '&')
                    {
                        Advance(); Advance();
                        tokens.Add(new Token(TokenType.AndAnd, "&&", null, loc));
                    }
                    else
                    {
                        Advance();
                        tokens.Add(new Token(TokenType.Invalid, "&", null, loc));
                    }
                    break;

                case ':':
                    if (Peek() == ':')
                    {
                        Advance(); Advance();
                        tokens.Add(new Token(TokenType.DoubleColon, "::", null, loc));
                    }
                    else
                    {
                        Advance();
                        tokens.Add(new Token(TokenType.Colon, ":", null, loc));
                    }
                    break;

                case '-':
                    if (Peek() == '>')
                    {
                        Advance(); Advance();
                        tokens.Add(new Token(TokenType.Arrow, "->", null, loc));
                    }
                    else if (Peek() == '=')
                    {
                        Advance(); Advance();
                        tokens.Add(new Token(TokenType.MinusEqual, "-=", null, loc));
                    }
                    else
                    {
                        Advance();
                        tokens.Add(new Token(TokenType.Minus, "-", null, loc));
                    }
                    break;

                case '+':
                    if (Peek() == '=')
                    {
                        Advance(); Advance();
                        tokens.Add(new Token(TokenType.PlusEqual, "+=", null, loc));
                    }
                    else
                    {
                        Advance();
                        tokens.Add(new Token(TokenType.Plus, "+", null, loc));
                    }
                    break;

                case '*':
                    Advance();
                    tokens.Add(new Token(TokenType.Star, "*", null, loc));
                    break;

                case '/':
                    Advance();
                    tokens.Add(new Token(TokenType.Slash, "/", null, loc));
                    break;

                case '%':
                    Advance();
                    tokens.Add(new Token(TokenType.Percent, "%", null, loc));
                    break;

                case '(':
                    Advance();
                    tokens.Add(new Token(TokenType.OpenParen, "(", null, loc));
                    break;

                case ')':
                    Advance();
                    tokens.Add(new Token(TokenType.CloseParen, ")", null, loc));
                    break;

                case '{':
                    Advance();
                    tokens.Add(new Token(TokenType.OpenBrace, "{", null, loc));
                    break;

                case '}':
                    Advance();
                    tokens.Add(new Token(TokenType.CloseBrace, "}", null, loc));
                    break;

                case '[':
                    Advance();
                    tokens.Add(new Token(TokenType.OpenBracket, "[", null, loc));
                    break;

                case ']':
                    Advance();
                    tokens.Add(new Token(TokenType.CloseBracket, "]", null, loc));
                    break;

                case ',':
                    Advance();
                    tokens.Add(new Token(TokenType.Comma, ",", null, loc));
                    break;

                case ';':
                    Advance();
                    tokens.Add(new Token(TokenType.Semicolon, ";", null, loc));
                    break;

                case '.':
                    Advance();
                    tokens.Add(new Token(TokenType.Dot, ".", null, loc));
                    break;

                default:
                    Advance();
                    tokens.Add(new Token(TokenType.Invalid, c.ToString(), null, loc));
                    break;
            }
        }

        tokens.Add(new Token(TokenType.Eof, string.Empty, null, new SourceLocation(_filePath, _line, _column)));
        return tokens;
    }

    private Token? ReadDirective(SourceLocation loc)
    {
        var sb = new StringBuilder();
        while (_pos < _source.Length && (char.IsLetterOrDigit(Current) || Current == '#' || Current == ':' || Current == '_'))
        {
            sb.Append(Current);
            Advance();
        }

        var text = sb.ToString();
        if (text == "#manifest")
            return new Token(TokenType.ManifestStart, text, null, loc);
        if (text == "#endmanifest")
            return new Token(TokenType.ManifestEnd, text, null, loc);
        if (text == "#signature" || text == "#signature:")
        {
            SkipWhitespace();
            var sigContent = new StringBuilder();
            while (_pos < _source.Length && Current != '\r' && Current != '\n')
            {
                sigContent.Append(Current);
                Advance();
            }
            return new Token(TokenType.SignatureDirective, text, sigContent.ToString().Trim(), loc);
        }

        return new Token(TokenType.Invalid, text, null, loc);
    }

    private Token ReadIdentifierOrKeyword(SourceLocation loc)
    {
        var sb = new StringBuilder();
        while (_pos < _source.Length && (char.IsLetterOrDigit(Current) || Current == '_'))
        {
            sb.Append(Current);
            Advance();
        }

        var text = sb.ToString();
        if (Keywords.TryGetValue(text, out var tokenType))
        {
            return new Token(tokenType, text, null, loc);
        }

        return new Token(TokenType.Identifier, text, null, loc);
    }

    private Token ReadNumber(SourceLocation loc)
    {
        var sb = new StringBuilder();
        bool isFloat = false;

        while (_pos < _source.Length && char.IsDigit(Current))
        {
            sb.Append(Current);
            Advance();
        }

        if (Current == '.' && char.IsDigit(Peek()))
        {
            isFloat = true;
            sb.Append(Current);
            Advance();

            while (_pos < _source.Length && char.IsDigit(Current))
            {
                sb.Append(Current);
                Advance();
            }
        }

        var text = sb.ToString();
        if (isFloat)
        {
            double.TryParse(text, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double fVal);
            return new Token(TokenType.FloatLiteral, text, fVal, loc);
        }
        else
        {
            long.TryParse(text, out long iVal);
            return new Token(TokenType.IntLiteral, text, iVal, loc);
        }
    }

    private Token ReadString(SourceLocation loc)
    {
        Advance(); // skip opening '"'
        var sb = new StringBuilder();

        while (_pos < _source.Length && Current != '"')
        {
            if (Current == '\\')
            {
                Advance();
                if (_pos >= _source.Length) break;
                char esc = Current;
                switch (esc)
                {
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    default: sb.Append(esc); break;
                }
            }
            else
            {
                sb.Append(Current);
            }
            Advance();
        }

        if (Current == '"')
        {
            Advance(); // skip closing '"'
        }

        return new Token(TokenType.StringLiteral, sb.ToString(), sb.ToString(), loc);
    }

    private void SkipWhitespaceAndComments()
    {
        while (_pos < _source.Length)
        {
            char c = Current;
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            {
                Advance();
            }
            else if (c == '/' && Peek() == '/')
            {
                SkipUntilNewline();
            }
            else if (c == '/' && Peek() == '*')
            {
                Advance(); Advance();
                while (_pos < _source.Length && !(Current == '*' && Peek() == '/'))
                {
                    Advance();
                }
                if (_pos < _source.Length)
                {
                    Advance(); Advance(); // skip */
                }
            }
            else
            {
                break;
            }
        }
    }

    private void SkipWhitespace()
    {
        while (_pos < _source.Length && (Current == ' ' || Current == '\t'))
        {
            Advance();
        }
    }

    private void SkipUntilNewline()
    {
        while (_pos < _source.Length && Current != '\n')
        {
            Advance();
        }
        if (_pos < _source.Length && Current == '\n')
        {
            Advance();
        }
    }
}
