namespace Ps2.Core;

public enum TokenType
{
    // Literals
    IntLiteral,
    FloatLiteral,
    StringLiteral,
    Identifier,

    // Keywords
    Let,
    Fn,
    Async,
    Await,
    If,
    Else,
    While,
    For,
    In,
    Match,
    Return,
    True,
    False,
    Null,
    Requires,
    As,

    // Algebraic constructors as tokens
    Some,
    None,
    Ok,
    Err,

    // Manifest & Directives
    ManifestStart,      // #manifest
    ManifestEnd,        // #endmanifest
    SignatureDirective, // #signature:

    // Operators
    Pipe,               // |>
    FatArrow,           // =>
    Arrow,              // ->
    DoubleColon,        // ::
    EqualEqual,         // ==
    BangEqual,          // !=
    Less,               // <
    LessEqual,          // <=
    Greater,            // >
    GreaterEqual,       // >=
    AndAnd,             // &&
    OrOr,               // ||
    Bang,               // !
    Plus,               // +
    Minus,              // -
    Star,               // *
    Slash,              // /
    Percent,            // %
    Equal,              // =
    PlusEqual,          // +=
    MinusEqual,         // -=

    // Delimiters
    OpenParen,          // (
    CloseParen,         // )
    OpenBrace,          // {
    CloseBrace,         // }
    OpenBracket,        // [
    CloseBracket,       // ]
    Comma,              // ,
    Colon,              // :
    Semicolon,          // ;
    Dot,                // .

    // Control
    Eof,
    Invalid
}

public sealed record Token(
    TokenType Type,
    string Text,
    object? LiteralValue,
    SourceLocation Location
)
{
    public override string ToString() => $"{Type}('{Text}') at {Location}";
}
