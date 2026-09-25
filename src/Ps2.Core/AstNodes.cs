using System.Collections.Generic;

namespace Ps2.Core;

public abstract record AstNode(SourceLocation Location);

public sealed record ProgramNode(
    CapabilityManifest Manifest,
    string? Signature,
    List<StatementNode> Statements,
    SourceLocation Location
) : AstNode(Location);

public abstract record StatementNode(SourceLocation Location) : AstNode(Location);

public sealed record VarDeclStatement(
    string Name,
    string? TypeAnnotation,
    ExpressionNode Initializer,
    bool IsMutable,
    SourceLocation Location
) : StatementNode(Location);

public sealed record AssignmentStatement(
    ExpressionNode Target,
    ExpressionNode Value,
    SourceLocation Location
) : StatementNode(Location);

public sealed record ParameterNode(
    string Name,
    string? TypeAnnotation,
    SourceLocation Location
) : AstNode(Location);

public sealed record FunctionDeclStatement(
    string Name,
    List<ParameterNode> Parameters,
    string? ReturnType,
    BlockStatement Body,
    bool IsAsync,
    SourceLocation Location
) : StatementNode(Location);

public sealed record IfStatement(
    ExpressionNode Condition,
    BlockStatement ThenBranch,
    StatementNode? ElseBranch,
    SourceLocation Location
) : StatementNode(Location);

public sealed record WhileStatement(
    ExpressionNode Condition,
    BlockStatement Body,
    SourceLocation Location
) : StatementNode(Location);

public sealed record ForInStatement(
    string Variable,
    ExpressionNode Iterable,
    BlockStatement Body,
    SourceLocation Location
) : StatementNode(Location);

public sealed record ReturnStatement(
    ExpressionNode? Value,
    SourceLocation Location
) : StatementNode(Location);

public sealed record BlockStatement(
    List<StatementNode> Statements,
    SourceLocation Location
) : StatementNode(Location);

public sealed record ExpressionStatement(
    ExpressionNode Expression,
    SourceLocation Location
) : StatementNode(Location);

public sealed record MatchCaseNode(
    PatternNode Pattern,
    AstNode Body, // ExpressionNode or BlockStatement
    SourceLocation Location
) : AstNode(Location);

public sealed record MatchStatement(
    ExpressionNode Expression,
    List<MatchCaseNode> Cases,
    SourceLocation Location
) : StatementNode(Location);

public sealed record MatchExpression(
    ExpressionNode Expression,
    List<MatchCaseNode> Cases,
    SourceLocation Location
) : ExpressionNode(Location);

// Patterns for match
public abstract record PatternNode(SourceLocation Location) : AstNode(Location);
public sealed record WildcardPatternNode(SourceLocation Location) : PatternNode(Location);
public sealed record LiteralPatternNode(object? Value, SourceLocation Location) : PatternNode(Location);
public sealed record IdentifierPatternNode(string Name, SourceLocation Location) : PatternNode(Location);
public sealed record OptionSomePatternNode(string VariableName, SourceLocation Location) : PatternNode(Location);
public sealed record OptionNonePatternNode(SourceLocation Location) : PatternNode(Location);
public sealed record ResultOkPatternNode(string VariableName, SourceLocation Location) : PatternNode(Location);
public sealed record ResultErrPatternNode(string VariableName, SourceLocation Location) : PatternNode(Location);

// Expressions
public abstract record ExpressionNode(SourceLocation Location) : AstNode(Location);

public enum Ps2LiteralType
{
    Int,
    Float,
    String,
    Bool,
    Null
}

public sealed record LiteralExpression(
    object? Value,
    Ps2LiteralType LiteralType,
    SourceLocation Location
) : ExpressionNode(Location);

public sealed record IdentifierExpression(
    string Name,
    SourceLocation Location
) : ExpressionNode(Location);

public enum BinaryOp
{
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    And,
    Or
}

public sealed record BinaryExpression(
    ExpressionNode Left,
    BinaryOp Op,
    ExpressionNode Right,
    SourceLocation Location
) : ExpressionNode(Location);

public enum UnaryOp
{
    Negate,
    Not
}

public sealed record UnaryExpression(
    UnaryOp Op,
    ExpressionNode Right,
    SourceLocation Location
) : ExpressionNode(Location);

public sealed record PipeExpression(
    ExpressionNode Left,
    ExpressionNode Right,
    SourceLocation Location
) : ExpressionNode(Location);

public sealed record CallExpression(
    ExpressionNode Callee,
    List<ExpressionNode> Arguments,
    SourceLocation Location
) : ExpressionNode(Location);

public sealed record MemberAccessExpression(
    ExpressionNode Target,
    string Member,
    SourceLocation Location
) : ExpressionNode(Location);

public sealed record IndexAccessExpression(
    ExpressionNode Target,
    ExpressionNode Index,
    SourceLocation Location
) : ExpressionNode(Location);

public sealed record LambdaExpression(
    List<ParameterNode> Parameters,
    ExpressionNode? ExpressionBody,
    BlockStatement? BlockBody,
    SourceLocation Location
) : ExpressionNode(Location);

public sealed record ListLiteralExpression(
    List<ExpressionNode> Elements,
    SourceLocation Location
) : ExpressionNode(Location);

public sealed record MapLiteralExpression(
    List<KeyValuePair<string, ExpressionNode>> KeyValues,
    SourceLocation Location
) : ExpressionNode(Location);

public sealed record OptionExpression(
    bool HasValue,
    ExpressionNode? Value,
    SourceLocation Location
) : ExpressionNode(Location);

public sealed record ResultExpression(
    bool IsOk,
    ExpressionNode Value,
    SourceLocation Location
) : ExpressionNode(Location);

public sealed record AwaitExpression(
    ExpressionNode Expression,
    SourceLocation Location
) : ExpressionNode(Location);
