using System;
using System.Collections.Generic;
using System.Linq;

namespace Ps2.Core;

public static class Ps2Linter
{
    public static List<Diagnostic> Lint(ProgramNode program)
    {
        var diagnostics = new List<Diagnostic>();

        // 1. Check capability declaration usage
        CheckCapabilities(program, diagnostics);

        // 2. Check unreachable code and unused variables
        CheckBlockStatements(program.Statements, diagnostics);

        return diagnostics;
    }

    private static void CheckCapabilities(ProgramNode program, List<Diagnostic> diags)
    {
        var manifest = program.Manifest;
        if (manifest.AllowAll) return;

        foreach (var stmt in program.Statements)
        {
            InspectCapabilitiesInStatement(stmt, manifest, diags);
        }
    }

    private static void InspectCapabilitiesInStatement(StatementNode stmt, CapabilityManifest manifest, List<Diagnostic> diags)
    {
        switch (stmt)
        {
            case VarDeclStatement varDecl:
                InspectCapabilitiesInExpression(varDecl.Initializer, manifest, diags);
                break;
            case AssignmentStatement assign:
                InspectCapabilitiesInExpression(assign.Target, manifest, diags);
                InspectCapabilitiesInExpression(assign.Value, manifest, diags);
                break;
            case FunctionDeclStatement fnDecl:
                InspectCapabilitiesInStatement(fnDecl.Body, manifest, diags);
                break;
            case IfStatement ifStmt:
                InspectCapabilitiesInExpression(ifStmt.Condition, manifest, diags);
                InspectCapabilitiesInStatement(ifStmt.ThenBranch, manifest, diags);
                if (ifStmt.ElseBranch != null) InspectCapabilitiesInStatement(ifStmt.ElseBranch, manifest, diags);
                break;
            case WhileStatement whileStmt:
                InspectCapabilitiesInExpression(whileStmt.Condition, manifest, diags);
                InspectCapabilitiesInStatement(whileStmt.Body, manifest, diags);
                break;
            case ForInStatement forStmt:
                InspectCapabilitiesInExpression(forStmt.Iterable, manifest, diags);
                InspectCapabilitiesInStatement(forStmt.Body, manifest, diags);
                break;
            case ReturnStatement retStmt:
                if (retStmt.Value != null) InspectCapabilitiesInExpression(retStmt.Value, manifest, diags);
                break;
            case BlockStatement block:
                foreach (var s in block.Statements)
                {
                    InspectCapabilitiesInStatement(s, manifest, diags);
                }
                break;
            case ExpressionStatement exprStmt:
                InspectCapabilitiesInExpression(exprStmt.Expression, manifest, diags);
                break;
            case MatchStatement matchStmt:
                InspectCapabilitiesInExpression(matchStmt.Expression, manifest, diags);
                foreach (var c in matchStmt.Cases)
                {
                    if (c.Body is StatementNode s) InspectCapabilitiesInStatement(s, manifest, diags);
                    else if (c.Body is ExpressionNode e) InspectCapabilitiesInExpression(e, manifest, diags);
                }
                break;
        }
    }

    private static void InspectCapabilitiesInExpression(ExpressionNode expr, CapabilityManifest manifest, List<Diagnostic> diags)
    {
        switch (expr)
        {
            case CallExpression call:
                string? calleeName = GetCalleeName(call.Callee);
                if (calleeName != null)
                {
                    if ((calleeName == "fs.read_file" || calleeName == "fs.list_dir" || calleeName == "fs.exists") && manifest.FsRead.Count == 0)
                    {
                        diags.Add(new Diagnostic(DiagnosticSeverity.Warning, "LINT_CAP_FS_READ", $"Call to '{calleeName}' requires 'fs.read' capability in manifest.", call.Location));
                    }
                    else if ((calleeName == "fs.write_file" || calleeName == "fs.delete_file") && manifest.FsWrite.Count == 0)
                    {
                        diags.Add(new Diagnostic(DiagnosticSeverity.Warning, "LINT_CAP_FS_WRITE", $"Call to '{calleeName}' requires 'fs.write' capability in manifest.", call.Location));
                    }
                    else if ((calleeName == "net.http_get" || calleeName == "net.http_post") && manifest.NetHttp.Count == 0)
                    {
                        diags.Add(new Diagnostic(DiagnosticSeverity.Warning, "LINT_CAP_NET_HTTP", $"Call to '{calleeName}' requires 'net.http' capability in manifest.", call.Location));
                    }
                    else if (calleeName == "sys.env" && manifest.Env.Count == 0)
                    {
                        diags.Add(new Diagnostic(DiagnosticSeverity.Warning, "LINT_CAP_ENV", $"Call to 'sys.env' requires 'env' capability in manifest.", call.Location));
                    }
                    else if (calleeName == "sys.exec" && manifest.ProcExec.Count == 0)
                    {
                        diags.Add(new Diagnostic(DiagnosticSeverity.Warning, "LINT_CAP_PROC_EXEC", $"Call to 'sys.exec' requires 'proc.exec' capability in manifest.", call.Location));
                    }
                }

                InspectCapabilitiesInExpression(call.Callee, manifest, diags);
                foreach (var arg in call.Arguments)
                {
                    InspectCapabilitiesInExpression(arg, manifest, diags);
                }
                break;

            case PipeExpression pipe:
                InspectCapabilitiesInExpression(pipe.Left, manifest, diags);
                InspectCapabilitiesInExpression(pipe.Right, manifest, diags);
                break;

            case BinaryExpression bin:
                InspectCapabilitiesInExpression(bin.Left, manifest, diags);
                InspectCapabilitiesInExpression(bin.Right, manifest, diags);
                break;

            case UnaryExpression un:
                InspectCapabilitiesInExpression(un.Right, manifest, diags);
                break;

            case MemberAccessExpression mem:
                InspectCapabilitiesInExpression(mem.Target, manifest, diags);
                break;

            case IndexAccessExpression idx:
                InspectCapabilitiesInExpression(idx.Target, manifest, diags);
                InspectCapabilitiesInExpression(idx.Index, manifest, diags);
                break;

            case LambdaExpression lam:
                if (lam.ExpressionBody != null) InspectCapabilitiesInExpression(lam.ExpressionBody, manifest, diags);
                if (lam.BlockBody != null) InspectCapabilitiesInStatement(lam.BlockBody, manifest, diags);
                break;

            case ListLiteralExpression list:
                foreach (var el in list.Elements) InspectCapabilitiesInExpression(el, manifest, diags);
                break;

            case MapLiteralExpression map:
                foreach (var kv in map.KeyValues) InspectCapabilitiesInExpression(kv.Value, manifest, diags);
                break;

            case MatchExpression matchExpr:
                InspectCapabilitiesInExpression(matchExpr.Expression, manifest, diags);
                foreach (var c in matchExpr.Cases)
                {
                    if (c.Body is StatementNode s) InspectCapabilitiesInStatement(s, manifest, diags);
                    else if (c.Body is ExpressionNode e) InspectCapabilitiesInExpression(e, manifest, diags);
                }
                break;
        }
    }

    private static string? GetCalleeName(ExpressionNode callee)
    {
        if (callee is IdentifierExpression id) return id.Name;
        if (callee is MemberAccessExpression mem && mem.Target is IdentifierExpression targetId)
        {
            return $"{targetId.Name}.{mem.Member}";
        }
        return null;
    }

    private static void CheckBlockStatements(IReadOnlyList<StatementNode> statements, List<Diagnostic> diags)
    {
        bool foundReturn = false;

        for (int i = 0; i < statements.Count; i++)
        {
            var stmt = statements[i];

            if (foundReturn)
            {
                diags.Add(new Diagnostic(
                    DiagnosticSeverity.Warning,
                    "LINT_UNREACHABLE_CODE",
                    "Unreachable statement detected after return statement.",
                    stmt.Location
                ));
            }

            if (stmt is ReturnStatement)
            {
                foundReturn = true;
            }

            // Check unused variables in this block
            if (stmt is VarDeclStatement varDecl && !varDecl.Name.StartsWith("_"))
            {
                bool isUsed = false;
                for (int j = i + 1; j < statements.Count; j++)
                {
                    if (IsIdentifierUsedInStatement(statements[j], varDecl.Name))
                    {
                        isUsed = true;
                        break;
                    }
                }

                if (!isUsed)
                {
                    diags.Add(new Diagnostic(
                        DiagnosticSeverity.Warning,
                        "LINT_UNUSED_VAR",
                        $"Variable '{varDecl.Name}' is declared but never used in this scope. Prefix with '_' if intentional.",
                        varDecl.Location
                    ));
                }
            }

            // Recursively check nested blocks
            if (stmt is BlockStatement block)
            {
                CheckBlockStatements(block.Statements, diags);
            }
            else if (stmt is IfStatement ifStmt)
            {
                CheckBlockStatements(ifStmt.ThenBranch.Statements, diags);
                if (ifStmt.ElseBranch is BlockStatement elseBlock)
                {
                    CheckBlockStatements(elseBlock.Statements, diags);
                }
            }
            else if (stmt is WhileStatement whileStmt)
            {
                CheckBlockStatements(whileStmt.Body.Statements, diags);
            }
            else if (stmt is ForInStatement forStmt)
            {
                CheckBlockStatements(forStmt.Body.Statements, diags);
            }
            else if (stmt is FunctionDeclStatement fnDecl)
            {
                CheckBlockStatements(fnDecl.Body.Statements, diags);
            }
        }
    }

    private static bool IsIdentifierUsedInStatement(StatementNode stmt, string identifier)
    {
        switch (stmt)
        {
            case VarDeclStatement varDecl:
                return IsIdentifierUsedInExpression(varDecl.Initializer, identifier);
            case AssignmentStatement assign:
                return IsIdentifierUsedInExpression(assign.Target, identifier) || IsIdentifierUsedInExpression(assign.Value, identifier);
            case IfStatement ifStmt:
                return IsIdentifierUsedInExpression(ifStmt.Condition, identifier) ||
                       IsIdentifierUsedInStatement(ifStmt.ThenBranch, identifier) ||
                       (ifStmt.ElseBranch != null && IsIdentifierUsedInStatement(ifStmt.ElseBranch, identifier));
            case WhileStatement whileStmt:
                return IsIdentifierUsedInExpression(whileStmt.Condition, identifier) ||
                       IsIdentifierUsedInStatement(whileStmt.Body, identifier);
            case ForInStatement forStmt:
                return IsIdentifierUsedInExpression(forStmt.Iterable, identifier) ||
                       IsIdentifierUsedInStatement(forStmt.Body, identifier);
            case ReturnStatement ret:
                return ret.Value != null && IsIdentifierUsedInExpression(ret.Value, identifier);
            case BlockStatement block:
                return block.Statements.Any(s => IsIdentifierUsedInStatement(s, identifier));
            case ExpressionStatement exprStmt:
                return IsIdentifierUsedInExpression(exprStmt.Expression, identifier);
            case MatchStatement matchStmt:
                return IsIdentifierUsedInExpression(matchStmt.Expression, identifier) ||
                       matchStmt.Cases.Any(c => (c.Body is StatementNode s && IsIdentifierUsedInStatement(s, identifier)) ||
                                                (c.Body is ExpressionNode e && IsIdentifierUsedInExpression(e, identifier)));
            default:
                return false;
        }
    }

    private static bool IsIdentifierUsedInExpression(ExpressionNode expr, string identifier)
    {
        switch (expr)
        {
            case IdentifierExpression id:
                return id.Name == identifier;
            case BinaryExpression bin:
                return IsIdentifierUsedInExpression(bin.Left, identifier) || IsIdentifierUsedInExpression(bin.Right, identifier);
            case UnaryExpression un:
                return IsIdentifierUsedInExpression(un.Right, identifier);
            case PipeExpression pipe:
                return IsIdentifierUsedInExpression(pipe.Left, identifier) || IsIdentifierUsedInExpression(pipe.Right, identifier);
            case CallExpression call:
                return IsIdentifierUsedInExpression(call.Callee, identifier) || call.Arguments.Any(a => IsIdentifierUsedInExpression(a, identifier));
            case MemberAccessExpression mem:
                return IsIdentifierUsedInExpression(mem.Target, identifier);
            case IndexAccessExpression idx:
                return IsIdentifierUsedInExpression(idx.Target, identifier) || IsIdentifierUsedInExpression(idx.Index, identifier);
            case LambdaExpression lam:
                bool shadows = lam.Parameters.Any(p => p.Name == identifier);
                if (shadows) return false;
                return (lam.ExpressionBody != null && IsIdentifierUsedInExpression(lam.ExpressionBody, identifier)) ||
                       (lam.BlockBody != null && lam.BlockBody.Statements.Any(s => IsIdentifierUsedInStatement(s, identifier)));
            case ListLiteralExpression list:
                return list.Elements.Any(e => IsIdentifierUsedInExpression(e, identifier));
            case MapLiteralExpression map:
                return map.KeyValues.Any(kv => IsIdentifierUsedInExpression(kv.Value, identifier));
            case OptionExpression opt:
                return opt.Value != null && IsIdentifierUsedInExpression(opt.Value, identifier);
            case ResultExpression res:
                return IsIdentifierUsedInExpression(res.Value, identifier);
            case MatchExpression matchExpr:
                return IsIdentifierUsedInExpression(matchExpr.Expression, identifier) ||
                       matchExpr.Cases.Any(c => (c.Body is StatementNode s && IsIdentifierUsedInStatement(s, identifier)) ||
                                                (c.Body is ExpressionNode e && IsIdentifierUsedInExpression(e, identifier)));
            default:
                return false;
        }
    }
}
