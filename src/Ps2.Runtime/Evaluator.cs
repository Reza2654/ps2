using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Ps2.Core;

namespace Ps2.Runtime;

public sealed class Evaluator
{
    private readonly CapabilityManifest _manifest;
    private readonly string _scriptDirectory;
    private readonly IReadOnlyList<string> _scriptArgs;
    private readonly EnvironmentScope _globalScope;

    public EnvironmentScope GlobalScope => _globalScope;

    public Evaluator(
        CapabilityManifest manifest,
        string scriptDirectory,
        IReadOnlyList<string>? scriptArgs = null,
        bool allowAll = false)
    {
        _manifest = manifest;
        _manifest.AllowAll = allowAll || manifest.AllowAll;
        _scriptDirectory = scriptDirectory;
        _scriptArgs = scriptArgs ?? Array.Empty<string>();
        _globalScope = new EnvironmentScope();

        StandardLibrary.Register(
            _globalScope,
            _manifest,
            _scriptDirectory,
            _scriptArgs,
            InvokeFunction
        );
    }

    public Ps2Value Execute(ProgramNode program)
    {
        Ps2Value lastValue = Ps2Value.Null;

        foreach (var stmt in program.Statements)
        {
            try
            {
                lastValue = ExecuteStatement(stmt, _globalScope);
            }
            catch (ReturnException ret)
            {
                return ret.Value;
            }
        }

        return lastValue;
    }

    private Ps2Value ExecuteStatement(StatementNode stmt, EnvironmentScope scope)
    {
        switch (stmt)
        {
            case VarDeclStatement varDecl:
            {
                var val = EvaluateExpression(varDecl.Initializer, scope);
                scope.Define(varDecl.Name, val, varDecl.IsMutable);
                return val;
            }

            case AssignmentStatement assign:
            {
                var val = EvaluateExpression(assign.Value, scope);
                if (assign.Target is IdentifierExpression idExpr)
                {
                    scope.Assign(idExpr.Name, val);
                }
                else if (assign.Target is IndexAccessExpression indexExpr)
                {
                    var targetVal = EvaluateExpression(indexExpr.Target, scope);
                    var idxVal = EvaluateExpression(indexExpr.Index, scope);
                    if (targetVal.Type == Ps2ValueType.List)
                    {
                        var list = targetVal.AsList();
                        int i = (int)idxVal.AsInt();
                        if (i >= 0 && i < list.Count)
                        {
                            list[i] = val;
                        }
                        else
                        {
                            throw new IndexOutOfRangeException($"Index {i} is out of bounds for list of size {list.Count}.");
                        }
                    }
                    else if (targetVal.Type == Ps2ValueType.Map)
                    {
                        var map = targetVal.AsMap();
                        map[idxVal.AsString()] = val;
                    }
                }
                else if (assign.Target is MemberAccessExpression memExpr)
                {
                    var targetVal = EvaluateExpression(memExpr.Target, scope);
                    if (targetVal.Type == Ps2ValueType.Map)
                    {
                        targetVal.AsMap()[memExpr.Member] = val;
                    }
                }
                return val;
            }

            case FunctionDeclStatement fnDecl:
            {
                var fnVal = Ps2Value.CreateFunction(fnDecl, scope);
                scope.Define(fnDecl.Name, fnVal, isMutable: false);
                return fnVal;
            }

            case IfStatement ifStmt:
            {
                var cond = EvaluateExpression(ifStmt.Condition, scope);
                if (cond.IsTruthy)
                {
                    return ExecuteBlock(ifStmt.ThenBranch, scope.CreateChild());
                }
                else if (ifStmt.ElseBranch != null)
                {
                    if (ifStmt.ElseBranch is BlockStatement elseBlock)
                    {
                        return ExecuteBlock(elseBlock, scope.CreateChild());
                    }
                    else
                    {
                        return ExecuteStatement(ifStmt.ElseBranch, scope);
                    }
                }
                return Ps2Value.Null;
            }

            case WhileStatement whileStmt:
            {
                Ps2Value last = Ps2Value.Null;
                while (EvaluateExpression(whileStmt.Condition, scope).IsTruthy)
                {
                    last = ExecuteBlock(whileStmt.Body, scope.CreateChild());
                }
                return last;
            }

            case ForInStatement forStmt:
            {
                var iterVal = EvaluateExpression(forStmt.Iterable, scope);
                Ps2Value last = Ps2Value.Null;

                if (iterVal.Type == Ps2ValueType.List)
                {
                    foreach (var item in iterVal.AsList())
                    {
                        var childScope = scope.CreateChild();
                        childScope.Define(forStmt.Variable, item);
                        last = ExecuteBlock(forStmt.Body, childScope);
                    }
                }
                else if (iterVal.Type == Ps2ValueType.Map)
                {
                    foreach (var kv in iterVal.AsMap())
                    {
                        var childScope = scope.CreateChild();
                        childScope.Define(forStmt.Variable, Ps2Value.From(kv.Key));
                        last = ExecuteBlock(forStmt.Body, childScope);
                    }
                }
                return last;
            }

            case ReturnStatement retStmt:
            {
                var retVal = retStmt.Value != null ? EvaluateExpression(retStmt.Value, scope) : Ps2Value.Null;
                throw new ReturnException(retVal);
            }

            case BlockStatement blockStmt:
            {
                return ExecuteBlock(blockStmt, scope.CreateChild());
            }

            case ExpressionStatement exprStmt:
            {
                return EvaluateExpression(exprStmt.Expression, scope);
            }

            case MatchStatement matchStmt:
                return EvaluateMatch(matchStmt.Expression, matchStmt.Cases, scope);

            default:
                throw new NotImplementedException($"Statement {stmt.GetType().Name} not implemented.");
        }
    }

    private Ps2Value ExecuteBlock(BlockStatement block, EnvironmentScope scope)
    {
        Ps2Value last = Ps2Value.Null;
        foreach (var stmt in block.Statements)
        {
            last = ExecuteStatement(stmt, scope);
        }
        return last;
    }

    public Ps2Value EvaluateExpression(ExpressionNode expr, EnvironmentScope scope)
    {
        switch (expr)
        {
            case LiteralExpression lit:
                return lit.LiteralType switch
                {
                    Ps2LiteralType.Int => Ps2Value.From(Convert.ToInt64(lit.Value)),
                    Ps2LiteralType.Float => Ps2Value.From(Convert.ToDouble(lit.Value)),
                    Ps2LiteralType.String => Ps2Value.From((string)lit.Value!),
                    Ps2LiteralType.Bool => Ps2Value.From((bool)lit.Value!),
                    _ => Ps2Value.Null
                };

            case IdentifierExpression id:
                return scope.Get(id.Name);

            case BinaryExpression bin:
                return EvaluateBinary(bin, scope);

            case UnaryExpression un:
                return EvaluateUnary(un, scope);

            case PipeExpression pipe:
                return EvaluatePipe(pipe, scope);

            case CallExpression call:
                return EvaluateCall(call, scope);

            case MemberAccessExpression mem:
                return EvaluateMemberAccess(mem, scope);

            case IndexAccessExpression idx:
                return EvaluateIndexAccess(idx, scope);

            case LambdaExpression lambda:
                return EvaluateLambda(lambda, scope);

            case ListLiteralExpression listLit:
            {
                var elements = listLit.Elements.Select(e => EvaluateExpression(e, scope)).ToList();
                return Ps2Value.From(elements);
            }

            case MapLiteralExpression mapLit:
            {
                var dict = new Dictionary<string, Ps2Value>();
                foreach (var kv in mapLit.KeyValues)
                {
                    dict[kv.Key] = EvaluateExpression(kv.Value, scope);
                }
                return Ps2Value.From(dict);
            }

            case OptionExpression optExpr:
                return optExpr.HasValue
                    ? Ps2Value.Some(optExpr.Value != null ? EvaluateExpression(optExpr.Value, scope) : Ps2Value.Null)
                    : Ps2Value.None();

            case ResultExpression resExpr:
                return resExpr.IsOk
                    ? Ps2Value.Ok(EvaluateExpression(resExpr.Value, scope))
                    : Ps2Value.Err(EvaluateExpression(resExpr.Value, scope));

            case AwaitExpression awaitExpr:
                return EvaluateExpression(awaitExpr.Expression, scope);

            case MatchExpression matchExpr:
                return EvaluateMatch(matchExpr.Expression, matchExpr.Cases, scope);

            default:
                throw new NotImplementedException($"Expression {expr.GetType().Name} not implemented.");
        }
    }

    private Ps2Value EvaluateMatch(ExpressionNode expression, List<MatchCaseNode> cases, EnvironmentScope scope)
    {
        var targetVal = EvaluateExpression(expression, scope);
        foreach (var caseNode in cases)
        {
            if (TryMatchPattern(caseNode.Pattern, targetVal, out var bindings))
            {
                var caseScope = scope.CreateChild();
                foreach (var kv in bindings)
                {
                    caseScope.Define(kv.Key, kv.Value);
                }

                if (caseNode.Body is BlockStatement bodyBlock)
                {
                    return ExecuteBlock(bodyBlock, caseScope);
                }
                else if (caseNode.Body is ExpressionNode bodyExpr)
                {
                    return EvaluateExpression(bodyExpr, caseScope);
                }
            }
        }
        return Ps2Value.Null;
    }

    private Ps2Value EvaluateBinary(BinaryExpression bin, EnvironmentScope scope)
    {
        if (bin.Op == BinaryOp.And)
        {
            var left = EvaluateExpression(bin.Left, scope);
            if (!left.IsTruthy) return left;
            return EvaluateExpression(bin.Right, scope);
        }

        if (bin.Op == BinaryOp.Or)
        {
            var left = EvaluateExpression(bin.Left, scope);
            if (left.IsTruthy) return left;
            return EvaluateExpression(bin.Right, scope);
        }

        var l = EvaluateExpression(bin.Left, scope);
        var r = EvaluateExpression(bin.Right, scope);

        switch (bin.Op)
        {
            case BinaryOp.Equal:
                return Ps2Value.From(l.Equals(r));

            case BinaryOp.NotEqual:
                return Ps2Value.From(!l.Equals(r));

            case BinaryOp.Add:
                if (l.Type == Ps2ValueType.String || r.Type == Ps2ValueType.String)
                {
                    return Ps2Value.From(l.AsString() + r.AsString());
                }
                if (l.Type == Ps2ValueType.Float || r.Type == Ps2ValueType.Float)
                {
                    return Ps2Value.From(l.AsFloat() + r.AsFloat());
                }
                return Ps2Value.From(l.AsInt() + r.AsInt());

            case BinaryOp.Subtract:
                if (l.Type == Ps2ValueType.Float || r.Type == Ps2ValueType.Float)
                    return Ps2Value.From(l.AsFloat() - r.AsFloat());
                return Ps2Value.From(l.AsInt() - r.AsInt());

            case BinaryOp.Multiply:
                if (l.Type == Ps2ValueType.Float || r.Type == Ps2ValueType.Float)
                    return Ps2Value.From(l.AsFloat() * r.AsFloat());
                return Ps2Value.From(l.AsInt() * r.AsInt());

            case BinaryOp.Divide:
                if (l.Type == Ps2ValueType.Float || r.Type == Ps2ValueType.Float)
                    return Ps2Value.From(l.AsFloat() / r.AsFloat());
                var rightInt = r.AsInt();
                if (rightInt == 0) throw new DivideByZeroException("Division by zero in ps2 script.");
                return Ps2Value.From(l.AsInt() / rightInt);

            case BinaryOp.Modulo:
                return Ps2Value.From(l.AsInt() % r.AsInt());

            case BinaryOp.Less:
                if (l.Type == Ps2ValueType.Float || r.Type == Ps2ValueType.Float)
                    return Ps2Value.From(l.AsFloat() < r.AsFloat());
                return Ps2Value.From(l.AsInt() < r.AsInt());

            case BinaryOp.LessEqual:
                if (l.Type == Ps2ValueType.Float || r.Type == Ps2ValueType.Float)
                    return Ps2Value.From(l.AsFloat() <= r.AsFloat());
                return Ps2Value.From(l.AsInt() <= r.AsInt());

            case BinaryOp.Greater:
                if (l.Type == Ps2ValueType.Float || r.Type == Ps2ValueType.Float)
                    return Ps2Value.From(l.AsFloat() > r.AsFloat());
                return Ps2Value.From(l.AsInt() > r.AsInt());

            case BinaryOp.GreaterEqual:
                if (l.Type == Ps2ValueType.Float || r.Type == Ps2ValueType.Float)
                    return Ps2Value.From(l.AsFloat() >= r.AsFloat());
                return Ps2Value.From(l.AsInt() >= r.AsInt());

            default:
                throw new NotImplementedException($"Binary op {bin.Op} not implemented.");
        }
    }

    private Ps2Value EvaluateUnary(UnaryExpression un, EnvironmentScope scope)
    {
        var r = EvaluateExpression(un.Right, scope);
        return un.Op switch
        {
            UnaryOp.Not => Ps2Value.From(!r.IsTruthy),
            UnaryOp.Negate => r.Type == Ps2ValueType.Float ? Ps2Value.From(-r.AsFloat()) : Ps2Value.From(-r.AsInt()),
            _ => throw new NotImplementedException($"Unary op {un.Op} not implemented.")
        };
    }

    private Ps2Value EvaluatePipe(PipeExpression pipe, EnvironmentScope scope)
    {
        var leftVal = EvaluateExpression(pipe.Left, scope);

        // If right is CallExpression: e.g. `data |> filter(x => ...)`
        if (pipe.Right is CallExpression call)
        {
            var calleeVal = EvaluateExpression(call.Callee, scope);
            var args = new List<Ps2Value> { leftVal };
            foreach (var arg in call.Arguments)
            {
                args.Add(EvaluateExpression(arg, scope));
            }
            return InvokeFunction(calleeVal, args);
        }

        // If right is directly an identifier/callable: e.g. `data |> println`
        var callable = EvaluateExpression(pipe.Right, scope);
        return InvokeFunction(callable, new[] { leftVal });
    }

    private Ps2Value EvaluateCall(CallExpression call, EnvironmentScope scope)
    {
        var callee = EvaluateExpression(call.Callee, scope);
        var args = call.Arguments.Select(a => EvaluateExpression(a, scope)).ToList();
        return InvokeFunction(callee, args);
    }

    private Ps2Value EvaluateMemberAccess(MemberAccessExpression mem, EnvironmentScope scope)
    {
        var target = EvaluateExpression(mem.Target, scope);

        if (target.Type == Ps2ValueType.Map)
        {
            var map = target.AsMap();
            if (map.TryGetValue(mem.Member, out var val))
            {
                return val;
            }
            return Ps2Value.Null;
        }

        if (target.Type == Ps2ValueType.Option)
        {
            var opt = target.AsOption();
            return mem.Member switch
            {
                "is_some" => Ps2Value.From(opt.HasValue),
                "is_none" => Ps2Value.From(!opt.HasValue),
                "value" => opt.Value ?? Ps2Value.Null,
                _ => Ps2Value.Null
            };
        }

        if (target.Type == Ps2ValueType.Result)
        {
            var res = target.AsResult();
            return mem.Member switch
            {
                "is_ok" => Ps2Value.From(res.IsOk),
                "is_err" => Ps2Value.From(!res.IsOk),
                "value" => res.Value,
                _ => Ps2Value.Null
            };
        }

        if (target.Type == Ps2ValueType.String && mem.Member == "length")
        {
            return Ps2Value.From(target.AsString().Length);
        }

        if (target.Type == Ps2ValueType.List && mem.Member == "length")
        {
            return Ps2Value.From(target.AsList().Count);
        }

        throw new InvalidOperationException($"Cannot access member '{mem.Member}' on value of type {target.Type}.");
    }

    private Ps2Value EvaluateIndexAccess(IndexAccessExpression idx, EnvironmentScope scope)
    {
        var target = EvaluateExpression(idx.Target, scope);
        var indexVal = EvaluateExpression(idx.Index, scope);

        if (target.Type == Ps2ValueType.List)
        {
            var list = target.AsList();
            int i = (int)indexVal.AsInt();
            if (i >= 0 && i < list.Count)
            {
                return list[i];
            }
            throw new IndexOutOfRangeException($"Index {i} out of range for list length {list.Count}.");
        }

        if (target.Type == Ps2ValueType.Map)
        {
            var map = target.AsMap();
            var key = indexVal.AsString();
            return map.TryGetValue(key, out var val) ? val : Ps2Value.Null;
        }

        if (target.Type == Ps2ValueType.String)
        {
            var s = target.AsString();
            int i = (int)indexVal.AsInt();
            if (i >= 0 && i < s.Length)
            {
                return Ps2Value.From(s[i].ToString());
            }
            throw new IndexOutOfRangeException($"String index {i} out of bounds.");
        }

        throw new InvalidOperationException($"Cannot index into value of type {target.Type}.");
    }

    private Ps2Value EvaluateLambda(LambdaExpression lambda, EnvironmentScope scope)
    {
        return Ps2Value.CreateNativeFunction("<lambda>", args =>
        {
            var childScope = scope.CreateChild();
            for (int i = 0; i < lambda.Parameters.Count; i++)
            {
                var val = i < args.Count ? args[i] : Ps2Value.Null;
                childScope.Define(lambda.Parameters[i].Name, val);
            }

            if (lambda.ExpressionBody != null)
            {
                return EvaluateExpression(lambda.ExpressionBody, childScope);
            }
            else if (lambda.BlockBody != null)
            {
                try
                {
                    return ExecuteBlock(lambda.BlockBody, childScope);
                }
                catch (ReturnException ret)
                {
                    return ret.Value;
                }
            }

            return Ps2Value.Null;
        });
    }

    public Ps2Value InvokeFunction(Ps2Value functionValue, IReadOnlyList<Ps2Value> arguments)
    {
        if (functionValue.Type == Ps2ValueType.NativeFunction)
        {
            var native = (Ps2NativeFunction)functionValue.RawValue!;
            return native.Callback(arguments);
        }

        if (functionValue.Type == Ps2ValueType.Function)
        {
            var userFn = (Ps2Function)functionValue.RawValue!;
            var decl = userFn.Decl;
            var closureScope = (EnvironmentScope)userFn.ClosureScope;
            var callScope = closureScope.CreateChild();

            for (int i = 0; i < decl.Parameters.Count; i++)
            {
                var argVal = i < arguments.Count ? arguments[i] : Ps2Value.Null;
                callScope.Define(decl.Parameters[i].Name, argVal);
            }

            try
            {
                return ExecuteBlock(decl.Body, callScope);
            }
            catch (ReturnException ret)
            {
                return ret.Value;
            }
        }

        throw new InvalidOperationException($"Attempted to call a non-function value of type {functionValue.Type}.");
    }

    private static bool TryMatchPattern(PatternNode pattern, Ps2Value value, out Dictionary<string, Ps2Value> bindings)
    {
        bindings = new Dictionary<string, Ps2Value>();

        switch (pattern)
        {
            case WildcardPatternNode:
                return true;

            case IdentifierPatternNode idPat:
                bindings[idPat.Name] = value;
                return true;

            case OptionSomePatternNode somePat:
                if (value.Type == Ps2ValueType.Option && value.AsOption().HasValue)
                {
                    bindings[somePat.VariableName] = value.AsOption().Value ?? Ps2Value.Null;
                    return true;
                }
                return false;

            case OptionNonePatternNode:
                return value.Type == Ps2ValueType.Option && !value.AsOption().HasValue;

            case ResultOkPatternNode okPat:
                if (value.Type == Ps2ValueType.Result && value.AsResult().IsOk)
                {
                    bindings[okPat.VariableName] = value.AsResult().Value;
                    return true;
                }
                return false;

            case ResultErrPatternNode errPat:
                if (value.Type == Ps2ValueType.Result && !value.AsResult().IsOk)
                {
                    bindings[errPat.VariableName] = value.AsResult().Value;
                    return true;
                }
                return false;

            case LiteralPatternNode litPat:
                if (litPat.Value == null) return value.IsNull;
                return value.Equals(Ps2Value.From((dynamic)litPat.Value));

            default:
                return false;
        }
    }
}
