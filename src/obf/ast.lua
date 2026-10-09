-- src/obf/ast.lua
-- AST node constructors and type tags for the covered Lua subset.
--
-- COVERED SUBSET (Lua 5.1 core, also valid under 5.4 / LuaJIT):
--   Chunk / Block
--   Statements:
--     LocalStatement        local a, b = e1, e2
--     AssignmentStatement   a, b = e1, e2   (targets: Name / Index)
--     CallStatement         f(x)  or  o:m(x)   (a Call/MethodCall used as statement)
--     IfStatement           if/elseif/else ... end
--     WhileStatement        while cond do ... end
--     RepeatStatement       repeat ... until cond
--     NumericForStatement   for i = a, b [, c] do ... end
--     GenericForStatement   for a, b in explist do ... end
--     FunctionDeclaration   function a.b.c[:m](args) ... end
--     LocalFunction         local function f(args) ... end
--     ReturnStatement       return explist
--     BreakStatement        break
--     DoStatement           do ... end
--   Expressions:
--     NilLiteral, TrueLiteral, FalseLiteral
--     NumberLiteral, StringLiteral
--     VarargLiteral        ...
--     FunctionExpression   function(args) ... end
--     TableConstructor     { ... }  with array items / keyed items / [expr]=expr
--     BinaryExpression     a + b, a .. b, a and b, etc.
--     UnaryExpression      -a, not a, #a
--     IndexExpression      a.b  /  a[b]
--     CallExpression       f(args)
--     MethodCallExpression o:m(args)
--     Identifier           a name reference
--
-- NOT covered (intentionally, to keep the self-hosting frontend small and the
-- round trip provable): goto/label, integer-division //, bitwise ops in the
-- parser (lexer tolerates them), 5.4 attributes <const>/<close>. Example inputs
-- stay within the covered subset.

local ast = {}

-- Generic constructor: attaches a `type` tag and copies fields.
local function node(t, fields)
  local n = fields or {}
  n.type = t
  return n
end

ast.node = node

-- ---- Blocks ----
function ast.Chunk(body) return node("Chunk", { body = body }) end
function ast.Block(stmts) return node("Block", { stmts = stmts }) end

-- ---- Statements ----
function ast.LocalStatement(names, exprs)
  return node("LocalStatement", { names = names, exprs = exprs })
end
function ast.AssignmentStatement(targets, exprs)
  return node("AssignmentStatement", { targets = targets, exprs = exprs })
end
function ast.CallStatement(expr)
  return node("CallStatement", { expr = expr })
end
function ast.IfStatement(clauses, elseBody)
  -- clauses: list of { cond = expr, body = {stmts} }; elseBody: {stmts} or nil
  return node("IfStatement", { clauses = clauses, elseBody = elseBody })
end
function ast.WhileStatement(cond, body)
  return node("WhileStatement", { cond = cond, body = body })
end
function ast.RepeatStatement(body, cond)
  return node("RepeatStatement", { body = body, cond = cond })
end
function ast.NumericForStatement(var, start, limit, step, body)
  return node("NumericForStatement", { var = var, start = start, limit = limit, step = step, body = body })
end
function ast.GenericForStatement(names, exprs, body)
  return node("GenericForStatement", { names = names, exprs = exprs, body = body })
end
function ast.FunctionDeclaration(nameExpr, isMethod, func)
  -- nameExpr: Identifier or chained IndexExpression; func: FunctionExpression
  return node("FunctionDeclaration", { nameExpr = nameExpr, isMethod = isMethod, func = func })
end
function ast.LocalFunction(name, func)
  return node("LocalFunction", { name = name, func = func })
end
function ast.ReturnStatement(exprs)
  return node("ReturnStatement", { exprs = exprs })
end
function ast.BreakStatement()
  return node("BreakStatement", {})
end
function ast.DoStatement(body)
  return node("DoStatement", { body = body })
end

-- ---- Expressions ----
function ast.NilLiteral() return node("NilLiteral", {}) end
function ast.TrueLiteral() return node("TrueLiteral", {}) end
function ast.FalseLiteral() return node("FalseLiteral", {}) end
function ast.NumberLiteral(value, text)
  return node("NumberLiteral", { value = value, text = text })
end
function ast.StringLiteral(value, long)
  return node("StringLiteral", { value = value, long = long })
end
function ast.VarargLiteral() return node("VarargLiteral", {}) end
function ast.FunctionExpression(params, isVararg, body)
  return node("FunctionExpression", { params = params, isVararg = isVararg, body = body })
end
function ast.TableConstructor(fields)
  -- fields: list of { kind = "item"|"named"|"keyed", key = ?, value = expr }
  return node("TableConstructor", { fields = fields })
end
function ast.BinaryExpression(op, left, right)
  return node("BinaryExpression", { op = op, left = left, right = right })
end
function ast.UnaryExpression(op, operand)
  return node("UnaryExpression", { op = op, operand = operand })
end
function ast.IndexExpression(obj, index, isDot)
  -- isDot true => a.b (index is an Identifier used as name); false => a[expr]
  return node("IndexExpression", { obj = obj, index = index, isDot = isDot })
end
function ast.CallExpression(callee, args)
  return node("CallExpression", { callee = callee, args = args })
end
function ast.MethodCallExpression(obj, method, args)
  return node("MethodCallExpression", { obj = obj, method = method, args = args })
end
function ast.Identifier(name)
  return node("Identifier", { name = name })
end

-- Parenthesized expression wrapper (semantically truncates multret to one value).
function ast.Paren(expr)
  return node("Paren", { expr = expr })
end

return ast
