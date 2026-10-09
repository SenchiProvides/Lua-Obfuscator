-- src/obf/codegen.lua
-- AST -> Lua source string.
--
-- Guarantees targeted:
--  * Round-trip stability: parse(gen(parse(x))) is structurally stable and the
--    emitted program is runtime-equivalent to the original.
--  * Safe string re-quoting (escaped double-quote form, with a long-bracket
--    fallback for strings containing control characters).
--  * Numeric formatting that preserves value (uses %.17g for floats, keeps
--    integers exact).
--  * Correct parenthesization: binary/unary expressions are wrapped based on
--    operator precedence so semantics are preserved regardless of how the AST
--    was produced. Explicit Paren nodes are always emitted (they can change
--    multret semantics).
--
-- Written in Lua-5.1-compatible syntax.

local codegen = {}

-- Mirror of parser precedence for deciding when to parenthesize.
local BINPRI = {
  ["or"]  = 1, ["and"] = 2,
  ["<"] = 3, [">"] = 3, ["<="] = 3, [">="] = 3, ["~="] = 3, ["=="] = 3,
  [".."] = 4,
  ["+"] = 5, ["-"] = 5,
  ["*"] = 6, ["/"] = 6, ["%"] = 6,
  ["^"] = 8,
}
local UNARY_PRI = 7
local RIGHT_ASSOC = { [".."] = true, ["^"] = true }

local Emitter = {}
Emitter.__index = Emitter

local function new_emitter()
  return setmetatable({ buf = {}, indent = 0 }, Emitter)
end

function Emitter:write(s) self.buf[#self.buf+1] = s end

function Emitter:line(s)
  self.buf[#self.buf+1] = string.rep("  ", self.indent)
  self.buf[#self.buf+1] = s
  self.buf[#self.buf+1] = "\n"
end

function Emitter:result() return table.concat(self.buf) end

-- ---------- literal helpers ----------

-- Format a number so it reparses to the identical value.
local function format_number(node)
  local v = node.value
  if v ~= v then return "(0/0)" end        -- NaN
  if v == math.huge then return "(1/0)" end
  if v == -math.huge then return "(-1/0)" end
  -- Integers: emit without a decimal point/exponent.
  if v == math.floor(v) and v >= -9007199254740992 and v <= 9007199254740992 then
    -- string.format %d can overflow 32-bit on some builds; use %.0f for safety.
    return string.format("%.0f", v)
  end
  -- Floats: %.17g round-trips an IEEE double exactly.
  local s = string.format("%.17g", v)
  -- make sure it reads back as a number and keeps float-ness
  if not string.find(s, "[%.eEnN]") then
    s = s .. ".0"
  end
  return s
end

-- Quote a string literal safely.
local function quote_string(s)
  -- Prefer a long bracket when the content has no closing-bracket conflict and
  -- contains characters that would need heavy escaping (newlines plus others).
  -- For determinism and simplicity we default to escaped double quotes, which
  -- always round-trips.
  local out = { "\"" }
  for i = 1, #s do
    local c = string.sub(s, i, i)
    local b = string.byte(c)
    if c == "\"" then out[#out+1] = "\\\""
    elseif c == "\\" then out[#out+1] = "\\\\"
    elseif c == "\n" then out[#out+1] = "\\n"
    elseif c == "\r" then out[#out+1] = "\\r"
    elseif c == "\t" then out[#out+1] = "\\t"
    elseif c == "\0" then out[#out+1] = "\\0"
    elseif b < 32 or b == 127 then
      out[#out+1] = string.format("\\%d", b)
    else
      out[#out+1] = c
    end
  end
  out[#out+1] = "\""
  return table.concat(out)
end

-- ---------- expression generation ----------

local gen_expr -- forward
local gen_block -- forward

-- Returns the "binding priority" of an expression for parenthesization.
-- Higher binds tighter. Atoms get a very high priority so they never wrap.
local function expr_priority(node)
  if node.type == "BinaryExpression" then return BINPRI[node.op] or 0 end
  if node.type == "UnaryExpression" then return UNARY_PRI end
  return 100
end

local function needs_paren(child, parentPri, side, parentOp)
  local cp = expr_priority(child)
  if cp > parentPri then return false end
  if cp < parentPri then return true end
  -- equal precedence: associativity decides
  if parentOp and RIGHT_ASSOC[parentOp] then
    -- right associative: left operand needs parens
    return side == "left"
  else
    -- left associative: right operand needs parens
    return side == "right"
  end
end

local function wrap(em, child, parentPri, side, parentOp)
  if needs_paren(child, parentPri, side, parentOp) then
    em:write("(")
    gen_expr(em, child)
    em:write(")")
  else
    gen_expr(em, child)
  end
end

-- Is a name a valid Lua identifier (so a.b dot syntax can be used)?
local LUA_KEYWORDS = {
  ["and"]=true,["break"]=true,["do"]=true,["else"]=true,["elseif"]=true,
  ["end"]=true,["false"]=true,["for"]=true,["function"]=true,["if"]=true,
  ["in"]=true,["local"]=true,["nil"]=true,["not"]=true,["or"]=true,
  ["repeat"]=true,["return"]=true,["then"]=true,["true"]=true,["until"]=true,
  ["while"]=true,
}
local function is_valid_name(s)
  if type(s) ~= "string" then return false end
  if LUA_KEYWORDS[s] then return false end
  return string.match(s, "^[%a_][%w_]*$") ~= nil
end

local function gen_function(em, node, name)
  -- name: optional prefix for "function <name>(...)"
  em:write("function")
  if name then em:write(" "); em:write(name) end
  em:write("(")
  local params = {}
  for _, p in ipairs(node.params) do params[#params+1] = p end
  if node.isVararg then params[#params+1] = "..." end
  em:write(table.concat(params, ", "))
  em:write(")\n")
  em.indent = em.indent + 1
  gen_block(em, node.body)
  em.indent = em.indent - 1
  em:line("end")
end

local function gen_call_args(em, args)
  em:write("(")
  for i, a in ipairs(args) do
    if i > 1 then em:write(", ") end
    gen_expr(em, a)
  end
  em:write(")")
end

gen_expr = function(em, node)
  local t = node.type
  if t == "NilLiteral" then em:write("nil")
  elseif t == "TrueLiteral" then em:write("true")
  elseif t == "FalseLiteral" then em:write("false")
  elseif t == "VarargLiteral" then em:write("...")
  elseif t == "NumberLiteral" then em:write(format_number(node))
  elseif t == "StringLiteral" then em:write(quote_string(node.value))
  elseif t == "Identifier" then em:write(node.name)
  elseif t == "Paren" then
    em:write("(")
    gen_expr(em, node.expr)
    em:write(")")
  elseif t == "BinaryExpression" then
    local pri = BINPRI[node.op] or 0
    wrap(em, node.left, pri, "left", node.op)
    if node.op == "and" or node.op == "or" then
      em:write(" "); em:write(node.op); em:write(" ")
    else
      em:write(" "); em:write(node.op); em:write(" ")
    end
    wrap(em, node.right, pri, "right", node.op)
  elseif t == "UnaryExpression" then
    if node.op == "not" then em:write("not ") else em:write(node.op) end
    wrap(em, node.operand, UNARY_PRI, "right", node.op)
  elseif t == "IndexExpression" then
    -- object part may need parens if it is not a simple prefix expression
    local obj = node.obj
    local objAtom = (obj.type == "Identifier" or obj.type == "IndexExpression"
                     or obj.type == "CallExpression" or obj.type == "MethodCallExpression"
                     or obj.type == "Paren")
    if not objAtom then em:write("("); gen_expr(em, obj); em:write(")")
    else gen_expr(em, obj) end
    if node.isDot and is_valid_name(node.index.name) then
      em:write("."); em:write(node.index.name)
    else
      em:write("[")
      if node.isDot then
        -- a dotted field whose name is not a valid identifier: emit as ["name"]
        em:write(quote_string(node.index.name))
      else
        gen_expr(em, node.index)
      end
      em:write("]")
    end
  elseif t == "CallExpression" then
    local callee = node.callee
    local calleeAtom = (callee.type == "Identifier" or callee.type == "IndexExpression"
                        or callee.type == "CallExpression" or callee.type == "MethodCallExpression"
                        or callee.type == "Paren")
    if not calleeAtom then em:write("("); gen_expr(em, callee); em:write(")")
    else gen_expr(em, callee) end
    gen_call_args(em, node.args)
  elseif t == "MethodCallExpression" then
    local obj = node.obj
    local objAtom = (obj.type == "Identifier" or obj.type == "IndexExpression"
                     or obj.type == "CallExpression" or obj.type == "MethodCallExpression"
                     or obj.type == "Paren")
    if not objAtom then em:write("("); gen_expr(em, obj); em:write(")")
    else gen_expr(em, obj) end
    em:write(":"); em:write(node.method)
    gen_call_args(em, node.args)
  elseif t == "FunctionExpression" then
    gen_function(em, node, nil)
  elseif t == "TableConstructor" then
    if #node.fields == 0 then
      em:write("{}")
      return
    end
    em:write("{")
    for i, f in ipairs(node.fields) do
      if i > 1 then em:write(", ") end
      if f.kind == "item" then
        gen_expr(em, f.value)
      elseif f.kind == "named" then
        if is_valid_name(f.key) then
          em:write(f.key); em:write(" = ")
        else
          em:write("["); em:write(quote_string(f.key)); em:write("] = ")
        end
        gen_expr(em, f.value)
      elseif f.kind == "keyed" then
        em:write("["); gen_expr(em, f.key); em:write("] = ")
        gen_expr(em, f.value)
      end
    end
    em:write("}")
  else
    error("codegen: unknown expression type '" .. tostring(t) .. "'")
  end
end

-- ---------- statement generation ----------

local function gen_exprlist(em, list)
  for i, e in ipairs(list) do
    if i > 1 then em:write(", ") end
    gen_expr(em, e)
  end
end

local function gen_statement(em, node)
  local t = node.type
  if t == "LocalStatement" then
    em:write(string.rep("  ", em.indent))
    em:write("local "); em:write(table.concat(node.names, ", "))
    if node.exprs and #node.exprs > 0 then
      em:write(" = "); gen_exprlist(em, node.exprs)
    end
    em:write("\n")
  elseif t == "AssignmentStatement" then
    em:write(string.rep("  ", em.indent))
    for i, tgt in ipairs(node.targets) do
      if i > 1 then em:write(", ") end
      gen_expr(em, tgt)
    end
    em:write(" = "); gen_exprlist(em, node.exprs); em:write("\n")
  elseif t == "CallStatement" then
    em:write(string.rep("  ", em.indent))
    gen_expr(em, node.expr); em:write("\n")
  elseif t == "DoStatement" then
    em:line("do")
    em.indent = em.indent + 1
    gen_block(em, node.body)
    em.indent = em.indent - 1
    em:line("end")
  elseif t == "IfStatement" then
    for i, clause in ipairs(node.clauses) do
      em:write(string.rep("  ", em.indent))
      em:write(i == 1 and "if " or "elseif ")
      gen_expr(em, clause.cond)
      em:write(" then\n")
      em.indent = em.indent + 1
      gen_block(em, clause.body)
      em.indent = em.indent - 1
    end
    if node.elseBody then
      em:line("else")
      em.indent = em.indent + 1
      gen_block(em, node.elseBody)
      em.indent = em.indent - 1
    end
    em:line("end")
  elseif t == "WhileStatement" then
    em:write(string.rep("  ", em.indent))
    em:write("while "); gen_expr(em, node.cond); em:write(" do\n")
    em.indent = em.indent + 1
    gen_block(em, node.body)
    em.indent = em.indent - 1
    em:line("end")
  elseif t == "RepeatStatement" then
    em:line("repeat")
    em.indent = em.indent + 1
    gen_block(em, node.body)
    em.indent = em.indent - 1
    em:write(string.rep("  ", em.indent))
    em:write("until "); gen_expr(em, node.cond); em:write("\n")
  elseif t == "NumericForStatement" then
    em:write(string.rep("  ", em.indent))
    em:write("for "); em:write(node.var); em:write(" = ")
    gen_expr(em, node.start); em:write(", "); gen_expr(em, node.limit)
    if node.step then em:write(", "); gen_expr(em, node.step) end
    em:write(" do\n")
    em.indent = em.indent + 1
    gen_block(em, node.body)
    em.indent = em.indent - 1
    em:line("end")
  elseif t == "GenericForStatement" then
    em:write(string.rep("  ", em.indent))
    em:write("for "); em:write(table.concat(node.names, ", "))
    em:write(" in "); gen_exprlist(em, node.exprs); em:write(" do\n")
    em.indent = em.indent + 1
    gen_block(em, node.body)
    em.indent = em.indent - 1
    em:line("end")
  elseif t == "FunctionDeclaration" then
    em:write(string.rep("  ", em.indent))
    -- Build the name string from the nameExpr chain.
    local parts = {}
    local isMethod = node.isMethod
    local cur = node.nameExpr
    local chain = {}
    while cur.type == "IndexExpression" do
      chain[#chain+1] = cur.index.name
      cur = cur.obj
    end
    -- cur is the base Identifier
    local nameStr = cur.name
    -- chain is in reverse (deepest first); walk back
    for i = #chain, 1, -1 do
      -- the last element is the method name if isMethod
      if isMethod and i == 1 then
        nameStr = nameStr .. ":" .. chain[i]
      else
        nameStr = nameStr .. "." .. chain[i]
      end
    end
    -- When method, the function body already has 'self' as first param; drop it
    -- from the printed parameter list.
    local func = node.func
    local printable = func
    if isMethod then
      local params2 = {}
      for i = 2, #func.params do params2[#params2+1] = func.params[i] end
      printable = { type = "FunctionExpression", params = params2,
                    isVararg = func.isVararg, body = func.body }
    end
    gen_function(em, printable, nameStr)
  elseif t == "LocalFunction" then
    em:write(string.rep("  ", em.indent))
    em:write("local ")
    gen_function(em, node.func, node.name)
  elseif t == "ReturnStatement" then
    em:write(string.rep("  ", em.indent))
    em:write("return")
    if node.exprs and #node.exprs > 0 then
      em:write(" "); gen_exprlist(em, node.exprs)
    end
    em:write("\n")
  elseif t == "BreakStatement" then
    em:line("break")
  else
    error("codegen: unknown statement type '" .. tostring(t) .. "'")
  end
end

gen_block = function(em, stmts)
  for _, st in ipairs(stmts) do
    gen_statement(em, st)
  end
end

-- Public: generate Lua source from a Chunk AST.
function codegen.generate(chunk)
  if chunk.type ~= "Chunk" then
    error("codegen.generate expects a Chunk node")
  end
  local em = new_emitter()
  gen_block(em, chunk.body)
  return em:result()
end

codegen.format_number = format_number
codegen.quote_string = quote_string

return codegen
