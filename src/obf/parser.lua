-- src/obf/parser.lua
-- Recursive-descent parser for the covered Lua subset (see ast.lua).
-- Honors Lua operator precedence and associativity, including the
-- right-associative '..' and '^'. Written in Lua-5.1-compatible syntax.

local Lexer = require("obf.lexer")
local ast = require("obf.ast")

local Parser = {}
Parser.__index = Parser

-- Binary operator precedence table: { left, right }.
-- Right precedence < left precedence encodes right-associativity ('..' and '^').
local BINPRI = {
  ["or"]  = { 1, 1 },
  ["and"] = { 2, 2 },
  ["<"]   = { 3, 3 }, [">"] = { 3, 3 }, ["<="] = { 3, 3 },
  [">="]  = { 3, 3 }, ["~="] = { 3, 3 }, ["=="] = { 3, 3 },
  [".."]  = { 5, 4 }, -- right associative
  ["+"]   = { 6, 6 }, ["-"] = { 6, 6 },
  ["*"]   = { 7, 7 }, ["/"] = { 7, 7 }, ["%"] = { 7, 7 },
  -- unary ops sit at priority 8
  ["^"]   = { 10, 9 }, -- right associative, binds tighter than unary
}
local UNARY_PRI = 8

function Parser.new(tokens, chunkname)
  local self = setmetatable({}, Parser)
  self.tokens = tokens
  self.pos = 1
  self.chunkname = chunkname or "?"
  return self
end

function Parser:peek(offset)
  return self.tokens[self.pos + (offset or 0)]
end

function Parser:cur()
  return self.tokens[self.pos]
end

function Parser:advance()
  local t = self.tokens[self.pos]
  self.pos = self.pos + 1
  return t
end

function Parser:error(msg, tok)
  tok = tok or self:cur()
  local line = tok and tok.line or 0
  error(string.format("%s:%d: parse error: %s", self.chunkname, line, msg), 0)
end

-- Does the current token match (type, value)? value optional.
function Parser:check(ttype, value)
  local t = self:cur()
  if t.type ~= ttype then return false end
  if value ~= nil and t.value ~= value then return false end
  return true
end

function Parser:accept(ttype, value)
  if self:check(ttype, value) then
    return self:advance()
  end
  return nil
end

function Parser:expect(ttype, value)
  if not self:check(ttype, value) then
    local want = value or ttype
    local got = self:cur()
    self:error("'" .. tostring(want) .. "' expected near '" .. tostring(got.value) .. "'")
  end
  return self:advance()
end

local function is_kw(t, kw) return t.type == "keyword" and t.value == kw end
local function is_op(t, op) return t.type == "op" and t.value == op end

-- Keywords that end a block.
local BLOCK_END = {
  ["end"] = true, ["else"] = true, ["elseif"] = true, ["until"] = true,
}

function Parser:is_block_end()
  local t = self:cur()
  if t.type == "eof" then return true end
  if t.type == "keyword" and BLOCK_END[t.value] then return true end
  return false
end

-- ---------- block / statement parsing ----------

function Parser:parse_chunk()
  local body = self:parse_block()
  if self:cur().type ~= "eof" then
    self:error("'<eof>' expected near '" .. tostring(self:cur().value) .. "'")
  end
  return ast.Chunk(body)
end

function Parser:parse_block()
  local stmts = {}
  while not self:is_block_end() do
    if is_kw(self:cur(), "return") then
      stmts[#stmts+1] = self:parse_return()
      -- return must be the last statement of a block
      self:accept("op", ";")
      break
    elseif is_kw(self:cur(), "break") then
      self:advance()
      stmts[#stmts+1] = ast.BreakStatement()
      self:accept("op", ";")
      break
    else
      local st = self:parse_statement()
      if st then stmts[#stmts+1] = st end
      self:accept("op", ";")
    end
  end
  return stmts
end

function Parser:parse_return()
  self:expect("keyword", "return")
  local exprs = {}
  if not self:is_block_end() and not is_op(self:cur(), ";") then
    exprs = self:parse_exprlist()
  end
  return ast.ReturnStatement(exprs)
end

function Parser:parse_statement()
  local t = self:cur()
  if t.type == "keyword" then
    if t.value == "local" then return self:parse_local()
    elseif t.value == "if" then return self:parse_if()
    elseif t.value == "while" then return self:parse_while()
    elseif t.value == "repeat" then return self:parse_repeat()
    elseif t.value == "for" then return self:parse_for()
    elseif t.value == "function" then return self:parse_function_decl()
    elseif t.value == "do" then return self:parse_do()
    else
      self:error("unexpected keyword '" .. t.value .. "'")
    end
  end
  -- Expression statement: either a call, or an assignment.
  return self:parse_expr_statement()
end

function Parser:parse_do()
  self:expect("keyword", "do")
  local body = self:parse_block()
  self:expect("keyword", "end")
  return ast.DoStatement(body)
end

function Parser:parse_local()
  self:expect("keyword", "local")
  if is_kw(self:cur(), "function") then
    self:advance()
    local name = self:expect("name").value
    local func = self:parse_funcbody(false)
    return ast.LocalFunction(name, func)
  end
  local names = { self:expect("name").value }
  while self:accept("op", ",") do
    names[#names+1] = self:expect("name").value
  end
  local exprs = {}
  if self:accept("op", "=") then
    exprs = self:parse_exprlist()
  end
  return ast.LocalStatement(names, exprs)
end

function Parser:parse_if()
  self:expect("keyword", "if")
  local clauses = {}
  local cond = self:parse_expr()
  self:expect("keyword", "then")
  local body = self:parse_block()
  clauses[#clauses+1] = { cond = cond, body = body }
  while is_kw(self:cur(), "elseif") do
    self:advance()
    local c = self:parse_expr()
    self:expect("keyword", "then")
    local b = self:parse_block()
    clauses[#clauses+1] = { cond = c, body = b }
  end
  local elseBody = nil
  if self:accept("keyword", "else") then
    elseBody = self:parse_block()
  end
  self:expect("keyword", "end")
  return ast.IfStatement(clauses, elseBody)
end

function Parser:parse_while()
  self:expect("keyword", "while")
  local cond = self:parse_expr()
  self:expect("keyword", "do")
  local body = self:parse_block()
  self:expect("keyword", "end")
  return ast.WhileStatement(cond, body)
end

function Parser:parse_repeat()
  self:expect("keyword", "repeat")
  local body = self:parse_block()
  self:expect("keyword", "until")
  local cond = self:parse_expr()
  return ast.RepeatStatement(body, cond)
end

function Parser:parse_for()
  self:expect("keyword", "for")
  local first = self:expect("name").value
  if is_op(self:cur(), "=") then
    self:advance()
    local start = self:parse_expr()
    self:expect("op", ",")
    local limit = self:parse_expr()
    local step = nil
    if self:accept("op", ",") then
      step = self:parse_expr()
    end
    self:expect("keyword", "do")
    local body = self:parse_block()
    self:expect("keyword", "end")
    return ast.NumericForStatement(first, start, limit, step, body)
  end
  -- generic for
  local names = { first }
  while self:accept("op", ",") do
    names[#names+1] = self:expect("name").value
  end
  self:expect("keyword", "in")
  local exprs = self:parse_exprlist()
  self:expect("keyword", "do")
  local body = self:parse_block()
  self:expect("keyword", "end")
  return ast.GenericForStatement(names, exprs, body)
end

function Parser:parse_function_decl()
  self:expect("keyword", "function")
  -- funcname ::= Name {'.' Name} [':' Name]
  local nameExpr = ast.Identifier(self:expect("name").value)
  while self:accept("op", ".") do
    local field = self:expect("name").value
    nameExpr = ast.IndexExpression(nameExpr, ast.Identifier(field), true)
  end
  local isMethod = false
  if self:accept("op", ":") then
    local field = self:expect("name").value
    nameExpr = ast.IndexExpression(nameExpr, ast.Identifier(field), true)
    isMethod = true
  end
  local func = self:parse_funcbody(isMethod)
  return ast.FunctionDeclaration(nameExpr, isMethod, func)
end

-- Parse the parameter list and body of a function. If isMethod, inject 'self'.
function Parser:parse_funcbody(isMethod)
  self:expect("op", "(")
  local params = {}
  local isVararg = false
  if isMethod then params[#params+1] = "self" end
  if not is_op(self:cur(), ")") then
    repeat
      if is_op(self:cur(), "...") then
        self:advance()
        isVararg = true
        break
      else
        params[#params+1] = self:expect("name").value
      end
    until not self:accept("op", ",")
  end
  self:expect("op", ")")
  local body = self:parse_block()
  self:expect("keyword", "end")
  return ast.FunctionExpression(params, isVararg, body)
end

-- Expression statement: parse a prefixexp; if followed by '=' or ',' it's an
-- assignment, otherwise it must be a function/method call used as a statement.
function Parser:parse_expr_statement()
  local first = self:parse_prefixexp()
  if is_op(self:cur(), "=") or is_op(self:cur(), ",") then
    local targets = { first }
    while self:accept("op", ",") do
      targets[#targets+1] = self:parse_prefixexp()
    end
    for _, tgt in ipairs(targets) do
      if tgt.type ~= "Identifier" and tgt.type ~= "IndexExpression" then
        self:error("cannot assign to this expression")
      end
    end
    self:expect("op", "=")
    local exprs = self:parse_exprlist()
    return ast.AssignmentStatement(targets, exprs)
  end
  if first.type ~= "CallExpression" and first.type ~= "MethodCallExpression" then
    self:error("syntax error: expected statement (call or assignment)")
  end
  return ast.CallStatement(first)
end

-- ---------- expression parsing ----------

function Parser:parse_exprlist()
  local list = { self:parse_expr() }
  while self:accept("op", ",") do
    list[#list+1] = self:parse_expr()
  end
  return list
end

function Parser:parse_expr()
  return self:parse_binexpr(0)
end

-- Precedence-climbing expression parser.
function Parser:parse_binexpr(limit)
  local left
  local t = self:cur()
  -- unary operators: not, -, #
  if is_kw(t, "not") or is_op(t, "-") or is_op(t, "#") then
    local op = t.value
    self:advance()
    local operand = self:parse_binexpr(UNARY_PRI)
    left = ast.UnaryExpression(op, operand)
  else
    left = self:parse_simpleexp()
  end

  while true do
    local c = self:cur()
    local op = nil
    if c.type == "op" and BINPRI[c.value] then op = c.value
    elseif c.type == "keyword" and (c.value == "and" or c.value == "or") then op = c.value end
    if op == nil then break end
    local pri = BINPRI[op]
    if pri[1] <= limit then break end
    self:advance()
    local right = self:parse_binexpr(pri[2])
    left = ast.BinaryExpression(op, left, right)
  end
  return left
end

function Parser:parse_simpleexp()
  local t = self:cur()
  if t.type == "number" then
    self:advance()
    return ast.NumberLiteral(t.value, t.text)
  elseif t.type == "string" then
    self:advance()
    return ast.StringLiteral(t.value, t.long)
  elseif t.type == "keyword" then
    if t.value == "nil" then self:advance(); return ast.NilLiteral()
    elseif t.value == "true" then self:advance(); return ast.TrueLiteral()
    elseif t.value == "false" then self:advance(); return ast.FalseLiteral()
    elseif t.value == "function" then
      self:advance()
      return self:parse_funcbody(false)
    end
  elseif t.type == "op" then
    if t.value == "..." then self:advance(); return ast.VarargLiteral()
    elseif t.value == "{" then return self:parse_table()
    end
  end
  -- otherwise a prefix expression (name, index, call, parenthesized)
  return self:parse_prefixexp()
end

function Parser:parse_table()
  self:expect("op", "{")
  local fields = {}
  while not is_op(self:cur(), "}") do
    local c = self:cur()
    if is_op(c, "[") then
      self:advance()
      local key = self:parse_expr()
      self:expect("op", "]")
      self:expect("op", "=")
      local value = self:parse_expr()
      fields[#fields+1] = { kind = "keyed", key = key, value = value }
    elseif c.type == "name" and is_op(self:peek(1), "=") then
      local name = self:advance().value
      self:advance() -- '='
      local value = self:parse_expr()
      fields[#fields+1] = { kind = "named", key = name, value = value }
    else
      local value = self:parse_expr()
      fields[#fields+1] = { kind = "item", value = value }
    end
    if not (self:accept("op", ",") or self:accept("op", ";")) then
      break
    end
  end
  self:expect("op", "}")
  return ast.TableConstructor(fields)
end

-- prefixexp ::= var | functioncall | '(' expr ')'  with suffix chains.
function Parser:parse_prefixexp()
  local base
  local t = self:cur()
  if is_op(t, "(") then
    self:advance()
    local inner = self:parse_expr()
    self:expect("op", ")")
    base = ast.Paren(inner)
  elseif t.type == "name" then
    self:advance()
    base = ast.Identifier(t.value)
  else
    self:error("unexpected symbol near '" .. tostring(t.value) .. "'")
  end
  return self:parse_suffixes(base)
end

function Parser:parse_suffixes(base)
  while true do
    local t = self:cur()
    if is_op(t, ".") then
      self:advance()
      local name = self:expect("name").value
      base = ast.IndexExpression(base, ast.Identifier(name), true)
    elseif is_op(t, "[") then
      self:advance()
      local index = self:parse_expr()
      self:expect("op", "]")
      base = ast.IndexExpression(base, index, false)
    elseif is_op(t, ":") then
      self:advance()
      local method = self:expect("name").value
      local args = self:parse_callargs()
      base = ast.MethodCallExpression(base, method, args)
    elseif is_op(t, "(") or is_op(t, "{") or t.type == "string" then
      local args = self:parse_callargs()
      base = ast.CallExpression(base, args)
    else
      break
    end
  end
  return base
end

-- Call arguments: '(' [explist] ')' | tableconstructor | string
function Parser:parse_callargs()
  local t = self:cur()
  if t.type == "string" then
    self:advance()
    return { ast.StringLiteral(t.value, t.long) }
  elseif is_op(t, "{") then
    return { self:parse_table() }
  elseif is_op(t, "(") then
    self:advance()
    local args = {}
    if not is_op(self:cur(), ")") then
      args = self:parse_exprlist()
    end
    self:expect("op", ")")
    return args
  else
    self:error("function arguments expected")
  end
end

-- ---------- public API ----------

-- Parse source text into a Chunk AST.
local function parse(src, chunkname)
  local tokens = Lexer.scan(src, chunkname)
  local p = Parser.new(tokens, chunkname)
  return p:parse_chunk()
end

return {
  Parser = Parser,
  parse = parse,
}
