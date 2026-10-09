-- src/obf/passes/string_encrypt.lua
-- Technique 3: String Encryption with Dynamic Keys.
--
-- An AST pass that replaces every string LITERAL VALUE with a call to an
-- embedded runtime decryptor. Keys are not stored verbatim: each string is
-- encrypted at build time and the runtime key is DERIVED at load time from
-- program state (a per-build salt, the string's index, and a fingerprint folded
-- over an embedded constant table). See src/obf/cipher.lua for the algorithm
-- and src/runtime/decryptor.lua for the canonical runtime.
--
-- What is / isn't encrypted:
--   * Encrypted: string VALUES wherever they appear as expressions (assignment
--     RHS, call arguments, return values, table item/keyed values, operands).
--   * NOT touched: identifiers, dotted field names (a.b), method names (o:m),
--     and named table keys ({ k = v }) -- these are stored as plain strings in
--     the AST (not StringLiteral nodes), so the walker never reaches them and
--     the program's structure is preserved.
--
-- Randomization: with different seeds the salt, the constant table, the byte
-- layout, and every emitted decryptor identifier differ; the same seed
-- reproduces output exactly. All randomness comes from ctx.prng.
--
-- Written in Lua-5.1-compatible syntax.

local ast = require("obf.ast")
local cipher = require("obf.cipher")

local pass = {}
pass.name = "string_encrypt"

-- ---------------------------------------------------------------------------
-- AST walking: rewrite StringLiteral expression nodes via `rewrite(node)`.
-- We walk every expression-bearing field but deliberately do NOT descend into
-- plain-string name fields (method names, dotted field names, named table
-- keys), which are not StringLiteral nodes anyway.
-- ---------------------------------------------------------------------------

local walk_expr, walk_exprlist, walk_block

-- Returns the (possibly replaced) expression node.
walk_expr = function(node, rewrite)
  if type(node) ~= "table" or node.type == nil then return node end
  local t = node.type

  if t == "StringLiteral" then
    return rewrite(node)
  elseif t == "Paren" then
    node.expr = walk_expr(node.expr, rewrite)
  elseif t == "BinaryExpression" then
    node.left = walk_expr(node.left, rewrite)
    node.right = walk_expr(node.right, rewrite)
  elseif t == "UnaryExpression" then
    node.operand = walk_expr(node.operand, rewrite)
  elseif t == "IndexExpression" then
    node.obj = walk_expr(node.obj, rewrite)
    -- a[expr] index is an expression; a.b (isDot) keeps its name as-is.
    if not node.isDot then
      node.index = walk_expr(node.index, rewrite)
    end
  elseif t == "CallExpression" then
    node.callee = walk_expr(node.callee, rewrite)
    walk_exprlist(node.args, rewrite)
  elseif t == "MethodCallExpression" then
    node.obj = walk_expr(node.obj, rewrite)
    -- node.method is a plain name, left untouched.
    walk_exprlist(node.args, rewrite)
  elseif t == "FunctionExpression" then
    walk_block(node.body, rewrite)
  elseif t == "TableConstructor" then
    for _, f in ipairs(node.fields) do
      if f.kind == "keyed" then
        f.key = walk_expr(f.key, rewrite)
      end
      -- f.key for "named" is a plain string -> untouched.
      f.value = walk_expr(f.value, rewrite)
    end
  end
  -- literals/identifiers/vararg: nothing to do
  return node
end

walk_exprlist = function(list, rewrite)
  if not list then return end
  for i = 1, #list do
    list[i] = walk_expr(list[i], rewrite)
  end
end

local function walk_statement(node, rewrite)
  local t = node.type
  if t == "LocalStatement" then
    walk_exprlist(node.exprs, rewrite)
  elseif t == "AssignmentStatement" then
    walk_exprlist(node.targets, rewrite)
    walk_exprlist(node.exprs, rewrite)
  elseif t == "CallStatement" then
    node.expr = walk_expr(node.expr, rewrite)
  elseif t == "DoStatement" then
    walk_block(node.body, rewrite)
  elseif t == "IfStatement" then
    for _, clause in ipairs(node.clauses) do
      clause.cond = walk_expr(clause.cond, rewrite)
      walk_block(clause.body, rewrite)
    end
    if node.elseBody then walk_block(node.elseBody, rewrite) end
  elseif t == "WhileStatement" then
    node.cond = walk_expr(node.cond, rewrite)
    walk_block(node.body, rewrite)
  elseif t == "RepeatStatement" then
    walk_block(node.body, rewrite)
    node.cond = walk_expr(node.cond, rewrite)
  elseif t == "NumericForStatement" then
    node.start = walk_expr(node.start, rewrite)
    node.limit = walk_expr(node.limit, rewrite)
    if node.step then node.step = walk_expr(node.step, rewrite) end
    walk_block(node.body, rewrite)
  elseif t == "GenericForStatement" then
    walk_exprlist(node.exprs, rewrite)
    walk_block(node.body, rewrite)
  elseif t == "FunctionDeclaration" then
    walk_expr(node.func, rewrite) -- descends into body (FunctionExpression)
  elseif t == "LocalFunction" then
    walk_expr(node.func, rewrite)
  elseif t == "ReturnStatement" then
    walk_exprlist(node.exprs, rewrite)
  end
  -- BreakStatement: nothing
end

walk_block = function(stmts, rewrite)
  for _, st in ipairs(stmts) do
    walk_statement(st, rewrite)
  end
end

-- ---------------------------------------------------------------------------
-- Decryptor prelude emission (randomized identifiers, substituted salt/table).
-- ---------------------------------------------------------------------------

local function build_constant_table(prng)
  -- 16..48 bytes of seeded random data; this feeds the runtime fingerprint.
  local n = prng:randomInt(16, 48)
  local C = {}
  for i = 1, n do C[i] = prng:randomInt(0, 255) end
  return C
end

local function render_byte_table(C)
  local parts = {}
  for i = 1, #C do parts[i] = tostring(C[i]) end
  return "{" .. table.concat(parts, ",") .. "}"
end

-- Emit the decryptor source with fresh names. Returns (code, decName).
local function render_decryptor(prng, salt, C)
  -- fresh, non-colliding identifiers for every local in the runtime
  local used = {}
  local function name(prefix)
    local nm
    repeat nm = prng:randomName(prefix) until not used[nm]
    used[nm] = true
    return nm
  end

  local Nu32   = name("_u")
  local Nmul   = name("_m")
  local Nxor   = name("_x")
  local Nfp    = name("_f")
  local Nfpfn  = name("_g")
  local Ndec   = name("_d")
  local NC     = name("_c")
  local Nsalt  = name("_s")
  -- loop / temp locals
  local a, b, j = name("_a"), name("_b"), name("_j")
  local res, bit, abit, bbit = name("_r"), name("_t"), name("_p"), name("_q")
  local x, ahi, alo, hi, lo = name("_X"), name("_h"), name("_l"), name("_H"), name("_L")
  local fp, i = name("_F"), name("_i")
  local idx, bb, state, outt, kb = name("_D"), name("_B"), name("_S"), name("_O"), name("_k")

  local TWO32 = "4294967296"
  local lines = {}
  local function L(s) lines[#lines+1] = s end

  L("-- [luaobf] embedded string decryptor (dynamic runtime-derived keys)")
  L("local " .. Nu32 .. "=function(" .. x .. ") " ..
    x .. "=" .. x .. "-math.floor(" .. x .. "/" .. TWO32 .. ")*" .. TWO32 ..
    " if " .. x .. "<0 then " .. x .. "=" .. x .. "+" .. TWO32 .. " end return " .. x .. " end")
  L("local " .. Nmul .. "=function(" .. a .. "," .. b .. ") " ..
    a .. "=" .. Nu32 .. "(" .. a .. ") " .. b .. "=" .. Nu32 .. "(" .. b .. ") " ..
    "local " .. ahi .. "=math.floor(" .. a .. "/65536) " ..
    "local " .. alo .. "=" .. a .. "-" .. ahi .. "*65536 " ..
    "local " .. hi .. "=" .. Nu32 .. "(" .. Nu32 .. "(" .. ahi .. "*" .. b .. ")*65536) " ..
    "local " .. lo .. "=" .. Nu32 .. "(" .. alo .. "*" .. b .. ") " ..
    "return " .. Nu32 .. "(" .. hi .. "+" .. lo .. ") end")
  L("local " .. Nxor .. "=function(" .. a .. "," .. b .. ") " ..
    "local " .. res .. "=0 local " .. bit .. "=1 " ..
    "for " .. j .. "=1,8 do " ..
    "local " .. abit .. "=" .. a .. "%2 local " .. bbit .. "=" .. b .. "%2 " ..
    "if " .. abit .. "~=" .. bbit .. " then " .. res .. "=" .. res .. "+" .. bit .. " end " ..
    a .. "=(" .. a .. "-" .. abit .. ")/2 " .. b .. "=(" .. b .. "-" .. bbit .. ")/2 " ..
    bit .. "=" .. bit .. "*2 end return " .. res .. " end")
  L("local " .. NC .. "=" .. render_byte_table(C))
  L("local " .. Nsalt .. "=" .. string.format("%.0f", salt))
  -- fingerprint folded over C at load time (dynamic key material)
  L("local " .. Nfpfn .. "=function() " ..
    "local " .. fp .. "=2166136261 " ..
    "for " .. i .. "=1,#" .. NC .. " do " ..
    fp .. "=" .. Nu32 .. "(" .. Nmul .. "(" .. fp .. ",16777619)+(" .. NC .. "[" .. i .. "]%256)) " ..
    fp .. "=" .. Nu32 .. "(" .. fp .. "+math.floor(" .. fp .. "/65536)) end " ..
    fp .. "=" .. Nu32 .. "(" .. Nmul .. "(" .. fp .. ",2246822519)) " ..
    fp .. "=" .. Nu32 .. "(" .. fp .. "+math.floor(" .. fp .. "/256)) " ..
    "return " .. Nu32 .. "(" .. fp .. ") end")
  L("local " .. Nfp .. "=" .. Nfpfn .. "()")
  -- per-string decrypt
  L("local " .. Ndec .. "=function(" .. idx .. "," .. bb .. ") " ..
    "local " .. state .. "=" .. Nu32 .. "(" .. Nsalt .. "+" ..
    Nmul .. "((" .. idx .. "+1)," .. string.format("%.0f", cipher.MULA) .. ")+" ..
    Nmul .. "(" .. Nfp .. "," .. string.format("%.0f", cipher.MULB) .. ")) " ..
    "local " .. outt .. "={} " ..
    "for " .. j .. "=1,#" .. bb .. " do " ..
    state .. "=" .. Nu32 .. "(" .. Nmul .. "(" .. state .. "," .. string.format("%.0f", cipher.LCG_A) ..
    ")+" .. string.format("%.0f", cipher.LCG_C) .. ") " ..
    "local " .. kb .. "=math.floor(" .. state .. "/16777216)%256 " ..
    outt .. "[" .. j .. "]=string.char(" .. Nxor .. "(" .. bb .. "[" .. j .. "]%256," .. kb .. ")) end " ..
    "return table.concat(" .. outt .. ") end")

  return table.concat(lines, "\n"), Ndec
end

-- ---------------------------------------------------------------------------
-- Pass entry point.
-- ---------------------------------------------------------------------------

function pass.run(chunk, ctx)
  local prng = ctx.prng

  -- Per-build cipher parameters (seeded; different seed -> different output).
  local salt = prng:randomInt(0, 4294967295)
  local C = build_constant_table(prng)
  local fp = cipher.fingerprint(C)

  -- Emit the decryptor prelude once; grab its decrypt function name.
  local code, decName = render_decryptor(prng, salt, C)
  ctx.prelude:register("string_encrypt.decryptor", code)

  -- Rewrite every string literal into: decName(idx, { enc bytes... })
  local index = 0
  local function rewrite(strNode)
    local i = index
    index = index + 1
    local enc = cipher.encrypt_string(strNode.value, salt, i, fp)
    -- build a table constructor of the encrypted bytes
    local fields = {}
    for k = 1, #enc do
      fields[k] = { kind = "item", value = ast.NumberLiteral(enc[k], tostring(enc[k])) }
    end
    local tbl = ast.TableConstructor(fields)
    local args = { ast.NumberLiteral(i, tostring(i)), tbl }
    -- Wrap in Paren so it is a single-value expression safe in any position
    -- (e.g. "a" .. x works, and multi-return truncation never surprises).
    return ast.Paren(ast.CallExpression(ast.Identifier(decName), args))
  end

  walk_block(chunk.body, rewrite)
  return chunk
end

return pass
