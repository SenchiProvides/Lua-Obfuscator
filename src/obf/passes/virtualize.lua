-- src/obf/passes/virtualize.lua
-- Technique 1: Code Virtualization (the core defense).
--
-- Selected function bodies are compiled into bytecode for a custom, per-build
-- randomized register VM, and the function in the output becomes a thin wrapper
-- that calls an embedded interpreter to execute that bytecode. A standard Lua
-- decompiler sees only the generic interpreter plus an opaque data blob; the
-- original control flow / expressions are gone.
--
-- SAFETY CONTRACT (the #1 rule): the compiler supports a well-defined subset of
-- the AST. If it meets ANY construct it does not fully and correctly support, it
-- ABORTS compilation of that function (returns nil) and the function is left as
-- ordinary native source. Correctness of the emitted program is never traded
-- for virtualization coverage.
--
-- PER-BUILD RANDOMIZATION (all driven by ctx.prng):
--   * opcode NUMBERS are a seeded permutation,
--   * the operand field ORDER inside an instruction array is seeded,
--   * the constant-pool ORDER is shuffled (indices are rewritten accordingly),
--   * every interpreter / dispatch / helper identifier is a fresh seeded name.
-- Same seed reproduces output exactly; different seeds change numbering + shape.
--
-- INTEGRATION WITH FEAT-002 (string encryption): virtualize runs BEFORE
-- string_encrypt (see src/obf/config.lua enabled_passes ordering). The bytecode
-- constant pool is emitted as ordinary StringLiteral AST nodes inside the
-- wrapper, so when string_encrypt runs afterwards it encrypts those constant
-- strings too -- the virtualized code's literals are hidden exactly like any
-- other literal, with no special-casing required.
--
-- REPORTING: the pass records ctx.report.virtualize = { count=N, names={...} }
-- so tests / the CLI can assert that functions were actually virtualized.
--
-- Written in Lua-5.1-compatible syntax. The EMITTED interpreter is likewise
-- 5.1/5.4/LuaJIT portable (no bit32, no 5.4-only operators, no goto).

local ast = require("obf.ast")

local pass = {}
pass.name = "virtualize"

-- ---------------------------------------------------------------------------
-- Opcode set (canonical names). Numbers are assigned per build via a seeded
-- permutation; see assign_opcodes().
-- ---------------------------------------------------------------------------
local OPNAMES = {
  "LOADK", "LOADBOOL", "LOADNIL", "MOVE", "GETUPVAL", "SETUPVAL",
  "GETGLOBAL", "SETGLOBAL", "GETTABLE", "SETTABLE", "NEWTABLE", "SETLIST",
  "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "CONCAT",
  "UNM", "NOT", "LEN", "EQ", "LT", "LE", "TEST", "TESTSET", "JMP",
  "CALL", "TAILCALL", "RETURN", "CLOSURE",
  "FORPREP", "FORLOOP", "TFORCALL", "VARARG", "SELF",
}

-- ===========================================================================
-- COMPILER: AST function body -> proto { code, consts, nparams, vararg, protos }
-- ===========================================================================
-- Abort mechanism: compile functions raise a table {abort=true,reason=..} via
-- error(); the top-level compile_function catches it and returns nil.
-- ---------------------------------------------------------------------------

local ABORT = {}
local function abort(reason)
  error(setmetatable({ abort = true, reason = reason }, ABORT), 0)
end

-- A compiler scope for one function.
local function new_fnstate(parent)
  return {
    parent = parent,
    code = {},          -- list of instructions {name, A, B, C, [extra]}
    consts = {},        -- constant pool values (in insertion order)
    constMap = {},      -- key -> index (1-based)
    protos = {},        -- nested protos
    nparams = 0,
    vararg = false,
    freereg = 0,        -- next free register
    maxreg = 0,
    -- lexical scope: list of {name=.., reg=.., upcell=bool} ; we use blocks
    actives = {},       -- active local variable list (stack): {name, reg}
    blocks = {},        -- stack of block markers (actives length) for scoping
    upvals = {},        -- list of upvalue descriptors {name, fromParentLocal=bool, index}
    upvalMap = {},      -- name -> upvalue index (1-based)
    labels = {},        -- for break: list of jump pcs to patch (loop stack)
    loopstack = {},     -- stack of {breaks={pc,...}}
  }
end

local function reserve(fs, n)
  n = n or 1
  local r = fs.freereg
  fs.freereg = fs.freereg + n
  if fs.freereg > fs.maxreg then fs.maxreg = fs.freereg end
  return r
end

local function setreg(fs, n) fs.freereg = n; if n > fs.maxreg then fs.maxreg = n end end

local function emit(fs, name, A, B, C, extra)
  local ins = { name, A, B, C }
  if extra then for k, v in pairs(extra) do ins[k] = v end end
  fs.code[#fs.code+1] = ins
  return #fs.code
end

-- Add a constant, dedup by (type,value). Returns 1-based index.
local function const_index(fs, v)
  local key = type(v) .. ":" .. tostring(v)
  local idx = fs.constMap[key]
  if idx then return idx end
  fs.consts[#fs.consts+1] = v
  idx = #fs.consts
  fs.constMap[key] = idx
  return idx
end

-- RK encoding: register r -> r (>=0); constant index k(1-based) -> -(k)
local function rk_const(fs, v) return -const_index(fs, v) end

-- ---- lexical scope management ----
local function enter_block(fs)
  fs.blocks[#fs.blocks+1] = { nactive = #fs.actives, freereg = fs.freereg }
end

local function leave_block(fs)
  local b = fs.blocks[#fs.blocks]
  fs.blocks[#fs.blocks] = nil
  -- remove locals declared in this block
  for i = #fs.actives, b.nactive + 1, -1 do fs.actives[i] = nil end
  fs.freereg = b.freereg
end

local function declare_local(fs, name, reg)
  fs.actives[#fs.actives+1] = { name = name, reg = reg }
end

-- Resolve a name to a local register in the current function, or nil.
local function find_local(fs, name)
  for i = #fs.actives, 1, -1 do
    if fs.actives[i].name == name then return fs.actives[i].reg end
  end
  return nil
end

-- Resolve a name to an upvalue index, creating the upvalue chain if the name is
-- a local (or upvalue) of an enclosing function. Returns index or nil.
local function resolve_upval(fs, name)
  if fs.upvalMap[name] then return fs.upvalMap[name] end
  local parent = fs.parent
  if not parent then
    -- Top-level (root) function: a free name may be a BOUNDARY upvalue, i.e. a
    -- local of the enclosing (native) scope passed in by the wrapper as a cell.
    if fs.boundary and fs.boundary[name] then
      local idx = #fs.upvals + 1
      fs.upvals[idx] = { name = name, boundary = true }
      fs.upvalMap[name] = idx
      fs.boundaryUsed = fs.boundaryUsed or {}
      fs.boundaryUsed[name] = true
      return idx
    end
    return nil
  end
  local preg = find_local(parent, name)
  if preg ~= nil then
    -- capture parent local
    local idx = #fs.upvals + 1
    fs.upvals[idx] = { name = name, inParentLocal = true, reg = preg }
    fs.upvalMap[name] = idx
    -- mark parent local as captured so the parent boxes it
    parent._captured = parent._captured or {}
    parent._captured[preg] = true
    return idx
  end
  local pup = resolve_upval(parent, name)
  if pup ~= nil then
    local idx = #fs.upvals + 1
    fs.upvals[idx] = { name = name, inParentLocal = false, parentUp = pup }
    fs.upvalMap[name] = idx
    return idx
  end
  return nil
end

-- ---------------------------------------------------------------------------
-- Expression compilation.
-- compile_expr(fs, node, dest) -> places result in register `dest`.
-- compile_expr_tmp(fs, node) -> allocates a temp register, returns its index.
-- compile_expr_rk(fs, node) -> returns an RK operand (const if literal).
-- ---------------------------------------------------------------------------

local compile_expr, compile_block, compile_statement, compile_expr_multi

-- Is this a constant-foldable literal we can store in the const pool?
local function literal_const(node)
  local t = node.type
  if t == "NumberLiteral" then return true, node.value end
  if t == "StringLiteral" then return true, node.value end
  return false
end

local function compile_expr_rk(fs, node)
  local ok, v = literal_const(node)
  if ok then return rk_const(fs, v) end
  local r = reserve(fs)
  compile_expr(fs, node, r)
  return r
end

-- Compile into dest register.
compile_expr = function(fs, node, dest)
  local t = node.type
  if t == "NilLiteral" then emit(fs, "LOADNIL", dest, 0)
  elseif t == "TrueLiteral" then emit(fs, "LOADBOOL", dest, 1)
  elseif t == "FalseLiteral" then emit(fs, "LOADBOOL", dest, 0)
  elseif t == "NumberLiteral" then emit(fs, "LOADK", dest, const_index(fs, node.value))
  elseif t == "StringLiteral" then emit(fs, "LOADK", dest, const_index(fs, node.value))
  elseif t == "VarargLiteral" then
    if not fs.vararg then abort("vararg in non-vararg function") end
    emit(fs, "VARARG", dest, 2) -- one value
  elseif t == "Identifier" then
    local reg = find_local(fs, node.name)
    if reg ~= nil then
      if reg ~= dest then emit(fs, "MOVE", dest, reg) end
    else
      local up = resolve_upval(fs, node.name)
      if up ~= nil then
        emit(fs, "GETUPVAL", dest, up - 1)
      else
        emit(fs, "GETGLOBAL", dest, const_index(fs, node.name))
      end
    end
  elseif t == "Paren" then
    compile_expr(fs, node.expr, dest)
  elseif t == "IndexExpression" then
    local save = fs.freereg
    local objr = reserve(fs)
    compile_expr(fs, node.obj, objr)
    local keyrk
    if node.isDot then
      keyrk = rk_const(fs, node.index.name)
    else
      keyrk = compile_expr_rk(fs, node.index)
    end
    emit(fs, "GETTABLE", dest, objr, keyrk)
    setreg(fs, save)
  elseif t == "BinaryExpression" then
    local op = node.op
    if op == "and" or op == "or" then
      -- short-circuit: compute left into dest; test; conditionally eval right.
      compile_expr(fs, node.left, dest)
      -- TEST: if (truthy(dest)) == skipWhen then skip the following JMP
      -- For `and`: if left is FALSE, result is left -> jump over right eval.
      -- For `or`:  if left is TRUE, result is left -> jump over right eval.
      local testB = (op == "and") and 1 or 0
      -- TEST A B : if truthy(R[A]) == (B~=0) then pc=pc+1 (skip next instr)
      emit(fs, "TEST", dest, testB)
      local jpc = emit(fs, "JMP", 0, 0) -- placeholder, patched to end
      compile_expr(fs, node.right, dest)
      -- patch jmp to here
      fs.code[jpc][3] = #fs.code - jpc
    else
      local save = fs.freereg
      local b = compile_expr_rk(fs, node.left)
      local c = compile_expr_rk(fs, node.right)
      local map = {
        ["+"]="ADD", ["-"]="SUB", ["*"]="MUL", ["/"]="DIV", ["%"]="MOD", ["^"]="POW",
      }
      if map[op] then
        emit(fs, map[op], dest, b, c)
      elseif op == ".." then
        -- CONCAT needs contiguous registers; fall back to a 2-register concat
        -- by materializing both operands into consecutive regs.
        setreg(fs, save)
        local r0 = reserve(fs)
        compile_expr(fs, node.left, r0)
        local r1 = reserve(fs)
        compile_expr(fs, node.right, r1)
        emit(fs, "CONCAT", dest, r0, r1)
      elseif op == "==" then emit(fs, "EQ", dest, b, c)
      elseif op == "~=" then
        emit(fs, "EQ", dest, b, c); emit(fs, "NOT", dest, dest)
      elseif op == "<" then emit(fs, "LT", dest, b, c)
      elseif op == ">" then emit(fs, "LT", dest, c, b)
      elseif op == "<=" then emit(fs, "LE", dest, b, c)
      elseif op == ">=" then emit(fs, "LE", dest, c, b)
      else abort("binop " .. tostring(op)) end
      setreg(fs, save)
    end
  elseif t == "UnaryExpression" then
    local save = fs.freereg
    local r = reserve(fs)
    compile_expr(fs, node.operand, r)
    if node.op == "-" then emit(fs, "UNM", dest, r)
    elseif node.op == "not" then emit(fs, "NOT", dest, r)
    elseif node.op == "#" then emit(fs, "LEN", dest, r)
    else abort("unop " .. tostring(node.op)) end
    setreg(fs, save)
  elseif t == "CallExpression" or t == "MethodCallExpression" then
    -- single-value context: compile as a call producing 1 result into dest.
    local save = fs.freereg
    local base = reserve(fs)
    compile_call_into(fs, node, base, 2) -- C=2 -> 1 result
    if base ~= dest then emit(fs, "MOVE", dest, base) end
    setreg(fs, save)
  elseif t == "FunctionExpression" then
    compile_closure(fs, node, dest)
  elseif t == "TableConstructor" then
    compile_table(fs, node, dest)
  else
    abort("expr type " .. tostring(t))
  end
end

-- Compile a function literal into a nested proto; emit CLOSURE into dest.
function compile_closure(fs, node, dest)
  local child = compile_function_proto(node, fs)
  if child == nil then abort("nested function unsupported") end
  local pidx = #fs.protos + 1
  fs.protos[pidx] = child
  emit(fs, "CLOSURE", dest, pidx)
end

-- Table constructor. Supports array items (incl. trailing multi-value call /
-- vararg), named keys, and [expr]=expr keyed entries.
function compile_table(fs, node, dest)
  emit(fs, "NEWTABLE", dest)
  local arrayIndex = 0
  local fields = node.fields
  for i = 1, #fields do
    local f = fields[i]
    if f.kind == "item" then
      local last = (i == #fields)
      local v = f.value
      local isMulti = last and (v.type == "CallExpression" or v.type == "MethodCallExpression" or v.type == "VarargLiteral")
      if isMulti then
        -- expand all results of a trailing call/vararg into the array part
        local save = fs.freereg
        local base = reserve(fs)
        local n = compile_expr_multi(fs, v, base, -1) -- -1 => all results
        -- SETLIST A B C extra=count base=destIndex ; count unknown -> use top
        emit(fs, "SETLIST", dest, base, 0, { [5] = 0, [6] = arrayIndex + 1 })
        setreg(fs, save)
        arrayIndex = arrayIndex + 1 -- marker; VM uses top for count
      else
        arrayIndex = arrayIndex + 1
        local save = fs.freereg
        local r = reserve(fs)
        compile_expr(fs, v, r)
        emit(fs, "SETLIST", dest, r, 1, { [5] = 1, [6] = arrayIndex })
        setreg(fs, save)
      end
    elseif f.kind == "named" then
      local save = fs.freereg
      local vrk = compile_expr_rk(fs, f.value)
      emit(fs, "SETTABLE", dest, rk_const(fs, f.key), vrk)
      setreg(fs, save)
    elseif f.kind == "keyed" then
      local save = fs.freereg
      local krk = compile_expr_rk(fs, f.key)
      local vrk = compile_expr_rk(fs, f.value)
      emit(fs, "SETTABLE", dest, krk, vrk)
      setreg(fs, save)
    else
      abort("table field kind " .. tostring(f.kind))
    end
  end
end

-- Compile a call (Call or MethodCall) placing results starting at register
-- `base`. nresults: desired result count+1 (C field): 2 => 1 result, 1 => 0
-- results, 0 => all results (multi). Returns nothing.
function compile_call_into(fs, node, base, cfield)
  -- ensure base is the current free top so args are contiguous above it.
  setreg(fs, base + 1)
  local args = node.args
  local argbase
  if node.type == "MethodCallExpression" then
    -- SELF: R[base+1]=obj ; R[base]=obj[method]
    local save = fs.freereg
    local objr = reserve(fs)
    compile_expr(fs, node.obj, objr)
    emit(fs, "SELF", base, objr, rk_const(fs, node.method))
    setreg(fs, base + 2) -- base = fn, base+1 = self
    argbase = base + 2
  else
    compile_expr(fs, node.callee, base)
    setreg(fs, base + 1)
    argbase = base + 1
  end
  -- compile arguments; detect trailing multi-value
  local nfixed = #args
  local multiTail = false
  for i = 1, nfixed do
    local a = args[i]
    local last = (i == nfixed)
    local isMulti = last and (a.type == "CallExpression" or a.type == "MethodCallExpression" or a.type == "VarargLiteral")
    local r = reserve(fs)
    if isMulti then
      compile_expr_multi(fs, a, r, -1)
      multiTail = true
    else
      compile_expr(fs, a, r)
    end
  end
  -- B field: number of args + 1, or 0 if multi tail (args up to top)
  local selfExtra = (node.type == "MethodCallExpression") and 1 or 0
  local bfield
  if multiTail then
    bfield = 0
  else
    bfield = nfixed + selfExtra + 1
  end
  emit(fs, "CALL", base, bfield, cfield)
  setreg(fs, base + math.max(0, (cfield - 1)))
end

-- Compile an expression that may yield multiple values into consecutive
-- registers starting at `base`. want: number of values, or -1 for "all".
-- Returns the known count (or -1).
compile_expr_multi = function(fs, node, base, want)
  local t = node.type
  if t == "CallExpression" or t == "MethodCallExpression" then
    local cfield = (want == -1) and 0 or (want + 1)
    compile_call_into(fs, node, base, cfield)
    return want
  elseif t == "VarargLiteral" then
    if not fs.vararg then abort("vararg in non-vararg function") end
    local bfield = (want == -1) and 0 or (want + 1)
    emit(fs, "VARARG", base, bfield)
    return want
  else
    -- single value
    compile_expr(fs, node, base)
    return 1
  end
end

-- ---------------------------------------------------------------------------
-- Statement compilation.
-- ---------------------------------------------------------------------------

-- Assign a list of expressions to a list of target registers (locals) honoring
-- Lua multiple-assignment semantics (evaluate RHS, then assign).
local function compile_adjusted_exprlist(fs, exprs, destbase, ntargets)
  -- Evaluate exprs into destbase..destbase+ntargets-1, adjusting last to multi.
  local n = #exprs
  if n == 0 then
    for i = 0, ntargets-1 do emit(fs, "LOADNIL", destbase + i, 0) end
    return
  end
  for i = 1, n do
    local e = exprs[i]
    local last = (i == n)
    local reg = destbase + (i - 1)
    if last and i <= ntargets and (e.type == "CallExpression" or e.type == "MethodCallExpression" or e.type == "VarargLiteral") then
      local want = ntargets - i + 1
      setreg(fs, reg)
      compile_expr_multi(fs, e, reg, want)
    elseif last and i < ntargets then
      -- single last expr but more targets: fill, then nil the rest
      setreg(fs, reg + 1)
      compile_expr(fs, e, reg)
      for k = i+1, ntargets do emit(fs, "LOADNIL", destbase + (k-1), 0) end
    else
      if i <= ntargets then
        setreg(fs, reg + 1)
        compile_expr(fs, e, reg)
      else
        -- extra expr beyond targets: still must evaluate for side effects into temp
        local tmp = reserve(fs)
        compile_expr(fs, e, tmp)
        fs.freereg = tmp
      end
    end
  end
end

compile_statement = function(fs, node)
  local t = node.type
  if t == "LocalStatement" then
    local base = fs.freereg
    local nt = #node.names
    reserve(fs, nt)
    compile_adjusted_exprlist(fs, node.exprs or {}, base, nt)
    setreg(fs, base + nt)
    for i = 1, nt do declare_local(fs, node.names[i], base + i - 1) end

  elseif t == "AssignmentStatement" then
    compile_assignment(fs, node)

  elseif t == "CallStatement" then
    local save = fs.freereg
    local base = reserve(fs)
    compile_call_into(fs, node.expr, base, 1) -- 0 results
    setreg(fs, save)

  elseif t == "DoStatement" then
    enter_block(fs)
    compile_block(fs, node.body)
    leave_block(fs)

  elseif t == "IfStatement" then
    compile_if(fs, node)

  elseif t == "WhileStatement" then
    compile_while(fs, node)

  elseif t == "RepeatStatement" then
    compile_repeat(fs, node)

  elseif t == "NumericForStatement" then
    compile_numfor(fs, node)

  elseif t == "GenericForStatement" then
    compile_genfor(fs, node)

  elseif t == "ReturnStatement" then
    compile_return(fs, node)

  elseif t == "BreakStatement" then
    local loop = fs.loopstack[#fs.loopstack]
    if not loop then abort("break outside loop") end
    local jpc = emit(fs, "JMP", 0, 0)
    loop.breaks[#loop.breaks+1] = jpc

  elseif t == "LocalFunction" then
    -- declare the local first (so the function can recurse by name)
    local reg = reserve(fs)
    declare_local(fs, node.name, reg)
    compile_closure(fs, node.func, reg)

  elseif t == "FunctionDeclaration" then
    compile_funcdecl(fs, node)

  else
    abort("statement type " .. tostring(t))
  end
end

function compile_assignment(fs, node)
  local targets = node.targets
  local exprs = node.exprs
  if #targets == 1 and #exprs == 1 then
    -- common fast path
    local tgt = targets[1]
    compile_store(fs, tgt, exprs[1])
    return
  end
  -- general multiple assignment: evaluate all RHS into temps, then store.
  -- Also evaluate target "prefix" (table/key) before RHS? Lua evaluates all
  -- expressions; order is unspecified between targets and values but values are
  -- computed. We evaluate target table/keys first, then values, then assign.
  local n = #targets
  -- Resolve each target to a store plan.
  local plans = {}
  for i = 1, n do
    local tgt = targets[i]
    if tgt.type == "Identifier" then
      plans[i] = { kind = "name", node = tgt }
    elseif tgt.type == "IndexExpression" then
      local save = fs.freereg
      local objr = reserve(fs)
      compile_expr(fs, tgt.obj, objr)
      local keyrk
      if tgt.isDot then keyrk = rk_const(fs, tgt.index.name)
      else
        local kr = reserve(fs)
        compile_expr(fs, tgt.index, kr)
        keyrk = kr
      end
      plans[i] = { kind = "index", objr = objr, keyrk = keyrk }
      -- keep these registers reserved; do not restore save
    else
      abort("assignment target")
    end
  end
  local valbase = fs.freereg
  reserve(fs, n)
  compile_adjusted_exprlist(fs, exprs, valbase, n)
  setreg(fs, valbase + n)
  for i = 1, n do
    local p = plans[i]
    local vreg = valbase + (i - 1)
    if p.kind == "name" then
      compile_store_name(fs, p.node.name, vreg)
    else
      emit(fs, "SETTABLE", p.objr, p.keyrk, vreg)
    end
  end
end

function compile_store_name(fs, name, vreg)
  local reg = find_local(fs, name)
  if reg ~= nil then
    if reg ~= vreg then emit(fs, "MOVE", reg, vreg) end
  else
    local up = resolve_upval(fs, name)
    if up ~= nil then
      -- Writing to a BOUNDARY upvalue cannot propagate back to the native outer
      -- local, so refuse to virtualize such a function (correctness first).
      if fs.upvals[up] and fs.upvals[up].boundary then
        abort("writes boundary upvalue " .. tostring(name))
      end
      emit(fs, "SETUPVAL", vreg, up - 1)
    else emit(fs, "SETGLOBAL", vreg, const_index(fs, name)) end
  end
end

function compile_store(fs, tgt, expr)
  if tgt.type == "Identifier" then
    local reg = find_local(fs, tgt.name)
    if reg ~= nil then
      compile_expr(fs, expr, reg)
      setreg(fs, math.max(fs.freereg, reg + 1))
    else
      local save = fs.freereg
      local r = reserve(fs)
      compile_expr(fs, expr, r)
      compile_store_name(fs, tgt.name, r)
      setreg(fs, save)
    end
  elseif tgt.type == "IndexExpression" then
    local save = fs.freereg
    local objr = reserve(fs)
    compile_expr(fs, tgt.obj, objr)
    local keyrk
    if tgt.isDot then keyrk = rk_const(fs, tgt.index.name)
    else keyrk = compile_expr_rk(fs, tgt.index) end
    local vrk = compile_expr_rk(fs, expr)
    emit(fs, "SETTABLE", objr, keyrk, vrk)
    setreg(fs, save)
  else
    abort("store target")
  end
end

function compile_funcdecl(fs, node)
  -- function a.b.c(...) / function a:m(...). Build the target as index/name
  -- then store the closure value.
  local func = node.func
  local save = fs.freereg
  local r = reserve(fs)
  compile_closure(fs, func, r)
  -- Store into nameExpr chain.
  local nameExpr = node.nameExpr
  if nameExpr.type == "Identifier" then
    compile_store_name(fs, nameExpr.name, r)
  elseif nameExpr.type == "IndexExpression" then
    local objr = reserve(fs)
    compile_expr(fs, nameExpr.obj, objr)
    local keyrk = rk_const(fs, nameExpr.index.name)
    emit(fs, "SETTABLE", objr, keyrk, r)
  else
    abort("function decl target")
  end
  setreg(fs, save)
end

function compile_if(fs, node)
  local endJumps = {}
  for ci = 1, #node.clauses do
    local clause = node.clauses[ci]
    -- evaluate condition into a temp; TEST + JMP to next clause
    local save = fs.freereg
    local cr = reserve(fs)
    compile_expr(fs, clause.cond, cr)
    -- if NOT truthy, jump to next clause. TEST A B: if truthy==B then skip JMP.
    emit(fs, "TEST", cr, 1) -- if truthy, skip the following jump (enter body)
    local jnext = emit(fs, "JMP", 0, 0) -- jump to next clause when false
    setreg(fs, save)
    enter_block(fs)
    compile_block(fs, clause.body)
    leave_block(fs)
    -- after body, jump to end (unless this is the last and no else)
    local jend = emit(fs, "JMP", 0, 0)
    endJumps[#endJumps+1] = jend
    -- patch jnext to here
    fs.code[jnext][3] = #fs.code - jnext
  end
  if node.elseBody then
    enter_block(fs)
    compile_block(fs, node.elseBody)
    leave_block(fs)
  end
  for _, j in ipairs(endJumps) do
    fs.code[j][3] = #fs.code - j
  end
end

function compile_while(fs, node)
  local top = #fs.code
  local save = fs.freereg
  local cr = reserve(fs)
  compile_expr(fs, node.cond, cr)
  emit(fs, "TEST", cr, 1) -- if truthy, skip the exit jump
  local jexit = emit(fs, "JMP", 0, 0)
  setreg(fs, save)
  fs.loopstack[#fs.loopstack+1] = { breaks = {} }
  enter_block(fs)
  compile_block(fs, node.body)
  leave_block(fs)
  local jback = emit(fs, "JMP", 0, 0)
  fs.code[jback][3] = top - jback -- jump back to loop top (re-eval cond)
  fs.code[jexit][3] = #fs.code - jexit
  local loop = fs.loopstack[#fs.loopstack]
  fs.loopstack[#fs.loopstack] = nil
  for _, bpc in ipairs(loop.breaks) do fs.code[bpc][3] = #fs.code - bpc end
end

function compile_repeat(fs, node)
  local top = #fs.code
  fs.loopstack[#fs.loopstack+1] = { breaks = {} }
  enter_block(fs)
  compile_block(fs, node.body)
  -- condition can reference block locals in Lua; evaluate before leave_block.
  local cr = fs.freereg
  reserve(fs, 1)
  compile_expr(fs, node.cond, cr)
  -- repeat..until cond: loop while cond is FALSE, exit when cond is TRUE.
  -- TEST A B: skip the next instruction (the back-jump) when truthy(R[A])==(B~=0).
  -- We want to SKIP the back-jump (i.e. fall through and exit the loop) when the
  -- until-condition is TRUE, and take the back-jump (loop again) when it is FALSE.
  -- So B must be 1: skip-when-truthy.
  emit(fs, "TEST", cr, 1)
  local jback = emit(fs, "JMP", 0, 0)
  fs.code[jback][3] = top - jback
  leave_block(fs)
  local loop = fs.loopstack[#fs.loopstack]
  fs.loopstack[#fs.loopstack] = nil
  for _, bpc in ipairs(loop.breaks) do fs.code[bpc][3] = #fs.code - bpc end
end

function compile_numfor(fs, node)
  -- registers: base = index, base+1 = limit, base+2 = step, base+3 = user var
  local base = fs.freereg
  reserve(fs, 4)
  compile_expr(fs, node.start, base)
  compile_expr(fs, node.limit, base + 1)
  if node.step then compile_expr(fs, node.step, base + 2)
  else emit(fs, "LOADK", base + 2, const_index(fs, 1)) end
  local prep = emit(fs, "FORPREP", base, 0)
  fs.loopstack[#fs.loopstack+1] = { breaks = {} }
  enter_block(fs)
  declare_local(fs, node.var, base + 3)
  local bodyStart = #fs.code
  compile_block(fs, node.body)
  leave_block(fs)
  local loopPc = emit(fs, "FORLOOP", base, 0)
  fs.code[prep][3] = loopPc - prep - 1 -- FORPREP jumps to the FORLOOP
  fs.code[loopPc][3] = bodyStart - loopPc -- FORLOOP jumps back to body start
  setreg(fs, base) -- release control registers after loop
  local loop = fs.loopstack[#fs.loopstack]
  fs.loopstack[#fs.loopstack] = nil
  for _, bpc in ipairs(loop.breaks) do fs.code[bpc][3] = #fs.code - bpc end
end

function compile_genfor(fs, node)
  -- base = iterator fn, base+1 = state, base+2 = control, base+3.. = loop vars
  local base = fs.freereg
  reserve(fs, 3)
  compile_adjusted_exprlist(fs, node.exprs, base, 3)
  setreg(fs, base + 3)
  local nvars = #node.names
  reserve(fs, nvars)
  -- jump to the TFORCALL at loop bottom
  local jprep = emit(fs, "JMP", 0, 0)
  fs.loopstack[#fs.loopstack+1] = { breaks = {} }
  enter_block(fs)
  for i = 1, nvars do declare_local(fs, node.names[i], base + 2 + i) end
  local bodyStart = #fs.code
  compile_block(fs, node.body)
  leave_block(fs)
  fs.code[jprep][3] = #fs.code - jprep
  -- TFORCALL A C: calls R[A](R[A+1],R[A+2]) -> R[A+3..A+2+C]; if R[A+3]~=nil
  -- then R[A+2]=R[A+3] and continue (set pc=E1 = bodyStart), else fall through.
  -- Operands: A=base (control), C=nvars, E1=absolute back-jump pc (bodyStart+1).
  local tpc = emit(fs, "TFORCALL", base, 0, nvars, { [5] = bodyStart + 1 })
  setreg(fs, base)
  local loop = fs.loopstack[#fs.loopstack]
  fs.loopstack[#fs.loopstack] = nil
  for _, bpc in ipairs(loop.breaks) do fs.code[bpc][3] = #fs.code - bpc end
end

function compile_return(fs, node)
  local exprs = node.exprs or {}
  if #exprs == 0 then
    emit(fs, "RETURN", 0, 1) -- 0 results
    return
  end
  local base = fs.freereg
  local n = #exprs
  local multiTail = false
  for i = 1, n do
    local e = exprs[i]
    local last = (i == n)
    local reg = base + (i - 1)
    setreg(fs, reg + 1)
    if last and (e.type == "CallExpression" or e.type == "MethodCallExpression" or e.type == "VarargLiteral") then
      compile_expr_multi(fs, e, reg, -1)
      multiTail = true
    else
      compile_expr(fs, e, reg)
    end
  end
  if multiTail then
    emit(fs, "RETURN", base, 0) -- all up to top
  else
    emit(fs, "RETURN", base, n + 1)
  end
  setreg(fs, base)
end

compile_block = function(fs, stmts)
  for _, st in ipairs(stmts) do
    compile_statement(fs, st)
  end
end

-- Compile a FunctionExpression into a proto. Returns proto or nil (abort).
-- parent: parent fnstate or nil.
-- boundary: (root only) set {name=true} of enclosing-scope locals that MAY be
--   captured as boundary upvalues (passed in by the wrapper as cells).
function compile_function_proto(func, parent, boundary)
  local fs = new_fnstate(parent)
  fs.boundary = boundary
  fs.vararg = func.isVararg and true or false
  fs.nparams = #func.params
  -- params occupy registers 0..nparams-1
  reserve(fs, fs.nparams)
  for i = 1, fs.nparams do declare_local(fs, func.params[i], i - 1) end
  local ok, err = pcall(function()
    compile_block(fs, func.body)
    -- implicit final return
    emit(fs, "RETURN", 0, 1)
  end)
  if not ok then
    if type(err) == "table" and getmetatable(err) == ABORT then
      return nil, err.reason
    end
    error(err) -- a real bug: propagate
  end
  return {
    code = fs.code,
    consts = fs.consts,
    nparams = fs.nparams,
    vararg = fs.vararg,
    protos = fs.protos,
    nups = #fs.upvals,
    upvals = fs.upvals,
    maxreg = fs.maxreg,
    captured = fs._captured or {},
  }
end

-- ===========================================================================
-- EMITTER: proto tree -> AST that reconstructs the proto data + CLOSURE calls.
-- ===========================================================================
-- The emitted wrapper looks like:
--   function(<params...>) return __VM(<protoTableLiteral>, {<upcells>}, {...}) end
-- where __VM is the embedded interpreter prelude. Nested protos are stored in
-- the proto table; CLOSURE at runtime builds inner wrappers that capture cells.
-- ---------------------------------------------------------------------------

-- Encode a Lua value as an AST literal node (number / string / boolean / nil).
local function value_to_ast(v)
  local tv = type(v)
  if tv == "number" then return ast.NumberLiteral(v, tostring(v))
  elseif tv == "string" then return ast.StringLiteral(v, false)
  elseif tv == "boolean" then return v and ast.TrueLiteral() or ast.FalseLiteral()
  elseif tv == "nil" then return ast.NilLiteral()
  else error("virtualize: non-literal constant " .. tv) end
end

-- Build an array TableConstructor from a list of AST value nodes.
local function array_ctor(valueNodes)
  local fields = {}
  for i = 1, #valueNodes do
    fields[i] = { kind = "item", value = valueNodes[i] }
  end
  return ast.TableConstructor(fields)
end

-- Build a keyed TableConstructor from { name = astNode, ... } preserving order.
local function record_ctor(pairs_list)
  local fields = {}
  for i = 1, #pairs_list do
    fields[i] = { kind = "named", key = pairs_list[i][1], value = pairs_list[i][2] }
  end
  return ast.TableConstructor(fields)
end

-- ---------------------------------------------------------------------------
-- Per-build encoding: shuffled opcode numbers + randomized instruction field
-- layout. OPNUM[name] = integer. FIELD[logical] = physical slot (1-based).
-- Logical fields: "op","A","B","C","E1","E2" (E1/E2 are the two optional
-- extra operands used by SETLIST and TFORCALL/numeric helpers).
-- ---------------------------------------------------------------------------
local function make_encoding(prng)
  -- shuffle opcode numbers 1..#OPNAMES
  local nums = {}
  for i = 1, #OPNAMES do nums[i] = i end
  prng:shuffle(nums)
  local OPNUM = {}
  for i = 1, #OPNAMES do OPNUM[OPNAMES[i]] = nums[i] end

  -- randomize the physical slot order of the 6 logical fields
  local logicals = { "op", "A", "B", "C", "E1", "E2" }
  local slots = {}
  for i = 1, #logicals do slots[i] = i end
  prng:shuffle(slots)
  local FIELD = {}
  for i = 1, #logicals do FIELD[logicals[i]] = slots[i] end

  return { OPNUM = OPNUM, FIELD = FIELD, NFIELDS = #logicals }
end

-- Serialize one compiler instruction {name,A,B,C,[5]=E1,[6]=E2} to a physical
-- array literal following FIELD layout, producing an AST TableConstructor.
local function instr_to_ast(ins, enc)
  local F = enc.FIELD
  local phys = {}
  local function put(logical, v)
    phys[F[logical]] = v or 0
  end
  put("op", enc.OPNUM[ins[1]])
  put("A", ins[2] or 0)
  put("B", ins[3] or 0)
  put("C", ins[4] or 0)
  put("E1", ins[5] or 0)
  put("E2", ins[6] or 0)
  local values = {}
  local nums = {}
  for i = 1, enc.NFIELDS do
    values[i] = ast.NumberLiteral(phys[i], tostring(phys[i]))
    nums[i] = phys[i] or 0
  end
  return array_ctor(values), nums
end

-- Convert a proto (recursively) into an AST TableConstructor literal.
-- The constant pool is shuffled; code constant indices are rewritten.
--
-- `guard` (optional) is the anti-tamper integrity descriptor:
--   { fold = fn(codeNums, nfields), nfields = N }
-- when present, each proto embeds a `ck` field = fold over the PHYSICAL
-- instruction number arrays, so the emitted VM can recompute+compare at runtime
-- (FEAT-005 integrity self-check).
local function proto_to_ast(proto, enc, prng, guard)
  -- shuffle constant pool
  local n = #proto.consts
  local perm = {}
  for i = 1, n do perm[i] = i end
  prng:shuffle(perm)
  -- newIndex[old] = new position
  local newIndex = {}
  local shuffled = {}
  for newpos = 1, n do
    local old = perm[newpos]
    shuffled[newpos] = proto.consts[old]
    newIndex[old] = newpos
  end
  -- Rewrite constant references after the pool shuffle. We must be precise
  -- about WHICH operands are constant indices / RK operands, because other
  -- operands (jump offsets in JMP/FORPREP/FORLOOP) can legitimately be
  -- negative and must NOT be treated as constant references.
  local function remapRK(v)
    if type(v) == "number" and v < 0 then return -newIndex[-v] end
    return v
  end
  -- RK_FIELDS[op] = set of operand positions (3=B,4=C) that are RK operands.
  local RK_B, RK_C = {}, {}
  local function markRK(op, b, c) if b then RK_B[op]=true end if c then RK_C[op]=true end end
  markRK("GETTABLE", false, true)
  markRK("SETTABLE", true, true)
  markRK("ADD", true, true); markRK("SUB", true, true); markRK("MUL", true, true)
  markRK("DIV", true, true); markRK("MOD", true, true); markRK("POW", true, true)
  markRK("EQ", true, true); markRK("LT", true, true); markRK("LE", true, true)
  markRK("SELF", false, true)
  local codeNodes = {}
  local physCode = {}  -- physical instruction number arrays (for integrity ck)
  for ci = 1, #proto.code do
    local ins = proto.code[ci]
    local name = ins[1]
    local a, b, c = ins[2], ins[3], ins[4]
    if name == "LOADK" or name == "GETGLOBAL" or name == "SETGLOBAL" then
      b = newIndex[b] -- B is a direct constant index
    end
    if RK_B[name] then b = remapRK(b) end
    if RK_C[name] then c = remapRK(c) end
    local clone = { name, a, b, c, ins[5], ins[6] }
    local node, nums = instr_to_ast(clone, enc)
    codeNodes[ci] = node
    physCode[ci] = nums
  end

  -- constants array as AST literals
  local constNodes = {}
  for i = 1, n do constNodes[i] = value_to_ast(shuffled[i]) end

  -- nested protos
  local protoNodes = {}
  for i = 1, #proto.protos do
    protoNodes[i] = proto_to_ast(proto.protos[i], enc, prng, guard)
  end

  -- upvalue descriptors: for CLOSURE at runtime we must know, per upvalue,
  -- whether it refers to a parent LOCAL register or a parent UPVALUE index.
  -- Encode as array of {kind, n}: kind 0 => parent local reg, 1 => parent upval.
  local upNodes = {}
  for i = 1, #(proto.upvals or {}) do
    local u = proto.upvals[i]
    if u.boundary then
      -- boundary upvalue (root only): provided directly by the wrapper; mkcl
      -- never consults this descriptor, but emit a stable placeholder.
      upNodes[i] = array_ctor({ ast.NumberLiteral(2, "2"), ast.NumberLiteral(i - 1, tostring(i - 1)) })
    elseif u.inParentLocal then
      upNodes[i] = array_ctor({ ast.NumberLiteral(0, "0"), ast.NumberLiteral(u.reg, tostring(u.reg)) })
    else
      upNodes[i] = array_ctor({ ast.NumberLiteral(1, "1"), ast.NumberLiteral(u.parentUp - 1, tostring(u.parentUp - 1)) })
    end
  end

  -- captured-local map: which registers of THIS proto must be boxed as cells
  -- (because an inner closure captures them). Encode as array of reg numbers.
  local capNodes = {}
  do
    local caps = {}
    for reg in pairs(proto.captured or {}) do caps[#caps+1] = reg end
    table.sort(caps)
    for i = 1, #caps do capNodes[i] = ast.NumberLiteral(caps[i], tostring(caps[i])) end
  end

  local record = {
    { "c", array_ctor(codeNodes) },
    { "k", array_ctor(constNodes) },
    { "p", array_ctor(protoNodes) },
    { "u", array_ctor(upNodes) },
    { "x", array_ctor(capNodes) },
    { "np", ast.NumberLiteral(proto.nparams, tostring(proto.nparams)) },
    { "va", proto.vararg and ast.TrueLiteral() or ast.FalseLiteral() },
  }
  if guard then
    -- Integrity self-check (FEAT-005): embed the expected checksum computed at
    -- build time over the PHYSICAL instruction arrays. The emitted VM recomputes
    -- the same fold over proto.c at runtime and compares against proto.ck; a
    -- flipped byte in either breaks the match and fires tamper_response.
    local ck = guard.fold(physCode, guard.nfields)
    record[#record+1] = { "ck", ast.NumberLiteral(ck, string.format("%.0f", ck)) }
  end
  return record_ctor(record)
end

-- ===========================================================================
-- INTERPRETER PRELUDE GENERATION
-- ===========================================================================
-- Emits the embedded VM as Lua source text with:
--   * opcode comparisons using the per-build shuffled numbers (enc.OPNUM),
--   * instruction field access using the per-build slot layout (enc.FIELD),
--   * fresh randomized identifiers for every local.
-- The result registers one prelude snippet and returns the name of the entry
-- function the wrappers call.
--
-- Register model note (correctness of upvalues): registers that are captured by
-- an inner closure are stored as 1-element CELL tables so a closure and its
-- enclosing function share the same mutable storage (true Lua upvalue
-- semantics). All register reads/writes go through gR()/sR() helpers which
-- transparently unwrap cells. Non-captured registers hold plain values.
-- ---------------------------------------------------------------------------

-- flatten (boolean): when true, the interpreter's fetch/execute cycle is emitted
-- as a control-flow-FLATTENED state machine (FEAT-004): a single `while true do`
-- dispatcher over a next-state variable with per-build randomized state IDs,
-- scrambled dispatcher ordering, and opaque-predicate junk states that are
-- never reached. When false (or nil) the readable structured reference loop is
-- emitted. BOTH forms execute identically; flattening is a mechanical rewrite.
--
-- guard (optional, FEAT-005): a table describing the anti-tamper weaving:
--   { nfields = N,                 -- physical slots per instruction
--     foldName = "<ident>",        -- name of the emitted checksum fold fn
--     tamperName = "<ident>",      -- name of the emitted tamper_response fn
--     debugName = "<ident>" }      -- name of the emitted anti-debug check fn
-- When present, gen_interpreter weaves calls to these guard functions into the
-- VM entry and (seed-chosen) dispatcher checkpoints so there is no single patch
-- point. The guard functions themselves are emitted by the antitamper pass and
-- registered at the FRONT of the prelude (so these references resolve as
-- top-level locals of the same output chunk). When nil, no weaving is done.
local function gen_interpreter(prng, enc, flatten, guard)
  local used = {}
  local function name(prefix)
    local nm
    repeat nm = prng:randomName(prefix) until not used[nm]
    used[nm] = true
    return nm
  end

  local F = enc.FIELD
  local O = enc.OPNUM
  -- physical field accessor: ins[slot]
  local function fld(insVar, logical) return insVar .. "[" .. F[logical] .. "]" end

  -- identifiers
  local VM     = name("_V")   -- entry: run a proto with upcells+args
  local mkcl   = name("_C")   -- make closure from proto+parent frame
  local proto  = name("_p")
  local up     = name("_u")   -- upvalue cells array (1-based)
  local args   = name("_a")
  local nargs  = name("_n")
  local code   = name("_c")
  local K      = name("_k")   -- consts
  local R      = name("_r")   -- register plain values
  local CELL   = name("_e")   -- cell map: reg -> {v=..}
  local pc     = name("_i")
  local ins    = name("_s")
  local op     = name("_o")
  local top    = name("_t")
  local va     = name("_g")   -- vararg table
  local gR     = name("_G")   -- read reg
  local sR     = name("_S")   -- write reg
  local RK     = name("_K")   -- resolve RK operand
  local x      = name("_x")   -- temp
  local y      = name("_y")
  local z      = name("_z")
  local j      = name("_j")
  local acc    = name("_A")
  local fn     = name("_f")
  local na     = name("_N")
  local ca     = name("_W")
  local rr     = name("_R")   -- rets
  local nret   = name("_m")
  local idx    = name("_d")
  local lim    = name("_l")
  local stp    = name("_P")
  local cont   = name("_b")
  local parent = name("_q")   -- parent frame passed to mkcl
  local pcells = name("_h")   -- parent cells
  local pR     = name("_w")   -- parent R
  local pUp    = name("_U")   -- parent up
  local cells2 = name("_H")
  local ud     = name("_D")   -- upval descriptor
  local nup    = name("_M")
  local f1, f2 = name("_X"), name("_Y")
  local iv     = name("_I")   -- inner vararg collecting
  local tfn    = name("_T")

  local L = {}
  local function w(s) L[#L+1] = s end

  local UNPK = name("_un") -- portable unpack (5.1/LuaJIT global, 5.4 table.unpack)
  w("-- [luaobf] embedded code-virtualization interpreter")
  w("local " .. UNPK .. "=unpack or table.unpack")
  w("local " .. VM)
  w("local " .. mkcl)
  -- make closure: wrap a nested proto, capturing cells from the current frame.
  -- parent = { R=<regs>, C=<cell map>, U=<up cells> }
  w(mkcl .. "=function(" .. proto .. "," .. parent .. ")")
  w("  local " .. pR .. "=" .. parent .. "[1]")
  w("  local " .. pcells .. "=" .. parent .. "[2]")
  w("  local " .. pUp .. "=" .. parent .. "[3]")
  w("  local " .. up .. "={}")
  w("  local " .. ud .. "=" .. proto .. ".u")
  w("  for " .. j .. "=1,#" .. ud .. " do")
  w("    local " .. x .. "=" .. ud .. "[" .. j .. "]")
  w("    if " .. x .. "[1]==0 then " .. up .. "[" .. j .. "]=" .. pcells .. "[" .. x .. "[2]]")
  w("    else " .. up .. "[" .. j .. "]=" .. pUp .. "[" .. x .. "[2]+1] end")
  w("  end")
  w("  return function(...) local " .. f1 .. "," .. f2 .. "=" .. VM .. "(" ..
    proto .. "," .. up .. ",{...},select('#',...)) return " .. UNPK .. "(" .. f1 .. ",1," .. f2 .. ") end")
  w("end")

  -- main interpreter
  w(VM .. "=function(" .. proto .. "," .. up .. "," .. args .. "," .. nargs .. ")")
  w("  local " .. code .. "=" .. proto .. ".c")
  w("  local " .. K .. "=" .. proto .. ".k")
  -- FEAT-005 integrity self-check woven at VM ENTRY: recompute the checksum of
  -- the bytecode (proto.c) and compare against the build-time expected value
  -- (proto.ck). A mismatch means the virtualized blob (or its embedded ck) was
  -- tampered with -> tamper_response. Honest runs always match, so this is
  -- silent. The number of weave SITES below is seed-chosen for randomized
  -- placement (entry + dispatcher checkpoints), so there is no single patch
  -- point.
  if guard then
    w("  if " .. guard.foldName .. "(" .. code .. "," .. guard.nfields ..
      ")~=" .. proto .. ".ck then " .. guard.tamperName .. "(1) end")
    w("  " .. guard.debugName .. "()")
  end
  w("  local " .. R .. "={}")
  w("  local " .. CELL .. "={}")
  -- set up captured-register cells
  w("  local " .. x .. "=" .. proto .. ".x")
  w("  for " .. j .. "=1,#" .. x .. " do " .. CELL .. "[" .. x .. "[" .. j .. "]]={} end")
  -- helpers
  w("  local function " .. gR .. "(" .. z .. ") local " .. y .. "=" .. CELL .. "[" .. z ..
    "] if " .. y .. " then return " .. y .. ".v else return " .. R .. "[" .. z .. "] end end")
  w("  local function " .. sR .. "(" .. z .. "," .. y .. ") local " .. x .. "=" .. CELL ..
    "[" .. z .. "] if " .. x .. " then " .. x .. ".v=" .. y .. " else " .. R .. "[" .. z .. "]=" .. y .. " end end")
  w("  local function " .. RK .. "(" .. z .. ") if " .. z .. "<0 then return " .. K ..
    "[-" .. z .. "] else return " .. gR .. "(" .. z .. ") end end")
  -- load params
  w("  for " .. j .. "=1," .. proto .. ".np do " .. sR .. "(" .. j .. "-1," .. args .. "[" .. j .. "]) end")
  -- vararg
  w("  local " .. va .. "=nil")
  w("  if " .. proto .. ".va then " .. va .. "={} local " .. z .. "=0")
  w("    for " .. j .. "=" .. proto .. ".np+1," .. nargs .. " do " .. z .. "=" .. z ..
    "+1 " .. va .. "[" .. z .. "]=" .. args .. "[" .. j .. "] end " .. va .. ".n=" .. z .. " end")
  -- Function-scoped loop locals. These are declared ONCE (not per-iteration)
  -- so that, in the flattened state-machine form, the fetch state and the
  -- dispatch state can share them even though they live in separate `if`
  -- branches of the dispatcher.
  w("  local " .. top .. "=0")
  w("  local " .. pc .. "=1")
  w("  local " .. ins)
  w("  local " .. op)
  -- field-access locals A,B,C,E1,E2 (E1/E2 declared inline by the SETLIST
  -- branch body as before).
  local Avar, Bvar, Cvar, E1var, E2var = name("_1"), name("_2"), name("_3"), name("_4"), name("_5")
  w("  local " .. Avar .. "," .. Bvar .. "," .. Cvar)

  -- FEAT-005: a second anti-tamper SITE woven into the dispatcher. An
  -- instruction counter triggers a periodic anti-debug check (bounded overhead
  -- via a generous seed-chosen period) so a debugger single-stepping the VM is
  -- caught not just at entry. Honest runs never trip it.
  local dcount, dperiod
  if guard then
    dcount = name("_dc")
    dperiod = prng:randomInt(64, 192)
    w("  local " .. dcount .. "=0")
  end

  -- The fetch/decode step, shared by both interpreter shapes. It reads the next
  -- instruction, advances pc, and unpacks the opcode + A/B/C operands into the
  -- function-scoped locals above.
  local checkpoint = ""
  if guard then
    checkpoint =
      dcount .. "=" .. dcount .. "+1 " ..
      "if " .. dcount .. "%" .. dperiod .. "==0 then " .. guard.debugName .. "() end "
  end
  local fetch_body =
    checkpoint ..
    ins .. "=" .. code .. "[" .. pc .. "] " .. pc .. "=" .. pc .. "+1 " ..
    op .. "=" .. fld(ins, "op") .. " " ..
    Avar .. "=" .. fld(ins, "A") .. " " ..
    Bvar .. "=" .. fld(ins, "B") .. " " ..
    Cvar .. "=" .. fld(ins, "C")

  -- emit each opcode branch. Use if/elseif chain keyed on shuffled numbers.
  local branches = {}
  local function br(opname, body)
    branches[#branches+1] = { O[opname], body }
  end

  br("LOADK", sR .. "(" .. Avar .. "," .. K .. "[" .. Bvar .. "])")
  br("LOADBOOL", sR .. "(" .. Avar .. ",(" .. Bvar .. "~=0))")
  br("LOADNIL", "for " .. j .. "=" .. Avar .. "," .. Avar .. "+" .. Bvar .. " do " .. sR .. "(" .. j .. ",nil) end")
  br("MOVE", sR .. "(" .. Avar .. "," .. gR .. "(" .. Bvar .. "))")
  br("GETUPVAL", sR .. "(" .. Avar .. "," .. up .. "[" .. Bvar .. "+1].v)")
  br("SETUPVAL", up .. "[" .. Bvar .. "+1].v=" .. gR .. "(" .. Avar .. ")")
  br("GETGLOBAL", sR .. "(" .. Avar .. ",_G[" .. K .. "[" .. Bvar .. "]])")
  br("SETGLOBAL", "_G[" .. K .. "[" .. Bvar .. "]]=" .. gR .. "(" .. Avar .. ")")
  br("GETTABLE", sR .. "(" .. Avar .. "," .. gR .. "(" .. Bvar .. ")[" .. RK .. "(" .. Cvar .. ")])")
  br("SETTABLE", gR .. "(" .. Avar .. ")[" .. RK .. "(" .. Bvar .. ")]=" .. RK .. "(" .. Cvar .. ")")
  br("NEWTABLE", sR .. "(" .. Avar .. ",{})")
  br("SETLIST",
    "local " .. E1var .. "=" .. fld(ins, "E1") .. " local " .. E2var .. "=" .. fld(ins, "E2") .. " " ..
    "local " .. na .. " if " .. E1var .. "==0 then " .. na .. "=" .. top .. "-" .. Bvar .. " else " .. na .. "=" .. E1var .. " end " ..
    "for " .. j .. "=1," .. na .. " do " .. gR .. "(" .. Avar .. ")[" .. E2var .. "+" .. j .. "-1]=" .. gR .. "(" .. Bvar .. "+" .. j .. "-1) end")
  br("ADD", sR .. "(" .. Avar .. "," .. RK .. "(" .. Bvar .. ")+" .. RK .. "(" .. Cvar .. "))")
  br("SUB", sR .. "(" .. Avar .. "," .. RK .. "(" .. Bvar .. ")-" .. RK .. "(" .. Cvar .. "))")
  br("MUL", sR .. "(" .. Avar .. "," .. RK .. "(" .. Bvar .. ")*" .. RK .. "(" .. Cvar .. "))")
  br("DIV", sR .. "(" .. Avar .. "," .. RK .. "(" .. Bvar .. ")/" .. RK .. "(" .. Cvar .. "))")
  br("MOD", sR .. "(" .. Avar .. "," .. RK .. "(" .. Bvar .. ")%" .. RK .. "(" .. Cvar .. "))")
  br("POW", sR .. "(" .. Avar .. "," .. RK .. "(" .. Bvar .. ")^" .. RK .. "(" .. Cvar .. "))")
  br("CONCAT",
    "local " .. acc .. "=" .. gR .. "(" .. Cvar .. ") for " .. j .. "=" .. Cvar .. "-1," .. Bvar ..
    ",-1 do " .. acc .. "=" .. gR .. "(" .. j .. ").." .. acc .. " end " .. sR .. "(" .. Avar .. "," .. acc .. ")")
  br("UNM", sR .. "(" .. Avar .. ",-" .. gR .. "(" .. Bvar .. "))")
  br("NOT", sR .. "(" .. Avar .. ",not " .. gR .. "(" .. Bvar .. "))")
  br("LEN", sR .. "(" .. Avar .. ",#" .. gR .. "(" .. Bvar .. "))")
  br("EQ", sR .. "(" .. Avar .. ",(" .. RK .. "(" .. Bvar .. ")==" .. RK .. "(" .. Cvar .. ")))")
  br("LT", sR .. "(" .. Avar .. ",(" .. RK .. "(" .. Bvar .. ")<" .. RK .. "(" .. Cvar .. ")))")
  br("LE", sR .. "(" .. Avar .. ",(" .. RK .. "(" .. Bvar .. ")<=" .. RK .. "(" .. Cvar .. ")))")
  br("TEST",
    "local " .. x .. "=" .. gR .. "(" .. Avar .. ") local " .. y .. "=(" .. x .. "~=nil and " .. x ..
    "~=false) if " .. y .. "==(" .. Bvar .. "~=0) then " .. pc .. "=" .. pc .. "+1 end")
  br("TESTSET", "")
  br("JMP", pc .. "=" .. pc .. "+" .. Bvar)
  br("CALL",
    "local " .. fn .. "=" .. gR .. "(" .. Avar .. ") local " .. na ..
    " if " .. Bvar .. "==0 then " .. na .. "=" .. top .. "-" .. Avar .. " else " .. na .. "=" .. Bvar .. "-1 end " ..
    "") -- CALL body is filled in below (needs an accurate result count)
  -- CALL is special: replace with a correct version (count via table.pack-like).
  br("RETURN",
    "local " .. ca .. "={} local " .. na ..
    " if " .. Bvar .. "==0 then " .. na .. "=" .. top .. "-" .. Avar .. " else " .. na .. "=" .. Bvar .. "-1 end " ..
    "for " .. j .. "=1," .. na .. " do " .. ca .. "[" .. j .. "]=" .. gR .. "(" .. Avar .. "+" .. j .. "-1) end " ..
    "return " .. ca .. "," .. na)
  br("CLOSURE",
    sR .. "(" .. Avar .. "," .. mkcl .. "(" .. proto .. ".p[" .. Bvar .. "],{" .. R .. "," .. CELL .. "," .. up .. "}))")
  br("FORPREP",
    sR .. "(" .. Avar .. "," .. gR .. "(" .. Avar .. ")-" .. gR .. "(" .. Avar .. "+2)) " .. pc .. "=" .. pc .. "+" .. Bvar)
  br("FORLOOP",
    "local " .. stp .. "=" .. gR .. "(" .. Avar .. "+2) local " .. idx .. "=" .. gR .. "(" .. Avar .. ")+" .. stp ..
    " local " .. lim .. "=" .. gR .. "(" .. Avar .. "+1) local " .. cont ..
    " if " .. stp .. ">=0 then " .. cont .. "=(" .. idx .. "<=" .. lim .. ") else " .. cont .. "=(" .. idx .. ">=" .. lim .. ") end " ..
    "if " .. cont .. " then " .. sR .. "(" .. Avar .. "," .. idx .. ") " .. sR .. "(" .. Avar .. "+3," .. idx .. ") " .. pc .. "=" .. pc .. "+" .. Bvar .. " end")
  br("TFORCALL",
    "local " .. tfn .. "=" .. gR .. "(" .. Avar .. ") " ..
    "local " .. rr .. "={" .. tfn .. "(" .. gR .. "(" .. Avar .. "+1)," .. gR .. "(" .. Avar .. "+2))} " ..
    "for " .. j .. "=1," .. Cvar .. " do " .. sR .. "(" .. Avar .. "+2+" .. j .. "," .. rr .. "[" .. j .. "]) end " ..
    "local " .. x .. "=" .. gR .. "(" .. Avar .. "+3) " ..
    "if " .. x .. "~=nil then " .. sR .. "(" .. Avar .. "+2," .. x .. ") " .. pc .. "=" .. fld(ins, "E1") .. " end")
  br("VARARG",
    "if " .. Bvar .. "==0 then " .. top .. "=" .. Avar .. " for " .. j .. "=1," .. va .. ".n do " .. sR ..
    "(" .. Avar .. "+" .. j .. "-1," .. va .. "[" .. j .. "]) " .. top .. "=" .. top .. "+1 end " ..
    "else for " .. j .. "=1," .. Bvar .. "-1 do " .. sR .. "(" .. Avar .. "+" .. j .. "-1," .. va .. "[" .. j .. "]) end end")
  br("SELF",
    sR .. "(" .. Avar .. "+1," .. gR .. "(" .. Bvar .. ")) " .. sR .. "(" .. Avar .. "," .. gR .. "(" .. Bvar .. ")[" .. RK .. "(" .. Cvar .. ")])")
  br("TAILCALL", "")

  -- Build the dispatch chain. We special-case CALL to get the result count
  -- correct using a single call captured into a table plus select on the same
  -- call is wrong; instead we use the length of the pack. To get an accurate
  -- count (including trailing nils) we rely on a small pack helper.
  -- Replace the CALL branch body with a correct implementation here.
  for _, b in ipairs(branches) do
    if b[1] == O["CALL"] then
      b[2] =
        "local " .. fn .. "=" .. gR .. "(" .. Avar .. ") local " .. na ..
        " if " .. Bvar .. "==0 then " .. na .. "=" .. top .. "-" .. Avar .. "-1 else " .. na .. "=" .. Bvar .. "-1 end " ..
        "local " .. ca .. "={} for " .. j .. "=1," .. na .. " do " .. ca .. "[" .. j .. "]=" .. gR .. "(" .. Avar .. "+" .. j .. ") end " ..
        "local " .. rr .. "={" .. fn .. "(" .. UNPK .. "(" .. ca .. ",1," .. na .. "))} " ..
        "local " .. nret .. "=#" .. rr .. " " ..
        "if " .. Cvar .. "==0 then " .. top .. "=" .. Avar ..
        " for " .. j .. "=1," .. nret .. " do " .. sR .. "(" .. Avar .. "+" .. j .. "-1," .. rr .. "[" .. j .. "]) " .. top .. "=" .. top .. "+1 end " ..
        "else for " .. j .. "=1," .. Cvar .. "-1 do " .. sR .. "(" .. Avar .. "+" .. j .. "-1," .. rr .. "[" .. j .. "]) end end"
    end
  end

  -- sort branches by opcode number for a stable (but shuffled) chain
  table.sort(branches, function(p, q) return p[1] < q[1] end)
  -- Assemble the opcode dispatch as a single flat string. The same chain is
  -- used by BOTH interpreter shapes (reference loop and flattened state
  -- machine), so correctness is shared and byte-for-byte equal per-opcode.
  local disp_parts = {}
  local first = true
  for _, b in ipairs(branches) do
    if b[2] ~= "" then
      if first then
        disp_parts[#disp_parts+1] = "if " .. op .. "==" .. b[1] .. " then " .. b[2]
        first = false
      else
        disp_parts[#disp_parts+1] = "elseif " .. op .. "==" .. b[1] .. " then " .. b[2]
      end
    end
  end
  disp_parts[#disp_parts+1] = "end"
  local dispatch_body = table.concat(disp_parts, " ")

  if not flatten then
    -- ---- REFERENCE SHAPE: readable structured fetch/execute loop ----
    w("  while true do")
    w("    " .. fetch_body)
    w("    " .. dispatch_body)
    w("  end")
    w("end")
  else
    -- ---- FLATTENED SHAPE: control-flow-flattened state machine ----
    -- The fetch/execute cycle is broken into states selected by a next-state
    -- variable in a single dispatcher loop. Real states:
    --   S_FETCH   -> run fetch/decode, then go to S_DISP
    --   S_DISP    -> run the opcode dispatch (may `return`), then go to S_FETCH
    -- plus a seeded number of JUNK states that are never entered at runtime
    -- (no real path ever assigns their IDs). The junk states contain opaque
    -- predicates and bogus transitions so a static read of the dispatcher looks
    -- like a maze; because nothing ever sets `st` to a junk ID, they cannot
    -- affect behavior. State IDs are a per-build random permutation and the
    -- branch ORDER in the dispatcher is shuffled, so linear reading order does
    -- not reflect execution order.
    local st  = name("_st")   -- next-state variable
    local jnk = name("_jk")   -- junk scratch

    -- Allocate distinct random state IDs. We draw unique integers from a wide
    -- range so numbering looks arbitrary and differs per seed.
    local idset = {}
    local function new_id()
      local v
      repeat v = prng:randomInt(1000, 999999) until not idset[v]
      idset[v] = true
      return v
    end
    local S_FETCH = new_id()
    local S_DISP  = new_id()
    local njunk = prng:randomInt(3, 6)
    local junk_ids = {}
    for i = 1, njunk do junk_ids[i] = new_id() end

    -- Build the list of dispatcher cases: {id, code}. For junk states, the body
    -- is unreachable, so we fill it with harmless opaque-predicate noise that
    -- "transitions" only among other junk ids (never to a real state).
    local cases = {}
    cases[#cases+1] = { S_FETCH, fetch_body .. " " .. st .. "=" .. S_DISP }
    cases[#cases+1] = { S_DISP, dispatch_body .. " " .. st .. "=" .. S_FETCH }
    for i = 1, njunk do
      local target = junk_ids[(i % njunk) + 1] -- cycle among junk ids only
      -- An opaque predicate that is ALWAYS false: (jnk*jnk) is never < 0 for a
      -- real number, so the body with the (non-existent) real transition never
      -- runs; the else keeps it bouncing within junk space. Even that is dead
      -- code at runtime because no real path assigns a junk id to `st`.
      local body =
        jnk .. "=" .. jnk .. "+1 " ..
        "if (" .. jnk .. "*" .. jnk .. ")<0 then " .. st .. "=" .. S_FETCH ..
        " else " .. st .. "=" .. target .. " end"
      cases[#cases+1] = { junk_ids[i], body }
    end
    -- Shuffle the order the cases appear in the dispatcher (execution order is
    -- driven by `st`, not textual order, so this is purely cosmetic maze).
    prng:shuffle(cases)

    w("  local " .. jnk .. "=0")
    w("  local " .. st .. "=" .. S_FETCH)
    w("  while true do")
    local firstc = true
    for _, c in ipairs(cases) do
      local kw = firstc and "    if " or "    elseif "
      w(kw .. st .. "==" .. c[1] .. " then " .. c[2])
      firstc = false
    end
    w("    end")
    w("  end")
    w("end")
  end

  local code_text = table.concat(L, "\n")
  return code_text, VM, mkcl, UNPK
end

pass._internal = {
  make_encoding = make_encoding,
  compile_function_proto = compile_function_proto,
  proto_to_ast = proto_to_ast,
  gen_interpreter = gen_interpreter,
}

-- ===========================================================================
-- SELECTION + REWRITE: pass.run
-- ===========================================================================
-- Walk the chunk; for each function literal / declaration body that the
-- compiler can fully handle, replace its body with a single return statement
-- that calls the interpreter entry on the proto's data. Functions the compiler
-- aborts on are left untouched (native). Reports the virtualized count.
-- ---------------------------------------------------------------------------

-- Build a wrapper FunctionExpression body (list of stmts) that, given the proto
-- AST literal, runs it. Entry call: VM(protoLit, {}, {params...}, select('#',...)).
-- Because the TOP-LEVEL virtualized function has no upvalues referencing an
-- outer VM frame (its free names resolve to globals/locals-captured-as-globals
-- are rejected by the compiler), we pass an empty upcell list; CLOSURE builds
-- nested closures with proper cells at runtime.
-- boundaryNames: ordered list of enclosing-scope names captured as boundary
--   upvalues. The wrapper boxes each into a cell { v = <name> } so the VM reads
--   current values (correct for read-only captures; writes were rejected at
--   compile time, guaranteeing propagation is never needed).
local function build_wrapper_body(protoLit, params, isVararg, VM, boundaryNames, prng, UNPK)
  -- args table: { p1, p2, ..., [...] }
  local argItems = {}
  for i = 1, #params do
    argItems[i] = { kind = "item", value = ast.Identifier(params[i]) }
  end
  if isVararg then
    argItems[#argItems+1] = { kind = "item", value = ast.VarargLiteral() }
  end
  local argsTbl = ast.TableConstructor(argItems)
  -- nargs = #params (+ select('#',...) if vararg)
  local nargsExpr
  if isVararg then
    nargsExpr = ast.BinaryExpression("+",
      ast.NumberLiteral(#params, tostring(#params)),
      ast.CallExpression(ast.Identifier("select"),
        { ast.StringLiteral("#", false), ast.VarargLiteral() }))
  else
    nargsExpr = ast.NumberLiteral(#params, tostring(#params))
  end
  -- upcell table: { { v = name1 }, { v = name2 }, ... }
  local upItems = {}
  for i = 1, #boundaryNames do
    upItems[i] = { kind = "item",
      value = ast.TableConstructor({ { kind = "named", key = "v", value = ast.Identifier(boundaryNames[i]) } }) }
  end
  local upTbl = ast.TableConstructor(upItems)
  -- local __ret, __n = VM(proto, upcells, args, nargs)   (randomized names)
  local retName = prng:randomName("_vr")
  local nName = prng:randomName("_vn")
  local call = ast.CallExpression(ast.Identifier(VM), {
    protoLit, upTbl, argsTbl, nargsExpr,
  })
  local decl = ast.LocalStatement({ retName, nName }, { call })
  -- return <UNPK>(__ret, 1, __n)   (UNPK = portable unpack defined in prelude)
  local ret = ast.ReturnStatement({
    ast.CallExpression(ast.Identifier(UNPK),
      { ast.Identifier(retName), ast.NumberLiteral(1, "1"), ast.Identifier(nName) }),
  })
  return { decl, ret }
end

-- Attempt to virtualize a FunctionExpression in place. Returns true on success.
-- enclosing: set of names bound by enclosing scopes; any free name in this set
--   is captured as a boundary upvalue (read-only; writes abort compilation).
local function try_virtualize_func(func, ctx, enc, VM, report, enclosing, UNPK)
  -- Compile the function as a ROOT proto. Free names that are enclosing-scope
  -- locals are captured as read-only BOUNDARY upvalues (passed by the wrapper
  -- as cells); any WRITE to such a name aborts compilation (we cannot propagate
  -- it back to the native local). Free names that are not enclosing locals are
  -- treated as globals (GETGLOBAL/SETGLOBAL). This keeps semantics exactly
  -- correct in all cases; unsupported shapes abort and fall back to native.
  local proto, reason = compile_function_proto(func, nil, enclosing)
  if proto == nil then
    report.skipped[#report.skipped+1] = reason or "unknown"
    return false
  end
  -- The boundary upvalue order is exactly proto.upvals (all are boundary at the
  -- root, since parent is nil). Build the ordered name list for the wrapper.
  local boundaryNames = {}
  for i = 1, #(proto.upvals or {}) do
    local u = proto.upvals[i]
    if not u.boundary then
      -- defensive: a non-boundary upvalue at root should be impossible.
      report.skipped[#report.skipped+1] = "unexpected-root-upval"
      return false
    end
    boundaryNames[i] = u.name
  end
  local protoLit = proto_to_ast(proto, enc, ctx.prng, ctx._vguard)
  func.body = build_wrapper_body(protoLit, func.params, func.isVararg, VM, boundaryNames, ctx.prng, UNPK)
  -- params and vararg-ness are unchanged; the wrapper references params by name
  -- and forwards `...` only when the original function was vararg.
  return true
end

-- Scope-safe selection. We virtualize a function only when every free variable
-- it uses is a GLOBAL (not an enclosing function's local). We compute the set of
-- names bound by enclosing function scopes as we descend; if a candidate
-- function references none of those as free variables, it is safe.
--
-- To keep this robust and simple we use the compiler itself as the oracle:
-- compile_function_proto(func, nil) treats every unresolved name as a global.
-- We additionally scan the function's free names against the enclosing-locals
-- set; if any free name is an enclosing local, we skip (leave native) because
-- virtualizing would change its meaning.

local collect_free -- forward

-- Returns a set {name=true} of free variable names referenced by a function
-- body (names not bound within the function itself). Used for safety checks.
local function free_names_of_function(func)
  local bound = {}
  local free = {}
  for _, p in ipairs(func.params) do bound[p] = true end
  collect_free(func.body, bound, free)
  return free
end

local function add_bound(bound, names)
  local saved = {}
  for _, n in ipairs(names) do saved[n] = bound[n]; bound[n] = true end
  return saved
end

-- Walk a block collecting free names given a mutable `bound` set. New locals
-- introduced in the block are added to `bound` (block scoping approximated as
-- function scoping, which is conservative/safe for the "is it a global?" test).
collect_free = function(stmts, bound, free)
  local walk_expr
  local function walk_list(list) if list then for _, e in ipairs(list) do walk_expr(e) end end end
  walk_expr = function(node)
    if type(node) ~= "table" or not node.type then return end
    local t = node.type
    if t == "Identifier" then
      if not bound[node.name] then free[node.name] = true end
    elseif t == "Paren" then walk_expr(node.expr)
    elseif t == "BinaryExpression" then walk_expr(node.left); walk_expr(node.right)
    elseif t == "UnaryExpression" then walk_expr(node.operand)
    elseif t == "IndexExpression" then
      walk_expr(node.obj)
      if not node.isDot then walk_expr(node.index) end
    elseif t == "CallExpression" then walk_expr(node.callee); walk_list(node.args)
    elseif t == "MethodCallExpression" then walk_expr(node.obj); walk_list(node.args)
    elseif t == "FunctionExpression" then
      local inner = free_names_of_function(node)
      for n in pairs(inner) do if not bound[n] then free[n] = true end end
    elseif t == "TableConstructor" then
      for _, f in ipairs(node.fields) do
        if f.kind == "keyed" then walk_expr(f.key) end
        walk_expr(f.value)
      end
    end
  end
  for _, st in ipairs(stmts) do
    local t = st.type
    if t == "LocalStatement" then
      walk_list(st.exprs)
      for _, nm in ipairs(st.names) do bound[nm] = true end
    elseif t == "LocalFunction" then
      bound[st.name] = true
      walk_expr(st.func)
    elseif t == "AssignmentStatement" then
      walk_list(st.targets); walk_list(st.exprs)
    elseif t == "CallStatement" then walk_expr(st.expr)
    elseif t == "DoStatement" then collect_free(st.body, bound, free)
    elseif t == "IfStatement" then
      for _, cl in ipairs(st.clauses) do walk_expr(cl.cond); collect_free(cl.body, bound, free) end
      if st.elseBody then collect_free(st.elseBody, bound, free) end
    elseif t == "WhileStatement" then walk_expr(st.cond); collect_free(st.body, bound, free)
    elseif t == "RepeatStatement" then collect_free(st.body, bound, free); walk_expr(st.cond)
    elseif t == "NumericForStatement" then
      walk_expr(st.start); walk_expr(st.limit); if st.step then walk_expr(st.step) end
      bound[st.var] = true; collect_free(st.body, bound, free)
    elseif t == "GenericForStatement" then
      walk_list(st.exprs)
      for _, nm in ipairs(st.names) do bound[nm] = true end
      collect_free(st.body, bound, free)
    elseif t == "FunctionDeclaration" then
      walk_expr(st.func)
    elseif t == "ReturnStatement" then walk_list(st.exprs)
    end
  end
end

-- The selection walker. `enclosing` is the set of names bound by enclosing
-- scopes. Strategy: try to virtualize the OUTERMOST candidate function first.
-- If it succeeds, every nested function it contains is absorbed into the same
-- proto tree (compiled as CLOSURE/nested protos) and we do NOT recurse into it.
-- If it aborts (an unsupported construct), we leave it native and descend to
-- try its nested functions individually. This maximizes coverage while never
-- emitting incorrect code.
local function select_and_rewrite(stmts, enclosing, ctx, enc, VM, report, UNPK)
  local attempt -- forward

  -- Recurse into a NON-virtualized function body, extending the enclosing set
  -- with that function's params + locals.
  local function descend(func)
    local inner = {}
    for k in pairs(enclosing) do inner[k] = true end
    for _, p in ipairs(func.params) do inner[p] = true end
    local dummy = {}
    collect_free(func.body, inner, dummy) -- side effect: adds inner locals
    select_and_rewrite(func.body, inner, ctx, enc, VM, report, UNPK)
  end

  -- Try to virtualize `func`; on failure, descend into it.
  attempt = function(func, name)
    if func._virtualized then return end
    if try_virtualize_func(func, ctx, enc, VM, report, enclosing, UNPK) then
      func._virtualized = true
      report.count = report.count + 1
      report.names[#report.names+1] = name
    else
      descend(func)
    end
  end

  local function scan_expr(node)
    if type(node) ~= "table" or not node.type then return end
    local tt = node.type
    if tt == "FunctionExpression" then
      attempt(node, "anon")
    elseif tt == "Paren" then scan_expr(node.expr)
    elseif tt == "BinaryExpression" then scan_expr(node.left); scan_expr(node.right)
    elseif tt == "UnaryExpression" then scan_expr(node.operand)
    elseif tt == "IndexExpression" then scan_expr(node.obj); if not node.isDot then scan_expr(node.index) end
    elseif tt == "CallExpression" then scan_expr(node.callee); if node.args then for _, a in ipairs(node.args) do scan_expr(a) end end
    elseif tt == "MethodCallExpression" then scan_expr(node.obj); if node.args then for _, a in ipairs(node.args) do scan_expr(a) end end
    elseif tt == "TableConstructor" then
      for _, f in ipairs(node.fields) do
        if f.kind == "keyed" then scan_expr(f.key) end
        scan_expr(f.value)
      end
    end
  end

  for _, st in ipairs(stmts) do
    local t = st.type
    if t == "LocalFunction" then
      attempt(st.func, st.name)
    elseif t == "FunctionDeclaration" then
      attempt(st.func, "decl")
    elseif t == "LocalStatement" then
      if st.exprs then for _, e in ipairs(st.exprs) do scan_expr(e) end end
    elseif t == "AssignmentStatement" then
      for _, e in ipairs(st.exprs) do scan_expr(e) end
    elseif t == "CallStatement" then scan_expr(st.expr)
    elseif t == "ReturnStatement" then
      if st.exprs then for _, e in ipairs(st.exprs) do scan_expr(e) end end
    elseif t == "DoStatement" then select_and_rewrite(st.body, enclosing, ctx, enc, VM, report, UNPK)
    elseif t == "IfStatement" then
      for _, cl in ipairs(st.clauses) do scan_expr(cl.cond); select_and_rewrite(cl.body, enclosing, ctx, enc, VM, report, UNPK) end
      if st.elseBody then select_and_rewrite(st.elseBody, enclosing, ctx, enc, VM, report, UNPK) end
    elseif t == "WhileStatement" then scan_expr(st.cond); select_and_rewrite(st.body, enclosing, ctx, enc, VM, report, UNPK)
    elseif t == "RepeatStatement" then select_and_rewrite(st.body, enclosing, ctx, enc, VM, report, UNPK); scan_expr(st.cond)
    elseif t == "NumericForStatement" then
      scan_expr(st.start); scan_expr(st.limit); if st.step then scan_expr(st.step) end
      select_and_rewrite(st.body, enclosing, ctx, enc, VM, report, UNPK)
    elseif t == "GenericForStatement" then
      for _, e in ipairs(st.exprs) do scan_expr(e) end
      select_and_rewrite(st.body, enclosing, ctx, enc, VM, report, UNPK)
    end
  end
end

function pass.run(chunk, ctx)
  local prng = ctx.prng
  local enc = make_encoding(prng)
  -- FEAT-004: when vm_flatten is enabled, emit the interpreter in its
  -- control-flow-flattened state-machine form. This is a mechanical, behavior-
  -- preserving rewrite of the same dispatch logic. vm_flatten has NO effect
  -- unless virtualize is on (there is no VM to flatten otherwise); that no-op
  -- dependency is naturally satisfied because this generator only runs inside
  -- the virtualize pass. The vm_flatten pass (src/obf/passes/vm_flatten.lua)
  -- records the report entry and asserts the dependency.
  local flatten = ctx.config and ctx.config.vm_flatten and true or false

  -- FEAT-005 anti-tamper weaving. When antitamper is enabled we:
  --   * pick per-build checksum parameters (seed, m1, m2) from ctx.prng,
  --   * pick the guard function identifiers NOW and stash them in ctx.guards,
  --     so the antitamper pass (which runs later) emits definitions with the
  --     SAME names and registers them at the front of the prelude,
  --   * embed a per-proto `ck` and weave verification + anti-debug calls into
  --     the emitted interpreter.
  -- The checksum fold here must match guards.lua / the emitted fold exactly.
  local guard = nil
  if ctx.config and ctx.config.antitamper then
    local checksum = require("obf.checksum")
    local gseed = prng:randomInt(1, 4294967295)
    local gm1 = prng:randomInt(1, 2147483647) * 2 + 1 -- odd
    local gm2 = prng:randomInt(1, 2147483647) * 2 + 1 -- odd
    local guards = {
      nfields  = enc.NFIELDS,
      seed     = gseed,
      m1       = gm1,
      m2       = gm2,
      foldName = prng:randomName("_tf"),
      tamperName = prng:randomName("_tr"),
      debugName  = prng:randomName("_td"),
    }
    ctx.guards = guards
    guard = {
      nfields = enc.NFIELDS,
      foldName = guards.foldName,
      tamperName = guards.tamperName,
      debugName = guards.debugName,
      fold = function(physCode, nfields)
        return checksum.fold_code(physCode, nfields, gseed, gm1, gm2)
      end,
    }
  end

  ctx._vguard = guard

  local code, VM, _mkcl, UNPK = gen_interpreter(prng, enc, flatten, guard)

  ctx.report = ctx.report or {}
  local report = { count = 0, names = {}, skipped = {} }

  -- Register the interpreter prelude (once).
  ctx.prelude:register("virtualize.interpreter", code)

  -- Enclosing scope at the chunk level: the chunk's own top-level locals are
  -- locals of the main chunk, so a function referencing one of them is
  -- capturing it. We record them as `enclosing` so they are compiled as
  -- read-only BOUNDARY upvalues (passed in by the wrapper as cells). Names NOT
  -- in this set resolve to globals. This keeps semantics exactly correct.
  local enclosing = {}
  local b = {}
  local dummy = {}
  collect_free(chunk.body, b, dummy) -- b = all top-level local names
  for k in pairs(b) do enclosing[k] = true end

  select_and_rewrite(chunk.body, enclosing, ctx, enc, VM, report, UNPK)

  report.flattened = flatten
  ctx.report.virtualize = report
  return chunk
end

return pass
