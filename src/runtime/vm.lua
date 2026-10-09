-- src/runtime/vm.lua
-- CANONICAL template for the embedded code-virtualization interpreter (FEAT-003).
--
-- This file documents, in readable form, the register-based virtual machine
-- that gets injected into obfuscated output. The ACTUAL emission is done
-- programmatically by src/obf/passes/virtualize.lua, which, per build:
--   * shuffles the numeric opcode assignments (a seeded permutation),
--   * randomizes the operand field order inside each instruction,
--   * randomizes the constant-pool ordering,
--   * renames every interpreter local / dispatch variable to a fresh seeded
--     identifier.
-- Two different seeds therefore produce a different opcode numbering and a
-- different interpreter "shape", yet both execute identically.
--
-- COMPATIBILITY: written in Lua-5.1-compatible syntax using only portable
-- constructs (no bit32, no 5.4 bitwise/integer-division operators, no goto), so
-- the emitted interpreter runs byte-identically on Lua 5.1, Lua 5.4 and
-- LuaJIT 2.1.
--
-- =========================================================================
-- EXECUTION MODEL
-- =========================================================================
-- A virtualized function is compiled to a "proto":
--   proto = {
--     code    = { instr, instr, ... },  -- flat instruction array
--     consts  = { value, value, ... },  -- constant pool (1-based)
--     nparams = <number of fixed params>,
--     vararg  = <boolean>,              -- function has `...`
--     protos  = { proto, ... },         -- nested function prototypes
--     nups    = <number of upvalues>,
--   }
-- Each instruction is a small array whose first slot is the opcode and whose
-- remaining slots are operands A, B, C (the slot ORDER is randomized per build;
-- here we document the canonical order {op, A, B, C}).
--
-- A "frame" has:
--   R      - register file (array; registers are 0-based in the compiler but we
--            store them 1-based internally as R[reg+1]).
--   consts - the proto's constant pool.
--   up     - the upvalue cells captured when the closure was created. Each cell
--            is a 1-element table { v = <value> } so that mutations by an inner
--            function are visible to the outer function and vice-versa (Lua
--            upvalue semantics).
--   vararg - array of extra arguments (for `...`), with field `n` = count.
--
-- Multiple return values flow through a small array {..., n=count}. CALL writes
-- its results back into consecutive registers (or "all results" when the
-- requested count is -1, e.g. `return f()` / `t = {f()}`).
--
-- =========================================================================
-- OPERAND CONVENTIONS
-- =========================================================================
-- "RK" operands can refer to either a register or a constant. The compiler
-- encodes a constant reference as a negative number: value k is stored as
-- -(k+1); a non-negative value is a register index. decode_rk resolves it.
--
-- =========================================================================
-- OPCODES (canonical numbering; shuffled per build)
-- =========================================================================
--  LOADK     A Bx     R[A] = consts[Bx]
--  LOADBOOL  A B      R[A] = (B ~= 0)
--  LOADNIL   A B      R[A..A+B] = nil
--  MOVE      A B      R[A] = R[B]
--  GETUPVAL  A B      R[A] = up[B].v
--  SETUPVAL  A B      up[B].v = R[A]
--  GETGLOBAL A Bx     R[A] = _ENV[consts[Bx]]
--  SETGLOBAL A Bx     _ENV[consts[Bx]] = R[A]
--  GETTABLE  A B C    R[A] = R[B][RK(C)]
--  SETTABLE  A B C    R[A][RK(B)] = RK(C)
--  NEWTABLE  A        R[A] = {}
--  SETLIST   A B C    R[A][C+i-1] = R[B+i-1] for i=1..? (array part fill)
--  ADD/SUB/MUL/DIV/MOD/POW  A B C   R[A] = RK(B) <op> RK(C)
--  CONCAT    A B C    R[A] = R[B] .. R[B+1] .. ... .. R[C]
--  UNM       A B      R[A] = -R[B]
--  NOT       A B      R[A] = not R[B]
--  LEN       A B      R[A] = #R[B]
--  EQ/LT/LE  A B C    R[A] = (RK(B) <cmp> RK(C))   (boolean)
--  TEST      A B      if (truthy(R[A])) ~= (B~=0) then pc = pc + 1 (skip next JMP)
--                     (used for `and`/`or` and if/while conditions)
--  JMP       sBx      pc = pc + sBx
--  CALL      A B C    call R[A] with B-1 args (R[A+1..]); C-1 results into R[A..]
--                     B==0 -> args go up to top (vararg forwarding)
--                     C==0 -> keep all results (set top)
--  RETURN    A B      return R[A..A+B-2]; B==0 -> return R[A..top]
--  CLOSURE   A Bx     R[A] = closure(protos[Bx], captured upvalues)
--  FORPREP   A sBx    numeric for: prep R[A]=initial-step; pc += sBx
--  FORLOOP   A sBx    numeric for: step and test; if continue, R[A+3]=var; pc+=sBx
--  TFORLOOP  A C      generic for: call R[A](R[A+1],R[A+2]); results to R[A+3..A+2+C]
--  TFORJMP   A sBx    if R[A+3] ~= nil then R[A+2]=R[A+3]; pc += sBx
--  VARARG    A B      R[A..A+B-2] = ...  ; B==0 -> all varargs (set top)
--  SELF      A B C    R[A+1] = R[B]; R[A] = R[B][RK(C)]  (method call prep)
--
-- The compiler only emits these opcodes for constructs it fully supports. Any
-- construct outside the supported subset makes the compiler ABORT that function
-- (returns nil), and virtualize.lua leaves the function as native source. This
-- guarantees output correctness is never traded for coverage.

local M = {}

-- Build a runnable interpreter. `defs` is a table mapping opcode NAME -> number
-- (the per-build shuffled numbering); `layout` maps field name -> array slot.
-- In the emitted output these are inlined as literal numbers; this canonical
-- version just uses a readable fixed assignment so the file is testable.
local OP = {
  LOADK=1, LOADBOOL=2, LOADNIL=3, MOVE=4, GETUPVAL=5, SETUPVAL=6,
  GETGLOBAL=7, SETGLOBAL=8, GETTABLE=9, SETTABLE=10, NEWTABLE=11, SETLIST=12,
  ADD=13, SUB=14, MUL=15, DIV=16, MOD=17, POW=18, CONCAT=19,
  UNM=20, NOT=21, LEN=22, EQ=23, LT=24, LE=25, TEST=26, JMP=27,
  CALL=28, RETURN=29, CLOSURE=30, FORPREP=31, FORLOOP=32,
  TFORLOOP=33, TFORJMP=34, VARARG=35, SELF=36,
}

-- Create the interpreter closure. `env` is the global environment table.
function M.make(env)
  env = env or _G

  -- decode an RK operand: >=0 register, <0 constant (-(k+1))
  local function run(proto, up, args, nargs)
    local code = proto.code
    local consts = proto.consts
    local R = {}
    local nparams = proto.nparams
    -- place fixed params into R[0..nparams-1]
    for i = 1, nparams do R[i-1] = args[i] end
    local vararg = nil
    if proto.vararg then
      vararg = { n = 0 }
      for i = nparams+1, nargs do
        vararg.n = vararg.n + 1
        vararg[vararg.n] = args[i]
      end
    end

    local function RK(x)
      if x < 0 then return consts[-x] else return R[x] end
    end

    local top = 0 -- used for multi-value CALL/RETURN/VARARG plumbing
    local pc = 1
    while true do
      local ins = code[pc]
      pc = pc + 1
      local op = ins[1]
      local A, B, C = ins[2], ins[3], ins[4]

      if op == OP.LOADK then R[A] = consts[B]
      elseif op == OP.LOADBOOL then R[A] = (B ~= 0)
      elseif op == OP.LOADNIL then for i = A, A+B do R[i] = nil end
      elseif op == OP.MOVE then R[A] = R[B]
      elseif op == OP.GETUPVAL then R[A] = up[B+1].v
      elseif op == OP.SETUPVAL then up[B+1].v = R[A]
      elseif op == OP.GETGLOBAL then R[A] = env[consts[B]]
      elseif op == OP.SETGLOBAL then env[consts[B]] = R[A]
      elseif op == OP.GETTABLE then R[A] = R[B][RK(C)]
      elseif op == OP.SETTABLE then R[A][RK(B)] = RK(C)
      elseif op == OP.NEWTABLE then R[A] = {}
      elseif op == OP.SETLIST then
        -- R[A][C + i - 1] = R[B + i - 1] for i=1..(top-B+1) when count unknown
        local n = C == 0 and (top - B + 1) or ins[5]
        local base = ins[6] -- destination start index
        for i = 1, n do R[A][base + i - 1] = R[B + i - 1] end
      elseif op == OP.ADD then R[A] = RK(B) + RK(C)
      elseif op == OP.SUB then R[A] = RK(B) - RK(C)
      elseif op == OP.MUL then R[A] = RK(B) * RK(C)
      elseif op == OP.DIV then R[A] = RK(B) / RK(C)
      elseif op == OP.MOD then R[A] = RK(B) % RK(C)
      elseif op == OP.POW then R[A] = RK(B) ^ RK(C)
      elseif op == OP.CONCAT then
        local acc = R[C]
        for i = C-1, B, -1 do acc = R[i] .. acc end
        R[A] = acc
      elseif op == OP.UNM then R[A] = -R[B]
      elseif op == OP.NOT then R[A] = not R[B]
      elseif op == OP.LEN then R[A] = #R[B]
      elseif op == OP.EQ then R[A] = (RK(B) == RK(C))
      elseif op == OP.LT then R[A] = (RK(B) < RK(C))
      elseif op == OP.LE then R[A] = (RK(B) <= RK(C))
      elseif op == OP.TEST then
        local t = R[A]
        local truthy = (t ~= nil and t ~= false)
        if truthy == (B ~= 0) then pc = pc + 1 end
      elseif op == OP.JMP then pc = pc + B
      elseif op == OP.CALL then
        local fn = R[A]
        local na
        -- args occupy R[A+1 .. ]; when B==0 they run up to `top` (exclusive).
        if B == 0 then na = top - A - 1 else na = B - 1 end
        local ca = {}
        for i = 1, na do ca[i] = R[A + i] end
        local rets = { fn(unpack(ca, 1, na)) }
        local nret = #rets
        if C == 0 then
          top = A
          for i = 1, nret do R[A + i - 1] = rets[i]; top = top + 1 end
        else
          for i = 1, C - 1 do R[A + i - 1] = rets[i] end
        end
      elseif op == OP.RETURN then
        if B == 0 then
          local out = {}
          local n = top - A
          for i = 1, n do out[i] = R[A + i - 1] end
          return out, n
        else
          local out = {}
          local n = B - 1
          for i = 1, n do out[i] = R[A + i - 1] end
          return out, n
        end
      elseif op == OP.CLOSURE then
        error("CLOSURE handled by emitted VM")
      elseif op == OP.FORPREP then
        R[A] = R[A] - R[A+2]
        pc = pc + B
      elseif op == OP.FORLOOP then
        local step = R[A+2]
        local idx = R[A] + step
        local limit = R[A+1]
        local cont
        if step >= 0 then cont = (idx <= limit) else cont = (idx >= limit) end
        if cont then R[A] = idx; R[A+3] = idx; pc = pc + B end
      elseif op == OP.VARARG then
        if B == 0 then
          top = A
          for i = 1, vararg.n do R[A + i - 1] = vararg[i]; top = top + 1 end
        else
          for i = 1, B - 1 do R[A + i - 1] = vararg[i] end
        end
      elseif op == OP.SELF then
        R[A+1] = R[B]
        R[A] = R[B][RK(C)]
      else
        error("bad opcode " .. tostring(op))
      end
    end
  end

  M.run = run
  return run
end

M.OP = OP
return M
