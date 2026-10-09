-- tests/test_virtualize.lua
-- Focused tests for Technique 1 (Code Virtualization, FEAT-003).
--
-- For each snippet we build a tiny self-contained program that prints a result,
-- then run it in two forms under the configured Lua interpreter (LUA_BIN):
--   1. NATIVE   : the original source.
--   2. VIRTUAL  : obfuscated with ONLY the virtualize pass enabled.
-- We assert the two produce byte-identical stdout. This proves every covered
-- construct is executed correctly by the embedded VM. A separate test proves an
-- UNSUPPORTED construct is left native (fallback) and still correct, and that
-- different seeds yield different interpreter bytes but equivalent behavior.
--
-- The interpreter under test is selected by LUA_BIN (default lua5.1) so the
-- suite runs under Lua 5.1, Lua 5.4 and LuaJIT.

local root = LUAOBF_ROOT or "."
package.path = root .. "/src/?.lua;" .. root .. "/tests/?.lua;" .. package.path

local harness = require("harness")
local pipeline = require("obf.pipeline")
local config = require("obf.config")

local s = harness.new("virtualize")
local LUA_BIN = os.getenv("LUA_BIN") or "lua5.1"

local function write_file(path, data)
  local f = assert(io.open(path, "wb")); f:write(data); f:close()
end
local function run_lua(path)
  local p = assert(io.popen(string.format('%s "%s" 2>&1', LUA_BIN, path), "r"))
  local out = p:read("*a"); p:close(); return out
end
local counter = 0
local function tmp()
  counter = counter + 1
  local base = os.getenv("TMPDIR") or "/tmp"
  return string.format("%s/luaobf_vt_%d_%d.tmp.lua", base, os.time() % 100000, counter)
end

-- Obfuscate with ONLY virtualize enabled; return (output, ctx).
local function virt(src, seed)
  local cfg = config.new({
    seed = seed or 7, target = "5.1",
    string_encrypt = false, virtualize = true, vm_flatten = false, antitamper = false,
  })
  return pipeline.process_ex(src, cfg)
end

-- Assert native and virtualized forms produce identical stdout, and (optionally)
-- that at least `minv` functions were virtualized.
local function check(label, src, minv)
  s:test("vm equivalence: " .. label .. " (" .. LUA_BIN .. ")", function()
    local obf, ctx = virt(src)
    local pn, pv = tmp(), tmp()
    write_file(pn, src); write_file(pv, obf)
    local on = run_lua(pn); local ov = run_lua(pv)
    os.remove(pn); os.remove(pv)
    s:assert_eq(ov, on, "stdout identical for " .. label)
    if minv then
      local c = ctx.report and ctx.report.virtualize and ctx.report.virtualize.count or 0
      s:assert_true(c >= minv, label .. ": expected >=" .. minv .. " virtualized, got " .. tostring(c))
    end
  end)
end

-- ---- covered-construct snippets ---------------------------------------------

check("arithmetic precedence", [[
local function f(a, b, c) return a + b * c - a / b end
local function g() return 2 ^ 3 ^ 2 end       -- right assoc -> 512
local function h() return -2 ^ 2 end          -- -4
print(f(10, 2, 3), g(), h())
]], 3)

check("string concat and coercion", [[
local function f(a, b) return a .. b .. "!" end
local function g(n) return "n=" .. n end       -- number coerced to string
print(f("ab", "cd"), g(42))
]], 2)

check("comparisons and boolean logic (short circuit)", [[
local function cmp(a, b) return a < b, a <= b, a == b, a ~= b, a > b, a >= b end
local function land(a, b) return a and b end
local function lor(a, b) return a or b end
local function sc() local calls = 0
  local function side() calls = calls + 1; return true end
  local r = false and side()       -- side must NOT run
  return calls, r
end
print(cmp(1, 2))
print(land(nil, 5), land(3, 5), lor(nil, 7), lor(3, 7))
print(sc())
]], 3)

check("if elseif else", [[
local function classify(n)
  if n < 0 then return "neg"
  elseif n == 0 then return "zero"
  else return "pos" end
end
print(classify(-5), classify(0), classify(9))
]], 1)

check("while loop with break", [[
local function firstmul(a, b, limit)
  local i = 1
  while true do
    local v = a * i
    if v % b == 0 then return v end
    if i > limit then break end
    i = i + 1
  end
  return -1
end
print(firstmul(3, 4, 100))
]], 1)

check("repeat until (immediate exit, multi-iteration, loop-local condition)", [[
local function immediate()
  -- until-condition is TRUE on the first check: body runs exactly once.
  local i = 0
  repeat i = i + 1 until true
  return i
end
local function multi(limit)
  -- multi-iteration; the until-condition reads the loop-local `i`.
  local i = 0
  repeat i = i + 1 until i >= limit
  return i
end
local function sumto(n)
  local i, s = 0, 0
  repeat
    i = i + 1
    s = s + i
  until i >= n
  return s
end
print(immediate(), multi(1), multi(4), multi(10), sumto(5))
]], 3)

check("repeat until with break (break fires before until condition)", [[
local function withbreak()
  local i = 0
  repeat
    i = i + 1
    if i == 3 then break end   -- break exits before the until check
  until i >= 10
  return i
end
local function noearly()
  -- break never fires; loop terminates via the until condition.
  local i = 0
  repeat
    i = i + 1
    if i == 100 then break end
  until i >= 4
  return i
end
print(withbreak(), noearly())
]], 2)

check("numeric for with step", [[
local function sumstep(a, b, step)
  local t = 0
  for i = a, b, step do t = t + i end
  return t
end
print(sumstep(1, 10, 1), sumstep(10, 1, -2), sumstep(0, 20, 5))
]], 1)

check("generic for over ipairs and pairs", [[
local function sumlist(t)
  local s = 0
  for _, v in ipairs(t) do s = s + v end
  return s
end
local function countkeys(t)
  local n = 0
  for k in pairs(t) do n = n + 1 end
  return n
end
print(sumlist({ 2, 4, 6, 8 }), countkeys({ a = 1, b = 2, c = 3 }))
]], 2)

check("closures capturing upvalues", [[
local function make_counter(start)
  local n = start
  return function()
    n = n + 1
    return n
  end
end
local c = make_counter(10)
print(c(), c(), c())
]], 1)

check("multiple return values", [[
local function minmax(a, b, c)
  local lo, hi = a, a
  if b < lo then lo = b end; if b > hi then hi = b end
  if c < lo then lo = c end; if c > hi then hi = c end
  return lo, hi
end
local function wrap() return minmax(7, 2, 9) end  -- forwards multret
print(minmax(3, 1, 2))
print(wrap())
]], 2)

check("recursion", [[
local function fact(n) if n <= 1 then return 1 end return n * fact(n - 1) end
local function fib(n) if n < 2 then return n end return fib(n-1) + fib(n-2) end
print(fact(6), fib(12))
]], 2)

check("table read write and length", [[
local function build(n)
  local t = {}
  for i = 1, n do t[i] = i * i end
  t.name = "sq"
  return t, #t
end
local tbl, len = build(5)
print(tbl[1], tbl[5], tbl.name, len)
]], 1)

check("method calls", [[
local V = {}
V.__index = V
function V.new(x) return setmetatable({ x = x }, V) end
function V:get() return self.x end
function V:add(o) return V.new(self.x + o.x) end
local a = V.new(3)
local b = V.new(4)
print(a:get(), a:add(b):get())
]], 2)

check("varargs", [[
local function sum(...)
  local t = 0
  for _, v in ipairs({ ... }) do t = t + v end
  return t
end
local function count(...) return select("#", ...) end
print(sum(1, 2, 3, 4), count(1, nil, 3))
]], 2)

check("nested table constructor with call expansion", [[
local function three() return 1, 2, 3 end
local function pack() return { three() } end       -- array fill from multret
local function mixed() return { "a", three(), key = "v" } end -- middle call -> 1 val
local t = pack()
print(#t, t[1], t[3])
local m = mixed()
print(m[1], m[2], m.key, #m)
]], 2)

-- ---- fallback: an unsupported construct is left NATIVE and still correct ----

s:test("fallback: writing an outer local keeps function native but correct (" .. LUA_BIN .. ")", function()
  local src = [[
local total = 0
local function bump(x)
  total = total + x   -- writes a boundary upvalue: compiler must fall back
  return total
end
print(bump(3), bump(4), total)
]]
  local obf, ctx = virt(src)
  -- bump must NOT be virtualized (it writes an outer local).
  local names = ctx.report.virtualize.names
  local sawBump = false
  for _, n in ipairs(names) do if n == "bump" then sawBump = true end end
  s:assert_true(not sawBump, "bump should be left native (fallback)")
  -- and the output must still match native execution exactly.
  local pn, pv = tmp(), tmp()
  write_file(pn, src); write_file(pv, obf)
  local on = run_lua(pn); local ov = run_lua(pv)
  os.remove(pn); os.remove(pv)
  s:assert_eq(ov, on, "fallback output still correct")
end)

-- ---- decompiler-resistance smoke: original structure is gone --------------

s:test("resistance: original expression text absent, behavior preserved (" .. LUA_BIN .. ")", function()
  local src = [[
local function secret(a, b) return a * 1337 + b * 7919 end
print(secret(2, 3))
]]
  local obf, ctx = virt(src)
  s:assert_true(ctx.report.virtualize.count >= 1, "secret virtualized")
  -- The identifiable literal arithmetic must not survive verbatim.
  s:assert_true(string.find(obf, "a * 1337", 1, true) == nil,
    "literal arithmetic text absent from virtualized output")
  -- The constants still exist (as data) but the source structure is gone;
  -- behavior must match.
  local pn, pv = tmp(), tmp()
  write_file(pn, src); write_file(pv, obf)
  local on = run_lua(pn); local ov = run_lua(pv)
  os.remove(pn); os.remove(pv)
  s:assert_eq(ov, on, "behavior preserved")
end)

-- ---- different seeds: different interpreter bytes, equal behavior ----------

s:test("seeds: different numbering/shape, same behavior (" .. LUA_BIN .. ")", function()
  local src = [[
local function f(n) local s = 0 for i = 1, n do s = s + i end return s end
print(f(100))
]]
  local a = virt(src, 11)
  local b = virt(src, 22)
  s:assert_neq(a, b, "different seeds produce different bytes")
  local pa, pb = tmp(), tmp()
  write_file(pa, a); write_file(pb, b)
  local oa = run_lua(pa); local ob = run_lua(pb)
  os.remove(pa); os.remove(pb)
  s:assert_eq(oa, ob, "both seeds behave identically")
  s:assert_eq(oa, "5050\n", "value correct")
end)

s:summary()
return { passed = s.passed, failed = s.failed }
