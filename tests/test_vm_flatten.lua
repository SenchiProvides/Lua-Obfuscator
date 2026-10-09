-- tests/test_vm_flatten.lua
-- Focused tests for Technique 2 (Control Flow Flattening of the VM interpreter,
-- FEAT-004).
--
-- The strategy mirrors tests/test_virtualize.lua: for each covered-construct
-- snippet we obfuscate twice with ONLY virtualize enabled -- once with
-- vm_flatten OFF (the structured REFERENCE interpreter) and once with
-- vm_flatten ON (the FLATTENED state-machine interpreter) -- run both under the
-- configured Lua interpreter (LUA_BIN) and assert they produce byte-identical
-- stdout, and that both match NATIVE execution. This proves the flattened form
-- is a faithful, behavior-preserving rewrite of the reference form.
--
-- We also assert:
--   * STRUCTURAL: the flattened interpreter is demonstrably flattened -- a
--     single dispatcher `while true do` loop over a state variable with
--     multiple randomized state IDs (far more states than the reference form).
--   * JUNK: removing the per-build variability (fixed seed) still yields
--     correct output, i.e. junk/opaque states never change behavior.
--   * VARIABILITY: two different seeds yield different flattened layouts
--     (different state numbering / junk count / names), both runtime-equivalent.
--
-- The interpreter under test is selected by LUA_BIN (default lua5.1), so the
-- suite runs under Lua 5.1, Lua 5.4 and LuaJIT.

local root = LUAOBF_ROOT or "."
package.path = root .. "/src/?.lua;" .. root .. "/tests/?.lua;" .. package.path

local harness = require("harness")
local pipeline = require("obf.pipeline")
local config = require("obf.config")

local s = harness.new("vm_flatten")
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
  return string.format("%s/luaobf_ft_%d_%d.tmp.lua", base, os.time() % 100000, counter)
end

-- Obfuscate with ONLY virtualize enabled; `flat` toggles vm_flatten.
local function obf(src, flat, seed)
  local cfg = config.new({
    seed = seed or 7, target = "5.1",
    string_encrypt = false, virtualize = true,
    vm_flatten = flat and true or false, antitamper = false,
  })
  return pipeline.process_ex(src, cfg)
end

-- Run a source string under LUA_BIN, returning stdout.
local function run_src(src)
  local p = tmp(); write_file(p, src)
  local out = run_lua(p); os.remove(p)
  return out
end

-- Core check: flattened == reference == native, for one snippet.
local function check(label, src)
  s:test("flat == reference == native: " .. label .. " (" .. LUA_BIN .. ")", function()
    local ref, refctx = obf(src, false)
    local flt, fltctx = obf(src, true)

    -- Both must have virtualized at least one function (otherwise there is no
    -- VM to flatten and the test would be vacuous).
    s:assert_true(refctx.report.virtualize.count >= 1, label .. ": reference virtualized >=1")
    s:assert_true(fltctx.report.virtualize.count >= 1, label .. ": flattened virtualized >=1")
    s:assert_true(fltctx.report.virtualize.flattened == true, label .. ": flattened flag set")
    s:assert_true(refctx.report.virtualize.flattened == false, label .. ": reference flag unset")

    local native = run_src(src)
    local refout = run_src(ref)
    local fltout = run_src(flt)
    s:assert_eq(refout, native, label .. ": reference matches native")
    s:assert_eq(fltout, native, label .. ": flattened matches native")
    s:assert_eq(fltout, refout, label .. ": flattened matches reference")
  end)
end

-- ---- the FEAT-003 construct snippets (same coverage as test_virtualize) -----

check("arithmetic precedence", [[
local function f(a, b, c) return a + b * c - a / b end
local function g() return 2 ^ 3 ^ 2 end
local function h() return -2 ^ 2 end
print(f(10, 2, 3), g(), h())
]])

check("string concat and coercion", [[
local function f(a, b) return a .. b .. "!" end
local function g(n) return "n=" .. n end
print(f("ab", "cd"), g(42))
]])

check("comparisons and boolean logic (short circuit)", [[
local function cmp(a, b) return a < b, a <= b, a == b, a ~= b, a > b, a >= b end
local function land(a, b) return a and b end
local function lor(a, b) return a or b end
local function sc() local calls = 0
  local function side() calls = calls + 1; return true end
  local r = false and side()
  return calls, r
end
print(cmp(1, 2))
print(land(nil, 5), land(3, 5), lor(nil, 7), lor(3, 7))
print(sc())
]])

check("if elseif else", [[
local function classify(n)
  if n < 0 then return "neg"
  elseif n == 0 then return "zero"
  else return "pos" end
end
print(classify(-5), classify(0), classify(9))
]])

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
]])

check("numeric for with step", [[
local function sumstep(a, b, step)
  local t = 0
  for i = a, b, step do t = t + i end
  return t
end
print(sumstep(1, 10, 1), sumstep(10, 1, -2), sumstep(0, 20, 5))
]])

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
]])

check("closures capturing upvalues", [[
local function make_counter(start)
  local n = start
  return function() n = n + 1; return n end
end
local c = make_counter(10)
print(c(), c(), c())
]])

check("multiple return values", [[
local function minmax(a, b, c)
  local lo, hi = a, a
  if b < lo then lo = b end; if b > hi then hi = b end
  if c < lo then lo = c end; if c > hi then hi = c end
  return lo, hi
end
local function wrap() return minmax(7, 2, 9) end
print(minmax(3, 1, 2))
print(wrap())
]])

check("recursion", [[
local function fact(n) if n <= 1 then return 1 end return n * fact(n - 1) end
local function fib(n) if n < 2 then return n end return fib(n-1) + fib(n-2) end
print(fact(6), fib(12))
]])

check("table read write and length", [[
local function build(n)
  local t = {}
  for i = 1, n do t[i] = i * i end
  t.name = "sq"
  return t, #t
end
local tbl, len = build(5)
print(tbl[1], tbl[5], tbl.name, len)
]])

check("method calls", [[
local V = {}
V.__index = V
function V.new(x) return setmetatable({ x = x }, V) end
function V:get() return self.x end
function V:add(o) return V.new(self.x + o.x) end
local a = V.new(3)
local b = V.new(4)
print(a:get(), a:add(b):get())
]])

check("varargs", [[
local function sum(...)
  local t = 0
  for _, v in ipairs({ ... }) do t = t + v end
  return t
end
local function count(...) return select("#", ...) end
print(sum(1, 2, 3, 4), count(1, nil, 3))
]])

check("nested table constructor with call expansion", [[
local function three() return 1, 2, 3 end
local function pack() return { three() } end
local function mixed() return { "a", three(), key = "v" } end
local t = pack()
print(#t, t[1], t[3])
local m = mixed()
print(m[1], m[2], m.key, #m)
]])

-- ---- STRUCTURAL: the flattened interpreter has a flattened dispatcher shape --

s:test("structural: single dispatcher loop over a state variable with many states (" .. LUA_BIN .. ")", function()
  local src = [[
local function f(n) local acc = 0 for i = 1, n do acc = acc + i end return acc end
print(f(10))
]]
  local flt = obf(src, true, 42)
  local ref = obf(src, false, 42)

  -- The flattened interpreter must contain a state variable (named with the
  -- "_st" prefix the flattener uses) compared against many distinct numeric
  -- state IDs inside a single while-true dispatcher.
  local stateVar = string.match(flt, "(_st%w+)")
  s:assert_true(stateVar ~= nil, "flattened output declares a state variable")

  -- Collect the distinct state IDs the dispatcher branches on: `<stateVar>==N`.
  local ids = {}
  local ncmp = 0
  for id in string.gmatch(flt, stateVar .. "==(%d+)") do
    ncmp = ncmp + 1
    ids[id] = true
  end
  local distinct = 0
  for _ in pairs(ids) do distinct = distinct + 1 end
  -- 2 real states (fetch + dispatch) + at least 3 junk states => >= 5 distinct.
  s:assert_true(distinct >= 5, "flattened dispatcher has >=5 distinct states, got " .. distinct)

  -- There must be exactly ONE top-level dispatch loop keyed on the state var:
  -- i.e. the state var is both initialized and compared, and the reference
  -- interpreter (vm_flatten off) does NOT contain this state variable pattern.
  local refHasState = string.match(ref, "_st%w+==%d") ~= nil
  s:assert_true(not refHasState, "reference interpreter has no flattened state dispatch")

  -- The flattened interpreter should have strictly MORE `while true do` /
  -- dispatch surface than the reference: concretely, the state IDs are large
  -- randomized numbers (>= 1000), unlike opcode numbers (small).
  local big = 0
  for id in pairs(ids) do if tonumber(id) >= 1000 then big = big + 1 end end
  s:assert_true(big >= 5, "state IDs are large randomized numbers (maze), got " .. big)

  -- behavior still correct
  s:assert_eq(run_src(flt), "55\n", "flattened structural sample correct")
end)

-- ---- JUNK: junk/opaque states never change behavior -------------------------

s:test("junk states do not change behavior across seeds (" .. LUA_BIN .. ")", function()
  -- Different seeds insert different junk states (count + ids + names). If any
  -- junk state could ever be reached it would corrupt output; so running many
  -- seeds and getting identical correct output demonstrates junk is inert.
  local src = [[
local function g(n)
  local s = 0
  for i = 1, n do
    if i % 2 == 0 then s = s + i else s = s - i end
  end
  return s
end
print(g(20))
]]
  local native = run_src(src)
  for _, seed in ipairs({ 1, 2, 3, 7, 13, 99, 1000, 54321 }) do
    local flt, ctx = obf(src, true, seed)
    s:assert_true(ctx.report.virtualize.flattened == true, "seed " .. seed .. " flattened")
    s:assert_eq(run_src(flt), native, "junk-inert: seed " .. seed .. " matches native")
  end
end)

-- ---- VARIABILITY: different seeds -> different layouts, all equivalent -------

s:test("different seeds yield different flattened layouts, both equivalent (" .. LUA_BIN .. ")", function()
  local src = [[
local function f(n) local s = 0 for i = 1, n do s = s + i end return s end
print(f(100))
]]
  local a = obf(src, true, 11)
  local b = obf(src, true, 22)
  s:assert_neq(a, b, "different seeds produce different flattened bytes")

  -- state ID sets should differ between the two builds.
  local function state_ids(txt)
    local v = string.match(txt, "(_st%w+)")
    local set = {}
    if v then for id in string.gmatch(txt, v .. "==(%d+)") do set[id] = true end end
    return set
  end
  local ida, idb = state_ids(a), state_ids(b)
  local differ = false
  for id in pairs(ida) do if not idb[id] then differ = true break end end
  if not differ then for id in pairs(idb) do if not ida[id] then differ = true break end end end
  s:assert_true(differ, "state ID numbering differs between seeds")

  -- both equivalent to native
  s:assert_eq(run_src(a), run_src(b), "both seeds behave identically")
  s:assert_eq(run_src(a), "5050\n", "value correct")
end)

-- ---- DEPENDENCY: vm_flatten is a no-op when virtualize is off ---------------

s:test("vm_flatten is a documented no-op when virtualize is off", function()
  local src = [[
local x = "hello"
print(x)
]]
  local cfg = config.new({
    seed = 5, target = "5.1",
    string_encrypt = false, virtualize = false,
    vm_flatten = true, antitamper = false,
  })
  local out, ctx = pipeline.process_ex(src, cfg)
  s:assert_true(ctx.report.vm_flatten ~= nil, "vm_flatten pass ran")
  s:assert_true(ctx.report.vm_flatten.active == false, "vm_flatten inactive (no VM to flatten)")
  -- output still runs and matches native
  s:assert_eq(run_src(out), run_src(src), "no-op output equivalent to native")
end)

s:summary()
return { passed = s.passed, failed = s.failed }
