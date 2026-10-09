-- tests/test_vm_selftest.lua
-- Build-time differential self-test for the code-virtualization VM (addresses
-- the safe-fallback CLASS GAP from the semantic review).
--
-- The safe-fallback contract only protects UNSUPPORTED constructs: an
-- unsupported construct aborts compilation of its function and is left native.
-- It does NOT protect a SUPPORTED-but-miscompiled opcode path -- such a
-- function is virtualized and may silently emit wrong code (this is exactly how
-- the inverted `repeat/until` TEST operand shipped green: `repeat` is supported,
-- so it was compiled, just incorrectly, and no test ran it through the VM).
--
-- This file is that missing safety net. For a battery of covered constructs it:
--   1. compiles the snippet through a FRESHLY generated VM (virtualize-only),
--   2. runs the virtualized output under the configured runtime (LUA_BIN),
--   3. runs the original natively,
--   4. asserts byte-identical stdout AND that the function was actually
--      virtualized (so we are testing the VM, not an accidental fallback).
--
-- It repeats across several PRNG seeds so a construct that is correct for one
-- opcode numbering but broken for another is still caught. If any supported
-- construct is miscompiled, this test FAILS -- turning "ships green" into
-- "fails the build" (make test is part of the build/verify gate).

local root = LUAOBF_ROOT or "."
package.path = root .. "/src/?.lua;" .. root .. "/tests/?.lua;" .. package.path

local harness = require("harness")
local pipeline = require("obf.pipeline")
local config = require("obf.config")

local s = harness.new("vm_selftest")
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
  return string.format("%s/luaobf_st_%d_%d.tmp.lua", base, os.time() % 100000, counter)
end

local function virt(src, seed)
  local cfg = config.new({
    seed = seed, target = "5.1",
    string_encrypt = false, virtualize = true, vm_flatten = false, antitamper = false,
  })
  return pipeline.process_ex(src, cfg)
end

-- The construct battery. Each entry must contain at least one function that the
-- compiler can virtualize; we assert count>=1 so a silent fallback can't hide a
-- miscompile. ALL loop forms are present on purpose (while/numeric-for/
-- generic-for/repeat), since the review's bug was in a loop form with no
-- behavioral coverage.
local BATTERY = {
  ["arith/precedence"] = [[
local function f(a,b,c) return a + b*c - a/b, 2^3^2, -2^2, 7 % 3, (-7) % 3 end
print(f(10,2,3))
]],
  ["concat/coerce"] = [[
local function f(a,b,n) return a..b.."!", "n="..n end
print(f("ab","cd",42))
]],
  ["compare/logic"] = [[
local function f(a,b) return a<b, a<=b, a==b, a~=b, (a and b), (a or b), not a end
print(f(1,2))
]],
  ["if/elseif/else"] = [[
local function g(n) if n<0 then return "neg" elseif n==0 then return "zero" else return "pos" end end
print(g(-1), g(0), g(5))
]],
  ["while/break"] = [[
local function g(n) local i,s=0,0 while true do i=i+1 if i>n then break end s=s+i end return s end
print(g(5))
]],
  ["repeat/until multi-iteration"] = [[
local function g(n) local i,s=0,0 repeat i=i+1 s=s+i until i>=n return s end
print(g(0), g(1), g(5))
]],
  ["repeat/until immediate-exit"] = [[
local function g() local i=0 repeat i=i+1 until true return i end
print(g())
]],
  ["repeat/until with break"] = [[
local function g() local i=0 repeat i=i+1 if i==3 then break end until i>=10 return i end
print(g())
]],
  ["repeat/until loop-local cond"] = [[
local function digits(x) local d=0 repeat d=d+1 x=math.floor(x/10) until x==0 return d end
print(digits(0), digits(7), digits(90125))
]],
  ["numeric-for/step"] = [[
local function g(a,b,st) local t=0 for i=a,b,st do t=t+i end return t end
print(g(1,10,1), g(10,1,-2), g(0,20,5))
]],
  ["generic-for"] = [[
local function g(t) local s=0 for _,v in ipairs(t) do s=s+v end return s end
print(g({2,4,6,8}))
]],
  ["closures/upvalues"] = [[
local function mk(n) return function() n=n+1 return n end end
local c=mk(10) print(c(),c(),c())
]],
  ["multret/recursion"] = [[
local function mm(a,b) if a<b then return a,b else return b,a end end
local function fib(n) if n<2 then return n end return fib(n-1)+fib(n-2) end
print(mm(3,1)) print(fib(12))
]],
  ["tables/length/method"] = [[
local V={} V.__index=V function V.new(x) return setmetatable({x=x},V) end function V:get() return self.x end
local t={} for i=1,5 do t[i]=i*i end t.name="sq"
print(t[1],t[5],t.name,#t, V.new(9):get())
]],
  ["varargs"] = [[
local function sum(...) local t=0 for _,v in ipairs({...}) do t=t+v end return t end
local function cnt(...) return select("#",...) end
print(sum(1,2,3,4), cnt(1,nil,3))
]],
}

local SEEDS = { 1, 7, 42, 1337 }

local order = {}
for k in pairs(BATTERY) do order[#order+1] = k end
table.sort(order)

for _, label in ipairs(order) do
  local src = BATTERY[label]
  s:test("selftest: " .. label .. " (" .. LUA_BIN .. ")", function()
    local native_path = tmp()
    write_file(native_path, src)
    local native_out = run_lua(native_path)
    os.remove(native_path)
    for _, seed in ipairs(SEEDS) do
      local obf, ctx = virt(src, seed)
      local c = ctx.report and ctx.report.virtualize and ctx.report.virtualize.count or 0
      s:assert_true(c >= 1,
        label .. ": expected >=1 virtualized function (seed " .. seed ..
        "), got " .. tostring(c) .. " -- a silent fallback would hide a miscompile")
      local vp = tmp()
      write_file(vp, obf)
      local vout = run_lua(vp)
      os.remove(vp)
      s:assert_eq(vout, native_out,
        label .. ": virtualized stdout must match native (seed " .. seed .. ")")
    end
  end)
end

s:summary()
return { passed = s.passed, failed = s.failed }
