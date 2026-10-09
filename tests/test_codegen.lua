-- tests/test_codegen.lua
-- Round-trip structural checks: parse(x) -> gen -> parse(gen) should produce an
-- equivalent AST, and generated source must load under the running interpreter.
local root = LUAOBF_ROOT or "."
package.path = root .. "/src/?.lua;" .. root .. "/tests/?.lua;" .. package.path

local harness = require("harness")
local parser = require("obf.parser")
local codegen = require("obf.codegen")

local s = harness.new("codegen")

-- Structural AST comparison ignoring the exact table identity. Compares the
-- subset of fields that define semantics.
local function ast_eq(a, b)
  if type(a) ~= type(b) then return false end
  if type(a) ~= "table" then return a == b end
  -- compare type tags
  if a.type ~= b.type then return false end
  -- gather keys from both
  local keys = {}
  for k in pairs(a) do keys[k] = true end
  for k in pairs(b) do keys[k] = true end
  for k in pairs(keys) do
    if k ~= "text" then -- numeric 'text' may be reformatted; value is what matters
      if not ast_eq(a[k], b[k]) then return false end
    end
  end
  return true
end

local function roundtrip(src)
  local ast1 = parser.parse(src, "orig")
  local gen = codegen.generate(ast1)
  local ast2 = parser.parse(gen, "regen")
  return ast1, ast2, gen
end

local CASES = {
  "local x = 1",
  "local a, b, c = 1, 2.5, 'str'",
  "x = 2 + 3 * 4 - 1",
  "x = 2 ^ 3 ^ 2",
  "x = -2 ^ 2",
  "x = 'a' .. 'b' .. 'c'",
  "x = not (a == b) and c or d",
  "if a then b() elseif c then d() else e() end",
  "while x < 10 do x = x + 1 end",
  "repeat y() until done",
  "for i = 1, 10, 2 do print(i) end",
  "for k, v in pairs(t) do print(k, v) end",
  "function a.b:m(x, y) return x + y end",
  "local function f(...) return ... end",
  "t = { 1, 2, k = 3, [1 + 1] = 4, ['weird key'] = 5 }",
  "print((f()))",
  "do local z = 1 end",
  "return 1, 2, 3",
}

for i, src in ipairs(CASES) do
  s:test("roundtrip #" .. i .. ": " .. src, function()
    local a1, a2, gen = roundtrip(src)
    s:assert_true(ast_eq(a1, a2), "AST stable; gen was: " .. gen)
    -- also ensure generated code loads
    local chunk, err = loadstring and loadstring(gen) or load(gen)
    s:assert_true(chunk ~= nil, "generated loads: " .. tostring(err) .. " | " .. gen)
  end)
end

s:test("number formatting preserves value", function()
  local vals = { 0, 1, -1, 42, 3.14159, 1e10, 0.5, 100000000, 2.5 }
  for _, v in ipairs(vals) do
    local src = "return " .. string.format("%.17g", v)
    local ast = parser.parse(src, "t")
    local gen = codegen.generate(ast)
    local chunk = (loadstring or load)(gen)
    s:assert_true(chunk ~= nil, "generated loads for " .. tostring(v))
    local got = chunk()
    s:assert_eq(got, v, "value preserved for " .. tostring(v))
  end
end)

s:test("string requoting handles specials", function()
  local original = "tab\there\nnewline\"quote\\back"
  local src = "return " .. codegen.quote_string(original)
  local ast = parser.parse(src, "t")
  local gen = codegen.generate(ast)
  local chunk = (loadstring or load)(gen)
  s:assert_true(chunk ~= nil, "generated loads")
  s:assert_eq(chunk(), original)
end)

s:test("two seeds wired but identity output stable", function()
  -- codegen itself is seed-independent (passes consume the prng); confirm the
  -- identity output is byte-stable regardless.
  local src = "local a = 1\nprint(a)\n"
  local g1 = codegen.generate(parser.parse(src, "t"))
  local g2 = codegen.generate(parser.parse(src, "t"))
  s:assert_eq(g1, g2, "identity codegen deterministic")
end)

s:summary()
return { passed = s.passed, failed = s.failed }
