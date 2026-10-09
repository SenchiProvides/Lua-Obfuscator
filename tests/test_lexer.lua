-- tests/test_lexer.lua
local root = LUAOBF_ROOT or "."
package.path = root .. "/src/?.lua;" .. root .. "/tests/?.lua;" .. package.path

local harness = require("harness")
local Lexer = require("obf.lexer")

local s = harness.new("lexer")

local function types(src)
  local toks = Lexer.scan(src, "test")
  local out = {}
  for _, t in ipairs(toks) do out[#out+1] = t.type end
  return toks, out
end

s:test("keywords and names", function()
  local toks = Lexer.scan("local x = y", "t")
  s:assert_eq(toks[1].type, "keyword")
  s:assert_eq(toks[1].value, "local")
  s:assert_eq(toks[2].type, "name")
  s:assert_eq(toks[2].value, "x")
  s:assert_eq(toks[3].value, "=")
  s:assert_eq(toks[4].value, "y")
  s:assert_eq(toks[5].type, "eof")
end)

s:test("numbers: int, float, hex, exponent", function()
  local toks = Lexer.scan("10 3.14 0xFF 1e3 0x1p4 .5", "t")
  s:assert_eq(toks[1].value, 10)
  s:assert_eq(toks[2].value, 3.14)
  s:assert_eq(toks[3].value, 255)
  s:assert_eq(toks[4].value, 1000)
  s:assert_eq(toks[5].value, 16)
  s:assert_eq(toks[6].value, 0.5)
end)

s:test("short string escapes", function()
  local toks = Lexer.scan([["a\tb\n\65\x42"]], "t")
  s:assert_eq(toks[1].type, "string")
  s:assert_eq(toks[1].value, "a\tb\nAB")
end)

s:test("single-quote strings", function()
  local toks = Lexer.scan("'hello'", "t")
  s:assert_eq(toks[1].value, "hello")
end)

s:test("long strings", function()
  local toks = Lexer.scan("[[line1\nline2]]", "t")
  s:assert_eq(toks[1].value, "line1\nline2")
  s:assert_eq(toks[1].long, true)
  local toks2 = Lexer.scan("[==[a]]b]==]", "t")
  s:assert_eq(toks2[1].value, "a]]b")
end)

s:test("comments skipped", function()
  local toks = Lexer.scan("-- comment\nx --[[ long\ncomment ]] y", "t")
  s:assert_eq(toks[1].value, "x")
  s:assert_eq(toks[2].value, "y")
  s:assert_eq(toks[3].type, "eof")
end)

s:test("operators long and short", function()
  local toks = Lexer.scan("a == b ~= c .. d ... <=", "t")
  s:assert_eq(toks[2].value, "==")
  s:assert_eq(toks[4].value, "~=")
  s:assert_eq(toks[6].value, "..")
  s:assert_eq(toks[8].value, "...")
  s:assert_eq(toks[9].value, "<=")
end)

s:test("line numbers", function()
  local toks = Lexer.scan("a\n\nb", "t")
  s:assert_eq(toks[1].line, 1)
  s:assert_eq(toks[2].line, 3)
end)

s:test("unfinished string errors", function()
  local ok = pcall(function() Lexer.scan('"abc', "t") end)
  s:assert_true(not ok, "should error on unfinished string")
end)

s:summary()
return { passed = s.passed, failed = s.failed }
