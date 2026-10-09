-- tests/test_parser.lua
local root = LUAOBF_ROOT or "."
package.path = root .. "/src/?.lua;" .. root .. "/tests/?.lua;" .. package.path

local harness = require("harness")
local parser = require("obf.parser")

local s = harness.new("parser")

local function parse(src) return parser.parse(src, "test") end

s:test("empty chunk", function()
  local c = parse("")
  s:assert_eq(c.type, "Chunk")
  s:assert_eq(#c.body, 0)
end)

s:test("local statement", function()
  local c = parse("local a, b = 1, 2")
  local st = c.body[1]
  s:assert_eq(st.type, "LocalStatement")
  s:assert_eq(#st.names, 2)
  s:assert_eq(st.names[1], "a")
  s:assert_eq(#st.exprs, 2)
end)

s:test("assignment and index", function()
  local c = parse("t.x[1] = 5")
  local st = c.body[1]
  s:assert_eq(st.type, "AssignmentStatement")
  s:assert_eq(st.targets[1].type, "IndexExpression")
end)

s:test("call and method call", function()
  local c = parse("print(1); obj:method(2, 3)")
  s:assert_eq(c.body[1].type, "CallStatement")
  s:assert_eq(c.body[1].expr.type, "CallExpression")
  s:assert_eq(c.body[2].expr.type, "MethodCallExpression")
  s:assert_eq(c.body[2].expr.method, "method")
end)

s:test("if/elseif/else", function()
  local c = parse("if a then x() elseif b then y() else z() end")
  local st = c.body[1]
  s:assert_eq(st.type, "IfStatement")
  s:assert_eq(#st.clauses, 2)
  s:assert_true(st.elseBody ~= nil, "else present")
end)

s:test("while and repeat", function()
  local c = parse("while x do y() end repeat a() until done")
  s:assert_eq(c.body[1].type, "WhileStatement")
  s:assert_eq(c.body[2].type, "RepeatStatement")
end)

s:test("numeric and generic for", function()
  local c = parse("for i=1,10,2 do end for k,v in pairs(t) do end")
  s:assert_eq(c.body[1].type, "NumericForStatement")
  s:assert_true(c.body[1].step ~= nil, "step present")
  s:assert_eq(c.body[2].type, "GenericForStatement")
  s:assert_eq(#c.body[2].names, 2)
end)

s:test("function declaration and method", function()
  local c = parse("function a.b.c() end function obj:m(x) end")
  s:assert_eq(c.body[1].type, "FunctionDeclaration")
  s:assert_eq(c.body[2].isMethod, true)
  -- method injects self as first param
  s:assert_eq(c.body[2].func.params[1], "self")
end)

s:test("local function", function()
  local c = parse("local function f(a) return a end")
  s:assert_eq(c.body[1].type, "LocalFunction")
  s:assert_eq(c.body[1].name, "f")
end)

s:test("operator precedence tree", function()
  -- 2 + 3 * 4 should parse as 2 + (3*4)
  local c = parse("x = 2 + 3 * 4")
  local e = c.body[1].exprs[1]
  s:assert_eq(e.type, "BinaryExpression")
  s:assert_eq(e.op, "+")
  s:assert_eq(e.right.op, "*")
end)

s:test("right-assoc concat and power", function()
  local c = parse("x = 2 ^ 3 ^ 2")
  local e = c.body[1].exprs[1]
  s:assert_eq(e.op, "^")
  -- right assoc: left is 2, right is (3^2)
  s:assert_eq(e.right.op, "^")
end)

s:test("table constructor forms", function()
  local c = parse("x = { 1, 2, k = 3, [1+1] = 4 }")
  local tbl = c.body[1].exprs[1]
  s:assert_eq(tbl.type, "TableConstructor")
  s:assert_eq(tbl.fields[1].kind, "item")
  s:assert_eq(tbl.fields[3].kind, "named")
  s:assert_eq(tbl.fields[4].kind, "keyed")
end)

s:test("error includes line number", function()
  local ok, err = pcall(parse, "local = ")
  s:assert_true(not ok, "should error")
  s:assert_true(string.find(tostring(err), ":%d+:") ~= nil, "error has line")
end)

s:summary()
return { passed = s.passed, failed = s.failed }
