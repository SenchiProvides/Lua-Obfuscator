-- tests/test_random.lua
local root = LUAOBF_ROOT or "."
package.path = root .. "/src/?.lua;" .. root .. "/tests/?.lua;" .. package.path

local harness = require("harness")
local Random = require("obf.random")

local s = harness.new("random")

s:test("same seed -> same sequence", function()
  local r1 = Random.new(12345)
  local r2 = Random.new(12345)
  for _ = 1, 100 do
    s:assert_eq(r1:nextRaw(), r2:nextRaw(), "raw sequence matches")
  end
end)

s:test("same seed -> same floats", function()
  local r1 = Random.new(99)
  local r2 = Random.new(99)
  for _ = 1, 50 do
    s:assert_eq(r1:random(), r2:random(), "float sequence matches")
  end
end)

s:test("different seeds -> different sequence", function()
  local r1 = Random.new(1)
  local r2 = Random.new(2)
  local differ = false
  for _ = 1, 20 do
    if r1:nextRaw() ~= r2:nextRaw() then differ = true end
  end
  s:assert_true(differ, "sequences should differ for different seeds")
end)

s:test("floats in [0,1)", function()
  local r = Random.new(7)
  for _ = 1, 1000 do
    local v = r:random()
    s:assert_true(v >= 0 and v < 1, "float in range: " .. tostring(v))
  end
end)

s:test("randomInt respects bounds", function()
  local r = Random.new(42)
  for _ = 1, 1000 do
    local v = r:randomInt(5, 10)
    s:assert_true(v >= 5 and v <= 10, "int in [5,10]: " .. tostring(v))
    s:assert_eq(v, math.floor(v), "int is integral")
  end
end)

s:test("randomInt distribution sanity", function()
  local r = Random.new(2024)
  local buckets = {}
  for i = 1, 6 do buckets[i] = 0 end
  for _ = 1, 6000 do
    local v = r:randomInt(1, 6)
    buckets[v] = buckets[v] + 1
  end
  -- each bucket should get a non-trivial share (expected 1000; allow wide band)
  for i = 1, 6 do
    s:assert_true(buckets[i] > 500 and buckets[i] < 1500,
      "bucket " .. i .. " count=" .. buckets[i])
  end
end)

s:test("choice and shuffle deterministic", function()
  local r1 = Random.new(55)
  local r2 = Random.new(55)
  local list1 = { "a", "b", "c", "d", "e" }
  local list2 = { "a", "b", "c", "d", "e" }
  s:assert_eq(r1:choice(list1), r2:choice(list2))
  r1:shuffle(list1)
  r2:shuffle(list2)
  for i = 1, #list1 do
    s:assert_eq(list1[i], list2[i], "shuffle deterministic at " .. i)
  end
end)

s:test("shuffle is a permutation", function()
  local r = Random.new(3)
  local list = {}
  for i = 1, 20 do list[i] = i end
  r:shuffle(list)
  local seen = {}
  for _, v in ipairs(list) do seen[v] = (seen[v] or 0) + 1 end
  for i = 1, 20 do s:assert_eq(seen[i], 1, "element " .. i .. " present once") end
end)

s:test("randomName valid identifier and deterministic", function()
  local r1 = Random.new(8)
  local r2 = Random.new(8)
  local n1 = r1:randomName("_x")
  local n2 = r2:randomName("_x")
  s:assert_eq(n1, n2, "names deterministic")
  s:assert_true(string.match(n1, "^[%a_][%w_]*$") ~= nil, "valid identifier: " .. n1)
end)

s:summary()
return { passed = s.passed, failed = s.failed }
