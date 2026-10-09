-- tables.lua: table + closure usage, deterministic.
local function make_counter(start)
  local n = start or 0
  return function()
    n = n + 1
    return n
  end
end

local c = make_counter(10)
print(c(), c(), c())

local data = { 5, 3, 8, 1, 9, 2, 7 }
table.sort(data)
print("sorted: " .. table.concat(data, ","))

local sum = 0
for _, v in ipairs(data) do sum = sum + v end
print("sum: " .. sum)

local counts = {}
local words = { "a", "b", "a", "c", "b", "a" }
for _, w in ipairs(words) do
  counts[w] = (counts[w] or 0) + 1
end
-- iterate deterministically by sorting keys
local keys = {}
for k in pairs(counts) do keys[#keys + 1] = k end
table.sort(keys)
for _, k in ipairs(keys) do
  print(k .. "=" .. counts[k])
end
