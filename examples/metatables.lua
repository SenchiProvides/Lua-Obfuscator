-- metatables.lua: metatable-based vector type, deterministic.
local Vector = {}
Vector.__index = Vector

function Vector.new(x, y)
  return setmetatable({ x = x, y = y }, Vector)
end

function Vector.__add(a, b)
  return Vector.new(a.x + b.x, a.y + b.y)
end

function Vector.__tostring(v)
  return "(" .. v.x .. ", " .. v.y .. ")"
end

function Vector:dot(other)
  return self.x * other.x + self.y * other.y
end

function Vector:length_squared()
  return self:dot(self)
end

local a = Vector.new(1, 2)
local b = Vector.new(3, 4)
local c = a + b
print("a = " .. tostring(a))
print("b = " .. tostring(b))
print("a + b = " .. tostring(c))
print("a . b = " .. a:dot(b))
print("|c|^2 = " .. c:length_squared())
