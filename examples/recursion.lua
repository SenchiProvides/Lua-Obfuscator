-- recursion.lua: recursive algorithms, deterministic.
local function factorial(n)
  if n <= 1 then return 1 end
  return n * factorial(n - 1)
end

local function gcd(a, b)
  while b ~= 0 do
    a, b = b, a % b
  end
  return a
end

local function ackermann(m, n)
  if m == 0 then return n + 1 end
  if n == 0 then return ackermann(m - 1, 1) end
  return ackermann(m - 1, ackermann(m, n - 1))
end

for i = 1, 10 do
  io.write(factorial(i))
  if i < 10 then io.write(" ") end
end
io.write("\n")

print("gcd(48, 36) = " .. gcd(48, 36))
print("gcd(1071, 462) = " .. gcd(1071, 462))
print("ackermann(2, 3) = " .. ackermann(2, 3))
print("ackermann(3, 3) = " .. ackermann(3, 3))
