-- fibonacci.lua: iterative and recursive Fibonacci, deterministic output.
local function fib_iter(n)
  local a, b = 0, 1
  for _ = 1, n do
    a, b = b, a + b
  end
  return a
end

local function fib_rec(n)
  if n < 2 then return n end
  return fib_rec(n - 1) + fib_rec(n - 2)
end

for i = 0, 15 do
  io.write(fib_iter(i))
  if i < 15 then io.write(" ") end
end
io.write("\n")

print("fib_rec(10) = " .. fib_rec(10))
print("fib_iter(20) = " .. fib_iter(20))
