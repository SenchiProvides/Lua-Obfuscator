-- numeric.lua: numeric loops, operator precedence, deterministic.
local function is_prime(n)
  if n < 2 then return false end
  local i = 2
  while i * i <= n do
    if n % i == 0 then return false end
    i = i + 1
  end
  return true
end

local primes = {}
local n = 2
while #primes < 10 do
  if is_prime(n) then primes[#primes + 1] = n end
  n = n + 1
end
print("primes: " .. table.concat(primes, ","))

-- precedence / associativity sanity (must survive codegen)
print(2 + 3 * 4)            -- 14
print((2 + 3) * 4)          -- 20
print(2 ^ 3 ^ 2)            -- 512 (right assoc)
print(-2 ^ 2)              -- -4 (unary binds looser than ^)
print("a" .. "b" .. "c")    -- abc (right assoc concat)
print(10 - 3 - 2)           -- 5 (left assoc)
print(not (1 == 2) and 3 < 4) -- true

local total = 0
for i = 1, 100 do total = total + i end
print("sum 1..100 = " .. total)

-- repeat/until: count digits of a number (loops at least once, exits via until)
local function digits(x)
  local d = 0
  repeat
    d = d + 1
    x = math.floor(x / 10)
  until x == 0
  return d
end
print("digits(0) = " .. digits(0))        -- 1 (body runs once even for 0)
print("digits(90125) = " .. digits(90125)) -- 5

print(string.format("%.4f", 22 / 7))
