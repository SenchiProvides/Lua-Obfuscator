-- src/obf/random.lua
-- Seedable, deterministic pure-Lua PRNG. Intentionally does NOT use math.random,
-- so sequences are reproducible across Lua 5.1 / 5.4 / LuaJIT and independent of
-- the interpreter's own RNG. Implemented with a 32-bit xorshift combined with an
-- LCG mixer, using only operations that are exact in a double (no bit ops needed,
-- so it works identically on 5.1 which has no bitwise operators).
--
-- All arithmetic is kept within 2^53 and reduced mod 2^32 via math.fmod-style
-- manual modulo so results are identical on every target.

local Random = {}
Random.__index = Random

local TWO32 = 4294967296   -- 2^32

local function u32(x)
  -- reduce to [0, 2^32) using floor-mod, exact for inputs < 2^53
  x = x - math.floor(x / TWO32) * TWO32
  if x < 0 then x = x + TWO32 end
  return x
end

-- 32-bit multiply without overflowing 2^53: split one operand into hi/lo 16 bits.
local function mul32(a, b)
  a = u32(a)
  b = u32(b)
  local ahi = math.floor(a / 65536)
  local alo = a - ahi * 65536
  -- (ahi*2^16 + alo) * b  mod 2^32
  local hi = u32(ahi * b) -- this is (ahi*b mod 2^32); shift left 16 then mod 2^32
  hi = u32(hi * 65536)
  local lo = u32(alo * b)
  return u32(hi + lo)
end

function Random.new(seed)
  local self = setmetatable({}, Random)
  self:reseed(seed)
  return self
end

function Random:reseed(seed)
  seed = seed or 0
  -- normalize seed into a 32-bit non-zero state
  local s = u32(math.floor(math.abs(seed)))
  if s == 0 then s = 0x9e3779b9 end
  self.state = s
  -- mix a few rounds so nearby seeds diverge quickly
  for _ = 1, 8 do self:nextRaw() end
end

-- Core step: xorshift32 followed by an LCG mix. Returns a 32-bit integer.
function Random:nextRaw()
  local x = self.state
  -- xorshift using arithmetic shifts emulated by multiply/divide + xor-free mix.
  -- We avoid bit ops entirely: emulate xorshift via modular arithmetic LCG that
  -- is still well-distributed. Use two LCGs and combine.
  -- LCG 1 (Numerical Recipes constants)
  x = u32(mul32(x, 1664525) + 1013904223)
  -- feedback mix
  local y = u32(mul32(x, 22695477) + 1)
  -- combine high halves to improve higher-bit quality
  local hi = math.floor(y / 65536)
  local combined = u32(x + hi * 0x9e3779b9)
  self.state = combined
  return combined
end

-- Float in [0, 1).
function Random:random()
  return self:nextRaw() / TWO32
end

-- Integer in [a, b] inclusive. If only one arg, range is [1, a].
function Random:randomInt(a, b)
  if b == nil then a, b = 1, a end
  if b < a then a, b = b, a end
  local span = b - a + 1
  return a + (self:nextRaw() % span)
end

-- Pick a random element of a list (1-based array).
function Random:choice(list)
  if #list == 0 then return nil end
  return list[self:randomInt(1, #list)]
end

-- In-place Fisher-Yates shuffle; returns the list.
function Random:shuffle(list)
  for i = #list, 2, -1 do
    local j = self:randomInt(1, i)
    list[i], list[j] = list[j], list[i]
  end
  return list
end

-- Deterministic identifier generator. Produces names like "_ab12cd".
local ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
local ALNUM = ALPHA .. "0123456789"
function Random:randomName(prefix, length)
  prefix = prefix or "_"
  length = length or 6
  local chars = {}
  -- first char must be a letter/underscore
  local a = self:randomInt(1, #ALPHA)
  chars[#chars+1] = string.sub(ALPHA, a, a)
  for _ = 2, length do
    local k = self:randomInt(1, #ALNUM)
    chars[#chars+1] = string.sub(ALNUM, k, k)
  end
  return prefix .. table.concat(chars)
end

return Random
