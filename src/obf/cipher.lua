-- src/obf/cipher.lua
-- Shared cipher core for the string-encryption pass (FEAT-002).
--
-- This module is used at OBFUSCATION time to encrypt string literals. The exact
-- same algorithm is emitted into the output as a runtime DECRYPTOR (see
-- src/runtime/decryptor.lua). Because both sides run byte-for-byte identical
-- arithmetic, an encrypted payload always decrypts back to the original string.
--
-- Compatibility: implemented in Lua-5.1-compatible syntax using ONLY pure
-- arithmetic (floor, modulo, multiply). It never uses bit32, the 5.4 native
-- bitwise operators, or integer-division, so XOR and the key schedule produce
-- identical results on Lua 5.1, Lua 5.4 and LuaJIT 2.1.
--
-- ---------------------------------------------------------------------------
-- ALGORITHM (must stay in lock-step with src/runtime/decryptor.lua)
-- ---------------------------------------------------------------------------
-- A per-build "constant data table" C (an array of bytes 0..255) is embedded in
-- the output. At load time the decryptor computes a runtime FINGERPRINT by
-- folding C through a mixing function. The same fingerprint is computed here at
-- obfuscation time. Because the fingerprint is derived from running-program
-- state (the embedded data walked at load time) rather than stored verbatim, a
-- static scrape of the file does not directly reveal the effective key.
--
-- For a string with 0-based index `idx`, the effective 32-bit key seed is:
--     seed = u32( salt  +  (idx + 1) * MULA  +  fp * MULB )
-- A keyed LCG is stepped once per output byte to produce a key byte 0..255, and
-- each plaintext byte is XORed (arithmetic) with that key byte. The result is a
-- reversible stream cipher: decrypt is the identical operation.

local cipher = {}

local TWO32 = 4294967296 -- 2^32

-- Key-schedule mixing constants. These are part of the algorithm contract and
-- are duplicated verbatim in the emitted decryptor.
cipher.MULA = 2654435761 -- Knuth multiplicative hash constant (0x9E3779B1)
cipher.MULB = 40503      -- odd mixing multiplier
cipher.LCG_A = 1103515245
cipher.LCG_C = 12345

local MULA = cipher.MULA
local MULB = cipher.MULB
local LCG_A = cipher.LCG_A
local LCG_C = cipher.LCG_C

-- Reduce to [0, 2^32).
local function u32(x)
  x = x - math.floor(x / TWO32) * TWO32
  if x < 0 then x = x + TWO32 end
  return x
end
cipher.u32 = u32

-- 32-bit multiply with no loss of precision beyond 2^53 (split hi/lo 16 bits).
local function mul32(a, b)
  a = u32(a); b = u32(b)
  local ahi = math.floor(a / 65536)
  local alo = a - ahi * 65536
  local hi = u32(u32(ahi * b) * 65536)
  local lo = u32(alo * b)
  return u32(hi + lo)
end
cipher.mul32 = mul32

-- Pure-arithmetic XOR of two bytes (0..255). Processes 8 bits with floor/mod.
local function xor8(a, b)
  local res = 0
  local bit = 1
  for _ = 1, 8 do
    local abit = a % 2
    local bbit = b % 2
    if abit ~= bbit then res = res + bit end
    a = (a - abit) / 2
    b = (b - bbit) / 2
    bit = bit * 2
  end
  return res
end
cipher.xor8 = xor8

-- Fold a constant data table into a 32-bit runtime fingerprint. Mirrored in the
-- decryptor; the decryptor runs this at load time over the embedded table.
local function fingerprint(C)
  local fp = 2166136261 -- FNV offset basis
  for i = 1, #C do
    fp = u32(mul32(fp, 16777619) + (C[i] % 256))
    fp = u32(fp + math.floor(fp / 65536))
  end
  -- final avalanche
  fp = u32(mul32(fp, 2246822519))
  fp = u32(fp + math.floor(fp / 256))
  return u32(fp)
end
cipher.fingerprint = fingerprint

-- Produce the key seed for a given string index.
local function key_seed(salt, idx, fp)
  return u32(salt + mul32((idx + 1), MULA) + mul32(fp, MULB))
end
cipher.key_seed = key_seed

-- Transform (encrypt or decrypt -- symmetric) a byte array `bytes` (0..255)
-- for string index `idx`. Returns a new byte array.
local function transform(bytes, salt, idx, fp)
  local state = key_seed(salt, idx, fp)
  local out = {}
  for j = 1, #bytes do
    state = u32(mul32(state, LCG_A) + LCG_C)
    -- take a well-mixed byte from the high bits of the state
    local kb = math.floor(state / 16777216) % 256
    out[j] = xor8(bytes[j] % 256, kb)
  end
  return out
end
cipher.transform = transform

-- Convenience: encrypt a Lua string -> byte array (encrypted).
function cipher.encrypt_string(s, salt, idx, fp)
  local bytes = {}
  for j = 1, #s do bytes[j] = string.byte(s, j) end
  return transform(bytes, salt, idx, fp)
end

-- Convenience: decrypt a byte array -> Lua string (used by tests in-process).
function cipher.decrypt_bytes(bytes, salt, idx, fp)
  local plain = transform(bytes, salt, idx, fp)
  local chars = {}
  for j = 1, #plain do chars[j] = string.char(plain[j]) end
  return table.concat(chars)
end

return cipher
