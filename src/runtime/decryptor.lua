-- src/runtime/decryptor.lua
-- CANONICAL template for the embedded string decryptor (FEAT-002).
--
-- This file documents, in readable form, the exact runtime that gets injected
-- into obfuscated output. The actual emission is done programmatically by
-- src/obf/passes/string_encrypt.lua, which:
--   * renames every local below to a fresh seeded identifier (so two seeds
--     yield different variable names / layout),
--   * substitutes the per-build salt and the constant data table C,
--   * emits it once via ctx.prelude:register (de-duplicated).
--
-- The algorithm is byte-for-byte identical to src/obf/cipher.lua, so a payload
-- encrypted at obfuscation time decrypts back exactly at runtime. It is written
-- in Lua-5.1-compatible syntax using pure arithmetic only (no bit32, no 5.4
-- bitwise operators, no integer-division), so it behaves identically under Lua
-- 5.1, Lua 5.4 and LuaJIT 2.1.
--
-- KEY DERIVATION (why the key is "dynamic"):
--   The constant table C is embedded, but the effective key is NOT. At load
--   time the decryptor walks C and folds it into a 32-bit FINGERPRINT (fp).
--   The per-string key seed is  u32(salt + (idx+1)*MULA + fp*MULB).  Because fp
--   is recomputed from running-program state every load (and the per-string
--   seed also depends on the string's index), the bytes on disk never contain
--   the key that is actually used to XOR a given string. Lifting just the
--   encrypted literal bytes is insufficient to recover plaintext without also
--   re-running the fingerprint fold over C.

local M = {}

local TWO32 = 4294967296

local function u32(x)
  x = x - math.floor(x / TWO32) * TWO32
  if x < 0 then x = x + TWO32 end
  return x
end

local function mul32(a, b)
  a = u32(a); b = u32(b)
  local ahi = math.floor(a / 65536)
  local alo = a - ahi * 65536
  local hi = u32(u32(ahi * b) * 65536)
  local lo = u32(alo * b)
  return u32(hi + lo)
end

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

-- The constant data table (substituted per build). Example placeholder:
local C = { 1, 2, 3 }

local MULA = 2654435761
local MULB = 40503
local LCG_A = 1103515245
local LCG_C = 12345

-- Runtime fingerprint, computed ONCE at load time from the embedded table C.
local FP
local function fingerprint()
  local fp = 2166136261
  for i = 1, #C do
    fp = u32(mul32(fp, 16777619) + (C[i] % 256))
    fp = u32(fp + math.floor(fp / 65536))
  end
  fp = u32(mul32(fp, 2246822519))
  fp = u32(fp + math.floor(fp / 256))
  return u32(fp)
end
FP = fingerprint()

local SALT = 0 -- substituted per build

-- Decrypt: dec(idx, bytes-array) -> original string.
local function dec(idx, b)
  local state = u32(SALT + mul32((idx + 1), MULA) + mul32(FP, MULB))
  local out = {}
  for j = 1, #b do
    state = u32(mul32(state, LCG_A) + LCG_C)
    local kb = math.floor(state / 16777216) % 256
    out[j] = string.char(xor8(b[j] % 256, kb))
  end
  return table.concat(out)
end

M.dec = dec
return M
