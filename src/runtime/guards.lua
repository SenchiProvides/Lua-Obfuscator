-- src/runtime/guards.lua
-- CANONICAL template for the embedded anti-debugging / anti-tamper guards
-- (FEAT-005, Technique 4: the active defense).
--
-- This file documents, in readable form, the runtime that src/obf/passes/
-- antitamper.lua emits into obfuscated output. The ACTUAL emission is done
-- programmatically by the pass, which, per build:
--   * renames every local below to a fresh seeded identifier,
--   * substitutes the per-build checksum parameters (seed, m1, m2),
--   * substitutes the configured tamper-response MODE (error|lock|silent),
--   * registers the guards at the FRONT of the prelude so the VM interpreter
--     (which is emitted later in the same chunk) can call them as in-scope
--     top-level locals.
--
-- COMPATIBILITY: pure Lua 5.1 syntax, pure arithmetic only (no bit32, no 5.4
-- bitwise/integer-division operators, no goto). Every check is tuned to be
-- PORTABLE and LOW-FALSE-POSITIVE across Lua 5.1, Lua 5.4 and LuaJIT 2.1: an
-- honest run (no debugger attached) NEVER trips a guard on any of the three.
--
-- =========================================================================
-- WHAT THE GUARDS DO
-- =========================================================================
-- 1. INTEGRITY SELF-CHECK (fold): recompute a checksum over a virtualized
--    function's bytecode (proto.c) and compare to the build-time expected value
--    (proto.ck). The VM calls fold() at entry and at seed-placed dispatcher
--    checkpoints. A flipped byte of the virtualized blob -> mismatch -> tamper.
--
-- 2. ANTI-DEBUG (anti_debug): detects, with generous thresholds so honest runs
--    never false-positive:
--      (a) a debug hook installed by someone else (debug.sethook single-step
--          driver): if debug.gethook() returns a hook we did not install,
--          that is a single-stepping/line-hook debugger.
--      (b) replaced core globals: a baseline identity of a few key globals is
--          captured at load; if one is swapped out later (a common instrument
--          /hook technique) the identity check fails.
--      (c) gross timing anomaly: os.clock deltas across checkpoints that are
--          absurdly large (orders of magnitude beyond any real run) indicate a
--          single-stepping debugger. The threshold is deliberately huge to
--          avoid penalizing slow honest runs / non-JIT 5.4.
--
-- 3. tamper_response(reason): the single reaction point, with modes:
--      "error"  -> error() with an opaque message (non-zero exit).
--      "lock"   -> benign infinite loop (process hangs / locks up).
--      "silent" -> set a corruption flag; the VM then yields wrong results
--                  rather than a clean crash (best-effort obfuscated failure).
--    Many woven call sites reference tamper_response, so there is no single
--    point to patch out.

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

-- Per-build checksum parameters (substituted). Placeholders here:
local SEED = 1
local M1 = 2654435761
local M2 = 40503
local NFIELDS = 6

-- Integrity fold over proto.c (array of instruction number arrays). MUST match
-- src/obf/checksum.lua fold_code exactly.
local function fold(code)
  local h = u32(SEED)
  for ci = 1, #code do
    local ins = code[ci]
    for si = 1, NFIELDS do
      local v = ins[si] or 0
      h = u32(mul32(h, M1) + (v % 65521) + 1)
      h = u32(h + math.floor(h / 65536))
    end
    h = u32(h + mul32(ci, 2654435761))
  end
  h = u32(mul32(h, M2))
  h = u32(h + math.floor(h / 256))
  return u32(h)
end

-- Corruption flag used by the "silent" mode.
local CORRUPT = false

-- Tamper reaction. MODE is substituted per build.
local MODE = "error"
local function tamper_response(reason)
  if MODE == "lock" then
    while true do end
  elseif MODE == "silent" then
    CORRUPT = true
    return nil
  else
    -- opaque message: does not reveal which check fired
    error("runtime error 0x" .. string.format("%x", (reason or 0) * 2654435 % 65536), 0)
  end
end

-- Baseline identities captured at LOAD time (before any debugger could swap
-- them). These are stable references on all three runtimes.
local BASE_type = type
local BASE_pcall = pcall
local BASE_tostring = tostring
local BASE_select = select
local BASE_debug = debug          -- may be nil if debug lib stripped (that's fine)
local T0 = os.clock()

-- Timing threshold: wildly generous. A real run (even non-JIT 5.4 on the
-- heaviest example) stays far under this; only a human-driven single-step
-- debugger approaches it. Chosen huge to guarantee no honest false-positive.
local TIME_LIMIT = 3600  -- seconds of cumulative wall-ish time

local function anti_debug()
  -- (b) replaced core globals: identity must be unchanged since load.
  if type ~= BASE_type or pcall ~= BASE_pcall or tostring ~= BASE_tostring
     or select ~= BASE_select then
    tamper_response(2)
    return
  end
  -- (a) foreign debug hook (single-step / line hook installed by a debugger).
  if BASE_debug and BASE_debug.gethook then
    local h = BASE_debug.gethook()
    if h ~= nil then
      tamper_response(3)
      return
    end
  end
  -- (c) gross timing anomaly.
  if os.clock() - T0 > TIME_LIMIT then
    tamper_response(4)
    return
  end
end

M.fold = fold
M.anti_debug = anti_debug
M.tamper_response = tamper_response
M.is_corrupt = function() return CORRUPT end
return M
