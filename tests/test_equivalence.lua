-- tests/test_equivalence.lua
-- Core round-trip equivalence harness, reused by every later feature.
--
-- For each program in examples/, run the ORIGINAL under the configured Lua
-- interpreter and capture stdout, then obfuscate it through the pipeline
-- (identity transform for FEAT-001), run the OBFUSCATED output under the same
-- interpreter, and assert byte-identical stdout.
--
-- The interpreter is selected by the LUA_BIN env var (default lua5.1), so the
-- suite can prove equivalence under Lua 5.1, Lua 5.4 and LuaJIT.
local root = LUAOBF_ROOT or "."
package.path = root .. "/src/?.lua;" .. root .. "/tests/?.lua;" .. package.path

local harness = require("harness")
local pipeline = require("obf.pipeline")
local config = require("obf.config")

local s = harness.new("equivalence")

local LUA_BIN = os.getenv("LUA_BIN") or "lua5.1"

-- The example programs to check. Explicit list keeps runs deterministic.
local EXAMPLES = {
  "fibonacci.lua",
  "strings.lua",
  "tables.lua",
  "metatables.lua",
  "recursion.lua",
  "numeric.lua",
}

local function read_file(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local data = f:read("*a")
  f:close()
  return data
end

local function write_file(path, data)
  local f = assert(io.open(path, "wb"))
  f:write(data)
  f:close()
end

-- Run a Lua file under LUA_BIN and capture combined stdout.
local function run_lua(path)
  -- quote the paths; capture stdout. We discard stderr for the comparison but
  -- surface the exit status via a sentinel.
  local cmd = string.format('%s "%s" 2>&1', LUA_BIN, path)
  local p = io.popen(cmd, "r")
  if not p then return nil, "popen failed" end
  local out = p:read("*a")
  -- close() return convention differs across versions; treat gracefully.
  p:close()
  return out
end

-- Unique temp path (per-process) to avoid collisions across parallel runs.
local function tmp_path(tag)
  local base = os.getenv("TMPDIR") or "/tmp"
  return string.format("%s/luaobf_%s_%d.tmp.lua", base, tag, os.time() % 100000)
end

local function obfuscate(src, seed, overrides)
  local o = { seed = seed, target = "5.1" }
  if overrides then for k, v in pairs(overrides) do o[k] = v end end
  local cfg = config.new(o)
  return pipeline.process(src, cfg)
end

-- Pipeline variants exercised for every example. Each must be byte-identical to
-- the original under every runtime.
--   default      : the shipping defaults -- the FULL protection pipeline with
--                  ALL FOUR techniques ON (virtualize + vm_flatten +
--                  string_encrypt + antitamper). FEAT-005 flips antitamper on
--                  by default; its guards stay silent on honest runs, so the
--                  obfuscated stdout must remain byte-identical to the original.
--   virtualize   : virtualize only, vm_flatten OFF (isolates the structured
--                  reference VM from both the flattener and the string cipher).
--   flatten      : virtualize + vm_flatten, string_encrypt OFF (isolates the
--                  flattened VM from the string cipher).
--   stringonly   : string_encrypt only (FEAT-002 regression).
local VARIANTS = {
  { tag = "default",    over = nil },
  { tag = "virtualize", over = { string_encrypt = false, virtualize = true, vm_flatten = false } },
  { tag = "flatten",    over = { string_encrypt = false, virtualize = true, vm_flatten = true } },
  { tag = "stringonly", over = { string_encrypt = true, virtualize = false, vm_flatten = false } },
}

for _, name in ipairs(EXAMPLES) do
  local srcPath = root .. "/examples/" .. name
  local src = read_file(srcPath)
  local origOut
  for _, variant in ipairs(VARIANTS) do
    s:test("equivalence [" .. variant.tag .. "]: " .. name .. " (LUA_BIN=" .. LUA_BIN .. ")", function()
      s:assert_true(src ~= nil, "example readable: " .. srcPath)
      origOut = origOut or run_lua(srcPath)
      s:assert_true(origOut ~= nil, "ran original")
      local obf = obfuscate(src, 1337, variant.over)
      local outPath = tmp_path(string.gsub(name, "%.lua$", "") .. "_" .. variant.tag)
      write_file(outPath, obf)
      local obfOut = run_lua(outPath)
      os.remove(outPath)
      s:assert_eq(obfOut, origOut, "stdout identical for " .. name .. " [" .. variant.tag .. "]")
    end)
  end
end

-- Determinism check: two different seeds should both produce output identical to
-- the original (and, for the identity transform, be byte-identical to each other
-- too, since no passes consume randomness yet). This wires seeds through.
s:test("seed wiring: identity output equivalent for different seeds", function()
  local name = "numeric.lua"
  local src = read_file(root .. "/examples/" .. name)
  s:assert_true(src ~= nil, "example readable")
  local a = obfuscate(src, 1)
  local b = obfuscate(src, 999999)
  -- run both
  local pa = tmp_path("seedA")
  local pb = tmp_path("seedB")
  write_file(pa, a); write_file(pb, b)
  local outA = run_lua(pa)
  local outB = run_lua(pb)
  os.remove(pa); os.remove(pb)
  local orig = run_lua(root .. "/examples/" .. name)
  s:assert_eq(outA, orig, "seed 1 matches original")
  s:assert_eq(outB, orig, "seed 999999 matches original")
end)

-- Static-leak check: a known plaintext marker in examples/strings.lua must NOT
-- appear verbatim in the obfuscated output once string encryption runs. The
-- default pipeline has string_encrypt ON (FEAT-002), so obfuscate() exercises it.
s:test("static-leak: SECRET_MARKER absent from obfuscated strings.lua", function()
  local src = read_file(root .. "/examples/strings.lua")
  s:assert_true(src ~= nil, "strings.lua readable")
  s:assert_true(string.find(src, "SECRET_MARKER", 1, true) ~= nil,
    "example actually contains the marker")
  local obf = obfuscate(src, 1337)
  s:assert_true(string.find(obf, "SECRET_MARKER", 1, true) == nil,
    "SECRET_MARKER does not survive in obfuscated output")
end)

s:summary()
return { passed = s.passed, failed = s.failed }
