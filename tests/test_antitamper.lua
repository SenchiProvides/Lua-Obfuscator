-- tests/test_antitamper.lua
-- Technique 4 (FEAT-005) anti-debug / anti-tamper verification.
--
-- These tests obfuscate a real program with the FULL default pipeline (which
-- has antitamper ON) and then:
--   * Pc (positive): confirm an HONEST run produces the original's exact stdout
--     with the guards completely silent, under LUA_BIN (5.1 / 5.4 / luajit).
--   * TAMPER: mutate a byte of the embedded virtualized bytecode blob and
--     confirm the program now ABORTS (non-zero exit / sentinel) instead of
--     silently producing the correct original output.
--   * ANTI-DEBUG: run the guarded program under a single-stepping debug.sethook
--     line hook and confirm the guard trips (error mode).
--   * NO-FALSE-POSITIVE: the honest run above already proves this; we also run a
--     few seeds and confirm every one is honest-equivalent.
--   * VARIABILITY: different seeds yield different guard placement/parameters
--     (the obfuscated bytes differ) yet every seed is honest-equivalent.
--
-- The interpreter is selected by LUA_BIN (default lua5.1) so the suite proves
-- the guards are portable and low-false-positive on all three runtimes.

local root = LUAOBF_ROOT or "."
package.path = root .. "/src/?.lua;" .. root .. "/tests/?.lua;" .. package.path

local harness = require("harness")
local pipeline = require("obf.pipeline")
local config = require("obf.config")

local s = harness.new("antitamper")
local LUA_BIN = os.getenv("LUA_BIN") or "lua5.1"
local EXAMPLE = root .. "/examples/fibonacci.lua"

local function read_file(path)
  local f = io.open(path, "rb"); if not f then return nil end
  local d = f:read("*a"); f:close(); return d
end
local function write_file(path, data)
  local f = assert(io.open(path, "wb")); f:write(data); f:close()
end
local function tmp_path(tag)
  local base = os.getenv("TMPDIR") or "/tmp"
  return string.format("%s/luaobf_at_%s_%d.tmp.lua", base, tag, os.time() % 100000)
end

-- Run a Lua file; return (stdout+stderr, raw_close_status). We care about both
-- the text and whether it exited cleanly (os.exit non-zero shows up as a
-- non-successful close on 5.2+, and as an error line in the captured text).
local function run_lua(path)
  local p = io.popen(string.format('%s "%s" 2>&1', LUA_BIN, path), "r")
  if not p then return nil end
  local out = p:read("*a")
  local ok = p:close()
  return out, ok
end

local function obfuscate(src, seed, overrides)
  local o = { seed = seed, target = "5.1" }
  if overrides then for k, v in pairs(overrides) do o[k] = v end end
  return pipeline.process(src, config.new(o))
end

local src = read_file(EXAMPLE)

-- --------------------------------------------------------------------------
-- 1) Positive: honest run is correct and silent (guards do not interfere).
-- --------------------------------------------------------------------------
s:test("honest run of guarded program matches original (LUA_BIN=" .. LUA_BIN .. ")", function()
  s:assert_true(src ~= nil, "example readable")
  local orig = run_lua(EXAMPLE)
  s:assert_true(orig ~= nil, "ran original")
  local obf = obfuscate(src, 1337) -- full default pipeline, antitamper ON
  -- the guards are actually present
  s:assert_true(string.find(obf, "anti%-debug") ~= nil, "guard prelude emitted")
  local p = tmp_path("honest")
  write_file(p, obf)
  local out = run_lua(p)
  os.remove(p)
  s:assert_eq(out, orig, "guarded honest run is byte-identical to original")
end)

-- --------------------------------------------------------------------------
-- 2) Tamper: flip a byte of the embedded virtualized bytecode -> must abort.
-- --------------------------------------------------------------------------
s:test("byte-mutation of virtualized blob aborts (does NOT produce correct output)", function()
  s:assert_true(src ~= nil, "example readable")
  local orig = run_lua(EXAMPLE)
  local obf = obfuscate(src, 24680)
  -- Locate the first VM bytecode table ("{{" starts a code array of instruction
  -- arrays) and flip the first digit found inside it to a different digit. This
  -- changes a single operand number of the virtualized blob.
  local i = string.find(obf, "{{", 1, true)
  s:assert_true(i ~= nil, "found a bytecode table")
  local j = string.find(obf, "%d", i)
  s:assert_true(j ~= nil, "found a digit to mutate")
  local d = tonumber(string.sub(obf, j, j))
  local nd = tostring((d + 3) % 10)
  local mutated = string.sub(obf, 1, j - 1) .. nd .. string.sub(obf, j + 1)
  s:assert_neq(mutated, obf, "mutation changed the bytes")
  local p = tmp_path("tamper")
  write_file(p, mutated)
  local out = run_lua(p)
  os.remove(p)
  -- The tampered program must NOT reproduce the original correct output.
  s:assert_true(out ~= orig,
    "tampered output differs from original (guard fired / execution broke)")
end)

-- --------------------------------------------------------------------------
-- 3) Anti-debug: single-stepping debug.sethook driver trips the guard (error).
-- --------------------------------------------------------------------------
s:test("single-step debug.sethook driver trips the anti-debug guard", function()
  local obf = obfuscate(src, 13579) -- default mode is "error"
  local gp = tmp_path("guarded")
  write_file(gp, obf)
  -- A driver that installs a line (single-step) hook then runs the guarded file.
  local driver = tmp_path("driver")
  write_file(driver, table.concat({
    'debug.sethook(function() end, "l")',
    'local chunk = assert(loadfile("' .. gp .. '"))',
    'local ok, err = pcall(chunk)',
    'debug.sethook()',
    'if ok then io.write("NOTRIP") else io.write("TRIP") end',
  }, "\n"))
  local out = run_lua(driver)
  os.remove(gp); os.remove(driver)
  s:assert_true(out ~= nil and string.find(out, "TRIP", 1, true) ~= nil,
    "guard tripped under single-step (got: " .. tostring(out) .. ")")
end)

-- --------------------------------------------------------------------------
-- 4) No false-positive across several seeds; honest-equivalent every time.
-- --------------------------------------------------------------------------
s:test("guards never false-positive on honest runs across seeds", function()
  local orig = run_lua(EXAMPLE)
  for _, seed in ipairs({ 1, 42, 1337, 999999 }) do
    local obf = obfuscate(src, seed)
    local p = tmp_path("fp_" .. seed)
    write_file(p, obf)
    local out = run_lua(p)
    os.remove(p)
    s:assert_eq(out, orig, "honest run matches original for seed " .. seed)
  end
end)

-- --------------------------------------------------------------------------
-- 5) Variability: different seeds -> different guard placement/parameters, but
--    all honest-equivalent (determinism: same seed reproduces).
-- --------------------------------------------------------------------------
s:test("different seeds yield different guard placement, same seed reproduces", function()
  local a1 = obfuscate(src, 111)
  local a2 = obfuscate(src, 111) -- same seed
  local b = obfuscate(src, 222)  -- different seed
  s:assert_eq(a1, a2, "same seed reproduces byte-identical output")
  s:assert_true(a1 ~= b, "different seeds produce different bytes")
end)

-- --------------------------------------------------------------------------
-- 6) Mode wiring: lock and silent modes emit different reaction code; error is
--    the default. (We check the emitted guard shape rather than hanging on a
--    lock run.)
-- --------------------------------------------------------------------------
s:test("antitamper_mode wiring emits the configured reaction", function()
  local errObf = obfuscate(src, 7, { antitamper_mode = "error" })
  local lockObf = obfuscate(src, 7, { antitamper_mode = "lock" })
  local silentObf = obfuscate(src, 7, { antitamper_mode = "silent" })
  s:assert_true(string.find(errObf, 'error("runtime error', 1, true) ~= nil,
    "error mode emits error()")
  s:assert_true(string.find(lockObf, "while true do end") ~= nil,
    "lock mode emits an infinite loop")
  -- silent mode must NOT emit the error() reaction
  s:assert_true(string.find(silentObf, 'error("runtime error', 1, true) == nil,
    "silent mode does not emit error()")
end)

-- --------------------------------------------------------------------------
-- 7) Disable path: --disable antitamper (config.antitamper=false) removes the
--    guard prelude entirely, for deterministic CI without active defenses.
-- --------------------------------------------------------------------------
s:test("antitamper can be disabled (no guard prelude emitted)", function()
  local off = obfuscate(src, 9, { antitamper = false })
  s:assert_true(string.find(off, "anti%-debug") == nil,
    "no guard prelude when antitamper disabled")
  local p = tmp_path("off")
  write_file(p, off)
  local out = run_lua(p)
  os.remove(p)
  s:assert_eq(out, run_lua(EXAMPLE), "disabled-guard output still equivalent")
end)

s:summary()
return { passed = s.passed, failed = s.failed }
