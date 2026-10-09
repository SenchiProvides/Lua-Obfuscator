-- src/obf/config.lua
-- Configuration table with defaults and per-technique toggles.
--
-- Toggles exist for each of the four protection techniques. For FEAT-001 the
-- pipeline pass list is empty regardless of toggles (identity transform); later
-- features consult these flags to decide which passes to run. Defaults for the
-- toggles are OFF here so the FEAT-001 identity behavior is explicit and stable;
-- later features will flip the shipping defaults.

local config = {}

local function defaults()
  return {
    -- protection technique toggles
    -- string_encrypt (FEAT-002), virtualize (FEAT-003) and vm_flatten (FEAT-004)
    -- ship ON by default. vm_flatten only has effect when virtualize is also on
    -- (it flattens the emitted VM interpreter); if virtualize is off it is a
    -- documented no-op. antitamper remains OFF until FEAT-005 lands.
    string_encrypt = true,
    virtualize     = true,
    vm_flatten     = true,
    -- antitamper (FEAT-005) ships ON. Its guards are tuned to be silent on
    -- honest runs across Lua 5.1 / 5.4 / LuaJIT (the equivalence suite proves
    -- it). The active integrity + anti-debug checks are woven into the VM, so
    -- antitamper only has teeth when virtualize is also on; with virtualize off
    -- it emits a standalone load-time anti-debug guard.
    antitamper     = true,
    -- antitamper reaction mode: "error" (opaque error -> non-zero exit, the
    -- default and the mode tests assert against), "lock" (benign infinite loop)
    -- or "silent" / "silent-corrupt" (corrupt state instead of crashing).
    antitamper_mode = "error",
    -- target Lua version: '5.1' (primary), '5.4', or 'luajit'
    target = "5.1",
    -- PRNG seed. nil means "pick a non-deterministic seed" (CLI will supply one);
    -- a fixed number makes a run fully reproducible.
    seed = nil,
    -- misc
    chunkname = "input",
  }
end

config.defaults = defaults

-- Create a fresh config, overlaying any provided overrides.
function config.new(overrides)
  local c = defaults()
  if overrides then
    for k, v in pairs(overrides) do c[k] = v end
  end
  return c
end

-- Validate a config, returning (true) or (false, message).
function config.validate(c)
  local valid_targets = { ["5.1"] = true, ["5.4"] = true, ["luajit"] = true }
  if not valid_targets[c.target] then
    return false, "invalid target '" .. tostring(c.target) .. "' (expected 5.1, 5.4 or luajit)"
  end
  if c.seed ~= nil and type(c.seed) ~= "number" then
    return false, "seed must be a number"
  end
  local valid_modes = { ["error"] = true, ["lock"] = true, ["silent"] = true, ["silent-corrupt"] = true }
  if c.antitamper_mode ~= nil and not valid_modes[c.antitamper_mode] then
    return false, "invalid antitamper_mode '" .. tostring(c.antitamper_mode) ..
      "' (expected error, lock, silent or silent-corrupt)"
  end
  return true
end

-- Return the ordered list of enabled pass module names based on toggles.
-- Order matters:
--   1. virtualize      compiles selected function bodies to VM bytecode and
--                      emits their constants as ordinary string/number literals.
--   2. string_encrypt  then encrypts ALL remaining string literals, INCLUDING
--                      the constant strings the virtualize pass just emitted,
--                      so virtualized code's literals are hidden too (FEAT-002
--                      composes with FEAT-003 without special-casing).
--   3. vm_flatten      scrambles the emitted VM's own control flow (FEAT-004).
--   4. antitamper      installs active guards last (FEAT-005).
function config.enabled_passes(c)
  local passes = {}
  if c.virtualize then passes[#passes+1] = "virtualize" end
  if c.string_encrypt then passes[#passes+1] = "string_encrypt" end
  if c.vm_flatten then passes[#passes+1] = "vm_flatten" end
  if c.antitamper then passes[#passes+1] = "antitamper" end
  return passes
end

return config
