-- src/obf/passes/antitamper.lua
-- Technique 4: Anti-Debugging & Anti-Tamper (the active defense), FEAT-005.
--
-- WHAT IT DOES
-- ------------
-- Emits runtime GUARDS into the obfuscated output and weaves calls to them
-- through the virtualized code so a running program actively defends itself:
--
--   1. INTEGRITY SELF-CHECK. The virtualize pass embeds, per virtualized
--      function, an expected checksum `ck` computed at build time over that
--      function's PHYSICAL VM bytecode (proto.c). This pass emits the matching
--      checksum fold (see src/obf/checksum.lua / src/runtime/guards.lua), and
--      the VM recomputes + compares it at entry and at seed-placed dispatcher
--      checkpoints. Flipping a byte of the virtualized blob (or its embedded
--      ck) breaks the match and fires tamper_response.
--
--   2. ANTI-DEBUG. A load-time baseline of core globals + os.clock is captured;
--      the emitted anti_debug() detects a foreign debug hook (a single-stepping
--      debug.sethook driver), replaced core globals, and gross timing anomalies.
--      Thresholds are deliberately generous so an HONEST run on Lua 5.1 / 5.4 /
--      LuaJIT never trips a guard (verified by the equivalence suite running the
--      full default pipeline with antitamper ON).
--
--   3. tamper_response(reason). A single reaction point with configurable modes
--      (antitamper_mode = "error" | "lock" | "silent"). Many woven call sites
--      reference it, so there is no single point to patch out.
--
-- RANDOMIZATION (seeded, via ctx.prng / ctx.guards populated by virtualize):
--   * the checksum parameters (seed, m1, m2),
--   * which guard call sites appear and the dispatcher checkpoint period,
--   * every guard variable / function identifier.
-- Same seed reproduces output; different seeds vary placement + parameters,
-- all honest-equivalent.
--
-- DEPENDENCY / NO-OP. The active integrity + anti-debug weaving lives in the
-- VM, so it only has teeth when `virtualize` is ON (there is a VM to guard).
-- When virtualize is OFF there is no VM: this pass still emits a standalone
-- prelude guard that runs anti-debug once at load so a flat (non-virtualized)
-- output is not left entirely undefended; it records that mode in the report.
--
-- Written in Lua-5.1-compatible syntax; the emitted guards are portable across
-- Lua 5.1 / 5.4 / LuaJIT 2.1 (pure arithmetic, no bit32 / goto / 5.4-only ops).

local cipher = require("obf.cipher")

local pass = {}
pass.name = "antitamper"

-- Resolve the configured tamper-response mode to the emitted MODE string.
-- Accepts "error" (default), "lock", "silent" (alias "silent-corrupt").
local function resolve_mode(cfg)
  local m = cfg and cfg.antitamper_mode or "error"
  if m == "silent-corrupt" then m = "silent" end
  if m ~= "error" and m ~= "lock" and m ~= "silent" then m = "error" end
  return m
end

-- Emit the guard prelude using the identifiers / parameters chosen by the
-- virtualize pass (ctx.guards). Returns the source string.
local function render_guards(prng, guards, mode)
  local used = {}
  local function name(prefix)
    local nm
    repeat nm = prng:randomName(prefix) until not used[nm]
    used[nm] = true
    return nm
  end

  -- local helper identifiers
  local Nu32  = name("_gu")
  local Nmul  = name("_gm")
  local Ncorr = name("_gc")   -- corruption flag (silent mode)
  local Bt    = name("_bt")   -- baseline type
  local Bp    = name("_bp")   -- baseline pcall
  local Bs    = name("_bs")   -- baseline tostring
  local Bse   = name("_be")   -- baseline select
  local Bd    = name("_bd")   -- baseline debug table
  local Bgh   = name("_bg")   -- baseline debug.gethook
  local T0    = name("_bc")   -- baseline clock

  -- The three PUBLIC guard functions share names chosen by virtualize so the
  -- woven VM calls resolve.
  local Nfold   = guards.foldName
  local Ntamper = guards.tamperName
  local Ndebug  = guards.debugName

  -- temp loop locals
  local a, b, j = name("_a"), name("_b"), name("_j")
  local ahi, alo, hi, lo = name("_h"), name("_l"), name("_H"), name("_L")
  local x = name("_x")
  local code, ci, si, v, h, ins = name("_cd"), name("_ci"), name("_si"), name("_v"), name("_hh"), name("_in")
  local hook = name("_hk")

  local TWO32 = "4294967296"
  local SEED = string.format("%.0f", guards.seed)
  local M1 = string.format("%.0f", guards.m1)
  local M2 = string.format("%.0f", guards.m2)
  local NF = tostring(guards.nfields)

  local lines = {}
  local function L(s) lines[#lines+1] = s end

  L("-- [luaobf] embedded anti-debug / anti-tamper guards")
  -- u32
  L("local " .. Nu32 .. "=function(" .. x .. ") " ..
    x .. "=" .. x .. "-math.floor(" .. x .. "/" .. TWO32 .. ")*" .. TWO32 ..
    " if " .. x .. "<0 then " .. x .. "=" .. x .. "+" .. TWO32 .. " end return " .. x .. " end")
  -- mul32
  L("local " .. Nmul .. "=function(" .. a .. "," .. b .. ") " ..
    a .. "=" .. Nu32 .. "(" .. a .. ") " .. b .. "=" .. Nu32 .. "(" .. b .. ") " ..
    "local " .. ahi .. "=math.floor(" .. a .. "/65536) " ..
    "local " .. alo .. "=" .. a .. "-" .. ahi .. "*65536 " ..
    "local " .. hi .. "=" .. Nu32 .. "(" .. Nu32 .. "(" .. ahi .. "*" .. b .. ")*65536) " ..
    "local " .. lo .. "=" .. Nu32 .. "(" .. alo .. "*" .. b .. ") " ..
    "return " .. Nu32 .. "(" .. hi .. "+" .. lo .. ") end")
  -- baselines captured at load
  L("local " .. Bt .. "=type")
  L("local " .. Bp .. "=pcall")
  L("local " .. Bs .. "=tostring")
  L("local " .. Bse .. "=select")
  L("local " .. Bd .. "=debug")
  L("local " .. Bgh .. "=" .. Bd .. " and " .. Bd .. ".gethook")
  L("local " .. T0 .. "=os.clock()")
  L("local " .. Ncorr .. "=false")

  -- tamper_response(reason)
  if mode == "lock" then
    L("local function " .. Ntamper .. "(" .. v .. ") while true do end end")
  elseif mode == "silent" then
    L("local function " .. Ntamper .. "(" .. v .. ") " .. Ncorr .. "=true return nil end")
  else
    L("local function " .. Ntamper .. "(" .. v .. ") " ..
      "error(\"runtime error 0x\"..string.format(\"%x\",((" .. v .. " or 0)*2654435)%65536),0) end")
  end

  -- anti_debug(): low-false-positive portable checks.
  L("local function " .. Ndebug .. "() " ..
    "if type~=" .. Bt .. " or pcall~=" .. Bp .. " or tostring~=" .. Bs .. " or select~=" .. Bse .. " then " ..
    Ntamper .. "(2) return end " ..
    "if " .. Bgh .. " then local " .. hook .. "=" .. Bgh .. "() " ..
    "if " .. hook .. "~=nil then " .. Ntamper .. "(3) return end end " ..
    "if os.clock()-" .. T0 .. ">3600 then " .. Ntamper .. "(4) return end end")

  -- fold(code): integrity checksum. MUST match src/obf/checksum.lua.
  L("local function " .. Nfold .. "(" .. code .. ") " ..
    "local " .. h .. "=" .. Nu32 .. "(" .. SEED .. ") " ..
    "for " .. ci .. "=1,#" .. code .. " do " ..
    "local " .. ins .. "=" .. code .. "[" .. ci .. "] " ..
    "for " .. si .. "=1," .. NF .. " do " ..
    "local " .. v .. "=" .. ins .. "[" .. si .. "] or 0 " ..
    h .. "=" .. Nu32 .. "(" .. Nmul .. "(" .. h .. "," .. M1 .. ")+(" .. v .. "%65521)+1) " ..
    h .. "=" .. Nu32 .. "(" .. h .. "+math.floor(" .. h .. "/65536)) end " ..
    h .. "=" .. Nu32 .. "(" .. h .. "+" .. Nmul .. "(" .. ci .. ",2654435761)) end " ..
    h .. "=" .. Nu32 .. "(" .. Nmul .. "(" .. h .. "," .. M2 .. ")) " ..
    h .. "=" .. Nu32 .. "(" .. h .. "+math.floor(" .. h .. "/256)) " ..
    "return " .. Nu32 .. "(" .. h .. ") end")

  -- Run an anti-debug check once at load (prelude level) too, so even a
  -- non-virtualized output performs the environment check.
  L(Ndebug .. "()")

  return table.concat(lines, "\n")
end

-- Standalone guard prelude for the NO-VM case (virtualize off). Emits only the
-- anti-debug baseline + a one-shot check at load. Uses its own fresh names.
local function render_standalone(prng, mode)
  local used = {}
  local function name(prefix)
    local nm
    repeat nm = prng:randomName(prefix) until not used[nm]
    used[nm] = true
    return nm
  end
  local Bt, Bp, Bs, Bse = name("_bt"), name("_bp"), name("_bs"), name("_be")
  local Bd, Bgh, T0 = name("_bd"), name("_bg"), name("_bc")
  local Nt, Nd = name("_tr"), name("_td")
  local v, hook = name("_v"), name("_hk")
  local lines = {}
  local function L(s) lines[#lines+1] = s end
  L("-- [luaobf] embedded anti-debug guards (standalone)")
  L("local " .. Bt .. "=type")
  L("local " .. Bp .. "=pcall")
  L("local " .. Bs .. "=tostring")
  L("local " .. Bse .. "=select")
  L("local " .. Bd .. "=debug")
  L("local " .. Bgh .. "=" .. Bd .. " and " .. Bd .. ".gethook")
  L("local " .. T0 .. "=os.clock()")
  if mode == "lock" then
    L("local function " .. Nt .. "(" .. v .. ") while true do end end")
  elseif mode == "silent" then
    L("local function " .. Nt .. "(" .. v .. ") return nil end")
  else
    L("local function " .. Nt .. "(" .. v .. ") " ..
      "error(\"runtime error 0x\"..string.format(\"%x\",((" .. v .. " or 0)*2654435)%65536),0) end")
  end
  L("local function " .. Nd .. "() " ..
    "if type~=" .. Bt .. " or pcall~=" .. Bp .. " or tostring~=" .. Bs .. " or select~=" .. Bse .. " then " ..
    Nt .. "(2) return end " ..
    "if " .. Bgh .. " then local " .. hook .. "=" .. Bgh .. "() " ..
    "if " .. hook .. "~=nil then " .. Nt .. "(3) return end end " ..
    "if os.clock()-" .. T0 .. ">3600 then " .. Nt .. "(4) return end end")
  L(Nd .. "()")
  return table.concat(lines, "\n")
end

function pass.run(chunk, ctx)
  ctx.report = ctx.report or {}
  local prng = ctx.prng
  local mode = resolve_mode(ctx.config)

  if ctx.guards then
    -- virtualize ran with guards enabled: emit the full woven guard set with the
    -- identifiers/parameters virtualize chose, at the FRONT of the prelude so the
    -- VM's woven calls resolve as in-scope top-level locals.
    local code = render_guards(prng, ctx.guards, mode)
    ctx.prelude:register_front("antitamper.guards", code)
    ctx.report.antitamper = {
      active = true,
      mode = mode,
      woven = true,
      virtualized = (ctx.report.virtualize and ctx.report.virtualize.count) or 0,
    }
  else
    -- No VM to weave into (virtualize off). Emit a standalone load-time guard.
    local code = render_standalone(prng, mode)
    ctx.prelude:register_front("antitamper.guards", code)
    ctx.report.antitamper = {
      active = true,
      mode = mode,
      woven = false,
      virtualized = 0,
    }
  end

  return chunk
end

-- expose for tests
pass._internal = { resolve_mode = resolve_mode }

return pass
