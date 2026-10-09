-- src/obf/pipeline.lua
-- Orchestrates the obfuscation pipeline:
--   source -> lexer -> parser -> AST -> [passes in order] -> codegen -> source
--
-- For FEAT-001 the pass list is empty (identity transform), so the pipeline
-- exercises the full round trip and proves parse->regenerate equivalence.
--
-- Each pass is a module under src/obf/passes/ exposing:
--   pass.name            (string)
--   pass.run(ast, ctx)   -> returns the (possibly new) ast
--
-- ctx is a shared context carrying:
--   ctx.config    the resolved config table
--   ctx.prng      a seeded Random instance (deterministic per seed)
--   ctx.ast       the current AST (updated as passes run)
--   ctx.prelude   a prelude registry so passes can inject runtime snippets
--                 (VM interpreter, decryptor, guards) into the output WITHOUT
--                 duplication. Later features emit ctx.prelude:render() ahead of
--                 the transformed chunk.
--   helpers for name generation etc.

local parser = require("obf.parser")
local codegen = require("obf.codegen")
local config = require("obf.config")
local Random = require("obf.random")

local pipeline = {}

-- ---- prelude registry ----
-- A simple ordered, de-duplicated collection of named runtime snippets. Passes
-- register snippets by key; registering the same key twice is a no-op, which is
-- how later passes avoid emitting the VM/runtime more than once.
local Prelude = {}
Prelude.__index = Prelude

local function new_prelude()
  return setmetatable({ order = {}, byKey = {} }, Prelude)
end

function Prelude:register(key, code)
  if self.byKey[key] == nil then
    self.byKey[key] = code
    self.order[#self.order+1] = key
  end
  return self.byKey[key]
end

-- Register a snippet so it renders BEFORE all currently-registered snippets.
-- Used by the anti-tamper pass (which runs LAST in the pipeline) to place its
-- guard definitions ahead of the VM interpreter in the emitted chunk, so the
-- interpreter's woven checkpoint calls can reference the guard locals (they are
-- top-level locals of the same output chunk, visible to everything that follows
-- them textually). Registering an existing key is a no-op.
function Prelude:register_front(key, code)
  if self.byKey[key] == nil then
    self.byKey[key] = code
    table.insert(self.order, 1, key)
  end
  return self.byKey[key]
end

function Prelude:has(key) return self.byKey[key] ~= nil end

function Prelude:render()
  local parts = {}
  for _, key in ipairs(self.order) do
    parts[#parts+1] = self.byKey[key]
  end
  return table.concat(parts, "\n")
end

pipeline.new_prelude = new_prelude

-- Build the shared context for a run.
local function make_ctx(cfg)
  local seed = cfg.seed or 0
  local ctx = {
    config = cfg,
    prng = Random.new(seed),
    prelude = new_prelude(),
  }
  -- helper: generate a fresh obfuscated identifier
  function ctx.newName(prefix)
    return ctx.prng:randomName(prefix or "_v")
  end
  return ctx
end

pipeline.make_ctx = make_ctx

-- Load the ordered pass modules enabled by config. Missing modules (not yet
-- implemented in this feature) are skipped gracefully so the identity pipeline
-- works before FEAT-002..005 land.
local function load_passes(cfg)
  local names = config.enabled_passes(cfg)
  local passes = {}
  for _, name in ipairs(names) do
    local ok, mod = pcall(require, "obf.passes." .. name)
    if ok and type(mod) == "table" and type(mod.run) == "function" then
      passes[#passes+1] = mod
    end
  end
  return passes
end

-- Run the whole pipeline on source text, returning (obfuscated source, ctx).
-- The ctx carries ctx.report, populated by passes (e.g. the virtualize pass
-- records ctx.report.virtualize = { count, names, skipped }).
function pipeline.process_ex(src, cfg)
  cfg = cfg or config.new()
  local ok, err = config.validate(cfg)
  if not ok then error("config error: " .. err, 0) end

  local chunk = parser.parse(src, cfg.chunkname or "input")
  local ctx = make_ctx(cfg)
  ctx.ast = chunk
  ctx.report = ctx.report or {}

  local passes = load_passes(cfg)
  for _, pass in ipairs(passes) do
    local result = pass.run(ctx.ast, ctx)
    if result ~= nil then ctx.ast = result end
  end

  local body = codegen.generate(ctx.ast)
  local prelude = ctx.prelude:render()
  local out
  if prelude ~= "" then
    out = prelude .. "\n" .. body
  else
    out = body
  end
  return out, ctx
end

-- Backwards-compatible: return only the obfuscated source.
function pipeline.process(src, cfg)
  local out = pipeline.process_ex(src, cfg)
  return out
end

return pipeline
