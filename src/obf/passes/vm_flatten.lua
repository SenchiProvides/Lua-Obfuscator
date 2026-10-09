-- src/obf/passes/vm_flatten.lua
-- Technique 2: Control Flow Flattening of the VM interpreter (FEAT-004).
--
-- WHAT IT DOES
-- ------------
-- The code-virtualization pass (FEAT-003, src/obf/passes/virtualize.lua) emits
-- an embedded register-VM interpreter. By default that interpreter reads as a
-- natural, structured fetch/execute loop:
--
--     while true do
--       <fetch/decode next instruction>
--       if op == N then ...
--       elseif op == M then ...
--       end
--     end
--
-- When vm_flatten is enabled, the SAME interpreter is emitted instead as a
-- control-flow-FLATTENED state machine: a single `while true do` dispatcher
-- over a next-state variable, where the fetch step and the dispatch step become
-- separate states selected by that variable, interleaved with opaque-predicate
-- JUNK states that are never reached at runtime. The state IDs are a per-build
-- random permutation, the order the states appear in the dispatcher is
-- shuffled, and all dispatcher variable names are freshly randomized. So the
-- textual reading order of the interpreter no longer reflects its execution
-- order: mapping the VM's internal logic becomes a maze.
--
-- Crucially this is a MECHANICAL, BEHAVIOR-PRESERVING rewrite of the exact same
-- dispatch logic. The opcode handlers are byte-for-byte identical between the
-- flattened and reference forms; only the surrounding loop structure differs.
-- Junk states cannot change behavior because no real execution path ever
-- assigns a junk state ID to the state variable (they are dead code that only
-- exists to inflate the maze for a static reader).
--
-- WHERE THE WORK HAPPENS
-- ----------------------
-- The actual flattened emission lives in virtualize.lua's gen_interpreter(),
-- which takes a `flatten` flag derived from ctx.config.vm_flatten. That is the
-- cleanest home for it because the flattener must share every randomized
-- identifier, opcode number and field layout with the interpreter it is
-- rewriting. This pass module therefore performs no AST transform of its own;
-- it runs AFTER virtualize in the pipeline (see config.enabled_passes ordering)
-- and simply records a report entry and documents / enforces the dependency.
--
-- DEPENDENCY (NO-OP RULE)
-- -----------------------
-- vm_flatten only has effect when virtualize is ON. If virtualize is OFF there
-- is no embedded VM to flatten, so this pass is a documented NO-OP: it records
-- that flattening was requested but had nothing to act on, and leaves the AST
-- untouched. (Because this pass runs after virtualize, and virtualize already
-- consulted ctx.config.vm_flatten, when virtualize is on the interpreter has
-- already been emitted in flattened form by the time we run here.)
--
-- COMPATIBILITY: the flattened interpreter uses only a state variable + a
-- `while true do` loop + if/elseif dispatch (NOT Lua `goto`, which Lua 5.1 does
-- not have), and no bit32 / 5.4-only operators, so it runs byte-identically on
-- Lua 5.1, Lua 5.4 and LuaJIT 2.1.

local pass = {}
pass.name = "vm_flatten"

function pass.run(chunk, ctx)
  ctx.report = ctx.report or {}
  local virt = ctx.report.virtualize

  if not (ctx.config and ctx.config.virtualize) or virt == nil then
    -- No virtualization happened => nothing to flatten. Documented no-op.
    ctx.report.vm_flatten = {
      active = false,
      reason = "virtualize disabled (no VM to flatten)",
    }
    return chunk
  end

  -- virtualize already emitted the interpreter honoring ctx.config.vm_flatten.
  ctx.report.vm_flatten = {
    active = virt.flattened and true or false,
    virtualized = virt.count or 0,
  }
  return chunk
end

return pass
