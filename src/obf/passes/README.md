# Protection passes

Each protection technique is an independent AST/codegen pass selectable via
config. A pass is a Lua module exposing:

```lua
return {
  name = "example",
  run = function(ast, ctx)
    -- transform ast in place (or return a new AST)
    -- use ctx.prng for all randomness (seeded, deterministic)
    -- use ctx.prelude:register(key, code) to inject runtime snippets once
    return ast
  end,
}
```

`ctx` is built by `src/obf/pipeline.lua` and carries:

- `ctx.config`  resolved config table (toggles, target, seed)
- `ctx.prng`    seeded `Random` instance (never use `math.random`)
- `ctx.ast`     the current AST
- `ctx.prelude` ordered, de-duplicated runtime-snippet registry
  (`register(key, code)` appends; `register_front(key, code)` prepends so a
  late pass can place definitions ahead of earlier preludes in the same chunk)
- `ctx.newName(prefix)` helper for fresh obfuscated identifiers
- `ctx.report` per-pass reporting (e.g. `ctx.report.virtualize`,
  `ctx.report.antitamper`)
- `ctx.guards` populated by `virtualize` when `antitamper` is on: the shared
  guard identifiers + checksum parameters that `antitamper` emits definitions for

The four implemented passes (run in this order, see `config.enabled_passes`):

- `virtualize.lua`     — code virtualization into a custom randomized register VM
- `string_encrypt.lua` — string encryption with runtime-derived dynamic keys
- `vm_flatten.lua`     — control-flow flattening of the emitted VM interpreter
- `antitamper.lua`     — anti-debug / anti-tamper runtime guards woven into the VM

The pipeline loads whatever passes config enables and skips modules that are not
present, so the chain degrades gracefully when techniques are disabled.
