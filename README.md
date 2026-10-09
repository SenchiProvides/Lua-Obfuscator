# luaobf — a Lua source-code obfuscator

`luaobf` is a self-hosted (written in Lua, emits Lua) source-code obfuscator and
anti-piracy code-protection tool. It parses a Lua program to an AST, runs a
configurable chain of protection passes, and regenerates runnable Lua.

It targets **Lua 5.1** primarily and also runs correctly under **Lua 5.4** and
**LuaJIT 2.1**. All obfuscator code is written in Lua-5.1-compatible syntax so it
runs on the oldest supported target, and the emitted output is validated to run
on all three.

> **Status:** feature-complete. The full compiler frontend (lexer → parser →
> AST → code generator), the seedable PRNG, the config/CLI, and the test harness
> prove parse → regenerate round-trip equivalence, and **all four protection
> techniques are implemented and ship ON by default**: code virtualization
> (technique 1), control-flow flattening of the VM (technique 2), string
> encryption with dynamic keys (technique 3), and anti-debug / anti-tamper
> guards (technique 4). Honest runs of every example produce byte-identical
> stdout under Lua 5.1, Lua 5.4 and LuaJIT 2.1 with the full pipeline on.

## Goal and honest threat model

The goal is to **raise the cost of reverse engineering and tampering** as high
as practical, through layered techniques:

1. **Code virtualization** *(implemented)* — compile critical functions into a
   custom, per-seed-randomized bytecode run by an embedded interpreter, so
   standard Lua decompilers cannot read them.
2. **Control-flow flattening** *(implemented)* — scramble the architecture of
   the embedded VM itself so its internal logic is a maze of flattened dispatch
   loops.
3. **String encryption with dynamic keys** *(implemented)* — hide string
   literals (text, URLs, keys) and derive the decryption keys at runtime from
   program state so they cannot be scraped statically.
4. **Anti-debug / anti-tamper guards** *(implemented)* — runtime checks woven
   through the VM that detect debuggers (single-stepping hooks, replaced core
   globals) or byte-level modification of the **virtualized blob** (integrity
   covers that blob, not every byte of the file) and trigger a configurable
   `tamper_response` (`error`, `lock`, or a deliberate `silent`/`silent-corrupt`
   degrade). See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the exact
   scope and reaction modes.

**Honesty note.** No obfuscator can make a running program literally
"uncrackable", "unpatchable", or "bug-free": any code that a CPU can execute, a
determined analyst can eventually execute and observe. Claims of absolute
protection are marketing, not engineering. What a good obfuscator does is make
the work expensive, slow, and error-prone enough to deter most attackers. We aim
for that, measured by automated correctness tests on every build.

## Covered Lua subset

The frontend covers the Lua 5.1 core grammar (also valid under 5.4 / LuaJIT):

- **Statements:** `local`, assignment, call, `if/elseif/else`, `while`,
  `repeat`, numeric `for`, generic `for`, function declaration, local function,
  `return`, `break`, `do` block.
- **Expressions:** `nil`/`true`/`false`, numbers (int, float, hex, exponent),
  strings (short with escapes, long brackets), vararg `...`, function literals,
  table constructors (array / `k=v` / `[expr]=expr`), binary and unary operators
  with correct precedence and associativity (including right-associative `..`
  and `^`), indexing (`a.b`, `a[b]`), calls, and method calls (`o:m(...)`).

Intentionally out of scope for the frontend: `goto`/labels, integer division
`//`, 5.4 bitwise operators in the parser, and 5.4 `<const>`/`<close>`
attributes. See the comment block at the top of `src/obf/ast.lua`.

## Install / requirements

No external Lua libraries (no luarocks/busted). You only need a stock
interpreter on your PATH:

- `lua5.1` (primary), and/or
- `lua` (5.4), and/or
- `luajit` (2.1).

## Usage

```sh
# obfuscate a file with the full default pipeline (all four techniques on)
lua bin/luaobf examples/fibonacci.lua -o out.lua

# print to stdout, reproducible with a fixed seed
lua bin/luaobf examples/fibonacci.lua --seed 1337 --stdout

# report what was protected (virtualized count, flattening, anti-tamper) to stderr
lua bin/luaobf examples/recursion.lua --report -o out.lua

# toggles: enable/disable individual techniques
lua bin/luaobf input.lua --disable string_encrypt --target 5.4 -o out.lua

# choose the anti-tamper reaction mode
lua bin/luaobf input.lua --antitamper-mode lock -o out.lua

# disable active defenses (e.g. for deterministic CI without guards)
lua bin/luaobf input.lua --disable antitamper -o out.lua
```

Run `lua bin/luaobf --help` for the full flag list.

### Config / flags

| Flag | Config key | Default | Meaning |
|------|------------|---------|---------|
| `--enable/--disable virtualize` | `virtualize` | on | Compile functions to the custom register VM (technique 1) |
| `--enable/--disable vm_flatten` | `vm_flatten` | on | Flatten the emitted VM interpreter's control flow (technique 2); no-op if `virtualize` is off |
| `--enable/--disable string_encrypt` | `string_encrypt` | on | Encrypt string values with runtime-derived keys (technique 3) |
| `--enable/--disable antitamper` | `antitamper` | on | Weave anti-debug + integrity guards into the output (technique 4) |
| `--antitamper-mode M` | `antitamper_mode` | `error` | Tamper reaction: `error` (opaque error, non-zero exit), `lock` (benign infinite loop), `silent`/`silent-corrupt` (corrupt state instead of crashing) |
| `--seed N` | `seed` | time-derived | PRNG seed; a fixed value makes output fully reproducible |
| `--target VER` | `target` | `5.1` | Target runtime: `5.1` / `5.4` / `luajit` |
| `-o FILE` / `--stdout` | — | stdout | Output destination |
| `--config FILE` | — | — | Load a Lua file returning a table of config overrides |
| `--report` | — | off | Print a protection report to stderr |

Pass order is fixed by `config.enabled_passes`: **virtualize → string_encrypt →
vm_flatten → antitamper**, so the string pass also encrypts the virtualized
bytecode's constant strings and the anti-tamper guards wrap the final VM.

### Regenerating demo outputs

`make demo` obfuscates every example with a fixed seed (`SEED`, default `1337`)
and asserts the obfuscated program reproduces the original's stdout exactly:

```sh
make demo                 # seed 1337
make demo SEED=42         # a different, still fully reproducible build
make clean                # remove the generated examples/*.obf.lua
```

The generated `examples/*.obf.lua` files are reproducible from the same seed and
are git-ignored. `make demo` is idempotent: it never re-obfuscates its own
`*.obf.lua` outputs.

## Build and test

```sh
make build                 # syntax-check all src/ and bin/ sources
make test                  # run the full suite under lua5.1 (default)
LUA_BIN=lua make test       # run under Lua 5.4
LUA_BIN=luajit make test    # run under LuaJIT 2.1
make demo                  # obfuscate examples/ and diff original vs obfuscated
make clean                 # remove generated .obf.lua / .tmp files
```

`make build` validates syntax by loading each source with the interpreter's own
`loadfile` (parse+compile without executing), so it needs no separate `luac`
binary. The equivalence suite spawns the interpreter selected by `LUA_BIN` on
both the original and obfuscated program and asserts byte-identical stdout.

## Architecture

```
source ─▶ lexer ─▶ parser ─▶ AST ─▶ [passes…] ─▶ codegen ─▶ obfuscated source
```

| File | Responsibility |
|------|----------------|
| `src/obf/lexer.lua`   | Tokenizer (keywords, names, numbers, strings, comments, operators) |
| `src/obf/parser.lua`  | Recursive-descent parser honoring precedence/associativity |
| `src/obf/ast.lua`     | AST node constructors + documented covered subset |
| `src/obf/codegen.lua` | AST → Lua source (safe requoting, value-preserving numbers, correct parens) |
| `src/obf/random.lua`  | Seedable pure-Lua PRNG (not `math.random`) |
| `src/obf/config.lua`  | Defaults, technique toggles, target version, seed |
| `src/obf/pipeline.lua`| Orchestration + prelude registry for runtime snippets |
| `src/obf/passes/`     | The four protection passes: `virtualize`, `string_encrypt`, `vm_flatten`, `antitamper` |
| `src/obf/cipher.lua`  | Pure-arithmetic stream cipher shared by build + emitted decryptor |
| `src/obf/checksum.lua`| Pure-arithmetic integrity fold shared by build + emitted guards |
| `src/runtime/`        | Canonical Lua templates embedded into output (`vm.lua`, `decryptor.lua`, `guards.lua`) |
| `bin/luaobf`          | CLI entry point |
| `tests/`              | Custom harness, unit tests, round-trip equivalence suite |
| `examples/`           | Deterministic sample programs used by the equivalence suite |

Each protection pass is a module exposing `run(ast, ctx)` where `ctx` carries the
config, the seeded PRNG, and a prelude registry so passes can inject shared
runtime code without duplication. See `src/obf/passes/README.md`.

### String encryption with dynamic keys

The `string_encrypt` pass (`src/obf/passes/string_encrypt.lua`) replaces every
string **value** in the program with a call to a small decryptor embedded at the
top of the output. Identifiers, dotted field names (`a.b`), method names
(`o:m`), and `{ k = v }` named keys are stored as plain names (not string
literals) and are left untouched, so program structure is preserved.

Keys are never written to disk. At build time each string is encrypted with a
reversible, pure-arithmetic stream cipher (XOR implemented bit-by-bit so results
are identical on 5.1 / 5.4 / LuaJIT — no `bit32`, no 5.4 bitwise operators, no
integer division). The effective per-string key seed is

```
seed = u32( salt + (index + 1) * MULA + fingerprint * MULB )
```

where `salt` is a per-build random value, `index` is the string's position, and
`fingerprint` is folded **at load time** over an embedded constant table. Because
the fingerprint is recomputed from running-program state on every load (and the
seed also depends on the string's index), the bytes on disk never contain the
key actually used to decrypt a given string — lifting the literal bytes alone is
not enough. The algorithm lives in `src/obf/cipher.lua` and is mirrored exactly
by the emitted runtime documented in `src/runtime/decryptor.lua`. With different
`--seed` values the salt, constant table, byte layout, and every emitted
decryptor identifier differ; the same seed reproduces output byte-for-byte.

### Code virtualization

The `virtualize` pass (`src/obf/passes/virtualize.lua`) compiles selected
function bodies into bytecode for a small **register virtual machine** and
replaces each such function with a thin wrapper that calls an embedded
interpreter to execute that bytecode. A decompiler then sees only the generic
interpreter plus an opaque data blob instead of the original control flow and
expressions.

- **Instruction set.** A compact register VM (`LOADK`, `MOVE`, arithmetic /
  comparison / logic ops, `CONCAT`, `NEWTABLE`/`GETTABLE`/`SETTABLE`,
  `GETGLOBAL`/`SETGLOBAL`, `CALL`, `RETURN`, `JMP`, `TEST`, `FORPREP`/`FORLOOP`,
  `TFORCALL` for generic `for`, `CLOSURE`, `VARARG`, `SELF`, `LEN`, `UNM`,
  `NOT`, …). Each opcode is documented in the pass and in the canonical runtime
  template `src/runtime/vm.lua`.
- **Covered semantics.** Lua truthiness (only `nil`/`false` are false),
  arithmetic and string↔number coercion, right-associative `..` and `^`,
  short-circuit `and`/`or`, multiple return values, varargs, numeric `for` with
  step, generic `for` over `pairs`/`ipairs`, closures that capture upvalues
  (shared mutable cells), recursion, table read/write, method calls, length,
  unary minus / `not`.
- **Correctness first — safe fallback.** The compiler supports a well-defined
  subset. If it meets **any** construct it does not fully and correctly support
  (or a function that writes to an enclosing-scope local across the
  virtualization boundary), it aborts that function and leaves it as ordinary
  native source. Virtualization coverage is never traded for correctness.
- **Per-build randomization.** The opcode numbers are a seeded permutation, the
  operand field order inside each instruction is seeded, the constant-pool order
  is shuffled, and every interpreter identifier is a fresh seeded name. Two
  different seeds therefore produce a different opcode numbering and interpreter
  shape, yet both execute identically; the same seed reproduces output exactly.
- **Composes with string encryption.** The pass runs **before** `string_encrypt`
  (see `config.enabled_passes`) and emits the bytecode constant pool as ordinary
  literals, so the string pass then encrypts the virtualized code's constant
  strings too — no special-casing required.
- **Reporting.** `--report` (or `ctx.report.virtualize`) lists how many
  functions were virtualized, so tests can assert the interpreter is actually
  exercised on the example programs.

Resistance is validated behaviorally: `tests/test_virtualize.lua` proves every
covered construct produces identical results virtualized vs native across all
three runtimes, that an unsupported construct falls back to native and stays
correct, and that different seeds stay equivalent. The emitted output also no
longer contains the original function's recognizable source structure (e.g. its
literal arithmetic expression text).

### Control-flow flattening of the VM

The `vm_flatten` pass (`src/obf/passes/vm_flatten.lua`) attacks the *second*
layer of defense: even an analyst who realizes the program runs a custom VM
must still map how that VM's interpreter works. Flattening turns the
interpreter's internal logic into a maze.

By default the virtualization pass emits a readable, structured fetch/execute
loop:

```lua
while true do
  <fetch/decode next instruction>
  if op == N then ...
  elseif op == M then ...
  end
end
```

With `vm_flatten` ON (the shipping default), the **same** interpreter is emitted
as a control-flow-**flattened state machine** instead: a single `while true do`
dispatcher over a next-state variable, where the fetch step and the dispatch
step become separate states selected by that variable, interleaved with
**opaque-predicate junk states** that are never reached at runtime. The textual
order of the states in the dispatcher no longer reflects execution order.

- **Per-build randomization (seeded via `ctx.prng`).** The state ID numbers are
  a random permutation drawn from a wide range, the order the states appear in
  the dispatcher is shuffled, the number of junk states varies, and the
  dispatcher variable names are freshly randomized. Same seed → byte-identical
  output; different seeds → a different flattened layout, both runtime-equivalent.
- **Faithful, behavior-preserving.** Flattening is a *mechanical* rewrite of the
  exact same dispatch logic: the per-opcode handler bodies are byte-for-byte
  identical between the flattened and the structured reference forms. A
  non-flattened reference interpreter stays available behind config
  (`vm_flatten = false`) so tests can diff flattened vs reference on the same
  bytecode.
- **Junk states cannot change behavior.** No real execution path ever assigns a
  junk state's ID to the state variable, so the junk/opaque states are dead code
  that only exists to inflate the maze for a static reader.
- **Dependency / no-op rule.** `vm_flatten` only has an effect when `virtualize`
  is also on — it flattens the emitted VM interpreter, so with no VM there is
  nothing to flatten. If `virtualize` is off, `vm_flatten` is a documented
  **no-op** (it records an inactive report entry and leaves the AST untouched).
- **Portability.** The flattened interpreter uses only a state variable, a
  `while true do` loop and `if/elseif` dispatch — **not** Lua `goto` (which
  5.1 lacks) — and no `bit32` / 5.4-only operators, so it runs byte-identically
  on Lua 5.1, Lua 5.4 and LuaJIT 2.1.

Validated by `tests/test_vm_flatten.lua`: the flattened interpreter matches both
the structured reference interpreter and native execution on every covered
construct; a structural assertion confirms the single dispatcher loop over a
state variable with multiple large randomized states; junk states stay inert
across many seeds; and different seeds yield different layouts that remain
runtime-equivalent.

### Anti-debug / anti-tamper guards

The `antitamper` pass (`src/obf/passes/antitamper.lua`) is the **active**
defense. It emits runtime guards (canonical template:
`src/runtime/guards.lua`) and weaves calls to them through the virtualized code
so the program defends itself while it runs. There are three parts:

- **Integrity self-check.** At build time the virtualize pass embeds, per
  virtualized function, an expected checksum `ck` folded over that function's
  **physical VM bytecode** (`src/obf/checksum.lua`). The emitted VM recomputes
  the same fold over its bytecode at entry and at seed-placed dispatcher
  checkpoints and compares it to `ck`. **Flipping a single byte of the
  virtualized blob (or of the embedded checksum) breaks the match and fires the
  tamper response** — the program cannot silently keep producing correct output.
- **Anti-debug checks.** A baseline of core globals (`type`, `pcall`,
  `tostring`, `select`), the `debug.gethook` identity, and `os.clock` are
  captured at load. The emitted `anti_debug()` detects a **foreign debug hook**
  (a single-stepping `debug.sethook` line hook installed by an analyst),
  **replaced core globals**, and **gross timing anomalies**. Thresholds are
  deliberately generous so an honest run on any supported runtime never trips a
  guard — proven by the equivalence suite running the full default pipeline.
- **`tamper_response(reason)`** — a single reaction point with configurable
  modes (`error` / `lock` / `silent`). Because many woven call sites reference
  it (every VM entry, plus the dispatcher checkpoints), there is no single point
  to patch out.

**Per-build randomization (seeded via `ctx.prng`).** The checksum parameters
(`seed`, `m1`, `m2`), the dispatcher checkpoint period, which call sites appear,
and every guard identifier differ per seed; the same seed reproduces output
exactly. **Portability:** the guards are pure arithmetic (no `bit32`, no 5.4-only
operators, no `goto`), so they run byte-identically on Lua 5.1 / 5.4 / LuaJIT.
When `virtualize` is off there is no VM to weave into, so the pass instead emits
a standalone load-time anti-debug guard.

Validated by `tests/test_antitamper.lua`: honest guarded runs are byte-identical
to the original on all three runtimes (guards silent); a byte-mutation of the
embedded bytecode aborts instead of producing the correct output; a
single-stepping `debug.sethook` driver trips the guard in error mode; several
seeds all stay honest-equivalent; and different seeds produce different guard
placement/parameters while the same seed reproduces output.

## Performance notes

Measured on the bundled examples (Lua 5.1, this sandbox; indicative, not a
benchmark):

- **Obfuscation time:** a few milliseconds per example for the full pipeline
  (e.g. `fibonacci.lua` ≈ 3 ms). It scales with program size, not runtime cost.
- **Output size:** virtualization + embedded runtimes inflate output
  substantially (e.g. `fibonacci.lua` 459 B → ~12 KB). This is expected: the VM
  interpreter, decryptor and guards are bundled once per output.
- **Runtime overhead:** virtualized functions run on an interpreted register VM,
  so they are **markedly slower** than native (often one to two orders of
  magnitude on tight numeric loops). This is the normal cost of virtualization.
  Non-virtualized code runs at native speed. For hot paths, scope virtualization
  to the functions that actually need protection rather than the whole program.
  LuaJIT narrows the gap considerably; non-JIT Lua 5.4 is the slowest target.

## Security / limitations (read this)

luaobf **raises the cost** of reverse engineering and tampering. It does **not**
make a program uncrackable, unpatchable, or bug-free, and anyone who tells you an
obfuscator can is selling something. Concrete limitations to keep in mind:

- **Determined analysts win eventually.** Any code the CPU runs can be traced,
  instrumented and understood with enough effort. Our goal is to make that
  effort large, slow and error-prone — a deterrent, not a wall.
- **Anti-debug is best-effort and bypassable.** The checks catch common,
  low-effort instrumentation (stock `debug.sethook` single-stepping, swapped
  globals). A patient attacker can stub `debug`, run under a modified
  interpreter, or patch out guard sites. We spread sites and keep them opaque to
  raise cost, not to guarantee detection.
- **Integrity checks protect the virtualized blob, not everything.** Tampering
  with virtualized bytecode is detected; native (non-virtualized) code and the
  guards themselves are not self-protected against a sufficiently coordinated
  patch that fixes both the data and its embedded checksum.
- **Low false-positive by design.** Thresholds are generous so honest runs never
  trip. That same generosity means the timing check only catches *gross*
  anomalies, not subtle ones.
- **Not a license system or a secret store.** Encrypted strings resist static
  scraping but are necessarily decryptable at runtime; do not treat obfuscation
  as encryption of secrets you cannot afford to leak.
- **Correctness is the hard guarantee.** What we *do* guarantee and test on every
  build is behavioral equivalence of honest runs across all three runtimes.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the attacker model, what
each technique raises the cost of, and the known limitations in more detail.

