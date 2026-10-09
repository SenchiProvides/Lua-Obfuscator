# luaobf threat model

This document states, honestly, what `luaobf` defends against, what each
technique raises the cost of, and where the limits are. The guiding principle:

> **The goal is to maximize the cost of reverse engineering and tampering. No
> running program is literally uncrackable, unpatchable, or bug-free.**

Any code a CPU can execute, a determined analyst can eventually execute, trace,
and understand. Obfuscation buys *time and effort*, not impossibility. We design
for a strong deterrent with a hard guarantee of **behavioral correctness on
honest runs**, verified on every build across Lua 5.1, Lua 5.4 and LuaJIT 2.1.

## Attacker model

We consider attackers who have the obfuscated `.lua` file and want to understand
its logic, extract embedded secrets, or modify its behavior. In rough order of
capability:

1. **Casual reader / static scraper.** Opens the file, greps for strings, URLs,
   keys, and recognizable logic; may run a Lua decompiler on bytecode.
2. **Dynamic analyst.** Runs the program under a stock interpreter with the
   `debug` library: installs `debug.sethook` to single-step or trace, dumps
   locals, prints call flow, swaps global functions to intercept calls.
3. **Patcher / tamperer.** Edits the file to change behavior — flips a constant,
   removes a check, rewrites a function — and re-runs it.
4. **Coordinated reverse engineer.** Combines all of the above over time:
   rebuilds the interpreter, stubs `debug`, lifts and replays the VM, and is
   willing to fix any self-consistency checks (e.g. recompute an embedded
   checksum after editing the data it covers).

luaobf raises the cost for attackers 1–3 significantly and raises it for 4 while
acknowledging that a sufficiently patient attacker 4 is not stopped.

## What each technique raises the cost of

### 1. Code virtualization (`src/obf/passes/virtualize.lua`)

- **Defeats:** off-the-shelf Lua decompilers and direct source reading. Critical
  functions no longer exist as Lua control flow / expressions; they are bytecode
  for a **custom, per-seed-randomized register VM** executed by an embedded
  interpreter.
- **Raises cost for:** the static reader (nothing recognizable to read) and the
  dynamic analyst (must understand a bespoke instruction set whose opcode
  numbers, operand layout and constant ordering differ per build).
- **Limit:** the interpreter is present in the file; a determined analyst can
  study it and lift the VM. Virtualized code is also much slower than native, so
  it is applied selectively (and falls back to native for unsupported
  constructs, never miscompiling).

### 2. Control-flow flattening of the VM (`src/obf/passes/vm_flatten.lua`)

- **Defeats:** easy mapping of the interpreter's own logic. The structured
  fetch/execute loop becomes a single dispatcher over a randomized next-state
  variable, with the fetch and dispatch steps split across states and
  interleaved with opaque-predicate **junk states** that never execute.
- **Raises cost for:** the analyst from technique 1 — understanding the VM now
  means untangling a maze whose textual order does not reflect execution order,
  and which differs per seed.
- **Limit:** flattening is a mechanical, behavior-preserving transform; an
  analyst who recovers the state transitions recovers the original loop. Junk
  states are dead code and add static noise, not runtime protection.

### 3. String encryption with dynamic keys (`src/obf/passes/string_encrypt.lua`)

- **Defeats:** static scraping of text, URLs, and key-like literals. String
  values are replaced by calls to an embedded decryptor; the plaintext does not
  appear in the file.
- **Raises cost for:** the static scraper especially — the decryption key is not
  stored verbatim. The per-string key seed is derived at **load time** from a
  fingerprint folded over an embedded constant table plus the string's index, so
  lifting the literal bytes alone does not yield the key.
- **Limit:** this is obfuscation, **not** secure encryption. The program must be
  able to decrypt its own strings at runtime, so a dynamic analyst can let it
  decrypt and read the results from memory. Never treat it as protection for
  secrets you cannot afford to leak.

### 4. Anti-debug / anti-tamper guards (`src/obf/passes/antitamper.lua`)

- **Defeats (common, low-effort cases):**
  - **Tampering** with virtualized bytecode: each virtualized function carries a
    build-time checksum (`ck`) over its physical bytecode; the VM recomputes and
    compares it at entry and at seed-placed checkpoints. A flipped byte breaks
    the match and triggers `tamper_response`, so the edited program cannot
    silently produce the correct output.
  - **Single-stepping debuggers:** a foreign `debug.sethook` line hook is
    detected via `debug.gethook`.
  - **Instrumentation by global replacement:** swapping `type` / `pcall` /
    `tostring` / `select` is detected against a load-time baseline.
  - **Gross timing anomalies:** absurd `os.clock` deltas (human-driven
    single-stepping) are detected with a deliberately huge threshold.
- **Reaction (`tamper_response`, configurable):** `error` (opaque error,
  non-zero exit), `lock` (benign infinite loop), or `silent`/`silent-corrupt`
  (corrupt state instead of crashing). Many woven call sites reference it, so
  there is no single patch point.
- **Low false-positive by design:** thresholds are generous enough that honest
  runs on all three runtimes never trip a guard. This is proven by the
  equivalence suite running the full default pipeline with anti-tamper on.
- **Limits:**
  - Anti-debug is **bypassable**: an attacker can stub the `debug` library, run
    under a modified interpreter, or patch out guard sites. The checks deter
    casual dynamic analysis; they do not stop a coordinated reverse engineer.
  - Integrity protection covers the **virtualized blob**. Native code and the
    guards themselves are not self-protected against an attacker who edits the
    data *and* recomputes/repairs the embedded checksum consistently.
  - The generous timing threshold that avoids false positives also means only
    gross timing anomalies are caught.

## The hard guarantee

What luaobf guarantees and tests on every build, as opposed to deters:

- **Honest-run correctness.** With the full default pipeline (all four
  techniques on), every example produces **byte-identical stdout** to the
  original under Lua 5.1, Lua 5.4 and LuaJIT 2.1.
- **Reproducibility.** The same `--seed` reproduces output byte-for-byte;
  different seeds produce different output, all honest-equivalent.
- **Safe fallback.** The virtualizer never miscompiles: unsupported constructs
  are left as native code rather than producing wrong behavior.

## Recommended use

- Virtualize the functions that actually need protection (licensing checks,
  critical algorithms), not necessarily the entire program, to limit runtime
  overhead.
- Keep real secrets server-side. Treat string encryption as anti-scraping, not
  as a vault.
- Use a fixed `--seed` for reproducible release builds; vary it between releases
  so each shipped build differs.
- Combine with out-of-band protections (server-side validation, code signing,
  licensing) — client-side obfuscation is one layer, not the whole defense.
