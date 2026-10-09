# Runtime templates

This directory holds Lua source templates that get embedded into obfuscated
output by the protection passes (later features):

- the VM interpreter (for the virtualization pass),
- the string decryptor (for string encryption with dynamic keys),
- the anti-tamper / anti-debug guards.

Passes register these snippets through `ctx.prelude:register(key, code)` in the
pipeline so a given runtime is emitted at most once, even when multiple passes
depend on it. The pipeline renders the prelude ahead of the transformed chunk.

FEAT-001 does not emit any runtime (identity transform); this directory and the
prelude mechanism exist so later features plug in without reworking the pipeline.
