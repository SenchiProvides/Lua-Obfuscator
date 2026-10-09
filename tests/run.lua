-- tests/run.lua
-- Test runner: discovers and runs all tests/test_*.lua, aggregates pass/fail,
-- and exits non-zero on any failure.
--
-- Each test file is expected to return a table { passed = N, failed = M }
-- (which is exactly what a harness Suite:summary()-style return provides via
-- the convention below).
--
-- Honors the LUA_BIN env var (consumed by equivalence tests) selecting which
-- interpreter runs the equivalence subprocesses; default lua5.1.

-- Resolve project root from this script's path.
local function dirname(p) return (string.match(p or "", "^(.*)[/\\][^/\\]+$")) end
local self = arg and arg[0] or "tests/run.lua"
local tests_dir = dirname(self) or "tests"
local root = dirname(tests_dir) or "."
if tests_dir == "." or tests_dir == "" then root = "." end

-- Expose root for test files and set module search path.
LUAOBF_ROOT = root
os.getenv = os.getenv -- (no-op, keeps linters calm)
package.path = table.concat({
  root .. "/src/?.lua",
  root .. "/src/?/init.lua",
  root .. "/tests/?.lua",
  package.path,
}, ";")

-- The ordered list of test modules. Explicit list keeps runs deterministic and
-- avoids depending on a directory-listing facility (not in stock Lua).
local TEST_FILES = {
  "test_lexer",
  "test_parser",
  "test_codegen",
  "test_random",
  "test_string_encrypt",
  "test_virtualize",
  "test_vm_selftest",
  "test_vm_flatten",
  "test_antitamper",
  "test_equivalence",
}

io.write("Running luaobf test suite\n")
io.write("  root   = " .. root .. "\n")
io.write("  LUA_BIN= " .. (os.getenv("LUA_BIN") or "lua5.1 (default)") .. "\n\n")

local total_pass, total_fail = 0, 0
local file_failures = 0

for _, name in ipairs(TEST_FILES) do
  local path = root .. "/tests/" .. name .. ".lua"
  local chunk, err = loadfile(path)
  if not chunk then
    io.write("[" .. name .. "] LOAD ERROR: " .. tostring(err) .. "\n")
    file_failures = file_failures + 1
  else
    local ok, result = pcall(chunk)
    if not ok then
      io.write("[" .. name .. "] RUNTIME ERROR: " .. tostring(result) .. "\n")
      file_failures = file_failures + 1
    elseif type(result) == "table" then
      total_pass = total_pass + (result.passed or 0)
      total_fail = total_fail + (result.failed or 0)
    else
      io.write("[" .. name .. "] WARNING: did not return a result table\n")
    end
  end
end

io.write(string.format("\n==== TOTAL: %d passed, %d failed, %d file errors ====\n",
  total_pass, total_fail, file_failures))

if total_fail > 0 or file_failures > 0 then
  os.exit(1)
end
os.exit(0)
