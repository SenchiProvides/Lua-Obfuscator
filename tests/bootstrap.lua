-- tests/bootstrap.lua
-- Shared bootstrap for test files: makes src/ and tests/ requirable regardless
-- of the directory the runner is launched from. Returns the project root path.
--
-- Resolution strategy: use the running script's path (arg[0]) when available,
-- else fall back to the LUAOBF_ROOT env var, else the current directory.

local function dirname(p)
  return (string.match(p or "", "^(.*)[/\\][^/\\]+$"))
end

local root
local self = arg and arg[0]
if self then
  local d = dirname(self)                 -- .../tests  (or .../ for run.lua)
  if d then
    -- run.lua lives in tests/, so project root is its parent
    local parent = dirname(d) or (d .. "/..")
    -- if the script itself is tests/<file>.lua, d is tests/, parent is root
    root = parent
  end
end
root = root or os.getenv("LUAOBF_ROOT") or "."

package.path = table.concat({
  root .. "/src/?.lua",
  root .. "/src/?/init.lua",
  root .. "/tests/?.lua",
  package.path,
}, ";")

return root
