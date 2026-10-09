-- strings.lua: string manipulation and heavy string content, deterministic.
-- Contains SECRET_MARKER so the static-leak test can prove the plaintext does
-- not survive verbatim in the obfuscated output.
local function reverse(s)
  local out = {}
  for i = #s, 1, -1 do
    out[#out + 1] = string.sub(s, i, i)
  end
  return table.concat(out)
end

local function title_case(s)
  return (string.gsub(s, "(%a)([%w]*)", function(first, rest)
    return string.upper(first) .. string.lower(rest)
  end))
end

local samples = { "hello world", "lua obfuscator", "round trip test" }
for _, s in ipairs(samples) do
  print(s .. " -> " .. reverse(s) .. " | " .. title_case(s))
end

local joined = table.concat({ "a", "b", "c", "d" }, "-")
print("joined: " .. joined)
print("len: " .. #joined)
print(string.format("fmt: %05.2f %s %d", 3.14159, "pi", 42))

-- Heavy string content: URLs, API-key-like tokens, a secret marker, and a
-- multi-line block with embedded quotes and escapes.
local config = {
  endpoint = "https://api.example.com/v1/resource?token=abc123",
  api_key  = "SECRET_MARKER-7f3a9c2e1b4d8f60",
  motd     = "line one\nline two\ttabbed\n\"quoted\" and \\backslash\\",
}
print("endpoint: " .. config.endpoint)
print("api_key: " .. config.api_key)
print("motd:\n" .. config.motd)

-- Full-byte and tricky-character strings to exercise the cipher.
local tricky = "quote=\" newline=\n tab=\t utf8=\226\152\131 nul-after=X"
print("tricky-len: " .. #tricky)
print("tricky-first: " .. string.byte(tricky, 1))

-- A string used as a dynamic table key value (encrypted, still equivalent).
local lookup = {}
lookup["dynamic key"] = "found-it"
print("lookup: " .. lookup["dynamic key"])
