-- src/obf/lexer.lua
-- Tokenizer for a Lua 5.1 grammar superset that is also valid under Lua 5.4.
-- Written in Lua-5.1-compatible syntax so it runs on Lua 5.1, Lua 5.4 and LuaJIT 2.1.
--
-- Produces a flat stream of tokens, each a table:
--   { type = <TokenType>, value = <string|number>, line = <int> }
-- Token types: "keyword", "name", "number", "string", "op", "eof".
--
-- The lexer skips short comments ("-- ...") and long comments ("--[[ ... ]]").

local Lexer = {}
Lexer.__index = Lexer

-- Lua 5.1 reserved words. (5.4 adds "goto" as a reserved word; we treat it as a
-- keyword too so sources using it tokenize, but the parser only accepts the 5.1 subset.)
local KEYWORDS = {
  ["and"] = true, ["break"] = true, ["do"] = true, ["else"] = true,
  ["elseif"] = true, ["end"] = true, ["false"] = true, ["for"] = true,
  ["function"] = true, ["if"] = true, ["in"] = true, ["local"] = true,
  ["nil"] = true, ["not"] = true, ["or"] = true, ["repeat"] = true,
  ["return"] = true, ["then"] = true, ["true"] = true, ["until"] = true,
  ["while"] = true, ["goto"] = true,
}

-- Multi-character operators, longest first so matching is greedy.
local LONG_OPS = {
  "...", "..", "==", "~=", "<=", ">=", "::",
}

local SINGLE_OPS = {
  ["+"]=true, ["-"]=true, ["*"]=true, ["/"]=true, ["%"]=true, ["^"]=true,
  ["#"]=true, ["<"]=true, [">"]=true, ["="]=true, ["("]=true, [")"]=true,
  ["{"]=true, ["}"]=true, ["["]=true, ["]"]=true, [";"]=true, [":"]=true,
  [","]=true, ["."]=true, ["&"]=true, ["|"]=true, ["~"]=true,
}

local function is_space(c)
  return c == " " or c == "\t" or c == "\r" or c == "\n" or c == "\f" or c == "\v"
end

local function is_digit(c)
  return c >= "0" and c <= "9"
end

local function is_hex(c)
  return (c >= "0" and c <= "9") or (c >= "a" and c <= "f") or (c >= "A" and c <= "F")
end

local function is_alpha(c)
  return (c >= "a" and c <= "z") or (c >= "A" and c <= "Z") or c == "_"
end

local function is_alnum(c)
  return is_alpha(c) or is_digit(c)
end

function Lexer.new(src, chunkname)
  local self = setmetatable({}, Lexer)
  self.src = src
  self.chunkname = chunkname or "?"
  self.pos = 1
  self.len = #src
  self.line = 1
  return self
end

function Lexer:error(msg)
  error(string.format("%s:%d: lexical error: %s", self.chunkname, self.line, msg), 0)
end

function Lexer:peek(offset)
  local i = self.pos + (offset or 0)
  if i > self.len then return nil end
  return string.sub(self.src, i, i)
end

function Lexer:advance()
  local c = string.sub(self.src, self.pos, self.pos)
  self.pos = self.pos + 1
  if c == "\n" then self.line = self.line + 1 end
  return c
end

-- Attempt to read a long bracket opener [[ or [=*[ at current position.
-- Returns the level (number of '=' signs) if matched (and consumes it), else nil.
function Lexer:read_long_bracket()
  local save = self.pos
  if self:peek() ~= "[" then return nil end
  local i = self.pos + 1
  local level = 0
  while string.sub(self.src, i, i) == "=" do
    level = level + 1
    i = i + 1
  end
  if string.sub(self.src, i, i) == "[" then
    self.pos = i + 1
    return level
  end
  self.pos = save
  return nil
end

-- Read the body of a long bracket (string or comment) given its level.
function Lexer:read_long_body(level)
  -- A newline immediately after the opening bracket is skipped per Lua rules.
  if self:peek() == "\r" then self:advance() end
  if self:peek() == "\n" then self:advance() end
  local close = "]" .. string.rep("=", level) .. "]"
  local idx = string.find(self.src, close, self.pos, true)
  if not idx then
    self:error("unfinished long bracket (level " .. level .. ")")
  end
  local body = string.sub(self.src, self.pos, idx - 1)
  -- advance over body + closing bracket, counting newlines for line numbers
  local chunk = string.sub(self.src, self.pos, idx + #close - 1)
  local _, nl = string.gsub(chunk, "\n", "")
  self.line = self.line + nl
  self.pos = idx + #close
  return body
end

function Lexer:skip_whitespace_and_comments()
  while true do
    local c = self:peek()
    if c == nil then return end
    if is_space(c) then
      self:advance()
    elseif c == "-" and self:peek(1) == "-" then
      self:advance(); self:advance() -- consume "--"
      local level = self:read_long_bracket()
      if level ~= nil then
        self:read_long_body(level) -- long comment
      else
        -- short comment: to end of line
        while self:peek() ~= nil and self:peek() ~= "\n" do
          self:advance()
        end
      end
    else
      return
    end
  end
end

function Lexer:read_string_short(quote)
  local line = self.line
  self:advance() -- opening quote
  local buf = {}
  while true do
    local c = self:peek()
    if c == nil or c == "\n" then
      self:error("unfinished string")
    end
    if c == quote then
      self:advance()
      break
    elseif c == "\\" then
      self:advance()
      local e = self:peek()
      if e == nil then self:error("unfinished string escape") end
      if e == "n" then buf[#buf+1] = "\n"; self:advance()
      elseif e == "t" then buf[#buf+1] = "\t"; self:advance()
      elseif e == "r" then buf[#buf+1] = "\r"; self:advance()
      elseif e == "a" then buf[#buf+1] = "\a"; self:advance()
      elseif e == "b" then buf[#buf+1] = "\b"; self:advance()
      elseif e == "f" then buf[#buf+1] = "\f"; self:advance()
      elseif e == "v" then buf[#buf+1] = "\v"; self:advance()
      elseif e == "\\" then buf[#buf+1] = "\\"; self:advance()
      elseif e == "\"" then buf[#buf+1] = "\""; self:advance()
      elseif e == "'" then buf[#buf+1] = "'"; self:advance()
      elseif e == "\n" then buf[#buf+1] = "\n"; self:advance()
      elseif e == "\r" then
        self:advance()
        if self:peek() == "\n" then self:advance() end
        buf[#buf+1] = "\n"
      elseif e == "x" then
        self:advance()
        local h = ""
        for _ = 1, 2 do
          local d = self:peek()
          if d ~= nil and is_hex(d) then h = h .. d; self:advance() end
        end
        if h == "" then self:error("hexadecimal digit expected") end
        buf[#buf+1] = string.char(tonumber(h, 16))
      elseif is_digit(e) then
        local num = ""
        for _ = 1, 3 do
          local d = self:peek()
          if d ~= nil and is_digit(d) then num = num .. d; self:advance() else break end
        end
        local n = tonumber(num)
        if n > 255 then self:error("decimal escape too large") end
        buf[#buf+1] = string.char(n)
      elseif e == "z" then
        -- 5.2+ skip-whitespace escape; accept and skip following whitespace
        self:advance()
        while self:peek() ~= nil and is_space(self:peek()) do self:advance() end
      else
        self:error("invalid escape sequence '\\" .. tostring(e) .. "'")
      end
    else
      buf[#buf+1] = c
      self:advance()
    end
  end
  return { type = "string", value = table.concat(buf), line = line, long = false }
end

function Lexer:read_string_long(level)
  local line = self.line
  local body = self:read_long_body(level)
  return { type = "string", value = body, line = line, long = true }
end

function Lexer:read_number()
  local line = self.line
  local start = self.pos
  local c = self:peek()
  if c == "0" and (self:peek(1) == "x" or self:peek(1) == "X") then
    self:advance(); self:advance()
    while self:peek() ~= nil and (is_hex(self:peek()) or self:peek() == "." ) do
      self:advance()
    end
    -- hex float exponent (p/P)
    if self:peek() == "p" or self:peek() == "P" then
      self:advance()
      if self:peek() == "+" or self:peek() == "-" then self:advance() end
      while self:peek() ~= nil and is_digit(self:peek()) do self:advance() end
    end
  else
    while self:peek() ~= nil and is_digit(self:peek()) do self:advance() end
    if self:peek() == "." then
      self:advance()
      while self:peek() ~= nil and is_digit(self:peek()) do self:advance() end
    end
    if self:peek() == "e" or self:peek() == "E" then
      self:advance()
      if self:peek() == "+" or self:peek() == "-" then self:advance() end
      while self:peek() ~= nil and is_digit(self:peek()) do self:advance() end
    end
  end
  local text = string.sub(self.src, start, self.pos - 1)
  local n = tonumber(text)
  if n == nil then self:error("malformed number near '" .. text .. "'") end
  return { type = "number", value = n, text = text, line = line }
end

function Lexer:read_name()
  local line = self.line
  local start = self.pos
  while self:peek() ~= nil and is_alnum(self:peek()) do self:advance() end
  local text = string.sub(self.src, start, self.pos - 1)
  if KEYWORDS[text] then
    return { type = "keyword", value = text, line = line }
  end
  return { type = "name", value = text, line = line }
end

function Lexer:read_op()
  local line = self.line
  for _, op in ipairs(LONG_OPS) do
    if string.sub(self.src, self.pos, self.pos + #op - 1) == op then
      for _ = 1, #op do self:advance() end
      return { type = "op", value = op, line = line }
    end
  end
  local c = self:peek()
  if SINGLE_OPS[c] then
    self:advance()
    return { type = "op", value = c, line = line }
  end
  self:error("unexpected symbol near '" .. tostring(c) .. "'")
end

function Lexer:next_token()
  self:skip_whitespace_and_comments()
  local c = self:peek()
  if c == nil then
    return { type = "eof", value = "<eof>", line = self.line }
  end
  if c == "\"" or c == "'" then
    return self:read_string_short(c)
  end
  if c == "[" and (self:peek(1) == "[" or self:peek(1) == "=") then
    local level = self:read_long_bracket()
    if level ~= nil then
      return self:read_string_long(level)
    end
    -- otherwise it's just a '[' operator; fall through
  end
  if is_digit(c) or (c == "." and self:peek(1) ~= nil and is_digit(self:peek(1))) then
    return self:read_number()
  end
  if is_alpha(c) then
    return self:read_name()
  end
  return self:read_op()
end

-- Tokenize the whole source into a list, terminated by an eof token.
function Lexer:tokenize()
  local tokens = {}
  while true do
    local tok = self:next_token()
    tokens[#tokens+1] = tok
    if tok.type == "eof" then break end
  end
  return tokens
end

-- Convenience: tokenize a string in one call.
function Lexer.scan(src, chunkname)
  return Lexer.new(src, chunkname):tokenize()
end

return Lexer
