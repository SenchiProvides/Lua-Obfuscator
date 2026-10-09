-- tests/harness.lua
-- Tiny custom test harness (no external deps). Provides a Suite object with
-- assertion helpers that accumulate pass/fail counts. Each test file requires
-- this, builds a suite, and returns the suite's result counts.

local harness = {}

local Suite = {}
Suite.__index = Suite

function harness.new(name)
  return setmetatable({ name = name, passed = 0, failed = 0, failures = {} }, Suite)
end

function Suite:record_ok()
  self.passed = self.passed + 1
end

function Suite:record_fail(label, msg)
  self.failed = self.failed + 1
  self.failures[#self.failures + 1] = { label = label, msg = msg }
  io.write(string.format("  [FAIL] %s: %s\n", tostring(label), tostring(msg)))
end

-- Run a single named test function, catching errors as failures.
function Suite:test(label, fn)
  local ok, err = pcall(fn)
  if ok then
    self:record_ok()
  else
    self:record_fail(label, err)
  end
end

-- Assertions (usable inside test fns; raise on failure).
function Suite:assert_true(cond, msg)
  if not cond then error(msg or "expected true", 2) end
end

function Suite:assert_eq(got, want, msg)
  if got ~= want then
    error(string.format("%s: expected %s, got %s",
      msg or "assert_eq", tostring(want), tostring(got)), 2)
  end
end

function Suite:assert_neq(got, notwant, msg)
  if got == notwant then
    error(string.format("%s: expected value different from %s",
      msg or "assert_neq", tostring(notwant)), 2)
  end
end

-- Print a summary line and return (passed, failed).
function Suite:summary()
  io.write(string.format("[%s] %d passed, %d failed\n", self.name, self.passed, self.failed))
  return self.passed, self.failed
end

harness.Suite = Suite
return harness
