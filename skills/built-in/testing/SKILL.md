---
name: testing
description: "Design effective tests and decide what to test: unit vs integration, edge cases, the arrange-act-assert shape, and writing the minimal failing test for a bug. Use when users want tests for code, ask what cases to cover, want to improve coverage meaningfully, or practice TDD. Triggers on mentions of test, unit test, integration test, coverage, edge cases, TDD, assert, mock, 测试, 单元测试, 用例, 覆盖率, 边界条件."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "No external dependencies. Works on macOS, Linux, and Windows."
---

# Testing

Good tests pin down behavior and fail for one clear reason. Chase meaningful cases, not a
coverage number.

## What to test (priority order)

1. **The contract** — for each function: typical input → expected output.
2. **Edge cases** — empty, single element, very large, zero/negative, null/None, unicode,
   boundary values (off-by-one), duplicates.
3. **Error paths** — invalid input rejected, exceptions raised/handled, partial failure.
4. **Regressions** — every fixed bug gets a test that fails before the fix and passes after.
5. **Integration seams** — where modules/services meet (fewer, broader tests here).

## Shape: Arrange–Act–Assert

```python
def test_discount_caps_at_zero():
    cart = Cart(items=[Item(price=10)])   # arrange
    total = cart.total(discount=2.0)      # act  (200% off)
    assert total == 0                     # assert: never negative
```

- One behavior per test; name it after the behavior (`test_discount_caps_at_zero`).
- Make failures readable: assert on specific values, not just "truthy".

## Practical guidance

- Prefer many small fast unit tests + a few integration tests (the test pyramid).
- Keep tests deterministic: no real network/clock/randomness — inject or mock them.
- Mock at boundaries you own; don't mock the thing under test.
- For a bug: write the **minimal failing test first**, then fix until it's green.
- Run the suite to confirm, and report what passed/failed — don't claim green without running it.
