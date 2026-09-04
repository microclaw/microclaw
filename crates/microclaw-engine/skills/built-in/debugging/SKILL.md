---
name: debugging
description: "A systematic method for finding the root cause of a bug, crash, error, or wrong output — reproduce, isolate, hypothesize, test, fix. Use when users report something broken, an exception/stack trace, flaky behavior, or 'why doesn't this work'. Triggers on mentions of bug, error, crash, stack trace, doesn't work, broken, exception, debug, root cause, 报错, 崩溃, 调试, 排查, 为什么不工作, 找原因."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "No external dependencies. Works on macOS, Linux, and Windows."
---

# Debugging

Don't guess-and-patch. Find the root cause first, then make the smallest fix.

## Method

1. **Reproduce reliably.** Get the exact steps, inputs, and environment that trigger it.
   A bug you can't reproduce, you can't confirm you've fixed.
2. **Read the actual error.** The stack trace usually names the file/line and the failing
   operation. Start there, not at your guess.
3. **Isolate.** Shrink the problem: comment out halves, hardcode inputs, binary-search the
   commit history (`git bisect`) or the code path until the failing piece is tiny.
4. **Form one hypothesis** about the cause, and make a prediction you can check ("if it's a
   null here, logging X will show None").
5. **Test the hypothesis** with a print/log/breakpoint or a minimal script — don't assume.
6. **Fix the cause, not the symptom.** Then re-run the reproduction to confirm it's gone,
   and check you didn't break a neighbor.
7. **Add a regression test** so it can't silently come back.

## Fast checks before deep diving

- Did it ever work? What changed (code, data, deps, env, time)? Check `git diff` / `git log`.
- Off-by-one, null/empty/zero, wrong type, wrong variable, stale cache, wrong env var.
- For "works on my machine": compare versions, paths, env vars, and locale/timezone.

## Useful instrumentation

```bash
# Narrow a flaky failure by running it many times
for i in $(seq 1 50); do <command> || { echo "failed on $i"; break; }; done
```

## Guidance

- State the root cause in one sentence before proposing the fix.
- If you can't reproduce it, say so and ask for the missing input/logs rather than guessing.
- Keep the fix minimal and explain why it addresses the cause.
