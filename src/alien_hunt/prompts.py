"""What a claim must look like: told to the model here, and enforced by confirm.py."""

from __future__ import annotations

MARKER = "DEFECT-OBSERVED"

# A reproducer may not use these: they read source text or get around the trace.
BLOCKED_MODULES = frozenset({"ast", "ctypes", "dis", "inspect", "linecache", "tokenize", "__main__"})
BLOCKED_ATTRS = frozenset(
    {("os", "_exit"), ("sys", "gettrace"), ("sys", "modules"), ("sys", "setprofile"), ("sys", "settrace")}
)

_BLOCKED = ", ".join(sorted(BLOCKED_MODULES) + [".".join(pair) for pair in sorted(BLOCKED_ATTRS)])

CLAIM_RULES = f"""Each claim needs text, class, files, functions, and a Python reproducer.
functions are dotted names such as pkg.module.func or pkg.module.Class.method (a constructor is Class.__init__). Name at least one: the run traces the reproducer, and a claim whose named functions were not entered is refused.
The reproducer must import the repository and call the function under test.
It prints {MARKER} to stdout from an if or except branch, with that text written in the print call, and exits 0, only when that call showed the defect. In every other case it exits 1.
The branch tests the defect itself: what the code promises against what it did. A script that only calls the function and exits 0 is refused, and `if __name__ == "__main__"` is not a branch.
Do not open the repository's .py files from the reproducer, and do not use {_BLOCKED}.
"""
