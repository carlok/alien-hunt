"""Fixture library with two planted defects.

`load_config` unpickles caller bytes. `allocate` documents a length it does not keep.
"""

import pickle


def load_config(blob: bytes):
    """Load a configuration blob supplied by the caller."""

    return pickle.loads(blob)


def allocate(n: int) -> list[int]:
    """Return a list of n zeros. n must be >= 0.

    The result length equals n.
    """

    if n > 0:
        return [0] * n
    return [0]
