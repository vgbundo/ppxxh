from ._xxh32 import xxh32
from ._xxh64 import xxh64
from ._xxh3_64 import xxh3_64

# Provide a top level interface similar to the Python standard library
# module hashlib.

algorithms_guaranteed = set(["xxh32", "xxh64", "xxh3_64"])
"""A set containing the names of the algorithms provided."""

algorithms_available = set(["xxh32", "xxh64", "xxh3_64"])
"""A set containing the names of the available algorithms.

These names will be recognized when passed to ``ppxxh.new()``.
"""


# ppxxh.new() can optionally be used as an alternative to direct
# access to the class objects.
def new(name, data=b"", *, seed=0, secret=None, usedforsecurity=False):
    """Return a hash object of the type indicated by `name`.

    Parameters
    ----------
    name : `str`
        The lowercase name of the desired hash object.  See
        ``algorithms_available`` for a list of accepted values.
    data : bytes-like object, optional
        Data to update the hash object after initialization.
    seed : unsigned int, optional, default=0, keyword only
        Used to initialize the hash.  32-bit for ``xxh32``, or
        64-bit for all others.
    secret : bytes-like object, optional, keyword only
        Used to initialize the ``xxh3_64`` hash (not  allowed for
        ``xxh32`` or ``xxh64``).  Minimum length is 136 bytes. Either
        `seed` or `secret` (or neither) may be provided, but not both.
        If `secret` is provided and is not None, then `seed` will be
        ignored.  The public API of the `reference implementation`_
        provides separate functions that allow `seed`, `secret`, or
        neither to be used.
    usedforsecurity : optional, keyword only
        If True, a ``ValueError`` will be raised because these hash
        algorithms are not suitable for security use.
    """
    if usedforsecurity:
        raise ValueError("xxh* are not suitable for security uses.")
    if name == "xxh32":
        return xxh32(data, seed=seed)
    if name == "xxh64":
        return xxh64(data, seed=seed)
    if name == "xxh3_64":
        return xxh3_64(data, seed=seed, secret=secret)
    raise ValueError(name, "not found.")
