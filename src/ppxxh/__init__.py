r"""
A Pure Python implementation of the XXHASH family of hash algorithms.

This pure python implementation of Yann Collet's XXHASH family of
non-cryptographic hash algorithms with no dependencies outside of the
python standard library is significantly slower than the
`reference implementation`_ of these hash algorithms, but they produce
the same outputs given the same inputs.

Notes
-----
``ppxxh`` is compatible with Python 3.0 and newer.

The interface and use of ``ppxxh`` is similar to the Python standard
library module ``hashlib``, while providing XXHASH hash algorithms.

Thus the various hash objects may be created using the ``ppxxh.new()``
function or directly instantiated from their classes.

.. _`reference implementation`:

The reference implementation of the XXHASH family are available at
https://github.com/Cyan4973/xxHash
"""

# All submodules are intended to be private with all api elements
# provided directly in this module or explicitly imported below.

# Provide a top level interface similar to the Python standard library
# module hashlib.
from ._top import algorithms_guaranteed
from ._top import algorithms_available
from ._top import new

# class names for hashes are all lowercase rather than Titlecase
# so that the class names match the names found in algorithms_guaranteed
# which are all lowercase to conform to hashlib.
from ._xxh32 import xxh32
from ._xxh64 import xxh64
from ._xxh3_64 import xxh3_64

__all__ = (
    "XXHASH_VERSION",
    "algorithms_guaranteed",
    "algorithms_available",
    "new",
    "xxh32",
    "xxh64",
    "xxh3_64",
)

__version__ = "0.3.0"
"""Version of the ppxxh module."""

XXHASH_VERSION = "0.8.1"
"""Compatible version of the xxHash library

Binaries compiled from the `reference implementation`_ are not used, but
output is compatible with the version of that library indicated.
"""
