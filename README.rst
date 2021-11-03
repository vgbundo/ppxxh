======
 ppxxh
======

ppxxh is a Pure Python implementation of the XXHASH family of hash
algorithms.

This pure python implementation of
`Yann Collet's XXHASH <https://github.com/Cyan4973/xxHash>`_ family of
non-cryptographic hash algorithms with no dependencies outside of the
python standard library is significantly slower than version 0.8.1 of
the `reference implementation`_ of these hash algorithms, but they
produce the same outputs given the same inputs. This equality of outputs
is checked with tests that duplicate portions of `xsum_sanity_check.c`
from the `reference implementation`_.

``ppxxh`` is compatible with Python 3.0 and newer.

The interface and use of ``ppxxh`` is similar to the Python standard
library module ``hashlib``, while providing XXHASH hash algorithms.
Thus the various hash objects may be created using the **ppxxh.new()**
function or directly instantiated from their classes.

Hash Methods
------------
The hash objects have these common methods:

update(data)
    Update the state of the hash object. Data may be passed to the hash
    object at initialization and/or by an arbitrary number of calls to
    **update()**.
digest()
    Return the hash digest as a bytes object.
hexdigest()
    Return the hash digest as a string of hexidecimal digits.
intdigest()
    Return the hash digest as an unsigned integer.

    This method is not part of the ``hashlib`` interface but is the
    typical output format of the `reference implementation`_ (except for
    xxh3_128)
copy()
    Return a copy (clone) of the hash object.

The ``xxh3_128`` hash objects also have a **intdigest2()** method that
returns the hash digest as a pair of 64-bit unsigned integers matching
the typical output format of the `reference implementation`_ for this
hash algorithm

As listed in **ppxxh.algorithms_guaranteed** and
**ppxxh.algorithms_guaranteed**, the hash algorithms provided are
**xxh32**, **xxh64**, **xxh3_64**, and **xxh3_128**.

The **ppxxh.generate_secret()** function duplicates the
``XXH3_generateSecret()`` function provided by the
`reference implementation`_ to use a low entropy bytes like object
of arbitrary length to generate a high entropy secret well suited to use
as the `secret` parameter of ``xxh3_64`` and ``xxh3_128``.

Example
-------
Calculate the digest in various forms for the bytes object,
``b'This is a bytes object, not a string!'``.  Specify a `seed`
value.  If this optional value were not provided, the hash object
would be initialized differently and the various resulting digest
values would all be different.

    >>> from ppxxh import xxh64
    >>> m = xxh64(seed=14414669413082423462)  # seed is optional
    >>> m.name
    'xxh64'
    >>> m.digest_size
    8
    >>> m.block_size
    32
    >>> m.update(b'This is a bytes')
    >>> m.hexdigest()  # a digest may be requested at any time
    '938907256708f46c'
    >>> m.update(b' object, not a string!')
    >>> m.digest()
    b'!^>f7\x84Ii'
    >>> m.hexdigest()
    '215e3e6637844969'
    >>> m.intdigest()
    2404427859801426281

A more condensed way to get the same result.

    >>> xxh64(b'This is a bytes object, not a string!',
    ...       seed=14414669413082423462).hexdigest()
    '215e3e6637844969'


.. _`reference implementation`:

The reference implementation of the XXHASH family are available at
https://github.com/Cyan4973/xxHash

(Python code formatted by ``black -l 79``)

Licensed under `MIT License <http://github.com/vgbundo/ppxxh/LICENSE>`_
