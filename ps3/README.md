# Problem Set 3

Hash :allthethings: :D

## Cheating

All the code you submit must be written by you. Submitting code written by
anyone else is cheating in the official sense. Please don't do that.

It's ok (and encouraged!) for students to work together by discussing problems
without sharing code. It's also ok to have someone look at your code to help
you debug a specific issue. But it's not ok to look at someone else's code to
copy it or to have anyone write code for you. Please don't explore the gray
area between these things.

For common operations like "open a file", "parse a JSON string", or "call
a library function", it's ok to copy two or three lines of code from
documentation, Stack Overflow, etc. But copying more than two or three lines
of code is probably not ok. If you do, you must clearly cite your source
in an inline comment that begins with COPIED. Citing your source doesn't
automatically make copying ok, but failing to cite your source turns one
violation into two violations. Please don't explore the gray area of what
counts as a "line of code".

## Problems

This assignment consists of 5 problems:

1. Generate SHA1 hash
1. Generate SHA256 hash
1. Verifying [SHAttered](https://shattered.io/) collision
1. Applying length-extension attack to SHA256
1. Generating HMAC with SHA256

## Submission

You may submit this assignment in multiple ways described below.

Note that you can submit partial assignment without solving all of
the problems first. We actually encourage you to submit early and often as
GradeScope will help you testing your solutions.

### Gradescope

GradeScope uses [`pytest`](https://docs.pytest.org/en/7.1.x/contents.html)
for the test runner. It usually shows pretty good error messages.
You can see some examples [here](https://docs.pytest.org/en/7.1.x/how-to/output.html).
If youll need any help with gradescope output, please ask in slack.

Note that we reserve the right to update GradeScope test suite as we come
across issues/bugs or find submissions which abuse things.

### Python Submission

This is the simplest approach and we recommend that most students take this option.
You simply need to submit a file named `ps3.py`. Note filename is important.
Its not `problems.py` or anything else. Its literally `filename == 'ps3.py'`.
This file should have these 5 functions defined:

- `problem1`
- `problem2`
- `problem3`
- `problem4`
- `problem5`

Yes we know this is very creative naming but it keeps things simple :D

Below you will find type-annotated stubs of the functions you need to implement.
You can copy-paste these stubs into `ps2.py` to get you started.
Note that parameter names are important. GradeScope will call these
functions with the same parameter names as defined in the stubs.
Also some of the functions have [doctests](https://github.com/cs-gy6903/resources#doctests)
defined which provide example output functions should produce.

GradeScope will run this code on Python3.10 so we recommend you use the same
Python version locally for development.
[pyenv](https://github.com/pyenv/pyenv) might be of use here if you need to
manage multiple Python versions.

```python
import typing


def problem1(data: bytes) -> bytes:
    """
    Compute SHA1 hash of data

    >>> problem1(b'hello').hex()
    'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
    """


def problem2(data: bytes) -> bytes:
    """
    Compute SHA256 hash of data

    >>> problem2(b'hello').hex()
    '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    """


class SHAttered(typing.TypedDict):
    """
    Hashes of proof PDFs from https://SHAttered.io/

    This clearly illustrates SHA1 should no longer be used
    for cryptography-sensesitive applications as SHA1 collissions
    have been found. Both blue and red PDFs have same SHA1 hash.

    Note that SHA256 is still safe. The same PDFs produce
    different SHA256 hashes as expected.
    """

    blue_pdf_sha1: bytes
    blue_pdf_sha256: bytes

    red_pdf_sha1: bytes
    red_pdf_sha256: bytes


def problem3() -> SHAttered:
    """
    Provide SHA1 and SHA256 hashes of https://SHAttered.io/ PDFs

    Note this function accepts no input. You can compute the hashes either:

    * hardcode hash values as PDFs are known hashes
    * compute hash by downloading the pdfs (e.g. with requests library)

    >>> hashes = problem3()
    >>> hashes['blue_pdf_sha1'] == hashes['red_pdf_sha1']
    True
    >>> hashes['blue_pdf_sha256'] == hashes['red_pdf_sha256']
    False
    """


def sha256_padding(length: int) -> bytes:
    """
    Get the padding for SHA256

    SHA256 works on consistent length blocks.
    If the data is not of the same block, it needs to padded
    so that SHA256 can be computed.

    The padding scheme is as follows:

    * add single 1-bit to input
    * add X variable number of 0-bits
    * add 64 bits (8 bytes) big-endian original message length

    The X variable number of bits is adjusted to make the padded
    message be 64 bytes long (SHA256 block size).
    """
    # for the mod its +8, not +9 (0x80 byte and 8 length bytes)
    # since otherwise 64 % 64 = 0 which means we subtract 0
    # and would pad with 64 bytes even though 0 are necessary
    zero_bytes = 64 - 1 - (length + 8) % 64
    return b"\x80" + b"\x00" * zero_bytes + (length * 8).to_bytes(8, "big")


def problem4(length: int, hash: bytes, suffix: bytes) -> bytes:
    """
    Apply length extension attack to SHA256 hash

    After above SHAttered you might think SHA256 is the perfect hash function.
    Lets break it thought with length extension attack!
    Length extension attack is applicable to any hash function
    using Merkle–Damgård construction.
    https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction

    Other hash functions which use different construction methods
    are not vulnerable. For example:

    * SHA3 is not vulnerable as it uses Sponge construction
      https://en.wikipedia.org/wiki/Sponge_function
    * BLAKE-family of hash functions is not vulnerable as it uses HAIFA construction
      https://en.wikipedia.org/wiki/HAIFA_construction

    Some background:

    * SHA256 pads messages in order to make them fit SHA256 block size
    * padding scheme is public (see above for implementation)
    * SHA256 has internal state. By "hashing" things, SHA256
      internally "scrambles" its state.
    * To hash longer inputs, SHA256 iterates over input by
      64 byte blocks and for each iteration keeps "scrambling" its state.
    * The resulting SHA256 hash is simply its state serialized to bytes
    * Note that last block does not do anything special

    To visualize that:

       ┌─────────────────────────────────────┬─────────────────┐
       │                input                │     padding     │
       ├───────────────────────────┬─────────┴─────────────────┤
       │           block           │           block           │
                     │                           │
                     ▼                           ▼
     initial   ┌──────────┐                ┌──────────┐
      state    │  SHA256  │                │  SHA256  │
    ──────────▶│  block   │        ┌──────▶│  block   │
               └──────────┘        │       └──────────┘
                     │   updated   │             │
                     │    state    │             ▼
                     └─────────────┘       ┌──────────┐
                                           │  SHA256  │
                                           │ hash of  │
                                           │  input   │
                                           └──────────┘

    Given last block of SHA256 does not do anything special and that the hash
    is simply the last state, we can use that to "extend" the hash.
    Lets say if we wanted now to hash new input consisting of:

    * old input
    * old input padding
    * additinal suffix

    To do that we can simply restore the SHA256 state from the given input hash
    which already contains both the original input and its padding.
    Once the state is restored, we can continue with SHA256 blocks as usual
    to hash rest of the blocks containing the new suffix.

       ┌─────────────────────────────────────┬─────────────────┬────────┬──────────────────┐
       │                input                │     padding     │ suffix │  suffix padding  │
       ├───────────────────────────┬─────────┴─────────────────┼────────┴──────────────────┤
       │           block           │           block           │           block           │
                     │                           │                           │
                     ▼                           ▼                           ▼
     initial   ┌──────────┐                ┌──────────┐                ┌──────────┐
      state    │  SHA256  │                │  SHA256  │                │  SHA256  │
    ──────────▶│  block   │        ┌──────▶│  block   │        ┌──────▶│  block   │
               └──────────┘        │       └──────────┘        │       └──────────┘
                     │   updated   │             │             │             │
                     │    state    │             ▼     restore │             │
                     └─────────────┘       ┌──────────┐ state  │             ▼
                                           │  SHA256  │        │       ┌──────────┐
                                           │ hash of  │ ───────┘       │  SHA256  │
                                           │  input   │                │ hash of  │
                                           └──────────┘                │  input   │
                                                                       │ +padding │
                                                                       │ +suffix  │
                                                                       └──────────┘

    To implement this in Python, the SHA256 implementation needs to allow
    to restore the internal SHA256 state. Python stdlib hashlib does not allow
    to do that. You can use https://pypi.org/project/sha256/ instead.
    It is preinstalled in Gradescope.

    > import sha256
    > h = sha256.sha256()
    > h.state = (b'oldhash', old_length + padding_length)

    This library does not have much documentation or examples in the README,
    however after the state is restored, it is very similar to native hashlib
    in its usage. Also feel free to check out its source code in GitHub.

    The input you will receive will be:

    * old input length (you do not actually need full input value)
    * SHA256 hash of the input
    * new suffix to extend the hash with

    >>> original_data = b'hello'
    >>> original_data_padded = original_data + sha256_padding(len(original_data))
    >>> extended_data = original_data_padded + b'world'

    >>> reference_hash = problem2(extended_data)
    >>> reference_hash.hex()
    '383b468b32a3705237b55d28a5440c77bda8b3b356cf8c6cfeeb69f305712df3'

    >>> extended_hash = problem4(len(original_data), problem2(original_data), b'world')
    >>> extended_hash.hex()
    '383b468b32a3705237b55d28a5440c77bda8b3b356cf8c6cfeeb69f305712df3'

    >>> reference_hash == extended_hash
    True
    """


def problem5(key: bytes, data: bytes) -> bytes:
    """
    HMAC given data with the provided key using SHA256

    >>> problem5(b'secret', b'data').hex()
    '1b2c16b75bd2a870c114153ccda5bcfca63314bc722fa160d690de133ccbb9db'
    """
```

### Binary Submission

If you feel adventurous, you can submit this assignment as an executable file
therefore allowing you to solve it in any other language.
Rust, C, C++, Java, JavaScript, even bash, etc can be used.
Note that GradeScope runs Ubuntu22.04 so the executable needs
to be POSIX-compatible and therefore no Windows executables.

To do that, you will need to submit either:

- script file with valid shebang. For example `ps3`, `ps3.sh`, `ps3.js`, etc.
  By script file we mean here the file is plain text file (not binary).
- compile an actual binary executable named `ps3` from submitted source code
  via `setup.sh` (see below).
  Note that you CANNOT submit binary file directly as its source-code
  will not be accessible. The binary needs to be compiled in GradeScope
  from submitted source code.

In either case the executable will have to do the following:

- accept `bson` input via `stdin`
- produce `bson` output to `stdout`

[`BSON`](https://www.mongodb.com/basics/bson) is used to explicitly allow binary
data in both input and output without any additional steps like hex encoding.

`BSON` input will be of the following structure:

- keys are the same as python function names described above
- for each key, value is a dictionary with parameters for the function
  as defined above.

For example for a single function defined as:

```python
def foo(a: int, b: str): pass
```

then the BSON input will be something like (represented as json here for clarity):

```json
{
  "foo": {
    "a": 1,
    "b": "test"
  }
}
```

`BSON` output will be of the following structure:

- keys are the same as python function names described above
- for each key, value is the return value of the function as described above

In other words, for each function described above bson input via stdin will
provide the function parameters and bson output to stdout should provide
function return values.

This way the data-structures between Python submission and binary submission
are interchangeable. As a matter of fact you can even generate bson input/output
in python via [`simple_bson`](https://pypi.org/project/simple-bson/):

```python
import sys
import simple_bson

# problem functions defined here

if __name__ == "__main__":
    inputs = simple_bson.loads(sys.stdin.buffer.read())
    solutions = {k: globals()[k](**v) for k, v in inputs.items()}
    sys.stdout.buffer.write(simple_bson.dumps(solutions))
```

Also see provided example bson files:

- `bson.in`
- `bson.out`

### `setup.sh`

If you submit `setup.sh` along with your submission, this is a hook script
which should allow you to:

- install additional dependencies if you need to although this assignment
  should not require any external libraries and standard library should be
  sufficient.
- install necessary system dependencies in order to compile binary
  solution from submitted source code

This should just be a simple bash script:

```bash
#!/usr/bin/env bash
# do things here
```
