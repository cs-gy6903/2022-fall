# Problem Set 4

```
    ┌────────────────┐  ┌────────────────┐       ┌────────────────┐
    │  plaintext[0]  │  │  plaintext[1]  │  ...  │  plaintext[n]  │
    └────────────────┘  └────────────────┘       └────────────────┘
             │                   │                        │
             ▼                   ▼                        ▼
       IV   .─.                 .─.                      .─.
     ─────▶( X )    ┌─────────▶( X )       ┌───────────▶( X )
            `─'     │           `─'        │             `─'
             │      │            │         │              │
             ▼      │            ▼         │              ▼
         ┌───────┐  │        ┌───────┐     │          ┌───────┐
         │       │  │        │       │     │          │       │
         │  AES  │  │        │  AES  │                │  AES  │
    K ──▶│Encrypt│  │   K ──▶│Encrypt│    ...    K ──▶│Encrypt│
         │ Block │  │        │ Block │                │ Block │
         │       │  │        │       │     │          │       │
         └───────┘  │        └───────┘     │          └───────┘
             │      │            │         │              │
             ├──────┘            ├─────────┘              │
             │                   │                        │
             ▼                   ▼                        ▼
    ┌────────────────┐  ┌────────────────┐       ┌────────────────┐
    │ ciphertext[0]  │  │ ciphertext[1]  │  ...  │ ciphertext[n]  │
    └────────────────┘  └────────────────┘       └────────────────┘
```

Let's take a tour of a few unauthenticated block cipher modes!

Though (most) modes of block cipher operation are generalizable over any PRP,
this problem set will exclusively use AES-128. ["AES"][1] is the name of the
cipher. "128" (given in bits, i.e. 16 bytes) is the size of the key given to
that cipher. AES supports multiple key sizes, but its block size is [always 128
bits][2] (16 bytes). Internally, AES performs multiple rounds of its core
cipher logic and [expands the input key][3] to feed into each round.

These are important details for undersanding how AES works internally, but are
not directly relevant to most implementations of this problem set (other than
the key and block sizes). Most library implementations of AES will handle the
key schedule and round management for you. However, if you wish to dig deeper
and use a lower-level library, leverage [AES round CPU instructions][4], or
implement AES yourself in this problem set, you'll need to manage these
complexities.

The recommended library for python submissions can be found [here][5].

## Cheating

All the code you submit must be written by you. Submitting code written by
anyone else is cheating in the official sense. Please don't do that.

It's ok (and encouraged!) for students to work together by discussing problems
without sharing code. It's also ok to have someone look at your code to help
you debug a specific issue. But it's not ok to look at someone else's code to
copy it or to have anyone write code for you. Please don't explore the gray
area between these things.

For common operations like "open a file", "parse a JSON string", or "call a
library function", it's ok to copy two or three lines of code from
documentation, Stack Overflow, etc. But copying more than two or three lines of
code is probably not ok. If you do, you must clearly cite your source in an
inline comment that begins with COPIED. Citing your source doesn't
automatically make copying ok, but failing to cite your source turns one
violation into two violations. Please don't explore the gray area of what
counts as a "line of code".

## Problems

Note that this pset is a little different, as some of the problems require
manual inspection and validation. Gradescope will still tell you whether your
solution is functionally correct, but will you will not be attributed the
relevant points until a TA or the professor verifies that your submission does
not use libraries where forbidden (this is covered in docstring problem
definitions in [`ps4.py`](./ps4.py)). Once you've solved all problems in the
pset (or as many as you think you will be able to solve), ping one of the TAs
and they'll review the relevant problems to attribute credit appropriately.

This assignment consists of 9 problems:

1. Implement PKCS#7 padding (**requires manual validaiton**)
1. Strip PKCS#7 padding
1. Encrypt a plaintext using AES ECB
1. Decrypt a ciphertext using AES ECB
1. Encrypt a plaintext using AES CBC (**requires manual validaiton**)
1. Decrypt a ciphertext using AES CBC
1. Increment counter portion of input `iv`
1. Encrypt a plaintext using AES CTR (**requires manual validaiton**)
1. Decrypt a ciphertext using AES CTR

## Submission

You may submit this assignment in multiple ways described below.

Note that you can submit partial assignment without solving all of the problems
first. We actually encourage you to submit early and often as GradeScope will
help you testing your solutions.

### Gradescope

GradeScope uses [`pytest`][6] for the test runner. It usually shows pretty good
error messages. You can see some examples [here][7]. If youll need any help
with gradescope output, please ask in slack.

Note that we reserve the right to update GradeScope test suite as we come
across issues/bugs or find submissions which abuse things.

### Python Submission

This is the simplest approach and we recommend that most students take this
option. You simply need to submit a file named `ps4.py`. Note filename is
important. Its not `problems.py` or anything else. Its literally `filename ==
'ps4.py'`. This file should have these 9 functions defined:

- `problem1`
- `problem2`
- `problem3`
- `problem4`
- `problem5`
- `problem6`
- `problem7`
- `problem8`
- `problem9`

You can find overviews of each problem in [the `ps4.py` docstrings](./ps4.py).
Note that parameter names are important. GradeScope will call these functions
with the same parameter names as defined in the stubs. Also some of the
functions have [doctests][8] defined which provide example output functions
should produce.

GradeScope will run this code on Python3.10 so we recommend you use the same
Python version locally for development. [pyenv][9] might be of use here if you
need to manage multiple Python versions.

### Binary Submission

See prior assignment READMEs for details on binary and logistics of
submissions.

[1]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
[2]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#cite_note-blocksize-2
[3]: https://en.wikipedia.org/wiki/AES_key_schedule
[4]: https://en.wikipedia.org/wiki/AES_instruction_set
[5]: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.algorithms.AES
[6]: https://docs.pytest.org/en/7.1.x/contents.html
[7]: https://docs.pytest.org/en/7.1.x/how-to/output.html
[8]: https://github.com/cs-gy6903/resources#doctests
[9]: https://github.com/pyenv/pyenv
