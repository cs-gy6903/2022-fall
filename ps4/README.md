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

Note that this pset is a little different, as all of the problems require
manual inspection and validation for credit to be granted. Gradescope will
still tell you whether your solution is functionally correct (look for the
`PASSED`/`FAILED` output per test case), but will you will not be attributed
the relevant points until a TA or the professor verifies that your submission
does not use libraries where forbidden (this is covered in docstring problem
definitions in [`ps4.py`](./ps4.py)). Once you've solved all problems in the
pset (or as many as you think you will be able to solve), ping one of the TAs
and they'll review the relevant problems to attribute credit appropriately.

The only library function you are permitted to use is AES in ECB mode. Still,
you must iterate over the input material block-by-block to compute your answer.
"One-shot" encryptions/decryptions are not allowed and will receive 0 points.

This assignment consists of 9 problems:

1. Implement PKCS#7 padding
1. Strip PKCS#7 padding
1. Encrypt a plaintext using AES ECB
1. Decrypt a ciphertext using AES ECB
1. Encrypt a plaintext using AES CBC
1. Decrypt a ciphertext using AES CBC
1. Increment counter portion of input `iv`
1. Encrypt a plaintext using AES CTR
1. Decrypt a ciphertext using AES CTR

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
You simply need to submit a file named `ps4.py`. Note filename is important.
Its not `problems.py` or anything else. Its literally `filename == 'ps4.py'`.
This file should have these 9 functions defined:

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
Note that parameter names are important. GradeScope will call these
functions with the same parameter names as defined in the stubs.
Also some of the functions have [doctests](https://github.com/cs-gy6903/resources#doctests)
defined which provide example output functions should produce.

GradeScope will run this code on Python3.10 so we recommend you use the same
Python version locally for development.
[pyenv](https://github.com/pyenv/pyenv) might be of use here if you need to
manage multiple Python versions.

### Binary Submission

See prior assignment READMEs for details on binary and logistics of
submissions.
