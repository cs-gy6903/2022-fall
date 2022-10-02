# Problem Set 2

This assignment will cover the basics of (finite-field) Diffie-Hellman key
agreement. While real-world key agreement has many pitfalls and edge cases,
this assignment will treat the underlying math in a simplified manner for
illustrative purposes. Please **DO NOT** use this assignment for real-world
cryptographic purposes.

See GradeScope for exact due-date of this assignment.

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

1. basic exponentiation
1. modular exponentiation
1. generate a Diffie-Hellman keypair, given an order
1. implement a parameter checker that takes as input a candidate set of
   Diffie-Hellman parameters, and returns a boolean indicating whether
   paramters are valid
1. given a public key, modulus, and base as inputs, return a generated public
   key and the shared secret

See the [Python Submission section](###Python Submission) for the easiest way
to submit your solutions, as well as further detail on input and output
formats.

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
You simply need to submit a file named `ps2.py`. Note filename is important.
Its not `problems.py` or anything else. Its literally `filename == 'ps2.py'`.
This file should have these functions defined:

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


def problem1(b: int, e: int) -> int:
    """
    Return base `b` raised to the exponent `e`

    >>> problem1(2, 3)
    8
    """


def problem2(b: int, e: int, m: int) -> int:
    """
    Return base `b` raised to the exponent `e` modulo prime modulus `m`

    >>> problem2(2, 3, 5)
    3
    """


class DHKeyPair(typing.TypedDict):
    """
    A wrapper type representing a Diffie-Hellman keypair, consisting of public
    key `A` and private exponent `a`.

    >>> DHKeyPair(a=1, A=2)
    {'a': 1, 'A': 2}
    >>> DHKeyPair({'a': 1, 'A': 2})
    {'a': 1, 'A': 2}
    """

    A: int
    a: int


def problem3(g: int, p: int) -> DHKeyPair:
    """
    Given a generator `g` and prime modulus `p`, return a valid Diffie-Hellman
    keypair under `p` and `g`. The keypair should be returned a dict with the
    private exponent `a` keyed by `'a'` and the public key `A` keyed by `'A'`.

    Recall that private exopnent `a` is computed as a random integer, and that
    public key `A` is computed as `g^a mod p`.

    # not doctest as output is random
    > problem3(7, 17)
    {'a': 8, 'A': 16}
    > problem3(7, 17)
    {'a': 12, 'A': 13}
    """


def problem4(g: int, p: int, a: int, A: int) -> bool:
    """
    Given a generator `g`, prime modulus `p`, private exponent `a`, and Alice's
    public key `A`, return a boolean indicating whether the parameter set is
    valid.

    Recall that:
        - trivial exponents (i.e. 0, 1) are invalid
        - the generator must me less than the modulus
        - private exponent `a` must be greater than generator `g` and less than
          prime modulus `p`: `g < a < p`.
        - because the public key is computed modulo `p`, it must be less than
          `p`
        - `A` must be computed as `g ^ a mod p`

    >>> problem4(5, 17, 0, 6)
    False
    >>> problem4(20, 17, 3, 6)
    False
    >>> problem4(5, 17, 3, 20)
    False
    >>> problem4(7, 17, 12, 13)
    True
    """


class DHNegotiatedSecret(typing.TypedDict):
    """
    A wrapper type representing a Diffie-Hellman secret, consisting of secret
    `s` and public key `A`.

    >>> DHNegotiatedSecret(s=1, A=2)
    {'s': 1, 'A': 2}
    >>> DHNegotiatedSecret({'s': 1, 'A': 2})
    {'s': 1, 'A': 2}
    """

    s: int
    A: int


def problem5(
    g: int, p: int, B: int, b: typing.Optional[int] = None
) -> DHNegotiatedSecret:
    """
    Given a generator `g`, prime modulus `p`, and Bob's public key `B`, first
    compute a valid Diffie-Hellman keypair for Alice consisting of public key
    `A` and private exponent `a`, using `g` and `p`. Then, using your private
    exponent `a`, compute the shared secret `s`. Return a DHNegotiatedSecret
    dict with your public key `A` keyed by `'A'` and the shared secret `s`
    keyed by `'s'`.

    Recall that Alice computes the shared secret `s` by raising Bob's public
    key `B` to their (Alice's) private exponent `a`, all modulo `p`. As an
    equation, this looks like `s = B^a mod p`.

    Please note that the optional parameter `b` is **not required for your
    solution**, and is only there for use by the auto-grader.

    # not doctest as output is random
    > problem5(5, 17, 9)
    {'A': 4, 's': 16}
    > problem5(5, 17, 9)
    {'A': 10, 's': 2}
    """
```

### Binary Submission

If you feel adventurous, you can submit this assignment as an executable file
therefore allowing you to solve it in any other language.
Rust, C, C++, Java, JavaScript, even bash, etc can be used.
Note that GradeScope runs Ubuntu22.04 so the executable needs
to be POSIX-compatible and therefore no Windows executables.

To do that, you will need to submit either:

- script file with valid shebang. For example `ps2`, `ps2.sh`, `ps2.js`, etc.
  By script file we mean here the file is plain text file (not binary).
- compile an actual binary executable named `ps2` from submitted source code
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
