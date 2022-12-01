# Problem Set 5

This is an extra credit assignment.

This assignment will cover the basics of EC point arithmetic.
All the math bits you need to know are described pretty
well on [wikipedia](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication).

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

1. computing multiplicative inverse
1. negating EC point
1. adding EC points
1. doubling EC point (adding itself)
1. multiplying EC point

Couple of generic hints:

- there is no division. If you see division in the formula,
  instead multiply by multiplicative inverse
- dont forget to `mod p` :allthethings:

Even though this assignment does not explicitly cover ECDH,
once you have EC point multiplication, you can see how that might
apply if you were to implement ECDH yourself :smile:
You can refer for `ps2` for some inspiration.

## Submission

Same methods apply as for the rest of the semester.
You can submit in Python or any language of your choice by using bson
for stdout and bson for stdout.

See [./ps5.py](./ps5.py) for all the function stubs.
