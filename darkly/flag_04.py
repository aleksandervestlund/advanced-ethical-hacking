from flag_03 import FLAG03
from sympy.ntheory import discrete_log, nextprime


# "Survey"
# Inspect element
# Modify the "value" of the "grade" input field to the correct value

FLAG04 = "a35b30c09e3acd66f73e163e388791ff"


def main() -> None:
    p1 = 2**64
    p2 = nextprime(p1)

    m1 = int(FLAG03, 16) % p1

    grade = discrete_log(p2, m1, 2)
    # grade = 16504815726749125136
    print(grade)


if __name__ == "__main__":
    main()
