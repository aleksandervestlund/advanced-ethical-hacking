from warmup.brute_force_email import brute_force_email
from warmup.constants import BIRTHDATE
from warmup.overflow_camel import overflow_camel


def main() -> None:
    if (valid_email := brute_force_email()) is None:
        raise ValueError("No valid email found")
    if (flag := overflow_camel(valid_email)) is None:
        raise ValueError("No valid size found")

    print(f"Email: {valid_email}, Birthdate: {BIRTHDATE}, Flag: {flag}")


if __name__ == "__main__":
    main()
