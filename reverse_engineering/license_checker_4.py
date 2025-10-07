from pwn import p8, remote


SOLUTION = b">@-U'#01W\"jOG>6>9:2$"

ATTEMPT = b"A" * len(SOLUTION)
RESULT = b'bL"nbd,)2+<b,,bL"nbd'

CHARSET = list(range(0x20, 0x7F))
OFFSET = len(CHARSET) + 1

P = remote("10.212.173.64", 32_204)


def compute_key(attempt: bytes, result: bytes) -> bytes:
    return bytes((r - a) & 0xFF for a, r in zip(attempt, result, strict=True))


def compute_valid_license(solution: bytes, key: bytes) -> bytes:
    valid_license = b""

    for s, k in zip(solution, key, strict=True):
        license_ = (s - k) & 0xFF

        if license_ < 0x20:
            license_ += OFFSET
        elif license_ >= 0x7F:
            license_ -= OFFSET

        valid_license += p8(license_)

    return valid_license


def main() -> None:
    key = compute_key(ATTEMPT, RESULT)
    valid_license = compute_valid_license(SOLUTION, key)
    print(f"License: {valid_license.decode()}")

    P.sendline(valid_license)
    P.interactive()


if __name__ == "__main__":
    main()
