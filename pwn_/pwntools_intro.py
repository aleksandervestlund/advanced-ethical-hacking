from pwn import p32, remote


P = remote("10.212.173.64", 32_179)


def main() -> None:
    for i in range(1, 201, 2):
        P.sendline(str(i).encode())

    P.sendline(b"END")

    payload = b"A" * 8

    P.send(p32(len(payload)) + payload)

    payload = b"A" * 4

    print(P.recvuntil(b"Hex:").decode())
    P.sendline(p32(42).hex().encode())

    P.recvuntil(b"Step 4 - Random numbers will be printed to you. Send back the number multiplied by 10 and xored with 7")
    P.recvline()

    while True:
        random_number = P.recvline().decode().strip()
        print(random_number)

        if "flag" in random_number:
            break

        random_number = str(int(random_number) * 10 ^ 7)

        P.sendline(random_number.encode())

    print(P.recvall().decode())

    P.interactive()


if __name__ == "__main__":
    main()
