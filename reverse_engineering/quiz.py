from pwn import remote


P = remote("10.212.173.64", 32_190)


def main() -> None:
    print(P.recvuntil(b"What is the size of a char in bytes on x86_64?").decode())
    P.sendline(b"1")

    print(P.recvuntil(b"What is the size of an int in bytes on x86_64?").decode())
    P.sendline(b"4")

    print(P.recvuntil(b"Where does .text start?").decode())
    text_loc = 0x401180
    print(text_loc)
    P.sendline(str(text_loc).encode())

    print(P.recvuntil(b"What did I just push onto the stack?").decode())
    prev_stack = 0x76532918
    print(prev_stack)
    P.sendline(str(prev_stack).encode())

    print(P.recvuntil(b"What is the current value of the rbx register?").decode())
    rbx_value = 0xDEAD
    print(rbx_value)
    P.sendline(str(rbx_value).encode())

    print(P.recvuntil(b"How big is the current stackframe?").decode())
    current_stack_frame = 0x230
    print(current_stack_frame)
    P.sendline(str(current_stack_frame).encode())

    print(P.recvall().decode())

    P.interactive()


if __name__ == "__main__":
    main()
