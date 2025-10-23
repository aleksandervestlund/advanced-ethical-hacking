from pathlib import Path

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from mpmath import mp


mp.prec = 100_000

a_bits = 6
aa: int = mp.power(2, a_bits)
bb: int = mp.floor(-mp.power(2, 115.4 * a_bits))
cc: int = mp.power(2, 20 * a_bits)
dd: int = mp.power(2, 30 * a_bits)
upper_bits_limit = 1_024

work_folder_2 = Path(__file__).parent.resolve()
PUBLIC_KEY_PATHS = [
    work_folder_2 / "89ac2f5d054927b31a20846eb2412e99.pem",
    work_folder_2 / "ad3d31762e209eb4520dbc2584eea37f.pem",
    work_folder_2 / "ca4054f7feb23e1bdde0ff5072d22bbe.pem",
    work_folder_2 / "e011a5a41ae8c174b2be34c138089ad8.pem",
]
ENCRYPTED_PATHS = [
    work_folder_2 / "4a77025e0c780c0cd0b56c2eb76d2ed5.bin",
    work_folder_2 / "77497066588b7e6bee6a0e386bffbaec.bin",
    work_folder_2 / "a1f34ea8878843420e5876e439241054.bin",
    work_folder_2 / "ef69cc522d4382195f202b6d09cb117f.bin",
]


def import_public_key(filepath: Path) -> RsaKey:
    with filepath.open("rb") as file:
        key = file.read()

    return RSA.import_key(key)


def import_ciphertext(filepath: Path) -> bytes:
    with filepath.open("rb") as file:
        return file.read()


def f(p: int) -> int:
    return p * (((aa * p + bb) * p + cc) * p + dd)


def generate_private_key(public_key: RsaKey) -> RsaKey:
    n = public_key.n

    low: int = 2 ** (upper_bits_limit - a_bits - 1)
    high: int = 2 ** (upper_bits_limit - a_bits) - 1

    while low <= high:
        mid = (low + high) // 2

        if f(mid) < n:
            low = mid + 1
        else:
            high = mid - 1

    p = high
    q = n // p
    phi = (p - 1) * (q - 1)
    e = public_key.e
    d = pow(e, -1, phi)
    return RSA.construct((n, e, d, p, q), consistency_check=True)


def decrypt(ciphertext: bytes, cipher: PKCS1OAEP_Cipher) -> str:
    return cipher.decrypt(ciphertext).decode()


def main() -> None:
    for public_key_path in PUBLIC_KEY_PATHS:
        public_key = import_public_key(public_key_path)
        private_key = generate_private_key(public_key)
        cipher = PKCS1_OAEP.new(private_key)

        for encrypted_path in ENCRYPTED_PATHS:
            ciphertext = import_ciphertext(encrypted_path)

            try:
                plaintext = decrypt(ciphertext, cipher)
            except ValueError:
                continue

            print(plaintext)


if __name__ == "__main__":
    main()
