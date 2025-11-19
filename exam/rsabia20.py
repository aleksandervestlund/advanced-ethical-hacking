import itertools
import math
from collections.abc import Sequence
from pathlib import Path

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey


DIM = 7

SUPPORT_FOLDER = Path(__file__).parent.resolve() / "support"
EMAIL = "aleksander.t.vestlund@ntnu.no"
ENCRYPTED_PATH = SUPPORT_FOLDER / f"{EMAIL}_rsa_ciphertext.bin"
B_VALUES_PATH = SUPPORT_FOLDER / f"{EMAIL}_b_values_and_public_key.txt"


def import_ciphertext(filepath: Path) -> bytes:
    with filepath.open("rb") as file:
        return file.read()


def decrypt(ciphertext: bytes, cipher: PKCS1OAEP_Cipher) -> str:
    return cipher.decrypt(ciphertext).decode()


def extract_values(filepath: Path) -> tuple[int, int, list[int]]:
    b_values: list[int] = []
    e = 0
    n = 0

    with filepath.open(encoding="utf-8") as f:
        contents = f.readlines()

    for line in contents:
        key, val = line.split(" = ")
        i_val = int(val)

        if key == "b":
            b_values.append(i_val)
        elif key == "e":
            e = i_val
        elif key == "n":
            n = i_val

    return n, e, b_values


def calculate_values(b_values: Sequence[int], n: int) -> tuple[int, int, int]:
    modulus = n**2

    for b1, b2 in itertools.permutations(b_values, 2):
        b1_inv = pow(b1, -1, modulus)
        ratio = (b2 * b1_inv) % modulus
        phi = pow(ratio, -1, modulus)
        trace = n - phi + 1
        discriminant = trace**2 - 4 * n
        root = math.isqrt(discriminant)

        if root**2 != discriminant:
            continue

        p = (trace - root) // 2
        q = (trace + root) // 2
        return phi, p, q

    raise ValueError("Failed to find phi, p and q")


def generate_private_key(path: Path) -> RsaKey:
    n, e, b_values = extract_values(path)
    phi, p, q = calculate_values(b_values, n)
    d = pow(e, -1, phi)
    return RSA.construct((n, e, d, p, q), consistency_check=True)


def main():
    key = generate_private_key(B_VALUES_PATH)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = import_ciphertext(ENCRYPTED_PATH)
    plaintext = decrypt(ciphertext, cipher)
    print(plaintext)


if __name__ == "__main__":
    main()
