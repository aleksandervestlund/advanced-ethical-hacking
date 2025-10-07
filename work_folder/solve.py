from pathlib import Path

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from sympy.ntheory import factorint


work_folder = Path(__file__).parent.resolve()
PUBLIC_KEY_PATH = work_folder / "ca4054f7feb23e1bdde0ff5072d22bbe.pem"
ENCRYPTED_PATH = work_folder / "ef69cc522d4382195f202b6d09cb117f.bin"


def import_public_key() -> RsaKey:
    with PUBLIC_KEY_PATH.open("rb") as file:
        key = file.read()
        return RSA.import_key(key)


def import_ciphertext() -> bytes:
    with ENCRYPTED_PATH.open("rb") as file:
        return file.read()


def generate_private_key(public_key: RsaKey) -> RsaKey:
    n = public_key.n
    e = public_key.e
    p, q = tuple(factorint(n))
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return RSA.construct((n, e, d, p, q), consistency_check=True)


def decrypt(ciphertext: bytes, cipher: PKCS1OAEP_Cipher) -> str:
    return cipher.decrypt(ciphertext).decode()


def main() -> None:
    public_key = import_public_key()
    private_key = generate_private_key(public_key)
    cipher = PKCS1_OAEP.new(private_key)

    ciphertext = import_ciphertext()
    plaintext = decrypt(ciphertext, cipher)
    print(plaintext)


if __name__ == "__main__":
    main()
