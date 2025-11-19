
# RSAbia via Philadelphia

## Objective

1. You are provided with a folder with a name that is your student email as registered on Bb for TTM4536
Within your folder, you are provided with:
2. 'YOUR_EMAIL_public.pem': RSA public key,
3. An encrypted file 'YOUR_EMAIL_rsa_ciphertext.bin': OAEP-encrypted message, and
4. Some leaked b values (2*dim=14 in total, where dim=7 is defined in the provided source code in item 4).
5. Instead of constructing RSA keys where the relation between p and q is a fourth-degree polynomial, as in
   Assignment 4b, now the leaked values b are computed with the values phi^3, phi^4, ..., phi^16.
   Together with those leaked values, also the source code 'generator.py' for generating RSA keys and leaking b values
   was leaked and is provided to you.
6. The code has been tested and confirmed to work correctly in Python 3.12 and Python 3.14, as long as the requirements
   written in 'requirements.txt' are installed.

Your task is to:
To submit the full content of the decrypted file 'YOUR_EMAIL_rsa_ciphertext.bin'

## Files in Your Folder

- YOUR_EMAIL_b_values_and_public_key.txt: b = \<value> lines, plus lines for n and e.
- YOUR_EMAIL_public.pem: RSA public key.
- YOUR_EMAIL_rsa_ciphertext.bin: OAEP-encrypted file.
- generator.py: Python source code showing how the leaked values b were computed.
- requirements.txt: Python requirements.

Good luck!
