import random
import zipfile

import Crypto.Util.number
import numpy as np
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


# Small sentences
sentences = [
    "The sun sets in the west.",
    "Birds fly high in the sky.",
    "I enjoy reading books.",
    "Coffee is my morning ritual.",
    "Rain falls gently on the roof.",
    "Children play in the park.",
    "Music soothes the soul.",
    "Stars twinkle at night.",
    "Flowers bloom in spring.",
    "Dogs are loyal companions.",
    "Laughter is contagious.",
    "Time flies when having fun.",
    "Oceans cover most of Earth.",
    "Dreams can come true.",
    "Friendship is valuable.",
    "Learning never ends.",
    "Good health is true wealth.",
    "Patience is a virtue.",
    "Knowledge is power.",
    "Honesty is the best policy.",
    "Practice makes perfect.",
    "Silence can be golden.",
    "Variety is the spice of life.",
    "Actions speak louder than words.",
    "Beauty is in the eye of the beholder.",
    "Curiosity killed the cat.",
    "Every cloud has a silver lining.",
    "Fortune favors the bold.",
    "Making haste often leads to waste.",
    "Sometimes ignorance is bliss.",
    "Apples are red and juicy.",
    "Cats purr when happy.",
    "Rivers flow to the sea.",
    "Books open new worlds.",
    "Wind blows through trees.",
    "Stars shine in the dark.",
    "Friends share secrets.",
    "Rain nourishes the earth.",
    "Mountains stand tall.",
    "Laughter fills the room.",
    "Dreams inspire action.",
    "Coffee wakes me up.",
    "Birds sing at dawn.",
    "Oceans are vast and deep.",
    "Flowers attract bees.",
    "Time heals all wounds.",
    "Music lifts the spirit.",
    "Sun warms the skin.",
    "Clouds drift lazily.",
    "Paths lead to adventure.",
    "Smiles brighten days.",
    "Leaves turn in autumn.",
    "Rivers carve canyons.",
    "Hope springs eternal.",
    "Waves crash on shore.",
    "Butterflies flutter by.",
    "Nights are for rest.",
    "Ideas spark innovation.",
    "Hugs comfort the sad.",
    "Snow covers the ground.",
    "Bridges connect places.",
    "Stories captivate minds.",
    "Fire provides warmth.",
    "Gardens grow vegetables.",
    "Echoes repeat sounds.",
    "Journeys build character.",
    "Whispers carry secrets.",
    "Thunder roars loudly.",
    "Paintings express emotions.",
    "Clocks measure time.",
    "Bees make sweet honey.",
    "Forests hide mysteries.",
    "Rivers bend and twist.",
    "Sunrises bring new days.",
    "Shadows follow light.",
    "Poems evoke feelings.",
    "Boats sail on water.",
    "Mountains challenge climbers.",
    "Rainbows follow storms.",
    "Voices sing in harmony.",
    "Trails invite exploration.",
    "Winds carry scents.",
    "Lakes reflect the sky.",
    "Fruits ripen on trees.",
    "Candles light the dark.",
    "Keys unlock doors.",
    "Mirrors show reflections.",
    "Bells ring clearly.",
    "Paths cross in life.",
    "Rivers meet the ocean.",
    "Stars guide sailors.",
    "Books hold knowledge.",
    "Winds whisper softly.",
    "Flowers bloom brightly.",
    "Dreams fuel ambitions.",
    "Laughter echoes far.",
    "Sun sets beautifully.",
    "Clouds form shapes.",
    "Birds build nests.",
    "Oceans hide treasures.",
    "Mountains inspire awe.",
    "Rain refreshes air.",
    "Friends offer support.",
    "Music plays melodies.",
    "Leaves rustle gently.",
    "Waves lap the beach.",
    "Butterflies dance lightly.",
    "Nights bring peace.",
    "Ideas change worlds.",
    "Hugs warm hearts.",
    "Snowflakes fall uniquely.",
    "Bridges span rivers.",
    "Stories teach lessons.",
    "Fire dances brightly.",
    "Gardens bloom colorfully.",
    "Echoes fade slowly.",
    "Journeys end home.",
    "Whispers intrigue listeners.",
    "Thunder startles suddenly.",
    "Paintings tell stories.",
    "Clocks tick steadily.",
    "Bees buzz busily.",
    "Forests teem with life.",
    "Rivers flow endlessly.",
    "Sunrises paint skies.",
    "Shadows lengthen evenings.",
    "Poems rhyme sweetly.",
    "Boats float gracefully.",
    "Mountains peak high.",
    "Rainbows arch gracefully.",
]


def generate_keys_and_extra(client_emails: list[str], bit_length=1024, output_zip="our_keys.zip"):
    dim = 7
    e = 65537

    with zipfile.ZipFile(output_zip, "w") as zipf:

        for email in client_emails:
            # Generate random and strong prime numbers p, q
            p = Crypto.Util.number.getStrongPrime(bit_length, e)
            q = Crypto.Util.number.getStrongPrime(bit_length, e)
            n = p * q
            phi = (p - 1) * (q - 1)
            d = Crypto.Util.number.inverse(e, phi)
            key = RSA.construct((n, e, d, p, q))

            H = [[0 for _ in range(dim)] for _ in range(dim)]
            for i in range(dim):
                for j in range(dim):
                    string_to_hash = str(i) + str(j) + email
                    h = SHA256.new()
                    h.update(bytes(string_to_hash.encode("ascii")))
                    H[i][j] = Crypto.Util.number.bytes_to_long(h.digest())

            mod = n**2

            qq01 = [2 * (dim + 1 - i) for i in range(dim)]
            vqq01 = [pow(phi, exp, mod) for exp in qq01]

            qq01 = [2 * (dim + 1 - i) - 1 for i in range(dim)]
            vqq02 = [pow(phi, exp, mod) for exp in qq01]

            all_b = []
            for i in range(dim):
                all_b.append(sum(H[i][j] * vqq01[j] for j in range(dim)) % mod)
            for i in range(dim):
                all_b.append(sum(H[i][j] * vqq02[j] for j in range(dim)) % mod)

            np_all_b = np.array(all_b)
            permutation_indices = np.random.permutation(len(np_all_b))
            shuffled_arr = np_all_b[permutation_indices]
            all_b = shuffled_arr.tolist()

            b_file_content = ""
            for val in all_b:
                b_file_content += f"b = {val}\n"
            b_file_content += f"n = {n}\n"
            b_file_content += f"e = {e}\n"

            # Client folder
            client_dir = f"clients/{email.replace('@', '_').replace('.', '_')}/"
            zipf.writestr(client_dir + email + "_b_values_and_public_key.txt", b_file_content)
            zipf.writestr(client_dir + email + "_public.pem", key.publickey().export_key("PEM"))

            # Generate and encrypt message
            selected_sentences = random.sample(sentences, 3)
            random_string = " ".join(selected_sentences)
            random_string = email + ": " + random_string
            message = random_string.encode("utf-8")

            public_key = key.publickey()
            cipher_rsa = PKCS1_OAEP.new(public_key)
            ciphertext = cipher_rsa.encrypt(message)
            zipf.writestr(client_dir + email + "_rsa_ciphertext.bin", ciphertext)

            # Our folder
            our_dir = f"our/{email.replace('@', '_').replace('.', '_')}/"
            zipf.writestr(our_dir + email + "_private.pem", key.export_key("PEM"))
            zipf.writestr(our_dir + email + "_original_message.txt", random_string)

    print(f"Everything generated and zipped in: {output_zip}")


def main() -> None:
    # Example usage: Replace with a list of emails from our clients
    client_emails = ["john.doe1@fake.com", "john.doe2@fake.com"]  # Add more
    generate_keys_and_extra(client_emails, bit_length=1024)  # Our internal RSA key generator


if __name__ == "__main__":
    main()
