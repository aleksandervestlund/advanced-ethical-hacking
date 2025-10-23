import hashlib
import itertools
import string
import timeit

from flag_07 import FLAG07


# Went to http://10.100.52.65:20930/whatever/
# Downloaded htpasswd

FLAG08 = "fea50f26be358bcc42d51daf1595394b"

PREFIX = "aleksander.t.vestlund"
SUFFIX = FLAG07[-8:]

CHARSET = string.ascii_lowercase + string.digits + string.punctuation


def brute_force_chars() -> str:
    length = 1

    while True:
        for suffix_tuple in itertools.product(CHARSET, repeat=length):
            suffix = "".join(suffix_tuple)
            candidate = PREFIX + suffix
            hash_ = hashlib.sha256(candidate.encode()).hexdigest()

            if hash_.endswith(SUFFIX):
                return candidate

        length += 1


def main() -> None:
    start_time = timeit.default_timer()
    candidate = brute_force_chars()
    # candidate = "aleksander.t.vestlund8'dwb"
    print(f"Password: {candidate}")
    print(f"Time taken: {timeit.default_timer() - start_time} seconds")


if __name__ == "__main__":
    main()
